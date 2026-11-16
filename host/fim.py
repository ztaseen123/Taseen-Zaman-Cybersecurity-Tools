#!/usr/bin/env python3
"""
fim - small file integrity monitor.

    fim.py init   -b /var/lib/fim/etc.json /etc /usr/local/bin
    fim.py check  -b /var/lib/fim/etc.json
    fim.py update -b /var/lib/fim/etc.json        # accept current state

Records sha256, mode, owner, size and mtime for everything under the given
paths and reports what changed since. If FIM_KEY (or --keyfile) is set the
baseline is signed with HMAC-SHA256, so someone who can rewrite the baseline
but doesn't have the key can't quietly bless their own changes. Keep the key
off the box you are monitoring, or at least out of reach of the account
you're worried about.

exit: 0 clean, 1 changes found, 2 usage/IO error, 3 baseline failed its HMAC
"""

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import socket
import stat
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

VERSION = 1
CHUNK = 1 << 20


def log(msg):
    print(f"fim: {msg}", file=sys.stderr)


def die(msg, code=2):
    log(msg)
    sys.exit(code)


def sha256(path):
    h = hashlib.sha256()
    # O_NOFOLLOW: if a file was swapped for a symlink between the lstat and
    # here, fail instead of hashing whatever it points at.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def walk(roots, excludes):
    """Yield (path, lstat) for every entry under roots. Never follows links."""
    def skip(p):
        return any(fnmatch.fnmatch(p, pat) for pat in excludes)

    for root in roots:
        root = os.path.abspath(root)
        if skip(root):
            continue
        try:
            st = os.lstat(root)
        except OSError as e:
            log(f"{root}: {e.strerror}")
            continue
        yield root, st
        if not stat.S_ISDIR(st.st_mode):
            continue
        for dirpath, dirs, files in os.walk(root, onerror=lambda e: log(f"{e.filename}: {e.strerror}")):
            dirs[:] = [d for d in dirs if not skip(os.path.join(dirpath, d))]
            for name in dirs + files:
                p = os.path.join(dirpath, name)
                if skip(p):
                    continue
                try:
                    yield p, os.lstat(p)
                except OSError as e:
                    log(f"{p}: {e.strerror}")


def snapshot(roots, excludes, jobs, old=None, quick=False):
    """-> {path: record}"""
    entries = {}
    to_hash = []
    for path, st in walk(roots, excludes):
        rec = {
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
        }
        if stat.S_ISREG(st.st_mode):
            rec.update(type="f", size=st.st_size, mtime=st.st_mtime_ns)
            prev = old.get(path) if old else None
            if (quick and prev and prev.get("type") == "f"
                    and prev["size"] == rec["size"] and prev["mtime"] == rec["mtime"]):
                rec["sha256"] = prev["sha256"]
            else:
                to_hash.append(path)
        elif stat.S_ISLNK(st.st_mode):
            rec.update(type="l", target=os.readlink(path))
        elif stat.S_ISDIR(st.st_mode):
            rec["type"] = "d"
        else:
            # sockets, fifos, device nodes. Don't open them (a fifo with no
            # writer blocks forever) but do notice if one appears or changes.
            rec.update(type="o", fmt=stat.S_IFMT(st.st_mode), rdev=st.st_rdev)
        entries[path] = rec

    def job(p):
        try:
            return p, sha256(p)
        except OSError as e:
            log(f"{p}: {e.strerror}")
            return p, None

    # hashlib drops the GIL on large updates so threads do help here
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for path, digest in pool.map(job, to_hash):
            entries[path]["sha256"] = digest
    return entries


def mac(key, body):
    # sort_keys + fixed separators so the bytes are the same on every run
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, blob, hashlib.sha256).hexdigest()


def load_key(args):
    if args.keyfile:
        with open(args.keyfile, "rb") as fh:
            key = fh.read().strip()
    else:
        key = os.environ.get("FIM_KEY", "").encode()
    if key and len(key) < 16:
        die("key is too short to be worth anything, use 16+ bytes")
    return key or None


def save(path, body, key):
    doc = {"body": body}
    if key:
        doc["hmac"] = mac(key, body)
    d = os.path.dirname(os.path.abspath(path))
    # temp file + rename: a crash mid-write must not leave a half baseline
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".fim-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def load(path, key):
    with open(path) as fh:
        doc = json.load(fh)
    body = doc["body"]
    if body.get("version") != VERSION:
        die(f"{path}: baseline version {body.get('version')}, expected {VERSION}")
    signed = "hmac" in doc
    if signed and not key:
        log("baseline is signed but no key given")
        sys.exit(3)
    if key and not signed:
        # an attacker stripping the hmac field must not downgrade us
        log("key given but baseline is unsigned")
        sys.exit(3)
    if signed and not hmac.compare_digest(doc["hmac"], mac(key, body)):
        log(f"{path}: HMAC mismatch, baseline was modified or the key is wrong")
        sys.exit(3)
    return body


def fmt_mode(m):
    return format(m, "04o")


def diff(old, new):
    """-> list of (kind, path, detail). kind is added/removed/content/meta."""
    out = []
    for path in sorted(old.keys() | new.keys()):
        a, b = old.get(path), new.get(path)
        if a is None:
            detail = f"mode {fmt_mode(b['mode'])} uid {b['uid']}"
            if b["mode"] & (stat.S_ISUID | stat.S_ISGID) and b["type"] == "f":
                detail += "  ** setuid/setgid **"
            out.append(("added", path, detail))
            continue
        if b is None:
            out.append(("removed", path, ""))
            continue
        if a["type"] != b["type"]:
            out.append(("content", path, f"type {a['type']} -> {b['type']}"))
            continue
        if a["type"] == "f" and a.get("sha256") != b.get("sha256"):
            if b.get("sha256") is None:
                out.append(("content", path, "unreadable now"))
            else:
                out.append(("content", path, f"sha256 {str(a.get('sha256'))[:12]} -> {b['sha256'][:12]}"))
        elif a["type"] == "l" and a["target"] != b["target"]:
            out.append(("content", path, f"link {a['target']} -> {b['target']}"))
        elif a["type"] == "o" and (a["fmt"], a["rdev"]) != (b["fmt"], b["rdev"]):
            out.append(("content", path, "special file changed"))

        meta = []
        if a["mode"] != b["mode"]:
            note = f"mode {fmt_mode(a['mode'])} -> {fmt_mode(b['mode'])}"
            gained = b["mode"] & ~a["mode"]
            if gained & (stat.S_ISUID | stat.S_ISGID):
                note += "  ** gained setuid/setgid **"
            elif gained & stat.S_IWOTH:
                note += "  (now world writable)"
            meta.append(note)
        if (a["uid"], a["gid"]) != (b["uid"], b["gid"]):
            meta.append(f"owner {a['uid']}:{a['gid']} -> {b['uid']}:{b['gid']}")
        if meta:
            out.append(("meta", path, ", ".join(meta)))
    return out


def cmd_init(args, key):
    if os.path.exists(args.baseline) and not args.force:
        die(f"{args.baseline} exists, use update or --force")
    if not args.paths:
        die("init needs at least one path")
    roots = [os.path.abspath(p) for p in args.paths]
    # never baseline the baseline
    excludes = args.exclude + [os.path.abspath(args.baseline)]
    t0 = time.time()
    entries = snapshot(roots, excludes, args.jobs)
    body = {"version": VERSION, "host": socket.gethostname(), "created": int(t0),
            "roots": roots, "excludes": excludes, "entries": entries}
    save(args.baseline, body, key)
    print(f"{len(entries)} entries in {time.time() - t0:.1f}s -> {args.baseline}"
          f"{' (signed)' if key else ' (unsigned)'}")
    return 0


def cmd_check(args, key, update=False):
    base = load(args.baseline, key)
    entries = snapshot(base["roots"], base["excludes"], args.jobs,
                       old=base["entries"], quick=args.quick)
    changes = diff(base["entries"], entries)

    if args.json:
        for kind, path, detail in changes:
            print(json.dumps({"change": kind, "path": path, "detail": detail,
                              "host": base["host"]}))
    else:
        mark = {"added": "+", "removed": "-", "content": "M", "meta": "m"}
        for kind, path, detail in changes:
            print(f"{mark[kind]} {path}" + (f"   {detail}" if detail else ""))
        counts = {k: sum(1 for c in changes if c[0] == k) for k in mark}
        print(f"{len(entries)} checked: " + ", ".join(f"{v} {k}" for k, v in counts.items()),
              file=sys.stderr)

    if update and changes:
        base["entries"] = entries
        base["created"] = int(time.time())
        save(args.baseline, base, key)
        log("baseline updated")
        return 0
    return 1 if changes else 0


def main():
    ap = argparse.ArgumentParser(description="File integrity monitor with a signed baseline.")
    ap.add_argument("command", choices=["init", "check", "update"])
    ap.add_argument("paths", nargs="*", help="what to baseline (init only)")
    ap.add_argument("-b", "--baseline", required=True)
    ap.add_argument("-x", "--exclude", action="append", default=[], metavar="GLOB",
                    help="skip paths matching this glob (init only, stored in the baseline)")
    ap.add_argument("-k", "--keyfile", help="HMAC key file, otherwise $FIM_KEY")
    ap.add_argument("-j", "--jobs", type=int, default=min(8, os.cpu_count() or 2))
    ap.add_argument("--quick", action="store_true",
                    help="trust size+mtime and skip rehashing unchanged files. "
                         "Fast, but mtime can be set back, so don't rely on it alone")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--force", action="store_true", help="let init overwrite")
    args = ap.parse_args()

    try:
        key = load_key(args)
        if args.command == "init":
            return cmd_init(args, key)
        return cmd_check(args, key, update=args.command == "update")
    except (OSError, json.JSONDecodeError, KeyError) as e:
        log(str(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
