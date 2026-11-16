#!/usr/bin/env python3
"""
sshwatch - dig brute force, spraying and "they got in" out of sshd logs.

Reads auth.log (Debian/Ubuntu) or secure (RHEL family), plain or gzipped,
or stdin with "-".

    sshwatch.py /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz
    journalctl -u ssh -o short-iso | sshwatch.py -
    sshwatch.py --json --allow 10.0.0.0/8 /var/log/secure

Exit status is 2 if anything critical turned up, 1 for lesser findings,
0 for nothing, so it can sit in cron and only mail on non-zero.
"""

import argparse
import gzip
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict, namedtuple
from datetime import datetime, timedelta

Event = namedtuple("Event", "ts host kind user src method")

# Classic syslog stamps have no year. rsyslog's newer default template and
# journalctl -o short-iso give ISO 8601 instead, so take either.
TS_BSD = re.compile(r"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d:\d\d:\d\d) (\S+) (.*)$")
TS_ISO = re.compile(r"^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)\S* (\S+) (.*)$")

# OpenSSH 9.8 moved per-connection work into a separate sshd-session binary,
# and that is the name that shows up in the log tag from then on.
TAG = re.compile(r"^sshd(?:-session)?\[(\d+)\]: (.*)$")

REPEATED = re.compile(r"^message repeated (\d+) times: \[ ?(.*?)\]$")

# The user field is attacker controlled and can contain spaces, or even
# " from 1.2.3.4 port 22" to frame another address. Matching the user
# greedily means the *last* "from X port N" on the line wins, which is the
# one sshd wrote itself.
RULES = [
    ("fail",    re.compile(r"^Failed (\S+) for (?:invalid user )?(.*) from (\S+) port \d+")),
    ("accept",  re.compile(r"^Accepted (\S+) for (.*) from (\S+) port \d+")),
    ("invalid", re.compile(r"^Invalid user()(.*) from (\S+)")),
    ("preauth", re.compile(r"^(?:Connection closed by|Disconnected from) "
                           r"(?:authenticating|invalid) user()(.*) (\S+) port \d+ \[preauth\]")),
]

MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2}


def open_log(path):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, errors="replace")


def parse_ts(line, now):
    """-> (datetime, host, rest) or None"""
    m = TS_ISO.match(line)
    if m:
        # Offset is dropped on purpose. Everything from one box carries the
        # same offset and all the maths here is relative.
        ts = datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")
        return ts, m.group(3), m.group(4)
    m = TS_BSD.match(line)
    if not m or m.group(1) not in MONTHS:
        return None
    hh, mm, ss = map(int, m.group(3).split(":"))
    try:
        ts = datetime(now.year, MONTHS[m.group(1)], int(m.group(2)), hh, mm, ss)
    except ValueError:
        # Feb 29 read back in a non leap year
        ts = datetime(now.year - 1, MONTHS[m.group(1)], int(m.group(2)), hh, mm, ss)
    if ts > now + timedelta(days=1):
        # December lines being read in January
        ts = ts.replace(year=ts.year - 1)
    return ts, m.group(4), m.group(5)


def parse(paths, stats, now=None):
    """Yield Events from the given logs. Order is whatever the files give us."""
    now = now or datetime.now()
    # pids that already logged a real failure, so the preauth disconnect that
    # follows isn't counted as another attempt
    failed_pids = set()

    def handle(ts, host, pid, msg):
        for kind, rx in RULES:
            m = rx.match(msg)
            if not m:
                continue
            method, user, src = m.groups()
            key = (host, pid)
            if kind == "fail":
                failed_pids.add(key)
            elif kind == "preauth":
                # Key-only servers never log "Failed password". The only trace
                # of a guess is the client giving up before auth finished.
                if key in failed_pids:
                    failed_pids.discard(key)
                    return None
                kind, method = "fail", "preauth"
            return Event(ts, host, kind, user.strip(), src, method or None)
        return None

    for path in paths:
        with open_log(path) as fh:
            for line in fh:
                stats["lines"] += 1
                got = parse_ts(line.rstrip("\n"), now)
                if not got:
                    continue
                ts, host, rest = got
                m = TAG.match(rest)
                if not m:
                    continue
                pid, msg = m.groups()
                times = 1
                rep = REPEATED.match(msg)
                if rep:
                    times, msg = int(rep.group(1)), rep.group(2)
                ev = handle(ts, host, pid, msg)
                if ev:
                    stats["events"] += times
                    for _ in range(times):
                        yield ev


def busiest(times, window):
    """Largest number of timestamps that fit inside one window. Sorted input."""
    best = lo = 0
    for hi, t in enumerate(times):
        while t - times[lo] > window:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def most_distinct(pairs, window):
    """pairs = sorted [(ts, key)]. Max distinct keys seen inside one window."""
    seen = Counter()
    best = lo = 0
    for ts, key in pairs:
        seen[key] += 1
        while ts - pairs[lo][0] > window:
            old = pairs[lo][1]
            seen[old] -= 1
            if not seen[old]:
                del seen[old]
            lo += 1
        best = max(best, len(seen))
    return best


def allowed(src, nets):
    if not nets:
        return False
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return False        # sshd logged a hostname (UseDNS yes)
    return any(ip in n for n in nets)


def analyse(events, opts):
    window = timedelta(minutes=opts.window)
    lookback = timedelta(minutes=opts.lookback)

    fails = defaultdict(list)           # src -> [Event]
    fails_by_user = defaultdict(list)   # user -> [(ts, src)]
    accepts = []
    bogus_users = set()

    for ev in events:
        if allowed(ev.src, opts.allow):
            continue
        if ev.kind == "fail":
            fails[ev.src].append(ev)
            fails_by_user[ev.user].append((ev.ts, ev.src))
        elif ev.kind == "accept":
            accepts.append(ev)
        elif ev.kind == "invalid":
            bogus_users.add(ev.user)

    findings = []

    for src, evs in fails.items():
        times = [e.ts for e in evs]
        peak = busiest(times, window)
        users = most_distinct([(e.ts, e.user) for e in evs], window)
        if peak < opts.threshold and users < opts.spray_users:
            continue
        per_user = Counter(e.user for e in evs)
        # lots of accounts, a couple of tries each = spraying.
        # few accounts hammered = plain guessing.
        spray = users >= opts.spray_users and len(evs) / len(per_user) <= 3
        findings.append({
            "rule": "password_spray" if spray else "brute_force",
            "severity": "high",
            "technique": "T1110.003" if spray else "T1110.001",
            "src": src,
            "host": evs[0].host,
            "count": len(evs),
            "peak": peak,
            "users": len(per_user),
            "top_users": [u for u, _ in per_user.most_common(5)],
            "first_seen": times[0],
            "last_seen": times[-1],
        })

    for ev in accepts:
        if ev.method == "password" and ev.user == "root":
            findings.append({
                "rule": "root_password_login",
                "severity": "medium",
                "technique": "T1078.003",
                "src": ev.src, "host": ev.host, "users": 1, "top_users": ["root"],
                "count": 1, "first_seen": ev.ts, "last_seen": ev.ts,
            })
        prior = [f for f in fails.get(ev.src, ())
                 if timedelta(0) <= ev.ts - f.ts <= lookback]
        if len(prior) < opts.success_after:
            continue
        findings.append({
            "rule": "login_after_failures",
            "severity": "critical",
            "technique": "T1110",
            "src": ev.src,
            "host": ev.host,
            "count": len(prior),
            "users": 1,
            "top_users": [ev.user],
            "method": ev.method,
            # same account they were guessing at, or did they pivot to another
            "guessed": any(f.user == ev.user for f in prior),
            "first_seen": prior[0].ts,
            "last_seen": ev.ts,
        })

    # One real account, many sources. Botnets spread guesses out so no single
    # address trips the per-source threshold. Accounts that don't exist are
    # skipped, otherwise "admin" and "test" light this up on every public host.
    for user, pairs in fails_by_user.items():
        if user in bogus_users:
            continue
        n = most_distinct(pairs, window)
        if n >= opts.distributed:
            findings.append({
                "rule": "distributed_guessing",
                "severity": "medium",
                "technique": "T1110.001",
                "src": None, "host": None,
                "count": len(pairs), "users": 1, "top_users": [user],
                "sources": n,
                "first_seen": pairs[0][0], "last_seen": pairs[-1][0],
            })

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], -f["count"]))
    return findings, fails


def describe(f):
    who = ", ".join(f["top_users"])
    if f["rule"] == "login_after_failures":
        same = "the account being guessed" if f["guessed"] else "a different account than the ones guessed"
        return (f"{f['src']} logged in as {who} on {f['host']} via {f['method']} "
                f"after {f['count']} failures ({same})")
    if f["rule"] == "brute_force":
        return (f"{f['src']}: {f['count']} failures, peak {f['peak']} per window, "
                f"{f['users']} account(s): {who}")
    if f["rule"] == "password_spray":
        return f"{f['src']}: {f['users']} accounts tried, {f['count']} failures. e.g. {who}"
    if f["rule"] == "root_password_login":
        return f"root logged in with a password from {f['src']} on {f['host']}"
    return f"{who}: failures from {f['sources']} different sources inside one window"


def report(findings, fails, stats, top):
    tags = {"critical": "CRIT", "high": "HIGH", "medium": "MED "}
    for f in findings:
        print(f"[{tags[f['severity']]}] {f['rule']:<22} {f['technique']:<10} "
              f"{f['first_seen']:%Y-%m-%d %H:%M} -> {f['last_seen']:%H:%M}")
        print(f"       {describe(f)}")
    if findings:
        print()
    print(f"{stats['lines']} lines, {stats['events']} auth events, "
          f"{len(fails)} failing sources, {len(findings)} findings")
    if top and fails:
        print("\nnoisiest sources:")
        ranked = sorted(fails.items(), key=lambda kv: -len(kv[1]))[:top]
        for src, evs in ranked:
            print(f"  {src:<40} {len(evs):>6}  {len({e.user for e in evs})} users")


def cidr(s):
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Find brute force, spraying and suspicious logins in sshd logs.")
    ap.add_argument("logs", nargs="+", help="log files, .gz ok, - for stdin")
    ap.add_argument("-w", "--window", type=int, default=10, metavar="MIN",
                    help="sliding window in minutes (10)")
    ap.add_argument("-t", "--threshold", type=int, default=10,
                    help="failures per window from one source (10)")
    ap.add_argument("--spray-users", type=int, default=8,
                    help="distinct accounts per window from one source (8)")
    ap.add_argument("--success-after", type=int, default=5,
                    help="failures before a login that make it suspicious (5)")
    ap.add_argument("--lookback", type=int, default=60, metavar="MIN",
                    help="how far back to count those failures (60)")
    ap.add_argument("--distributed", type=int, default=10,
                    help="sources per window against one real account (10)")
    ap.add_argument("-a", "--allow", type=cidr, action="append", default=[],
                    metavar="CIDR", help="ignore this network, repeatable")
    ap.add_argument("--top", type=int, default=10, help="noisiest sources to list (10)")
    ap.add_argument("--json", action="store_true", help="one finding per line")
    opts = ap.parse_args(argv)

    stats = Counter()
    try:
        events = sorted(parse(opts.logs, stats), key=lambda e: e.ts)
    except OSError as e:
        sys.exit(f"sshwatch: {e}")
    findings, fails = analyse(events, opts)

    if opts.json:
        for f in findings:
            print(json.dumps(f, default=lambda d: d.isoformat()))
    else:
        report(findings, fails, stats, opts.top)

    if any(f["severity"] == "critical" for f in findings):
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
