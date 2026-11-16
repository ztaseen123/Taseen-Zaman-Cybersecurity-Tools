#!/usr/bin/env python3
"""
tlscheck - what is this endpoint actually serving?

    tlscheck.py example.com mail.example.com:993 10.20.0.5:8443
    tlscheck.py -f endpoints.txt --warn-days 21 --json
    tlscheck.py --starttls smtp mx1.example.com:25

For each endpoint: certificate dates, names, key and signature strength,
whether the chain validates against the local trust store, and which
protocol versions the server will still negotiate.

Exit status follows the nagios convention: 0 ok, 1 warning, 2 critical.

Needs the 'cryptography' package for certificate parsing.
"""

import argparse
import json
import socket
import ssl
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
except ImportError:
    sys.exit("tlscheck: pip install cryptography")

OK, WARN, CRIT = 0, 1, 2
LABEL = {OK: "ok", WARN: "WARN", CRIT: "CRIT"}

VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
OLD = {"TLSv1.0", "TLSv1.1"}


def split_target(s, default_port=443):
    """host, host:port, [v6]:port"""
    s = s.strip()
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, int(rest.lstrip(":") or default_port)
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, int(port)
    return s, default_port      # bare name, or a bare v6 address


def smtp_starttls(sock):
    """Talk just enough SMTP to get the server to switch to TLS."""
    fh = sock.makefile("rb")

    def reply():
        # multi-line replies look like "250-..." and end with "250 ..."
        while True:
            line = fh.readline()
            if not line:
                raise ConnectionError("smtp: server hung up")
            if line[3:4] != b"-":
                return int(line[:3])

    if reply() != 220:
        raise ConnectionError("smtp: no 220 banner")
    sock.sendall(b"EHLO tlscheck.invalid\r\n")
    if reply() != 250:
        raise ConnectionError("smtp: EHLO refused")
    sock.sendall(b"STARTTLS\r\n")
    if reply() != 220:
        raise ConnectionError("smtp: STARTTLS not offered")


def connect(host, port, ctx, timeout, starttls=None):
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if starttls == "smtp":
            smtp_starttls(sock)
        # SNI even when we are not verifying, or a vhost setup hands back
        # its default certificate instead of the one we asked about
        return ctx.wrap_socket(sock, server_hostname=host)
    except BaseException:
        sock.close()
        raise


def unverified_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe_version(host, port, version, timeout, starttls):
    """True / False if the server does or doesn't accept it, None if we can't tell."""
    ctx = unverified_ctx()
    try:
        # python warns that 1.0/1.1 are deprecated. yes, that's the point.
        warnings.simplefilter("ignore", DeprecationWarning)
        # Distro OpenSSL builds sit at security level 2, which silently
        # refuses to even offer TLS 1.0/1.1. Drop to 0 for the probe so a
        # server that still accepts them gets caught.
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ssl.SSLError, ValueError):
        return None
    try:
        with connect(host, port, ctx, timeout, starttls) as s:
            return s.version() is not None
    except ssl.SSLError as e:
        # "no protocols available" is us, not them
        if "NO_PROTOCOLS_AVAILABLE" in str(e).upper().replace(" ", "_"):
            return None
        return False
    except OSError:
        # reset or timeout mid-handshake is how plenty of servers say no
        return False


def key_desc(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC {pub.curve.name}", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return type(pub).__name__.replace("PublicKey", "").lstrip("_"), None


def names_of(cert):
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return [str(v) for v in san.get_values_for_type(x509.DNSName)] + \
               [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        return []


def check(target, opts):
    host, port = split_target(target)
    res = {"target": f"{host}:{port}", "issues": [], "status": OK}

    def flag(level, msg):
        res["issues"].append({"level": LABEL[level], "msg": msg})
        res["status"] = max(res["status"], level)

    # 1. grab whatever certificate is presented, valid or not
    try:
        with connect(host, port, unverified_ctx(), opts.timeout, opts.starttls) as s:
            der = s.getpeercert(binary_form=True)
            res["negotiated"] = s.version()
            res["cipher"] = s.cipher()[0]
    except (OSError, ssl.SSLError, ConnectionError) as e:
        flag(CRIT, f"connect failed: {e}")
        return res

    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    # *_utc only exists from cryptography 42
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    days = (not_after - now).days
    kind, bits = key_desc(cert.public_key())
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "none"

    res.update(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        names=names_of(cert),
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_left=days,
        key=f"{kind} {bits}" if bits else kind,
        sig_hash=sig,
        serial=format(cert.serial_number, "x"),
    )

    if now < not_before:
        flag(CRIT, f"not valid until {not_before:%Y-%m-%d}")
    if days < 0:
        flag(CRIT, f"expired {-days} days ago")
    elif days <= opts.crit_days:
        flag(CRIT, f"expires in {days} days")
    elif days <= opts.warn_days:
        flag(WARN, f"expires in {days} days")

    if kind == "RSA" and bits < 2048:
        flag(CRIT, f"{bits} bit RSA key")
    elif kind.startswith("EC") and bits < 224:
        flag(CRIT, f"{bits} bit EC key")
    elif kind == "DSA":
        flag(WARN, "DSA key")
    if sig in ("md5", "sha1"):
        flag(CRIT, f"signed with {sig}")

    # 2. same handshake again, this time letting OpenSSL judge chain + name
    if not opts.no_verify:
        ctx = ssl.create_default_context(cafile=opts.cafile)
        try:
            connect(host, port, ctx, opts.timeout, opts.starttls).close()
            res["trusted"] = True
        except ssl.SSLCertVerificationError as e:
            res["trusted"] = False
            why = e.verify_message or str(e)
            if cert.issuer == cert.subject:
                why = "self-signed"
            # an expired cert already got flagged above, don't say it twice
            if "expired" not in why:
                flag(CRIT, f"does not verify: {why}")
        except (OSError, ssl.SSLError) as e:
            flag(WARN, f"verified handshake failed: {e}")

    # 3. protocol versions
    protos = {}
    for name, ver in VERSIONS:
        protos[name] = probe_version(host, port, ver, opts.timeout, opts.starttls)
    res["protocols"] = protos
    old_on = sorted(n for n in OLD if protos[n])
    if old_on:
        flag(WARN, f"still accepts {', '.join(old_on)}")
    if protos["TLSv1.2"] is False and protos["TLSv1.3"] is False:
        flag(CRIT, "no TLS 1.2 or 1.3")

    # TLS 1.3 suites are all AEAD + ephemeral, only 1.2 and down need a look
    c = res["cipher"]
    if res["negotiated"] != "TLSv1.3":
        if not c.startswith(("ECDHE", "DHE")):
            flag(WARN, f"no forward secrecy ({c})")
        if any(bad in c for bad in ("RC4", "3DES", "DES-CBC", "NULL", "EXP", "MD5")):
            flag(CRIT, f"weak cipher {c}")
    return res


def show(res):
    print(f"[{LABEL[res['status']]:>4}] {res['target']}")
    if "subject" in res:
        protos = " ".join(
            f"{n.replace('TLSv', '')}{'+' if v else '-' if v is False else '?'}"
            for n, v in res["protocols"].items())
        print(f"       {res['subject']}")
        print(f"       issuer  {res['issuer']}")
        print(f"       expires {res['not_after'][:10]} ({res['days_left']}d)   "
              f"{res['key']}, {res['sig_hash']}")
        print(f"       {res['negotiated']} {res['cipher']}   offers: {protos}")
    for i in res["issues"]:
        print(f"       {i['level']}: {i['msg']}")


def main():
    ap = argparse.ArgumentParser(description="Audit TLS certificates and protocol support.")
    ap.add_argument("targets", nargs="*", help="host[:port], default port 443")
    ap.add_argument("-f", "--file", help="one target per line, # comments ok")
    ap.add_argument("--warn-days", type=int, default=30)
    ap.add_argument("--crit-days", type=int, default=7)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--starttls", choices=["smtp"])
    ap.add_argument("--cafile", help="trust this bundle instead of the system store (internal CA)")
    ap.add_argument("--no-verify", action="store_true", help="skip the chain/hostname check")
    ap.add_argument("-j", "--jobs", type=int, default=16)
    ap.add_argument("--json", action="store_true")
    opts = ap.parse_args()

    targets = list(opts.targets)
    if opts.file:
        with open(opts.file) as fh:
            targets += [l.split("#")[0].strip() for l in fh if l.split("#")[0].strip()]
    if not targets:
        ap.error("nothing to check")

    with ThreadPoolExecutor(max_workers=opts.jobs) as pool:
        results = list(pool.map(lambda t: check(t, opts), targets))

    if opts.json:
        for r in results:
            r["status"] = LABEL[r["status"]].lower()
            print(json.dumps(r))
        return max({"ok": OK, "warn": WARN, "crit": CRIT}[r["status"]] for r in results)
    for r in results:
        show(r)
    return max(r["status"] for r in results)


if __name__ == "__main__":
    sys.exit(main())
