# security-tools

Security and sysadmin scripts. Mostly defensive: log analysis, host
integrity, TLS auditing, incident triage. The port scanners, the Apache log
counter and the AD queries started out as coursework.

Python and Bash for the most part, with some Perl and PowerShell. Nothing
here needs installing; each script stands on its own.

| Script | What it does | Lang |
|---|---|---|
| [detection/sshwatch.py](detection/sshwatch.py) | Finds brute force, password spraying and logins that follow a run of failures in sshd logs | Python |
| [host/fim.py](host/fim.py) | File integrity monitor with an HMAC-signed baseline | Python |
| [host/triage.sh](host/triage.sh) | Live response collector for a Linux host you suspect is compromised | Bash |
| [network/tlscheck.py](network/tlscheck.py) | Certificate and protocol audit for TLS endpoints, nagios exit codes | Python |
| [network/portscan.pl](network/portscan.pl) | Threaded TCP connect scanner | Perl |
| [network/portscan.py](network/portscan.py) | Simple sequential TCP scanner, ports 1-1023 | Python |
| [detection/apache_ip_hits.pl](detection/apache_ip_hits.pl) | Counts hits from given IPs in an Apache access log | Perl |
| [identity/pwcheck.py](identity/pwcheck.py) | Password strength / entropy estimate | Python |
| [identity/ad_groups.ps1](identity/ad_groups.ps1) | Common AD group queries, ready to paste | PowerShell |

Requirements: Python 3.8+, Bash 4+, Perl 5 with threads. `tlscheck.py` needs
`cryptography` (`pip install -r requirements.txt`); everything else is
standard library.

## sshwatch

```
$ detection/sshwatch.py samples/auth.log
[CRIT] login_after_failures   T1110      2026-11-10 03:11 -> 03:14
       203.0.113.77 logged in as root on bastion01 via password after 48 failures (the account being guessed)
[HIGH] brute_force            T1110.001  2026-11-10 03:11 -> 03:14
       203.0.113.77: 48 failures, peak 48 per window, 1 account(s): root
[HIGH] password_spray         T1110.003  2026-11-10 20:40 -> 20:41
       192.0.2.146: 15 accounts tried, 15 failures. e.g. admin, test, oracle, postgres, ubuntu
[MED ] distributed_guessing   T1110.001  2026-11-11 12:30 -> 12:34
       deploy: failures from 12 different sources inside one window
...
148 lines, 114 auth events, 17 failing sources, 6 findings
```

Takes `auth.log` or `secure`, rotated `.gz` files, or stdin
(`journalctl -u ssh -o short-iso | sshwatch.py -`). `--json` prints one
finding per line for shipping somewhere else. `--allow CIDR` drops a network
you trust, like a jump host range. Exits 2 on a critical finding so cron
only mails when it matters.

| Rule | ATT&CK | Fires when |
|---|---|---|
| `login_after_failures` | T1110 | a source logs in after 5+ failures in the previous hour |
| `brute_force` | T1110.001 | 10+ failures from one source inside 10 minutes |
| `password_spray` | T1110.003 | one source tries 8+ accounts with only a few guesses each |
| `distributed_guessing` | T1110.001 | 10+ sources fail against the same real account inside one window |
| `root_password_login` | T1078.003 | root logs in with a password at all |

All thresholds are flags. Things it handles that are easy to get wrong:

- Syslog timestamps have no year, so December logs read in January have to be pushed back a year.
- OpenSSH 9.8 and later log as `sshd-session`, not `sshd`.
- On key-only servers there is never a "Failed password" line. A guess only
  shows up as a preauth disconnect, so those are counted, once per connection.
- The username in the log is attacker-controlled. A username like
  `x from 10.0.0.5 port 22 ssh2` makes a naive regex blame the wrong address.
  The parser takes the last `from ... port` on the line. There's a test for it.

Tests: `python3 -m unittest discover -s tests`

## fim

```
$ export FIM_KEY=$(cat /root/.fimkey)
$ host/fim.py init -b /var/lib/fim/base.json -x '*.swp' /etc /usr/local/bin
1841 entries in 0.4s -> /var/lib/fim/base.json (signed)

$ host/fim.py check -b /var/lib/fim/base.json
M /etc/ssh/sshd_config   sha256 87428fc52280 -> 7f8b1dfc466b
+ /etc/cron.d/sysupdate   mode 0644 uid 0
m /usr/local/bin/backup   mode 0755 -> 4755  ** gained setuid/setgid **
1842 checked: 1 added, 0 removed, 1 content, 1 meta
```

Tracks sha256, mode, owner and link targets. Symlinks are never followed,
and fifos and device nodes are recorded but not opened. `update` accepts the
current state as the new baseline.

The baseline is the weak point of any FIM: whoever can edit it can hide
their changes. With a key set, the baseline carries an HMAC-SHA256 and
`check` exits 3 if it doesn't match. It also refuses a baseline that has had
its signature stripped. This only helps if the key lives somewhere the
attacker isn't, so run the check from another host over a read-only mount,
or pull the key from a vault at run time.

`--quick` skips rehashing files whose size and mtime haven't changed. Fine
for an hourly run, but mtime can be set back, so do a full run daily.

Exit codes: 0 clean, 1 changes, 2 error, 3 baseline failed verification.

## tlscheck

```
$ network/tlscheck.py www.example.com mail.example.com:993 10.20.0.5:8443
[  ok] www.example.com:443
       CN=www.example.com
       issuer  CN=Example Issuing CA
       expires 2027-06-04 (199d)   EC secp256r1 256, sha256
       TLSv1.3 TLS_AES_256_GCM_SHA384   offers: 1.0- 1.1- 1.2+ 1.3+
[CRIT] 10.20.0.5:8443
       CN=other.example
       issuer  CN=other.example
       expires 2026-11-19 (2d)   RSA 1024, sha1
       TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384   offers: 1.0+ 1.1+ 1.2+ 1.3-
       CRIT: expires in 2 days
       CRIT: 1024 bit RSA key
       CRIT: signed with sha1
       CRIT: does not verify: self-signed
       WARN: still accepts TLSv1.0, TLSv1.1
```

Checks expiry, hostname and chain validation, key size, signature hash, and
which protocol versions the server will negotiate. `-f` reads targets from a
file, `--cafile` validates against an internal CA, `--starttls smtp` handles
mail servers on 25/587, `--json` for machines.

The protocol probe lowers the local OpenSSL security level for that one
connection. Without that, a modern client won't offer TLS 1.0 at all and
every server looks fine. If the local OpenSSL build has the old protocols
compiled out, the column shows `?` instead of guessing.

## triage.sh

```
$ sudo host/triage.sh -o /mnt/usb
[*] processes
[*] network
...
[*] worth a look first:
    !! processes running a deleted binary: 1 (see proc/deleted_exe.txt)
    !! processes running from tmp/shm: 1 (see proc/exe_in_tmp.txt)
    !! processes with LD_PRELOAD set: 1 (see proc/ld_preload_env.txt)

3eb201f4296c...  triage-web02-20261116T010321Z.tar.gz
```

Collects in order of volatility: processes and sockets, sessions, accounts,
persistence (cron, systemd units and timers, rc files, `ld.so.preload`,
authorized_keys), then suid files, recent changes and package verification,
then logs. Every command and its exit status goes into `collection.log`,
every file into `MANIFEST.sha256`.

It writes only to the output directory. Point that at removable media or a
network mount, not the disk you might image afterwards. Password hashes are
not copied, only whether each account has one. `-q` skips the slow
filesystem walks.

It is a triage tool. It tells you whether to pull the box off the network
and where to start looking. It is not a substitute for a memory capture.

## Use

The scanners make connections that the other end can see and log. Only run
them against systems you own or have written permission to test.

MIT licensed, see [LICENSE](LICENSE).
