import argparse
import os
import sys
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta as td

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "detection"))
import sshwatch  # noqa: E402

NOW = datetime(2026, 11, 15, 12, 0, 0)
SAMPLE = os.path.join(HERE, "..", "samples", "auth.log")


def events_from(text):
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write(text)
    try:
        return list(sshwatch.parse([fh.name], Counter(), now=NOW))
    finally:
        os.unlink(fh.name)


class Parsing(unittest.TestCase):
    def test_bsd_and_iso_stamps(self):
        evs = events_from(
            "Nov  3 04:05:06 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n"
            "2026-11-03T04:05:07.123456-05:00 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2\n")
        self.assertEqual([e.ts for e in evs],
                         [datetime(2026, 11, 3, 4, 5, 6), datetime(2026, 11, 3, 4, 5, 7)])

    def test_december_read_in_january(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("Dec 31 23:59:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n")
        try:
            ev, = sshwatch.parse([fh.name], Counter(), now=datetime(2027, 1, 2))
        finally:
            os.unlink(fh.name)
        self.assertEqual(ev.ts.year, 2026)

    def test_injected_source_is_ignored(self):
        ev, = events_from(
            "Nov  3 04:05:06 h sshd[1]: Failed password for invalid user "
            "x from 198.51.100.24 port 22 ssh2 from 203.0.113.9 port 40122 ssh2\n")
        self.assertEqual(ev.src, "203.0.113.9")
        self.assertIn("198.51.100.24", ev.user)

    def test_repeated_lines_expand(self):
        evs = events_from(
            "Nov  3 04:05:06 h sshd[1]: message repeated 3 times: "
            "[ Failed password for root from 192.0.2.1 port 1 ssh2]\n")
        self.assertEqual(len(evs), 3)

    def test_preauth_close_not_double_counted(self):
        evs = events_from(
            "Nov  3 04:05:06 h sshd[9]: Failed password for root from 192.0.2.1 port 1 ssh2\n"
            "Nov  3 04:05:07 h sshd[9]: Connection closed by authenticating user root 192.0.2.1 port 1 [preauth]\n"
            "Nov  3 04:05:08 h sshd-session[10]: Connection closed by authenticating user root 192.0.2.1 port 2 [preauth]\n")
        self.assertEqual([(e.kind, e.method) for e in evs],
                         [("fail", "password"), ("fail", "preauth")])


class Detection(unittest.TestCase):
    def run_sample(self, *extra):
        events = sorted(sshwatch.parse([SAMPLE], Counter(), now=NOW), key=lambda e: e.ts)
        opts = argparse.Namespace(window=10, lookback=60, threshold=10, spray_users=8,
                                  success_after=5, distributed=10, allow=[])
        for a in extra:
            opts.allow.append(sshwatch.cidr(a))
        return sshwatch.analyse(events, opts)[0]

    def test_sample_findings(self):
        rules = Counter(f["rule"] for f in self.run_sample())
        self.assertEqual(rules, {"login_after_failures": 1, "brute_force": 2,
                                 "password_spray": 1, "distributed_guessing": 1,
                                 "root_password_login": 1})

    def test_one_typo_then_login_is_quiet(self):
        hits = [f for f in self.run_sample() if f["src"] == "198.51.100.40"]
        self.assertEqual(hits, [])

    def test_allowlist(self):
        srcs = {f["src"] for f in self.run_sample("203.0.113.0/24")}
        self.assertNotIn("203.0.113.77", srcs)

    def test_busiest(self):
        t0 = datetime(2026, 1, 1)
        times = [t0, t0 + td(minutes=1), t0 + td(minutes=30), t0 + td(minutes=31), t0 + td(minutes=32)]
        self.assertEqual(sshwatch.busiest(times, td(minutes=10)), 3)


if __name__ == "__main__":
    unittest.main()
