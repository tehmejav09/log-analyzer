"""
Log Analyzer
Reads a server-style log file and highlights failed logins, including
repeated failures from the same source that look like a brute-force attempt.
Part of the Cipherora Projects series.

Works on plain text log lines. A sample log is included so you can try it
without needing a real server.
"""

import re
from collections import defaultdict

# Matches common "failed login" style lines, e.g.:
# 2026-09-01 03:14:02 Failed password for admin from 198.51.100.23 port 51422
FAILED_LOGIN_PATTERN = re.compile(
    r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?'
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# Flag a source IP as a likely brute-force attempt once it crosses this many
# failed attempts in the log.
BRUTE_FORCE_THRESHOLD = 5


def parse_log(lines):
    """Return a list of failed-login events: (date, user, ip)."""
    events = []
    for line in lines:
        match = FAILED_LOGIN_PATTERN.search(line)
        if match:
            events.append((match.group("date"), match.group("user"), match.group("ip")))
    return events


def summarize(events):
    """Group failed attempts by source IP and by targeted username."""
    by_ip = defaultdict(list)
    by_user = defaultdict(int)

    for date, user, ip in events:
        by_ip[ip].append((date, user))
        by_user[user] += 1

    return by_ip, by_user


def report(events):
    by_ip, by_user = summarize(events)

    print(f"Total failed login attempts: {len(events)}\n")

    if not events:
        print("No failed logins found in this log.")
        return

    print("By source IP:")
    for ip, attempts in sorted(by_ip.items(), key=lambda x: -len(x[1])):
        flag = "  <-- possible brute force" if len(attempts) >= BRUTE_FORCE_THRESHOLD else ""
        print(f"  {ip}: {len(attempts)} attempt(s){flag}")

    print("\nMost targeted usernames:")
    for user, count in sorted(by_user.items(), key=lambda x: -x[1])[:5]:
        print(f"  {user}: {count} attempt(s)")


# A small built-in sample log, so the script works with no setup.
SAMPLE_LOG = """
2026-09-01 03:14:01 Failed password for admin from 198.51.100.23 port 51422
2026-09-01 03:14:04 Failed password for admin from 198.51.100.23 port 51430
2026-09-01 03:14:07 Failed password for root from 198.51.100.23 port 51438
2026-09-01 03:14:10 Failed password for admin from 198.51.100.23 port 51445
2026-09-01 03:14:13 Failed password for admin from 198.51.100.23 port 51451
2026-09-01 03:14:16 Failed password for admin from 198.51.100.23 port 51459
2026-09-01 08:02:11 Failed password for jsmith from 203.0.113.9 port 44210
2026-09-01 12:45:33 Accepted password for jsmith from 203.0.113.9 port 44512
""".strip().splitlines()


if __name__ == "__main__":
    import sys

    print("Log Analyzer")

    if len(sys.argv) > 1:
        path = sys.argv[1]
        print(f"Reading {path} ...\n")
        with open(path) as f:
            lines = f.readlines()
    else:
        print("No file given, using the built-in sample log.")
        print("Run 'python3 log_analyzer.py yourfile.log' to check a real file.\n")
        lines = SAMPLE_LOG

    events = parse_log(lines)
    report(events)
