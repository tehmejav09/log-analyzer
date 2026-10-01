# Log Analyzer

A small Python tool that reads a server-style log file and highlights
failed logins, including repeated failures from the same IP that look
like a brute-force attempt.

A sample log is built in, so it runs with no setup.

## What it does

- Finds "Failed password" style log lines and pulls out the date,
  username and source IP
- Groups failed attempts by IP, and flags any IP with 5 or more
  attempts as a possible brute force
- Shows the most targeted usernames

## How to run it

    python3 log_analyzer.py

This uses the built-in sample log. To check a real file:

    python3 log_analyzer.py yourfile.log

## Example output

    Total failed login attempts: 7

    By source IP:
      198.51.100.23: 6 attempt(s)  <-- possible brute force
      203.0.113.9: 1 attempt(s)

    Most targeted usernames:
      admin: 5 attempt(s)
      root: 1 attempt(s)

## Why I built it

Part of a series of small security projects on Cipherora
(cipherora.com), where I write up what I built, what broke, and what
I learned.
