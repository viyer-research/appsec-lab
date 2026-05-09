# Lab 06 — Command Injection
# Christopher Stills 

## Vulnerability

The code was vulnerable because it directly used user input inside a system command to run ping.

# Exploit

An attacker could add extra commands like ; whoami or && ls, which would let them run unauthorized system commands instead of just pinging a host.

# Fix

The issue was fixed by removing unsafe command execution and validating the input so only safe hostname characters are allowed before running the command in a secure way.