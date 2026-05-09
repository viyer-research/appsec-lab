# Lab 05 — Sensitive Data Exposure
# Christopher Stills

## Vulnerability
The app stored secret API keys directly in the source code.

## Exploit
If the code was leaked or uploaded publicly, attackers could steal the API keys and access cloud or payment services.

## Fix
I fixed the issue by moving the secrets into environment variables instead of hardcoding them in the code.