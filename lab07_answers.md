# Lab 07 — XXE Injection

## Vulnerability
The original code used unsafe XML parsing which allowed XXE attacks and entity expansion attacks.

## Exploit
An attacker could upload malicious XML containing external entities to read files or crash the server using entity expansion attacks like Billion Laughs.

## Fix
The code was updated to use defusedxml for secure XML parsing and block dangerous XML entities and DTDs.