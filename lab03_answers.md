# Lab 03 — Broken Authentication
# Christopher Stills 

## Vulnerability
The app used an old and weak hashing method to store passwords.

## Exploit
A hacker could crack weak password hashes more easily and gain access to user accounts.

## Fix
I fixed it by using bcrypt to securely hash passwords before storing them in the database.