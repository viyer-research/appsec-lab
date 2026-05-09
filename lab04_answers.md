# Lab 04 — IDOR
# Christopher Stills


## Vulnerability
The app allowed users to access invoices just by changing the invoice ID in the URL.

## Exploit
A user could view someone else's invoice by typing a different invoice number.

## Fix
I fixed the issue by checking that the invoice belongs to the logged-in user before returning it.