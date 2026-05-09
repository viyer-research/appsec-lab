# Lab 01 — SQL Injection
# Christopher Stills

# The Vulnerability
The login system was unsafe because it trusted whatever the user typed in.

# How It Could Get Exploited
Someone could type weird text like:

' OR '1'='1

and the app could accidentally let them log in without the correct password.

## How I Fixed It
 I fixed it by changing the login code so the app checks usernames and passwords safely instead of trusting the user input.