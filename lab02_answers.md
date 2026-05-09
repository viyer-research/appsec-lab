# Lab 02 — Cross-Site Scripting

## What Was The Vulnerability
The app displayed whatever the user typed directly on the page without checking it first.

## How Someone Could Exploit It
Someone could type harmful script code into the search box and the browser could run it.

## How To Fix
I fixed it by making the app safely display user input as text instead of executable code.