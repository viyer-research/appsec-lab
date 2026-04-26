# Lab 06 Answers

## Q1 — Dangerous subprocess call

```python
result = subprocess.run(f"ping -c 4 {hostname}", shell=True, capture_output=True, text=True)
```

`shell=True` passes the entire string to the system shell, so shell metacharacters (`;`, `&&`, `|`, `$()`) are interpreted as commands.

## Q2 — Attack payloads

**Read /etc/passwd:**
- Input: `8.8.8.8; cat /etc/passwd`
- Server runs: `ping -c 4 8.8.8.8; cat /etc/passwd`

**Create pwned.txt:**
- Input: `8.8.8.8 && touch pwned.txt`
- Server runs: `ping -c 4 8.8.8.8 && touch pwned.txt`

## Q3 — Why list args prevent injection

With `shell=False`, Python passes arguments directly to the executable's argv array — no shell interprets them. The string `8.8.8.8; cat /etc/passwd` becomes a single argument to `ping`, not two separate commands. The semicolon is never processed by a shell.

## Q4 — Fix

```python
import re
if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', hostname):
    return {"error": "Invalid hostname"}, 400

result = subprocess.run(["ping", "-c", "4", hostname], shell=False, capture_output=True, text=True)
```

Two layers: regex allowlist rejects anything that isn't a valid hostname, and `shell=False` with a list prevents any shell interpretation.
