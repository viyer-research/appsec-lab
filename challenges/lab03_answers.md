# Lab 03 Answers

## Q1 — Copilot's algorithm

Copilot used `hashlib.md5()` — no salt. MD5 is fast and unsalted, making it trivial to crack with rainbow tables.

## Q2 — Why MD5 is catastrophic

The hash `5f4dcc3b5aa765d61d8327deb882cf99` for "password" appears in precomputed rainbow tables. An attacker doesn't need to crack anything — they just look it up in a reverse hash database instantly.

## Q3 — Same password, same hash

Both users get the identical hash. An attacker who cracks one now has access to every account using that password. They can also see which users share passwords.

## Q4 — Fix

```python
def register_user(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))

def verify_login(username, password):
    row = db.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    return bcrypt.checkpw(password.encode(), row["password"])
```

## Q5 — Why bcrypt is slow

The ~250ms is a feature. bcrypt is *designed* to be slow (adjustable via `rounds`) so brute-force attacks become impractical. An attacker trying 10 billion MD5 hashes/sec gets only ~4 bcrypt guesses/sec.
