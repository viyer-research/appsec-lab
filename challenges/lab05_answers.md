# Lab 05 Answers

## Q1 — Hardcoded secrets

- `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"` — AWS access key
- `AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"` — AWS secret key
- `STRIPE_SECRET_KEY = "sk_live_abc123xyz456"` — Stripe live API key
- `DB_PASSWORD = "admin123"` — Database password

## Q2 — Is deleting enough?

No. Git stores history. The secret exists in every commit that touched the file. `git push` mirrors it to GitHub's servers. Even after deletion, anyone with repo access (or a cached copy) can find it in the commit history. The only fix is to rotate the credential.

## Q3 — Automated discovery

Tools like **trufflehog** or **gitleaks** scan GitHub repos (including commit history) for known secret patterns (AWS keys, Stripe keys, private keys). Attackers also use GitHub's code search API to find leaked keys across public repos within minutes of a push.

## Q4 — Fix

```python
import os
from dotenv import load_dotenv
load_dotenv()

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
```

Sample `.env`:
```
AWS_ACCESS_KEY_ID=your-key-here
AWS_SECRET_ACCESS_KEY=your-secret-here
STRIPE_SECRET_KEY=your-stripe-key-here
```

## Q5 — Required gitignore entry

`.env` — must be in `.gitignore` to prevent the env file from being committed.
