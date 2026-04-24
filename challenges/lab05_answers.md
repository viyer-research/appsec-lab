## Lab 05: Sensitive Data Exposure Answers

### Q1. Hardcoded Secrets List
The following secrets were hardcoded as string literals:
* `AWS_ACCESS_KEY` / `AWS_ACCESS`: **AWS IAM Access Key ID** (Pattern: `AKIA...`)
* `AWS_SECRET_KEY`: **AWS Secret Access Key**
* `STRIPE_API_KEY`: **Stripe Secret API Key** (Pattern: `sk_test_...`)


### Q2. Persistence in Git History
**No, the secret is not safe.** Even if you delete the code and commit the change, the secret remains in the **Git history** (the `.git` directory). Anyone who clones the repository can simply checkout an older commit or use `git log -p` to see the keys you deleted. To properly fix this, you would have to rewrite the repository's history (e.g., using BFG Repo-Cleaner) or, more practically, **rotate (revoke and replace) the keys immediately**.


### Q3. Automated Discovery
Attackers use **automated secret scanners** that crawl GitHub's real-time public event feed. 
* **Tools:** `TruffleHog`, `Gitleaks`, or custom regex bots.
* **Technique:** They scan for specific patterns like `AKIA` (AWS) or `sk_live` (Stripe) and automatically attempt to use the keys the moment they are pushed.


### Q4. Fixed Code and `.env` Template

**Fixed `workspace/integrations.py`:**
```python
import os
from dotenv import load_dotenv
import boto3
import stripe

# Load variables from .env file into environment
load_dotenv()

# Fetch from environment variables with no defaults for sensitive data
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION     = os.getenv("AWS_REGION", "us-east-1")
STRIPE_API_KEY = os.getenv("STRIPE_SECRET_KEY")

# Initialize clients
stripe.api_key = STRIPE_API_KEY

def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION,
    )
```

**Sample `.env` file:**
```bash
# This file should be in your .gitignore!
AWS_ACCESS_KEY_ID=AKIA_MOCK_VALUE_123
AWS_SECRET_ACCESS_KEY=mock_secret_key_value_abc
AWS_REGION=us-east-1
STRIPE_SECRET_KEY=sk_test_mock_stripe_key_456
```


### Q5. Essential `.gitignore` Entry
To prevent this vulnerability from recurring, you must add the following file to your `.gitignore`:
```text
.env
```
This ensures that the local configuration file containing the real secrets stays on your machine and is never uploaded to the shared repository.
