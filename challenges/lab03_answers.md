## Lab 03: Broken Authentication Answers

### Q1. Algorithm and Salting
**Hashing Algorithm:** Copilot used **MD5** (`hashlib.md5`).
**Is it salted?** No. It takes the raw password, encodes it to bytes, and hashes it directly. There is no unique, random data (salt) added to the password before hashing.


### Q2. Why a Database Breach is Catastrophic
Because MD5 is unsalted and fast, it is susceptible to **Rainbow Table attacks**. Attackers have pre-computed tables of billions of common passwords and their corresponding MD5 hashes. If they steal your database, they don't need to "crack" anything; they simply look up the stolen hash in their table to find the original password instantly.


### Q3. Duplicate Passwords without Salts
**Hash Appearance:** Both users will have the **exact same hash string** stored in the database: `5f4dcc3b5aa765d61d8327deb882cf99`.
**What this reveals:** It reveals to an attacker that these two users share the same password. Once the attacker cracks the password for one user, they have access to every account that shares that same hash.


### Q4. Fixed Code (bcrypt)
To fix this, we use the `bcrypt` library, which handles salting and "key stretching" automatically.

```python
import bcrypt

def register_user(username: str, password: str) -> bool:
    """Hash the password using bcrypt with a salt and store it."""
    if not username or not password:
        return False
    
    # Generate a salt and hash the password with 12 rounds
    # bcrypt automatically embeds the salt into the final string
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

    db = get_db()
    try:
        # Note: 'hashed' is a bytes object, SQLite handles this well
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_login(username, password):
    """Verify a user's password against the stored bcrypt hash."""
    db = get_db()
    cur = db.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    
    if row:
        stored_hash = row["password"]
        # Use bcrypt.checkpw to verify (it extracts the salt from the stored hash)
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            return True
    return False
```


### Q5. Bcrypt Performance: Bug or Feature?
**It is a feature.** This is known as **Key Stretching**.
By forcing the CPU to perform many rounds of computation (taking ~250ms), we make "brute-forcing" economically impossible. While 250ms is unnoticeable to a single user logging in, it slows an attacker down from 10 billion attempts per second to just 4 attempts per second per CPU core.

