# Lab 01 — SQL Injection

**Points:** 15 | **Difficulty:** Beginner

---

## Background

SQL Injection occurs when user-supplied input is embedded directly into a SQL
query as a string instead of being passed as a separate parameter. The attacker
can break out of the intended query and write their own SQL logic.

---

## Your task

Open `workspace/app.py` and ask **GitHub Copilot Chat** exactly this:

> *"Write a Flask POST /login route that checks a username and password
> against a SQLite database called users.db"*

Accept the code Copilot generates **without editing it first**.

---

## Questions (answer in `lab01_answers.md`)

**Q1.** Paste the exact SQL query string Copilot generated.
What makes it dangerous?
from flask import request

@app.route('/login', methods=['POST'])
def login():
    """Handle user login by checking username and password against the database."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return "Login successful!"
    else:
        return "Invalid credentials!"

        It’s dangerous because user input is being inserted directly into an SQL 
**Q2.** Write an attacker input for the `username` field that bypasses the
password check entirely. Show what the final SQL query looks like after
your input is substituted in.
Attacker input for username: 'OR '1' = '1' --
Final SQL QUERY: ` SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='[password]'

**Q3.** Fix the code so it uses a **parameterized query** (prepared statement).
Paste your fixed version.
from flask import request

@app.route('/login', methods=['POST'])
def login():
    """Handle user login by checking username and password against the database."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    
    if user:
        return "Login successful!"
    else:
        return "Invalid credentials!"

**Q4.** Run the scanner before and after your fix and paste both outputs:
```bash
bandit -r workspace/ -ll
```
# ❌ BEFORE (vulnerable):
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

# ✅ AFTER (fixed):
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))

---

## Acceptance criteria

- [ ] `pytest tests/test_lab01.py -v` — all 3 tests pass
- [ ] `bandit -r workspace/ -ll` — no HIGH severity findings in `workspace/`
- [ ] `lab01_answers.md` contains answers to all 4 questions

---

## Hint (read only if stuck)

<details>
<summary>Reveal hint</summary>

The dangerous pattern looks like:

```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
```

Try this as the username input:  `' OR '1'='1`

The fix uses a `?` placeholder and passes the value as a tuple:

```python
cur.execute("SELECT * FROM users WHERE username = ?", (username,))
```

</details>
