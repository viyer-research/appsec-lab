# Lab 01 Answers

## Q1 — The vulnerable query

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

User input is dropped straight into the SQL string. An attacker can break out of the quotes and rewrite the query logic.

## Q2 — Exploit

- **Username:** `' OR '1'='1`
- **Password:** `anything`

Resulting SQL:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything'
```

The `OR '1'='1'` makes the WHERE clause always true, bypassing auth.

## Q3 — Fix

```python
query = "SELECT username, password FROM users WHERE username = ?"
user = db.execute(query, (username,)).fetchone()
if user and bcrypt.checkpw(password.encode(), user["password"] if isinstance(user["password"], bytes) else user["password"].encode()):
    return "Login successful!", 200
return "Invalid credentials", 401
```

Parameterized query prevents injection. Password verified with bcrypt instead of plain-text comparison.

## Q4 — Bandit results

**Before fix:** HIGH — `B201:flask_debug_true` (debug mode exposes Werkzeug debugger, allows arbitrary code execution)

**After fix:** No HIGH findings.
