# Lab 01 — SQL Injection Answers

## Q1: Paste the exact SQL query string Copilot generated. What makes it dangerous?

**The vulnerable query:**

```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

**Why it's dangerous:**
User input from `username` and `password` is directly embedded into the SQL string using an f-string. An attacker can break out of the string literal and inject arbitrary SQL code. For example, if they provide `' OR '1'='1` as the username, the resulting query becomes:

```sql
SELECT * FROM users WHERE username='' OR '1'='1' AND password='[password]'
```

This query returns all users because `'1'='1'` is always true, bypassing authentication.

---

## Q2: Write an attacker input for the `username` field that bypasses the password check entirely. Show what the final SQL query looks like after your input is substituted in

**Attacker input for username:**

```
' OR '1'='1' --
```

**Final SQL query after substitution:**

```sql
SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='anything'
```

**Explanation:**

- The `' OR '1'='1' --` closes the username string literal
- `OR '1'='1'` makes the WHERE condition always true
- The `--` comment syntax ignores the rest of the query (the password check)
- Result: The query returns all users regardless of password

---

## Q3: Fix the code so it uses a **parameterized query** (prepared statement). Paste your fixed version

**Fixed code:**

```python
@app.route('/login', methods=['POST'])
def login():
    """Handle user login by checking username and password against the database."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    db = get_db()
    user = db.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    
    if user is None:
        return "Invalid credentials", 401
    
    if bcrypt.checkpw(password.encode(), user[0]):
        return "Login successful", 200
    
    return "Invalid credentials", 401
```

**Key security improvements:**

- Uses `?` placeholders instead of string formatting
- Passes parameters as a tuple to `execute()`
- SQLite treats parameters as data, never as executable code
- SQL injection is impossible

---

## Q4: Run the scanner before and after your fix and paste both outputs

**BEFORE FIX (vulnerable):**

```
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   Location: workspace/app.py:68:14
67     cursor = db.cursor()
68     query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
69     cursor.execute(query)

--------------------------------------------------
>> Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
   Severity: High   Confidence: Medium
   CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
   Location: workspace/app.py:131:4
130         init_db()
131     app.run(debug=True)

--------------------------------------------------

Code scanned:
 Total lines of code: 60
 Total lines skipped (#nosec): 0

Run metrics:
 Total issues (by severity):
  Undefined: 0
  Low: 1
  Medium: 1
  High: 1
```

**AFTER FIX (parameterized query):**

```
>> Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
   Severity: High   Confidence: Medium
   CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
   Location: workspace/app.py:131:4
130         init_db()
131     app.run(debug=True)

--------------------------------------------------

Code scanned:
 Total lines of code: 60
 Total lines skipped (#nosec): 0

Run metrics:
 Total issues (by severity):
  Undefined: 0
  Low: 1
  Medium: 0
  High: 1
```

**Result:** ✅ The SQL injection vulnerability (B608) has been successfully eliminated!

---

## Summary

The SQL injection vulnerability was caused by string interpolation of user input directly into SQL queries. The fix uses **parameterized queries** (prepared statements) which separate SQL code from data. In SQLite, parameter placeholders (`?`) ensure user input is always treated as data, never as executable SQL code.

All tests pass: ✅ `pytest tests/test_lab01.py -v` (3/3 passed)
