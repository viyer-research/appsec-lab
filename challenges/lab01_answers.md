## Lab 01: SQL Injection Answers

### Q1. Exact SQL Query String
The exact query generated is:
```python
query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
```
**Why it is dangerous:**
The code uses a Python f-string to insert user input directly into the SQL command. Because the input isn't sanitized or separated from the command logic, an attacker can input special SQL characters (like `'`, `--`, or `;`) to change the structure of the query. This allows them to bypass authentication or manipulate the database.


### Q2. Attacker Input & Resulting Query
**Attacker Input:**
* Username: `' OR '1'='1' --`
* Password: (can be anything)

**Final SQL Query after substitution:**
```sql
SELECT username FROM users WHERE username = '' OR '1'='1' --' AND password = 'password'
```
**Explanation:** The `'` closes the username string, `OR '1'='1'` makes the `WHERE` clause always true, and `--` comments out the rest of the query (ignoring the password check entirely).


### Q3. Fixed Code (Parameterized Query)
To fix this, you must use **placeholders (`?`)** provided by the database driver. This ensures the database treats the input strictly as data, not as executable code.

```python
@app.route("/login", methods=["POST"])
def login():
    """Authenticate a user by username and password."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    
    # FIX: Use parameterized placeholders instead of f-strings
    query = "SELECT username FROM users WHERE username = ? AND password = ?"
    cur = db.execute(query, (username, password))
    user = cur.fetchone()

    if user:
        session["user"] = user["username"]
        return {"message": "Logged in"}, 200
    return {"message": "Invalid credentials"}, 401
```

### Q4. Bandit Scanner Outputs

**Before Fix (Vulnerable):**
```text
[low] B608:hardcoded_sql_expressions
  Possible SQL injection vector through string-based query construction.
  Location: workspace/app.py:84
83:     # Intentionally simple query that checks username and password
84:     query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
85:     cur = db.execute(query)
```

**After Fix (Secure):**
```text
Run started:
...
--------------------------------------------------
Ran 1 tests in 0.05s:
  1 success, 0 failures, 0 skipped
--------------------------------------------------
No issues identified.
```