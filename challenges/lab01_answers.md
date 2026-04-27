# Lab 01 Answers
# Q1
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
# This query is dangerous because it allows user input to directly iserted into the SQL statement, which makes the application vulernable. An attacker can simply manipulate the input to change the logic of the query and gain access to the application.

# Q2 
Username: ' OR '1'='1
Password: 1234

Final SQL query:
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '1234'

# Q3
query = "SELECT * FROM users WHERE username = ? AND password = ?"
user = db.execute(query, (username, password)).fetchone()

# Q4
# Before Fix (Vulernable Code):
Test results:
>> Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
   Severity: High   Confidence: Medium
   CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b201_flask_debug_true.html
   Location: workspace/app.py:114:4
113             init_db()
114         app.run(debug=True)

--------------------------------------------------

Code scanned:
        Total lines of code: 46
        Total lines skipped (#nosec): 0

Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low: 1
                Medium: 0
                High: 1
        Total issues (by confidence):
                Undefined: 0
                Low: 0
                Medium: 2
                High: 0

# After fix (Secure Code): 
Test results:
        No issues identified.

Code scanned:
        Total lines of code: 57
        Total lines skipped (#nosec): 0

Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low: 1
                Medium: 0
                High: 0
        Total issues (by confidence):
                Undefined: 0
                Low: 0
                Medium: 1
                High: 0
