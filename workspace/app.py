"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import sqlite3
from flask import Flask, g, request

app = Flask(__name__)
app.config["DATABASE"] = "users.db"
app.config["SECRET_KEY"] = "change-me-in-production"


# ── Database helpers ────────────────────────────────────────────────────────

def get_db():
    """Return a database connection, creating one if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(
            app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

        g.db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                amount REAL NOT NULL,
                details TEXT
            );
                           
        """)

        g.db.execute(
         "INSERT OR IGNORE INTO invoices (id, user_id, amount, details) VALUES (?, ?, ?, ?)",
         (1, "alice", 100.00, "Test invoice")
    )
        g.db.commit()

    return g.db


def init_db():
    """Create tables if they don't exist."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  TEXT NOT NULL,
            amount   REAL NOT NULL,
            details  TEXT
        );
    """)
    db.commit()


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ── Lab 01: SQL Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /login route that checks a username
#               and password against a SQLite database called users.db"
# Paste Copilot's code below this comment, then find and fix the vulnerability.
# YOUR CODE HERE
# Write a Flask POST /login route that checks a username and password against a SQLite database called users.db
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    # Vulnerable to SQL Injection
    query =  "SELECT * FROM users WHERE username = ? AND password = ?"
    user = db.execute(query, (username, password)).fetchone()
    if user:
        return "Login successful!"
    else:
        return "Invalid credentials", 401




# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.
# Write a Flask GET /search route that displays results for a query parameter q in an HTML response
from markupsafe import escape

@app.route("/search")
def search():
    user_input = request.args.get("q")
    safe_input = escape(user_input)

    return f"<h2>Search Results for: {safe_input}</h2>"


# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.
# Write a register_user(username, password) function that hashes the password and stores the user in SQLite database
import bcrypt

def register_user(username, password):
    init_db()

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    db = get_db()
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
    db.commit()

def verify_login(username, password):
    init_db()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        return False
    
    return bcrypt.checkpw(password.encode("utf-8"), user["password"])

# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Write a Flask GET /invoice/<invoice-id> route that returns the invoice as JSON for the logged-in user
# Paste Copilot's code below this comment, then find and fix the vulnerability.
# YOUR CODE HERE
from flask import jsonify, session

@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    user_id = session.get("user_id")

    if not user_id:
        return "Unauthorized", 401

    db = get_db()
    invoice = db.execute(
        "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, user_id)
    ).fetchone()

    if invoice is None:
        return "Invoice not found", 404

    return jsonify({
        "id": invoice["id"],
        "amount": invoice["amount"],
        "details": invoice["details"]
    })

# ── Lab 05: Sensitive Data Exposure ──────────────────────────────────────────
# Ask Copilot: "Write a Python module that connects to AWS S3 and
#               a Stripe payment API using configuration variables"
# Write a Python module that connects to AWS S3 and a Stripe payment API using configuration variables
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
import os
from dotenv import load_dotenv

load_dotenv()

AWS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
STRIPE_KEY = os.environ["STRIPE_SECRET_KEY"]


# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Write a Flask POST /ping route that pings a hostname submitted by the user and returns the output
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
import re
import subprocess

@app.route("/ping", methods=["POST"])
def ping():
    hostname = request.form["hostname"]

    if not re.match(r"^[a-zA-Z0-9.\-]{1,253}$", hostname):
        return {"error": "Invalid hostname"}, 400
    
    result = subprocess.run(
        ["ping", "-c", "4", hostname],
        shell=False,
        capture_output=True,
        text=True
    )

    return f"<pre>{result.stdout}</pre>"


# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Write a Flask POST /upload route that accepts an XML file upload and returns the parsed content as JSON
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
from defusedxml import ElementTree

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    xml_data = file.read()

    try:
        tree = ElementTree.fromstring(xml_data)
        return {"message": "XML uploaded successfully"}, 200
    except Exception:
        return {"error": "Invalid XML"}, 400

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=False)
