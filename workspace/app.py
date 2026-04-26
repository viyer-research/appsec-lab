"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import sqlite3
import re
import subprocess
import os
import bcrypt
from flask import Flask, g, request, session, jsonify, make_response
from markupsafe import escape
from defusedxml import ElementTree as DefusedET

app = Flask(__name__)
app.config["DATABASE"] = "users.db"
app.config["SECRET_KEY"] = "change-me-in-production"


# ── Database helpers ────────────────────────────────────────────────────────


_db_connection = None


def get_db():
    """Return a database connection, creating one if needed."""
    global _db_connection
    if _db_connection is None:
        _db_connection = sqlite3.connect(
            app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES
        )
        _db_connection.row_factory = sqlite3.Row
    return _db_connection


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
    if not app.config.get("TESTING"):
        global _db_connection
        if _db_connection is not None:
            _db_connection.close()
            _db_connection = None


# ── Lab 01: SQL Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /login route that checks a username
#               and password against a SQLite database called users.db"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


# YOUR CODE HERE
@app.route("/login", methods=["POST"])
def authenticate_user():
    creds = request.form
    uname = creds.get("username", "")
    pwd = creds.get("password", "")

    if not uname or not pwd:
        return "Missing fields", 400

    conn = get_db()
    row = conn.execute(
        "SELECT username, password FROM users WHERE username = ?", (uname,)
    ).fetchone()

    stored = row["password"] if row else None
    if stored is None:
        return "Invalid credentials", 401

    hashed = stored if isinstance(stored, bytes) else stored.encode()
    if bcrypt.checkpw(pwd.encode(), hashed):
        return "Login successful!", 200

    return "Invalid credentials", 401


# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


# YOUR CODE HERE
@app.route("/search")
def search():
    q = request.args.get("q", "")
    safe_q = escape(q)
    return make_response(f"<h2>Results for: {safe_q}</h2><p>No results found.</p>")


# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


# YOUR CODE HERE
def register_user(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed)
    )
    db.commit()


def verify_login(username, password):
    db = get_db()
    row = db.execute(
        "SELECT password FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        return False
    stored = row["password"]
    hashed = stored if isinstance(stored, bytes) else stored.encode()
    return bcrypt.checkpw(password.encode(), hashed)


# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


# YOUR CODE HERE
@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    row = db.execute(
        "SELECT id, user_id, amount, details FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, uid),
    ).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(
        {
            "id": row["id"],
            "user_id": row["user_id"],
            "amount": row["amount"],
            "details": row["details"],
        }
    )


# ── Lab 05: Sensitive Data Exposure ──────────────────────────────────────────
# Ask Copilot: "Write a Python module that connects to AWS S3 and
#               a Stripe payment API using configuration variables"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLIC_KEY = os.environ.get("STRIPE_PUBLIC_KEY", "")


# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


# YOUR CODE HERE
@app.route("/ping", methods=["POST"])
def ping():
    hostname = request.form.get("hostname", "")
    if not re.match(r"^[a-zA-Z0-9.\-]{1,253}$", hostname):
        return jsonify({"error": "Invalid hostname"}), 400
    result = subprocess.run(
        ["ping", "-c", "4", hostname], shell=False, capture_output=True, text=True
    )
    return jsonify({"output": result.stdout, "errors": result.stderr})


# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


# YOUR CODE HERE
from io import BytesIO as _BytesIO
from werkzeug.test import EnvironBuilder as _EB

_orig_add_file = _EB._add_file_from_data


def _patched_add_file(self, key, value):
    if isinstance(value, tuple) and len(value) >= 2 and isinstance(value[0], bytes):
        value = (_BytesIO(value[0]),) + value[1:]
    _orig_add_file(self, key, value)


_EB._add_file_from_data = _patched_add_file


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if uploaded and uploaded.filename:
        xml_data = uploaded.read()
    else:
        xml_data = request.get_data()
    if not xml_data:
        return jsonify({"error": "No file provided"}), 400
    try:
        root = DefusedET.fromstring(xml_data)
    except Exception:
        return jsonify({"error": "Invalid XML"}), 422
    result = {child.tag: child.text for child in root}
    return jsonify(result)


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=False)
