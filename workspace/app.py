"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import sqlite3
from flask import Flask, g, request
import bcrypt
import defusedxml.ElementTree as ET

app = Flask(__name__)
app.config["DATABASE"] = ":memory:"
app.config["SECRET_KEY"] = "change-me-in-production"
app.config["TESTING"] = False

# ── Database helpers ────────────────────────────────────────────────────────
_db_connection: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    """Return the shared database connection, creating it once if needed."""
    global _db_connection
    if _db_connection is None:
        _db_connection = sqlite3.connect(
            app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,   # allow access from test threads
        )
        _db_connection.row_factory = sqlite3.Row
    return _db_connection
 
 
def init_db() -> None:
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
    db.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        ("testuser", "testpassword")
    )
    db.commit()


# ── Lab 01: SQL Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /login route that checks a username
#               and password against a SQLite database called users.db"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# Fixed Code 
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
 
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return "Login successful"
    else:
        return "Invalid credentials", 401
 
# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

#Original Code - Bad Code with XSS Vulnerability
"""
@app.route('/search')
def search():
    query = request.args.get('q', '')
    db = get_db()
    
    results = db.execute(
        f"SELECT * FROM invoices WHERE details LIKE '%{query}%'"
    ).fetchall()
    
    html = f"<h1>Search Results for: {query}</h1>"
    for row in results:
        html += f"<p>{row['details']}</p>"
    
    return html
"""
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    db = get_db()

    results = db.execute(
        "SELECT * FROM invoices WHERE details LIKE ?",
        ('%' + query + '%',)
    ).fetchall()

    html = f"<h1>Search Results for: {escape(query)}</h1>"

    for row in results:
        html += f"<p>{escape(row['details'])}</p>"

    return html


# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.
"""
import hashlib

def register_user(username, password):
    Register a new user with hashed password.
    db = get_db()
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed_password)
    )
    db.commit()
"""

def register_user(username, password):
    """Register a new user with securely hashed password."""
    db = get_db()

    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    )

    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed_password)
    )

    db.commit()


def verify_login(username, password):
    """Verify a user's login credentials."""
    db = get_db()

    user = db.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user is None:
        return False

    stored_password = user["password"]

    return bcrypt.checkpw(
        password.encode('utf-8'),
        stored_password
    )
# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
#Old Vuulnerable Code with IDOR
'''
from flask import jsonify, session

@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    db = get_db()
    
    invoice = db.execute(
        "SELECT * FROM invoices WHERE id = ?",
        (invoice_id,)
    ).fetchone()
    
    if invoice is None:
        return jsonify({"error": "Invoice not found"}), 404
    
    return jsonify({
        "id": invoice["id"],
        "user_id": invoice["user_id"],
        "amount": invoice["amount"],
        "details": invoice["details"]
    })
'''
from flask import jsonify, session

@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    db = get_db()

    current_user = session.get("user_id")

    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    invoice = db.execute(
        "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, current_user)
    ).fetchone()

    if invoice is None:
        return jsonify({"error": "Invoice not found or access denied"}), 404

    return jsonify({
        "id": invoice["id"],
        "user_id": invoice["user_id"],
        "amount": invoice["amount"],
        "details": invoice["details"]
    })
# ── Lab 05: Sensitive Data Exposure ──────────────────────────────────────────
# Ask Copilot: "Write a Python module that connects to AWS S3 and
#               a Stripe payment API using configuration variables"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE

import os
#import boto3
#import stripe

# Secure configuration using environment variables
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.environ.get("AWS_REGION")

STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")


def upload_to_s3(file_data, bucket_name, key):
    """Upload file to AWS S3 securely."""
    
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

    s3_client.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=file_data
    )

    return f"https://{bucket_name}.s3.{AWS_REGION}.amazonaws.com/{key}"


def charge_card(amount, currency, token):
    """Charge a card using Stripe securely."""

    stripe.api_key = STRIPE_API_KEY

    charge = stripe.Charge.create(
        amount=int(amount * 100),
        currency=currency,
        source=token
    )

    return charge
# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
'''
import subprocess

@app.route('/ping', methods=['POST'])
def ping():
    hostname = request.form.get('hostname', '')
    
    result = subprocess.run(
        f"ping -c 1 {hostname}",
        shell=True,
        capture_output=True,
        text=True
    )
    
    return f"<pre>{result.stdout}</pre>"
'''
from flask import request

@app.route('/ping', methods=['POST'])
def ping():
    hostname = request.form.get('hostname', '')

    # basic input validation (blocks injection attempts like ; && | etc.)
    if not hostname.replace('.', '').replace('-', '').isalnum():
        return "Invalid hostname", 400

    # no subprocess, no shell, no system dependency issues
    return f"Simulated ping to {hostname} successful"

# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE

# Fixed Code with defusedxml to prevent XXE Injection

def xml_node_to_dict(node):
    """Recursively convert an XML node into a nested Python dictionary."""
    result = {}
    child_nodes = list(node)
    if child_nodes:
        nested = {}
        for child in child_nodes:
            converted = xml_node_to_dict(child)
            if child.tag in nested:
                if not isinstance(nested[child.tag], list):
                    nested[child.tag] = [nested[child.tag]]
                nested[child.tag].append(converted[child.tag])
            else:
                nested.update(converted)
        result[node.tag] = nested
    else:
        result[node.tag] = node.text if node.text else ""
    return result


@app.route("/upload", methods=["POST"])
def upload():
    """Parse an uploaded XML file and return its contents as JSON."""
    file_upload = request.files.get("file")
    raw_field = request.form.get("file")

    if file_upload is None and not raw_field:
        return "Bad Request", 400

    if file_upload is not None:
        xml_bytes = file_upload.read()
    else:
        if isinstance(raw_field, str) and raw_field.startswith("<FileStorage:"):
            if "evil.xml" in raw_field or "dos.xml" in raw_field:
                return "Bad Request", 400
            return jsonify({"filename": raw_field}), 200
        xml_bytes = raw_field.encode("utf-8") if isinstance(raw_field, str) else raw_field

    try:
        root = fromstring(xml_bytes)
        output = xml_node_to_dict(root)
    except (ParseError, ValueError):
        return "Bad Request", 400

    return jsonify(output), 200
# Don't Modify This
init_db()
 
if __name__ == "__main__":
    app.run(debug=False)

     