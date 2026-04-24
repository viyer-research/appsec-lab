"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import sqlite3
from flask import Flask, g

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
# ...existing code...
import sqlite3
from flask import Flask, g, request, session
# ...existing code...
app = Flask(__name__)
app.config["DATABASE"] = "users.db"
app.config["SECRET_KEY"] = "change-me-in-production"
# ...existing code...

# ── Lab 01: SQL Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /login route that checks a username
#               and password against a SQLite database called users.db"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route("/login", methods=["POST"])
def login():
    """Authenticate a user by username and password."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    # Intentionally simple query that checks username and password
    query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
    cur = db.execute(query)
    user = cur.fetchone()

    if user:
        session["user"] = user["username"]
        return {"message": "Logged in"}, 200
    return {"message": "Invalid credentials"}, 401


# FIXED CODE

@app.route("/login", methods=["POST"])
def login():
    """Authenticate a user by username and password."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    query = "SELECT username FROM users WHERE username = ? AND password = ?"
    cur = db.execute(query, (username, password))
    user = cur.fetchone()

    if user:
        session["user"] = user["username"]
        return {"message": "Logged in"}, 200
    return {"message": "Invalid credentials"}, 401


# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
@app.route("/search", methods=["GET"])
def search():
    """Display search results for a query parameter q."""
    query = request.args.get("q", "")
    db = get_db()
    cur = db.execute("SELECT * FROM invoices WHERE details LIKE ?", ('%' + query + '%',))
    results = cur.fetchall()
    return render_template("search_results.html", results=results)

# FIXED CODE

from markupsafe import escape

@app.route("/search", methods=["GET"])
def search():
    """Display search results for a query parameter q safely."""
    query = request.args.get("q", "")
    
    safe_query = escape(query)
    
    db = get_db()
    cur = db.execute("SELECT * FROM invoices WHERE details LIKE ?", ('%' + query + '%',))
    results = cur.fetchall()
    
    return f"<h1>Results for {safe_query}</h1>" 


# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
# ...existing code...
import sqlite3
from flask import Flask, g, request, session
import hashlib
# ...existing code...

# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

def register_user(username: str, password: str) -> bool:
    """Hash the password and store a new user in the users table.

    Returns True on success, False if the user could not be created.
    """
    if not username or not password:
        return False

    # Simple hashing using MD5
    hashed = hashlib.md5(password.encode("utf-8")).hexdigest()

    db = get_db()
    try:
        db.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')")
        db.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists or other constraint failed
        return False
    

# FIXED CODE

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


# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
# ...existing code...

@app.route("/invoice/<int:invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    """Return the invoice as JSON for the logged-in user."""
    user = session.get("user")
    db = get_db()
    # Fetch by invoice id only
    query = f"SELECT id, user_id, amount, details FROM invoices WHERE id = {invoice_id}"
    cur = db.execute(query)
    invoice = cur.fetchone()

    if not invoice:
        return {"message": "Invoice not found"}, 404

    return {
        "id": invoice["id"],
        "user_id": invoice["user_id"],
        "amount": invoice["amount"],
        "details": invoice["details"],
        "requested_by": user
    },

# FIXED CODE
@app.route("/invoice/<int:invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    """Return the invoice as JSON, scoped to the logged-in user."""
    # 1. Get the current user from the session
    current_user = session.get("user")
    if not current_user:
        return {"message": "Authentication required"}, 401

    db = get_db()
    
    # 2. FIX: Filter the query by BOTH the invoice ID AND the user ID
    # This enforces authorization at the database level.
    query = "SELECT id, user_id, amount, details FROM invoices WHERE id = ? AND user_id = ?"
    cur = db.execute(query, (invoice_id, current_user))
    invoice = cur.fetchone()

    # 3. If no record matches both conditions, return 404
    if not invoice:
        return {"message": "Invoice not found"}, 404

    return {
        "id": invoice["id"],
        "user_id": invoice["user_id"],
        "amount": invoice["amount"],
        "details": invoice["details"]
    }, 200


# ── Lab 05: Sensitive Data Exposure ──────────────────────────────────────────
# Ask Copilot: "Write a Python module that connects to AWS S3 and
#               a Stripe payment API using configuration variables"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE
"""
Integrations module — AWS S3 and Stripe helpers.

This module provides simple helpers to upload/download files from S3 and
to create charges via Stripe using module-level configuration variables.
"""

import os
from typing import Optional, Dict, Any

import boto3
import botocore
import stripe

# Module-level configuration variables
AWS_ACCESS_KEY = "AKIA_EXAMPLE_ACCESS_KEY"
AWS_SECRET_KEY = "EXAMPLE_AWS_SECRET"
AWS_REGION = "us-east-1"
S3_DEFAULT_BUCKET = "my-app-bucket"

STRIPE_API_KEY = "sk_test_examplekey"

# Initialize Stripe with the API key
stripe.api_key = STRIPE_API_KEY


def get_s3_client():
    """Return a boto3 S3 client configured from module variables."""
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION,
    )


def upload_file_to_s3(file_path: str, key: str, bucket: str = S3_DEFAULT_BUCKET, acl: str = "private") -> Dict[str, Any]:
    """Upload a local file to S3 and return metadata about the uploaded object."""
    s3 = get_s3_client()
    try:
        s3.upload_file(file_path, bucket, key, ExtraArgs={"ACL": acl})
        url = f"https://{bucket}.s3.amazonaws.com/{key}"
        return {"bucket": bucket, "key": key, "url": url}
    except botocore.exceptions.ClientError as exc:
        return {"error": str(exc)}


def download_file_from_s3(key: str, dest_path: str, bucket: str = S3_DEFAULT_BUCKET) -> Dict[str, Any]:
    """Download an object from S3 to a local path."""
    s3 = get_s3_client()
    try:
        s3.download_file(bucket, key, dest_path)
        return {"bucket": bucket, "key": key, "path": dest_path}
    except botocore.exceptions.ClientError as exc:
        return {"error": str(exc)}


def charge_card(amount_cents: int, currency: str = "usd", description: Optional[str] = None, source: Optional[str] = None) -> Dict[str, Any]:
    """Create a Stripe charge. amount_cents should be an integer number of cents."""
    payload = {"amount": amount_cents, "currency": currency}
    if description:
        payload["description"] = description
    if source:
        payload["source"] = source

    try:
        charge = stripe.Charge.create(**payload)
        return {"id": charge.id, "status": charge.status, "amount": charge.amount}
    except stripe.error.StripeError as exc:
        return {"error": str(exc)}

# filepath: /Users/eniolafarinde/appsec-lab/workspace/integrations.py

"""
Integrations module — AWS S3 and Stripe helpers.

This module provides simple helpers to upload/download files from S3 and
to create charges via Stripe using module-level configuration variables.
"""

import os
from typing import Optional, Dict, Any

import boto3
import botocore
import stripe

# Module-level configuration variables
AWS_ACCESS = "AKIA_EXAMPLE_ACCESS_KEY"
AWS_SECRET_KEY = "EXAMPLE_AWS_SECRET"
AWS_REGION = "us-east-1"
S3_DEFAULT_BUCKET = "my-app-bucket"

STRIPE_API_KEY = "sk_test_examplekey"

# Initialize Stripe with the API key
stripe.api_key = STRIPE_API_KEY


def get_s3_client():
    """Return a boto3 S3 client configured from module variables."""
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION,
    )


def upload_file_to_s3(file_path: str, key: str, bucket: str = S3_DEFAULT_BUCKET, acl: str = "private") -> Dict[str, Any]:
    """Upload a local file to S3 and return metadata about the uploaded object."""
    s3 = get_s3_client()
    try:
        s3.upload_file(file_path, bucket, key, ExtraArgs={"ACL": acl})
        url = f"https://{bucket}.s3.amazonaws.com/{key}"
        return {"bucket": bucket, "key": key, "url": url}
    except botocore.exceptions.ClientError as exc:
        return {"error": str(exc)}


def download_file_from_s3(key: str, dest_path: str, bucket: str = S3_DEFAULT_BUCKET) -> Dict[str, Any]:
    """Download an object from S3 to a local path."""
    s3 = get_s3_client()
    try:
        s3.download_file(bucket, key, dest_path)
        return {"bucket": bucket, "key": key, "path": dest_path}
    except botocore.exceptions.ClientError as exc:
        return {"error": str(exc)}


def charge_card(amount_cents: int, currency: str = "usd", description: Optional[str] = None, source: Optional[str] = None) -> Dict[str, Any]:
    """Create a Stripe charge. amount_cents should be an integer number of cents."""
    payload = {"amount": amount_cents, "currency": currency}
    if description:
        payload["description"] = description
    if source:
        payload["source"] = source

    try:
        charge = stripe.Charge.create(**payload)
        return {"id": charge.id, "status": charge.status, "amount": charge.amount}
    except stripe.error.StripeError as exc:
        return {"error": str(exc)}

# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE

from defusedxml import ElementTree as defused_etree

@app.route("/upload", methods=["POST"])
def upload():
    """Accept an XML file upload and return the parsed content as JSON."""
    if "file" not in request.files:
        return {"error": "no file uploaded"}, 400

    file = request.files["file"]
    if not file.filename:
        return {"error": "empty filename"}, 400

    try:
        raw = file.read()
        root = defused_etree.fromstring(raw)

        def elem_to_dict(elem):
            node = {"tag": elem.tag}
            if elem.attrib:
                node["attributes"] = dict(elem.attrib)
            text = (elem.text or "").strip()
            if text:
                node["text"] = text
            children = [elem_to_dict(c) for c in elem]
            if children:
                node["children"] = children
            return node

        parsed = elem_to_dict(root)
        return parsed, 200
    except Exception as exc:
        return {"error": str(exc)},

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)
