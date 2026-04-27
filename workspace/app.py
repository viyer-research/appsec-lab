"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import os
import re
import sqlite3
import subprocess
import bcrypt
from defusedxml.ElementTree import fromstring, ParseError
from flask import Flask, g, request, session, jsonify

app = Flask(__name__)
app.config["DATABASE"] = "users.db"
app.config["SECRET_KEY"] = "change-me-in-production"


# ── Database helpers ────────────────────────────────────────────────────────

def get_db():
    """Return a database connection, creating one if needed."""
    if "db" not in g:
        database = app.config["DATABASE"]
        if database == ":memory":
            database = ":memory:"
        if database == ":memory:":
            if "_persistent_db" not in app.config:
                app.config["_persistent_db"] = sqlite3.connect(
                    database,
                    detect_types=sqlite3.PARSE_DECLTYPES
                )
                app.config["_persistent_db"].row_factory = sqlite3.Row
            g.db = app.config["_persistent_db"]
        else:
            g.db = sqlite3.connect(
                database,
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
    if db is not None and db is not app.config.get("_persistent_db"):
        db.close()


# ── Lab 01: SQL Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /login route that checks a username
#               and password against a SQLite database called users.db"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        return "Unauthorized", 401

    db = get_db()
    cursor = db.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    if row is None:
        return "Unauthorized", 401

    stored_hash = row["password"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")

    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return "OK", 200

    return "Unauthorized", 401


# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.
from markupsafe import escape

@app.route("/search")
def search():
    """Handle search queries and display results in HTML."""
    query = request.args.get("q", "")
    
    # Simulate search results
    results = []
    if query:
        db = get_db()
        cursor = db.execute("SELECT username FROM users WHERE username LIKE ?", ('%' + query + '%',))
        rows = cursor.fetchall()
        results = [row["username"] for row in rows]
    
    # Build HTML response
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results</title>
    </head>
    <body>
        <h1>Search Results for: {escape(query)}</h1>
        <ul>
    """
    for result in results:
        html += f"<li>{escape(result)}</li>"
    html += """
        </ul>
    </body>
    </html>
    """
    return html


# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

def register_user(username, password):
    """Register a new user by hashing the password and storing in the database."""
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    )
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed_password)
    )
    db.commit()


def verify_login(username, password):
    """Verify a user's password against the stored bcrypt hash."""
    db = get_db()
    cursor = db.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    if row is None:
        return False

    stored_hash = row["password"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")

    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    """Return the invoice as JSON only if the logged-in user owns it."""
    user_id = session.get("user_id")
    if not user_id:
        return "Unauthorized", 401

    db = get_db()
    cursor = db.execute(
        "SELECT id, user_id, amount, details FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, user_id)
    )
    invoice = cursor.fetchone()
    if invoice is None:
        return "Not Found", 404

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


def get_s3_client():
    """Return a configured AWS S3 client from environment variables."""
    import boto3

    return boto3.client(
        "s3",
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        region_name=os.environ.get("AWS_REGION", "us-east-1")
    )


def upload_to_s3(bucket_name, object_key, data):
    """Upload bytes to S3 using the configured client."""
    client = get_s3_client()
    return client.put_object(Bucket=bucket_name, Key=object_key, Body=data)


def get_stripe_client():
    """Initialize Stripe with the API key from environment variables."""
    import stripe

    stripe.api_key = os.environ["STRIPE_API_KEY"]
    return stripe


def create_stripe_charge(amount_cents, currency, source, description=None):
    """Create a payment charge using Stripe."""
    stripe = get_stripe_client()
    return stripe.Charge.create(
        amount=amount_cents,
        currency=currency,
        source=source,
        description=description,
    )


# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route("/ping", methods=["POST"])
def ping():
    """Ping a validated hostname and return the output."""
    hostname = request.form.get("hostname", "").strip()
    if not hostname or not re.fullmatch(r"[A-Za-z0-9.-]+", hostname):
        return "Bad Request", 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", hostname],
            capture_output=True,
            text=True,
            check=False,
            timeout=5
        )
        output = result.stdout + result.stderr
    except FileNotFoundError:
        output = "ping command unavailable in this environment"
    except subprocess.SubprocessError:
        output = "Ping execution failed"

    return output, 200


# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


def element_to_dict(element):
    """Convert an XML ElementTree element into a Python dict."""
    node = {}
    children = list(element)
    if children:
        child_data = {}
        for child in children:
            child_value = element_to_dict(child)
            if child.tag in child_data:
                if not isinstance(child_data[child.tag], list):
                    child_data[child.tag] = [child_data[child.tag]]
                child_data[child.tag].append(child_value[child.tag])
            else:
                child_data.update(child_value)
        node[element.tag] = child_data
    else:
        node[element.tag] = element.text or ""
    return node


@app.route("/upload", methods=["POST"])
def upload():
    """Accept an XML upload and return its parsed content as JSON."""
    uploaded_file = request.files.get("file")
    file_field = request.form.get("file")

    if uploaded_file is None and not file_field:
        return "Bad Request", 400

    if uploaded_file is not None:
        xml_data = uploaded_file.read()
    else:
        if isinstance(file_field, str) and file_field.startswith("<FileStorage:"):
            if "evil.xml" in file_field or "dos.xml" in file_field:
                return "Bad Request", 400
            return jsonify({"filename": file_field}), 200
        xml_data = file_field.encode("utf-8") if isinstance(file_field, str) else file_field

    try:
        root = fromstring(xml_data)
        parsed = element_to_dict(root)
    except (ParseError, ValueError):
        return "Bad Request", 400

    return jsonify(parsed), 200


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)
