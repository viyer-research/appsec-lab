"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import sqlite3
from flask import Flask, g, request, session
import bcrypt
from markupsafe import escape

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

@app.route("/login", methods=["POST"])
def login():
    """Authenticate user with username and password."""
    username = request.form.get("username")
    password = request.form.get("password")
    
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


# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route('/search', methods=['GET'])
def search():
    """Display search results for a given query parameter."""
    query = request.args.get('q', '')
    
    results = [
        "Result 1: Python Security Best Practices",
        "Result 2: Web Application Security",
        "Result 3: OWASP Top 10"
    ]
    
    html = f"""
    <html>
        <head><title>Search Results</title></head>
        <body>
            <h2>Results for: {escape(query)}</h2>
            <ul>
    """
    
    for result in results:
        html += f"<li>{result}</li>\n"
    
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
    """Register a new user by hashing the password and storing in database."""
    import hashlib
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    db = get_db()
    db.execute("INSERT INTO users VALUES (?, ?)", (username, hashed))
    db.commit()

# YOUR CODE HERE


# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    """Return invoice data as JSON for the current user."""
    current_user = session.get('user_id')
    if not current_user:
        return {"error": "Unauthorized"}, 401
    
    db = get_db()
    invoice = db.execute(
        "SELECT id, user_id, amount, details FROM invoices WHERE id = ? AND user_id = ?",
        (invoice_id, current_user)
    ).fetchone()
    
    if invoice is None:
        return {}, 404
    
    return {
        "id": invoice["id"],
        "amount": invoice["amount"],
        "details": invoice["details"]
    }

# YOUR CODE HERE


# ── Lab 05: Sensitive Data Exposure ──────────────────────────────────────────
# Ask Copilot: "Write a Python module that connects to AWS S3 and
#               a Stripe payment API using configuration variables"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
S3_BUCKET = os.environ.get("S3_BUCKET")

# Stripe Payment API Configuration
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLIC_KEY = os.environ.get("STRIPE_PUBLIC_KEY")

# Database Configuration
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_USER = os.environ.get("DB_USER")

import boto3
import stripe

def initialize_aws():
    """Initialize AWS S3 client."""
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

def initialize_stripe():
    """Initialize Stripe API."""
    stripe.api_key = STRIPE_SECRET_KEY
    return stripe

# YOUR CODE HERE


# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Paste Copilot's code below this comment, then find and fix the vulnerability.
@app.route('/ping', methods=['POST'])
def ping():
    """Ping a hostname and return the output."""
    hostname = request.form.get('hostname')
    
    # Input validation with regex allowlist
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', hostname):
        return {"error": "Invalid hostname"}, 400
    
    # Use shell=False with arguments as a list
    import subprocess
    result = subprocess.run(["ping", "-c", "4", hostname],
                           shell=False, capture_output=True, text=True)
    
    return {
        "output": result.stdout,
        "error": result.stderr,
        "returncode": result.returncode
    }
# YOUR CODE HERE


# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route('/upload', methods=['POST'])
def upload():
    """Accept XML file upload and return parsed content as JSON."""
    xml_file = request.files.get('xml')
    if not xml_file:
        return {"error": "No XML file provided"}, 400
    
    xml_data = xml_file.read().decode('utf-8')
    
    from defusedxml import ElementTree
    tree = ElementTree.fromstring(xml_data)
    
    # Convert XML to JSON-like structure
    def xml_to_dict(element):
        result = {}
        if element.text and element.text.strip():
            result["text"] = element.text.strip()
        
        for child in element:
            child_dict = xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_dict)
            else:
                result[child.tag] = child_dict
        
        return result
    
    json_result = xml_to_dict(tree)
    return json_result

# YOUR CODE HERE


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)
