# Q1
 return f"<h1>Search Results for '{query}'</h1>"

# Q2
http://amaz0n.com/search?q=<script>alert('hacked')</script>

# Q3
A real attacker could use `document cookie` to steal a user's session cookie and send it to another server. The attacker can now hijack the session and bypass the login process to gain unauthorized access to the user's account.

# Q4
from markupsafe import escape
@app.route("/search")
def search():
    user_input = request.args.get("q")
    safe_input = escape(user_input)

    return f"<h1>Search Results for '{safe_input}'</h1>"

# Q5
Content Security Policy (CSP) is a HTTP header that helps block this attack with restrictions on scripts and browser resources. 