## Lab 07: XML External Entity (XXE) Injection Answers

### Q1. Parser and Settings
**The parser used is likely:** `lxml.etree` or `xml.etree.ElementTree`.
**Are external entities enabled?** Most powerful parsers like `lxml` have external entity resolution **enabled by default** or require explicit flags to disable them. While Python's built-in `xml.etree` is somewhat limited, it can still be vulnerable to billion laughs attacks (entity expansion), and `lxml` is highly vulnerable to XXE (external file reading) unless configured otherwise.


### Q2. Malicious XXE Payload
The following payload defines an external entity named `&xxe;` that points to the system's password file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <content>&xxe;</content>
</root>
```

### Q3. Other Attacks: SSRF
**Attack Name:** Server-Side Request Forgery (SSRF).
**How it works:** An attacker can point the `SYSTEM` entity to an internal URL (e.g., `http://169.254.169.254/latest/meta-data/`) instead of a local file, forcing the server to make requests to internal resources that aren't exposed to the public internet.


### Q4. Fixed Code (`defusedxml`)
The `defusedxml` library is the industry standard for Python to prevent XML-based attacks. It wraps standard parsers but explicitly disables dangerous features.

```python
from flask import request
from defusedxml import ElementTree as SafeET

@app.route("/upload", methods=["POST"])
def upload():
    """Accept an XML file upload safely and return content as JSON."""
    if "file" not in request.files:
        return {"error": "No file uploaded"}, 400

    file = request.files["file"]
    try:
        # FIX: defusedxml ignores DTDs and External Entities by default
        raw_xml = file.read()
        root = SafeET.fromstring(raw_xml)

        # Basic conversion of XML tags to a dictionary
        data = {child.tag: child.text for child in root}
        return data, 200

    except Exception as e:
        # This will catch XML parsing errors or security violations
        return {"error": "Invalid or unsafe XML provided"}, 400
```


### Q5. Hardening `lxml` Directly
If you cannot use `defusedxml` and must use `lxml`, you must initialize the parser with these three specific security flags:

1.  `resolve_entities=False` (Stops the parser from resolving the `&xxe;` reference)
2.  `no_network=True` (Prevents the parser from making network requests for DTDs)
3.  `dtd_validation=False` (Disables DTD processing entirely)

