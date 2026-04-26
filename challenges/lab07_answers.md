# Lab 07 Answers

## Q1 — Copilot's parser

Copilot used `lxml.etree.XMLParser()` with default settings. External entities are **enabled** by default in lxml — the parser will resolve `SYSTEM` entities and fetch local files or network resources.

## Q2 — XXE payload

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

The parser resolves the `&xxe;` entity, reads `/etc/passwd`, and the server returns its contents in the JSON response.

## Q3 — Other XXE attacks

**SSRF (Server-Side Request Forgery):** An attacker defines an entity pointing to an internal URL (`<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`) to scan internal networks or access cloud metadata endpoints.

## Q4 — Fix

```python
from defusedxml import ElementTree
root = ElementTree.fromstring(xml_data)
```

`defusedxml` is a drop-in replacement that blocks external entities, DTD processing, and entity expansion by default.

## Q5 — Secure lxml settings

```python
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False
)
```
