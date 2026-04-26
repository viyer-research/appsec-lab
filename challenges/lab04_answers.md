# Lab 04 Answers

## Q1 — Copilot's query

```python
invoice = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
```

No `user_id` filter — any logged-in user can fetch any invoice by ID.

## Q2 — Attack steps

1. Log in as User A
2. Request `/invoice/1` — it works (your own invoice)
3. Change the ID: `/invoice/2` — now you're reading User B's invoice
4. Enumerate IDs 1–1000 to dump every invoice in the database

## Q3 — Why 403 is worse than 404

A `403` confirms the resource exists but you're denied access. A `404` doesn't confirm existence. With 403, an attacker knows which invoice IDs are valid and can target the owner. With 404, they learn nothing.

## Q4 — Fix

```python
row = db.execute(
    "SELECT * FROM invoices WHERE id = ? AND user_id = ?",
    (invoice_id, session.get("user_id"))
).fetchone()
if not row:
    return jsonify({"error": "Not found"}), 404
```

Scopes the query to the current user. Returns 404 for both "doesn't exist" and "not yours".
