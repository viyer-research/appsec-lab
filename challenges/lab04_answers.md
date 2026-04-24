## Lab 04: Insecure Direct Object Reference (IDOR) Answers

### Q1. The Vulnerable Query
**The database query Copilot generated is:**
```python
query = f"SELECT id, user_id, amount, details FROM invoices WHERE id = {invoice_id}"
cur = db.execute(query)
```
**Does it filter by User ID?** No. The query only filters by the `id` of the invoice itself. It retrieves the record based purely on the primary key provided in the URL, regardless of who is currently logged into the session.


### Q2. Step-by-Step Attack Scenario
1.  **Login:** The attacker logs into their own account (User A).
2.  **Observation:** The attacker views their own invoice and notices the URL looks like `/invoice/101`.
3.  **Manipulation:** The attacker guesses that other invoices exist with nearby IDs. They change the URL in their browser or via a tool like Postman to `/invoice/102`.
4.  **Exploitation:** Because the server code only checks if the user is logged in (Authentication) but doesn't check if they own invoice #102 (Authorization), the server returns the private details of User B's invoice.


### Q3. 403 Forbidden vs. 404 Not Found
Returning a `403 Forbidden` confirms to an attacker that the resource **definitely exists**, even if they aren't allowed to see it. This allows an attacker to "enumerate" (map out) the database to see how many users or invoices exist.

Returning a `404 Not Found` (or a generic error) is safer because it provides **zero information**. The attacker cannot distinguish between an ID that doesn't exist and an ID that belongs to someone else.


### Q4. Fixed Code (Scoped Query)
The fix involves adding the `user_id` from the session directly into the `WHERE` clause of the SQL query. This ensures that even if an attacker requests another person's ID, the database will return no results.

```python
@app.route("/invoice/<int:invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    """Return the invoice as JSON, scoped to the logged-in user."""
    current_user = session.get("user")
    if not current_user:
        return {"message": "Authentication required"}, 401

    db = get_db()
    query = "SELECT id, user_id, amount, details FROM invoices WHERE id = ? AND user_id = ?"
    cur = db.execute(query, (invoice_id, current_user))
    invoice = cur.fetchone()
    if not invoice:
        return {"message": "Invoice not found"}, 404

    return {
        "id": invoice["id"],
        "user_id": invoice["user_id"],
        "amount": invoice["amount"],
        "details": invoice["details"]
    }, 200
```
