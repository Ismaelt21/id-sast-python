# VULNERABLE: Flask SQL Injection - Training Sample
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# Severity: CRITICAL
# Description: Flask routes pass user-controlled request parameters directly into SQL

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DB = "app.db"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user")
def get_user():
    """VULNERABLE: Query param injected directly into SQL."""
    user_id = request.args.get("id")  # e.g. ?id=1 OR 1=1--
    conn = get_db()
    # VULN: No parameterization — user_id comes directly from the URL
    query = "SELECT * FROM users WHERE id = " + user_id
    result = conn.execute(query).fetchone()
    return jsonify(dict(result)) if result else ("Not found", 404)


@app.route("/search")
def search():
    """VULNERABLE: Search field injected into LIKE clause."""
    term = request.args.get("q", "")
    conn = get_db()
    # VULN: term can escape the LIKE clause — e.g. %' UNION SELECT...--
    query = "SELECT id, name, email FROM users WHERE name LIKE '%" + term + "%'"
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/login", methods=["POST"])
def login():
    """VULNERABLE: Login endpoint susceptible to authentication bypass."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    conn = get_db()
    # VULN: Classic auth bypass — username: admin'--
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    user = conn.execute(query).fetchone()
    if user:
        return jsonify({"status": "ok", "user": dict(user)})
    return jsonify({"status": "fail"}), 401


@app.route("/order")
def get_order():
    """VULNERABLE: ORDER BY injection (cannot use parameterized for column names)."""
    sort_col = request.args.get("sort", "id")
    conn = get_db()
    # VULN: sort_col is attacker-controlled — allows UNION-based exfiltration
    query = f"SELECT * FROM orders ORDER BY {sort_col}"
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/report")
def report():
    """VULNERABLE: Multiple params concatenated into a single query."""
    start = request.args.get("start", "2024-01-01")
    end = request.args.get("end", "2024-12-31")
    dept = request.args.get("dept", "sales")
    conn = get_db()
    # VULN: All three params are injectable
    query = (
        "SELECT * FROM sales WHERE date BETWEEN '"
        + start
        + "' AND '"
        + end
        + "' AND department = '"
        + dept
        + "'"
    )
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(debug=True)