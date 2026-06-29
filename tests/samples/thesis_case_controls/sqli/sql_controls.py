"""Negative controls for SQL injection."""

import sqlite3
from flask import Flask, request


app = Flask(__name__)


@app.route("/accounts/raw")
def account_lookup_vulnerable():
    customer_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    query = (
        "SELECT id, email, tier "
        "FROM accounts "
        f"WHERE id = '{customer_id}' "
        "AND archived = 0"
    )
    cursor.execute(query)
    return cursor.fetchone()


@app.route("/accounts/parameterized")
def account_lookup_safe():
    customer_id = int(request.args.get("id", "0"))
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    query = (
        "SELECT id, email, tier "
        "FROM accounts "
        "WHERE id = ? AND archived = 0"
    )
    cursor.execute(query, (customer_id,))
    return cursor.fetchone()


def format_account_slug(account_name: str) -> str:
    """Innocuous helper that resembles user-driven formatting."""

    return account_name.strip().lower().replace(" ", "-")

