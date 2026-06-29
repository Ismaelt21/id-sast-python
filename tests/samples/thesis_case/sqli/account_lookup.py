"""Positive benchmark: SQL injection in a realistic account lookup flow."""

import sqlite3
from flask import Flask, request


app = Flask(__name__)


@app.route("/accounts/by-id")
def account_lookup():
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


@app.route("/accounts/search")
def account_search():
    term = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    query = (
        "SELECT id, email, tier "
        "FROM accounts "
        "WHERE email LIKE '%" + term + "%' "
        "ORDER BY created_at DESC"
    )
    cursor.execute(query)
    return cursor.fetchall()

