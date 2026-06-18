# VULNERABLE: Nested / Multi-layer SQL Injection - Training Sample
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# Severity: CRITICAL
# Description: Injection buried inside helper functions, decorators, or indirect call chains

import sqlite3


# ── Helper that looks "safe" but is not ────────────────────────────────────────

def _build_where_clause(field, value):
    """VULNERABLE: Utility that constructs raw WHERE — called by multiple routes."""
    # VULN: Consumers assume this escapes; it does not
    return f"{field} = '{value}'"


def _execute(query):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(query)          # VULN: raw execute — no parameterization
    return cur.fetchall()


# ── Layer 1 calls helper → helper is the sink ──────────────────────────────────

def get_user(username):
    """VULNERABLE: Two layers deep — injection lives in _build_where_clause."""
    where = _build_where_clause("username", username)
    query = "SELECT * FROM users WHERE " + where
    return _execute(query)


def get_product(product_id):
    """VULNERABLE: Integer-looking param still injectable if not cast."""
    where = _build_where_clause("id", product_id)
    query = "SELECT * FROM products WHERE " + where
    return _execute(query)


# ── Subquery injection ──────────────────────────────────────────────────────────

def get_users_in_group(group_name):
    """VULNERABLE: Injection inside a subquery."""
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULN: group_name injected into inner SELECT
    query = (
        "SELECT * FROM users WHERE group_id IN "
        "(SELECT id FROM groups WHERE name = '" + group_name + "')"
    )
    cur.execute(query)
    return cur.fetchall()


# ── Conditional / dynamic column injection ─────────────────────────────────────

def dynamic_search(filters: dict):
    """VULNERABLE: Dict keys and values both flow into query unescaped."""
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULN: both key (column name) and value (column value) are attacker-controlled
    clauses = " AND ".join(
        f"{col} = '{val}'" for col, val in filters.items()
    )
    query = "SELECT * FROM records WHERE " + clauses
    cur.execute(query)
    return cur.fetchall()


# ── Stored-procedure style: second-order injection ─────────────────────────────

def register_user(username, email):
    """VULNERABLE: Stores tainted data; second-order injection when retrieved."""
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULN: Saves malicious payload — injection fires when username is later reused
    cur.execute(
        "INSERT INTO users (username, email) VALUES ('"
        + username + "', '" + email + "')"
    )
    conn.commit()


def promote_user_by_username(raw_username_from_db):
    """VULNERABLE: Reads stored tainted data and reuses it unsafely — second-order."""
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULN: payload was injected at registration; fires here on reuse
    query = "UPDATE users SET role='admin' WHERE username='" + raw_username_from_db + "'"
    cur.execute(query)
    conn.commit()


# ── Recursive helper ───────────────────────────────────────────────────────────

def build_in_clause(values: list):
    """VULNERABLE: Recursively builds IN(...) list from user values."""
    if not values:
        return "(NULL)"
    # VULN: No quoting/escaping of individual elements
    return "(" + ", ".join("'" + str(v) + "'" for v in values) + ")"


def get_users_by_ids(ids: list):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULN: build_in_clause does no sanitization
    query = "SELECT * FROM users WHERE id IN " + build_in_clause(ids)
    cur.execute(query)
    return cur.fetchall()