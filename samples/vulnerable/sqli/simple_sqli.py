# VULNERABLE: SQL Injection - Training Sample
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# Severity: CRITICAL
# Description: User input is directly concatenated into SQL queries without sanitization

import sqlite3

def get_user_by_id(user_id):
    """VULNERABLE: Direct string concatenation in SQL query."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULN: user_id is concatenated directly — attacker can inject SQL
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def get_user_by_name(username):
    """VULNERABLE: f-string interpolation into SQL."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULN: f-string allows arbitrary SQL — e.g. username = "' OR '1'='1"
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


def login(username, password):
    """VULNERABLE: Classic login bypass via SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULN: Attacker can set username = "admin' --" to bypass password check
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    return user is not None


def search_products(keyword):
    """VULNERABLE: LIKE clause injection."""
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()

    # VULN: Unsanitized LIKE clause — can be abused to dump all records
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    return cursor.fetchall()


def delete_user(user_id):
    """VULNERABLE: Destructive query with injected input."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULN: Injection here can delete arbitrary rows or entire tables
    query = "DELETE FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    conn.commit()


if __name__ == "__main__":
    # Simulated attacker input
    malicious_id = "1 OR 1=1"
    malicious_user = "' OR '1'='1' --"

    print(get_user_by_id(malicious_id))
    print(get_user_by_name(malicious_user))
    print(login("admin' --", "anything"))