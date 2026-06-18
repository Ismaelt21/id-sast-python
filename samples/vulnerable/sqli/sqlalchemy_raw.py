# VULNERABLE: SQLAlchemy Raw SQL Injection - Training Sample
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# Severity: CRITICAL
# Description: SQLAlchemy's text() used with string formatting bypasses ORM protections

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///app.db")
Session = sessionmaker(bind=engine)


def find_user(username):
    """VULNERABLE: text() with Python string formatting — no binding."""
    session = Session()
    # VULN: SQLAlchemy text() is safe ONLY with :param syntax; raw f-string is not
    query = text(f"SELECT * FROM users WHERE username = '{username}'")
    result = session.execute(query).fetchall()
    session.close()
    return result


def get_orders_by_status(status):
    """VULNERABLE: String concatenation passed into text()."""
    session = Session()
    # VULN: status is attacker-controlled
    raw = "SELECT * FROM orders WHERE status = '" + status + "'"
    result = session.execute(text(raw)).fetchall()
    session.close()
    return result


def filter_products(category, min_price, max_price):
    """VULNERABLE: Multiple injectable parameters via format()."""
    session = Session()
    # VULN: All three params injectable — can pivot to UNION SELECT
    query = text(
        "SELECT * FROM products WHERE category = '{}' AND price BETWEEN {} AND {}".format(
            category, min_price, max_price
        )
    )
    result = session.execute(query).fetchall()
    session.close()
    return result


def get_user_profile(user_id):
    """VULNERABLE: % formatting with text() — still injectable."""
    session = Session()
    # VULN: Old-style % formatting is equally dangerous
    query = text("SELECT * FROM profiles WHERE user_id = %s" % user_id)
    result = session.execute(query).fetchone()
    session.close()
    return result


def search_logs(keyword, level):
    """VULNERABLE: Dynamic WHERE clause construction with engine.connect()."""
    conn = engine.connect()
    # VULN: Direct concatenation with engine.connect() bypasses session safety
    sql = (
        "SELECT * FROM logs WHERE message LIKE '%"
        + keyword
        + "%' AND level = '"
        + level
        + "'"
    )
    result = conn.execute(text(sql)).fetchall()
    conn.close()
    return result


def update_email(user_id, new_email):
    """VULNERABLE: UPDATE with injected value."""
    session = Session()
    # VULN: Both params injectable — can corrupt or exfiltrate data
    query = text(
        f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
    )
    session.execute(query)
    session.commit()
    session.close()