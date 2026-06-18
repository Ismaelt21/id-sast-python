# VULNERABLE: SQL Injection from Multiple Input Sources - Training Sample
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# Severity: CRITICAL
# Description: Demonstrates injection from HTTP headers, cookies, env vars, files, and args

import sqlite3
import os
import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


DB = "app.db"


def _run(query):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(query)      # VULN: raw execute throughout
    return cur.fetchall()


# ── Source 1: URL query parameters ────────────────────────────────────────────

def from_query_param(environ):
    """VULNERABLE: Reads 'id' from WSGI query string."""
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    user_id = qs.get("id", [""])[0]
    # VULN: user_id is attacker-controlled via URL
    return _run("SELECT * FROM users WHERE id = " + user_id)


# ── Source 2: HTTP headers ─────────────────────────────────────────────────────

def from_http_header(environ):
    """VULNERABLE: X-User-Name header used in SQL without sanitization."""
    username = environ.get("HTTP_X_USER_NAME", "anonymous")
    # VULN: custom header injected directly
    return _run("SELECT * FROM sessions WHERE username = '" + username + "'")


# ── Source 3: Cookie value ─────────────────────────────────────────────────────

def from_cookie(cookie_string):
    """VULNERABLE: Session token from Cookie header used in SQL."""
    # Naïve cookie parsing
    cookies = dict(c.strip().split("=", 1) for c in cookie_string.split(";") if "=" in c)
    session_id = cookies.get("session_id", "")
    # VULN: cookie value injected — attacker can forge cookies
    return _run("SELECT * FROM sessions WHERE token = '" + session_id + "'")


# ── Source 4: Environment variable ────────────────────────────────────────────

def from_env_var():
    """VULNERABLE: DB filter read from environment variable."""
    tenant = os.environ.get("TENANT_ID", "default")
    # VULN: env var may be set by attacker in some deployment models
    return _run("SELECT * FROM data WHERE tenant = '" + tenant + "'")


# ── Source 5: JSON request body ────────────────────────────────────────────────

def from_json_body(raw_body: str):
    """VULNERABLE: Parses JSON and uses values in SQL unescaped."""
    data = json.loads(raw_body)
    email = data.get("email", "")
    role = data.get("role", "user")
    # VULN: both JSON fields injectable
    return _run(
        "SELECT * FROM users WHERE email = '" + email + "' AND role = '" + role + "'"
    )


# ── Source 6: File content ─────────────────────────────────────────────────────

def from_file(filepath: str):
    """VULNERABLE: Reads a username from a file and uses it in SQL."""
    with open(filepath) as f:
        username = f.read().strip()
    # VULN: file content is attacker-controlled (e.g. uploaded file)
    return _run("SELECT * FROM users WHERE username = '" + username + "'")


# ── Source 7: Command-line arguments ──────────────────────────────────────────

def from_argv():
    """VULNERABLE: CLI arg used directly in SQL — e.g. script.py "' OR 1=1--"."""
    import sys
    search_term = sys.argv[1] if len(sys.argv) > 1 else ""
    # VULN: argv[1] injected without validation
    return _run("SELECT * FROM products WHERE name LIKE '%" + search_term + "%'")


# ── Source 8: Third-party API response ────────────────────────────────────────

def from_external_api(api_response: dict):
    """VULNERABLE: Trusts external API response and inserts into SQL."""
    user_id = api_response.get("userId")          # could be tampered at API level
    # VULN: external data treated as trusted
    return _run("SELECT * FROM profiles WHERE external_id = '" + str(user_id) + "'")


# ── Source 9: Referer header ──────────────────────────────────────────────────

class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """VULNERABLE: HTTP Referer header used in audit-log SQL query."""
        referer = self.headers.get("Referer", "")
        # VULN: Referer is fully attacker-controlled
        _run("INSERT INTO audit_log (source) VALUES ('" + referer + "')")
        self.send_response(200)
        self.end_headers()