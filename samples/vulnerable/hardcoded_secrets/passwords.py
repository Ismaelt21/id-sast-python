# VULNERABLE: Hardcoded Passwords - Training Sample
# CWE-798: Use of Hard-coded Credentials
# CWE-259: Use of Hard-coded Password
# Severity: HIGH
# Description: Passwords embedded in source code survive rotation and are exposed
#              through version control history, even after the line is deleted

import hashlib
import sqlite3
import ldap3
import paramiko
import psycopg2


# ── Global constants ───────────────────────────────────────────────────────────

ADMIN_PASSWORD      = "Admin@1234!"                # VULN: plaintext admin password
DB_PASSWORD         = "db_s3cr3t_2024"             # VULN: database password
MASTER_KEY          = "master_encryption_key_v1"   # VULN: encryption master key
INTERNAL_API_SECRET = "int3rnal-@pi-s3cr3t"        # VULN: service-to-service secret
BACKUP_PASSPHRASE   = "BackupP@ss#99"              # VULN: backup encryption passphrase


# ── Authentication functions ─────────────────────────────────────────────────

def check_admin(password: str) -> bool:
    """VULNERABLE: Admin password comparison against hardcoded string."""
    # VULN: hardcoded comparison — password is in plaintext in source
    return password == "Admin@1234!"


def verify_internal_token(token: str) -> bool:
    """VULNERABLE: Internal service token compared against hardcoded value."""
    # VULN: anyone who reads the source bypasses this check
    EXPECTED_TOKEN = "svc-token-abc123xyz789"
    return token == EXPECTED_TOKEN


def legacy_login(username: str, password: str) -> bool:
    """VULNERABLE: Backdoor hardcoded credential for 'support' account."""
    # VULN: backdoor — support / sup3rS3cretBackdoor always works
    if username == "support" and password == "sup3rS3cretBackdoor":
        return True
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        return hashlib.md5(password.encode()).hexdigest() == row[0]
    return False


# ── Database connections ──────────────────────────────────────────────────────

def get_db_connection():
    """VULNERABLE: Production DB credentials hardcoded."""
    # VULN: credentials committed to source — visible to all developers
    return psycopg2.connect(
        host="prod-db.example.com",
        database="appdb",
        user="appuser",
        password="Pr0d-DB-P@ssw0rd!2024"   # VULN
    )


def get_reporting_db():
    """VULNERABLE: Read-only replica credentials hardcoded."""
    import pymysql
    return pymysql.connect(
        host="replica.db.internal",
        user="reporter",
        password="R3p0rt3r_P@ss",          # VULN
        database="analytics"
    )


# ── LDAP / Active Directory ───────────────────────────────────────────────────

def ldap_authenticate(username: str, user_password: str) -> bool:
    """VULNERABLE: LDAP service account password hardcoded."""
    server = ldap3.Server("ldap://dc.company.internal")
    # VULN: service account password in plaintext
    conn = ldap3.Connection(
        server,
        user="CN=svc-app,OU=ServiceAccounts,DC=company,DC=internal",
        password="Ldap$vc@cc0unt2024"    # VULN
    )
    conn.bind()
    # Now search for user...
    return conn.result["result"] == 0


# ── SSH / remote connections ──────────────────────────────────────────────────

def ssh_deploy(host: str, command: str):
    """VULNERABLE: SSH private key passphrase hardcoded."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # VULN: password and key passphrase both hardcoded
    client.connect(
        host,
        username="deploy",
        password="DeployP@ss#2024",          # VULN
        passphrase="KeyP@ssphrase_deploy"    # VULN
    )
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode()


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt_data(plaintext: str) -> bytes:
    """VULNERABLE: Encryption key hardcoded — confidentiality depends on keeping source secret."""
    from cryptography.fernet import Fernet
    import base64
    # VULN: hardcoded key — key rotation impossible without code change
    KEY = b"dGhpc2lzYXRlc3RrZXl0aGF0aXMzMmJ5dGVzMTIzNA=="
    f = Fernet(base64.urlsafe_b64decode(KEY))
    return f.encrypt(plaintext.encode())


# ── Configuration dict ────────────────────────────────────────────────────────

SERVICES = {
    "payment_gateway": {
        "url":      "https://pay.internal/api",
        "username": "payment_svc",
        "password": "P@ymentS3rv1ce!"    # VULN: service password in config dict
    },
    "notification_service": {
        "endpoint": "http://notify.internal",
        "api_key":  "notify-k3y-abc-123" # VULN: API key in config dict
    }
}