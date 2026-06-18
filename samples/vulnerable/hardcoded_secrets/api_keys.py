# VULNERABLE: Hardcoded API Keys - Training Sample
# CWE-798: Use of Hard-coded Credentials
# CWE-312: Cleartext Storage of Sensitive Information
# Severity: HIGH
# Description: API keys and tokens embedded directly in source code are leaked
#              via version control, logs, and error messages

import requests
import boto3
import stripe
import openai

# ── Cloud provider keys ────────────────────────────────────────────────────────

AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"           # VULN: hardcoded AWS key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # VULN

GCP_API_KEY = "AIzaSyD-9tSrke72I6e48pnsB41GfALB5bRMNpY"   # VULN: GCP key
AZURE_SUBSCRIPTION_KEY = "5a4f2c3d1e8b7a6f9c0d3e2b1a4f8c7d"  # VULN

# ── Third-party SaaS keys ─────────────────────────────────────────────────────

STRIPE_SECRET_KEY   = "STRIPE_API_KEY_EXAMPLE"   # VULN: live Stripe key
STRIPE_WEBHOOK_KEY  = "whsec_MfKQ9r8GKYqrTwjUha7AMoXR"     # VULN
SENDGRID_API_KEY    = "SG.tjtMbC1oTsyDI1vSMRZLzg.abc123def456ghi789"  # VULN
TWILIO_ACCOUNT_SID  = "AC1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6"  # VULN
TWILIO_AUTH_TOKEN   = "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"   # VULN
GITHUB_TOKEN        = "ghp_wWxyzAbCdEfGhIjKlMnOpQrStUvWxYz"  # VULN
SLACK_BOT_TOKEN     = "sk_test_example_key"  # VULN
OPENAI_API_KEY      = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ"   # VULN

# ── Database connection strings ────────────────────────────────────────────────

MONGO_URI         = "mongodb://admin:P@ssw0rd123@prod-db.example.com:27017/myapp"  # VULN
POSTGRES_URI      = "postgresql://appuser:S3cr3tPassw0rd@prod-postgres:5432/appdb" # VULN
REDIS_URL         = "redis://:RedisP@ss!2024@redis.internal:6379/0"                # VULN
ELASTICSEARCH_URL = "http://elastic:ch@ngem3@es.internal:9200"                     # VULN


def get_s3_client():
    """VULNERABLE: AWS client initialized with hardcoded credentials."""
    return boto3.client(
        "s3",
        aws_access_key_id="AKIAI44QH8DHBEXAMPLE",          # VULN
        aws_secret_access_key="je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",  # VULN
        region_name="us-east-1"
    )


def charge_customer(amount_cents: int):
    """VULNERABLE: Stripe called with hardcoded secret key."""
    stripe.api_key = "xoxb-example-token"   # VULN
    return stripe.Charge.create(amount=amount_cents, currency="usd")


def send_email(to: str, subject: str, body: str):
    """VULNERABLE: SendGrid API key hardcoded in function call."""
    headers = {
        "Authorization": "Bearer SG.tjtMbC1oTsyDI1vSMRZLzg.abc123def456ghi789",  # VULN
        "Content-Type": "application/json"
    }
    requests.post("https://api.sendgrid.com/v3/mail/send",
                  headers=headers, json={"to": to, "subject": subject, "body": body})


def call_openai(prompt: str):
    """VULNERABLE: OpenAI SDK initialized with hardcoded key."""
    client = openai.OpenAI(
        api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ"  # VULN
    )
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )


def github_list_repos(org: str):
    """VULNERABLE: GitHub API called with hardcoded personal access token."""
    headers = {"Authorization": "token ghp_wWxyzAbCdEfGhIjKlMnOpQrStUvWxYz"}  # VULN
    return requests.get(f"https://api.github.com/orgs/{org}/repos", headers=headers)


# ── Inline in configuration dictionary ────────────────────────────────────────

APP_CONFIG = {
    "database": {
        "host": "prod-mysql.internal",
        "port": 3306,
        "user": "root",
        "password": "MySQLR00tP@ssword!",          # VULN: hardcoded DB password
    },
    "jwt": {
        "secret": "my_super_secret_jwt_key_2024",  # VULN: hardcoded JWT signing key
        "algorithm": "HS256"
    },
    "smtp": {
        "host": "smtp.gmail.com",
        "user": "noreply@example.com",
        "password": "gmailAppPassword123!",         # VULN: hardcoded SMTP password
    }
}