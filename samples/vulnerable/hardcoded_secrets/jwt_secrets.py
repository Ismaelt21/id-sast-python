# VULNERABLE: Hardcoded JWT Secrets - Training Sample
# CWE-798: Use of Hard-coded Credentials
# CWE-347: Improper Verification of Cryptographic Signature
# Severity: CRITICAL
# Description: Hardcoded JWT signing keys allow attackers to forge arbitrary tokens;
#              weak/disabled verification allows privilege escalation

import jwt
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Hardcoded signing secrets ─────────────────────────────────────────────────

JWT_SECRET          = "secret"                          # VULN: trivially guessable
JWT_SECRET_WEAK     = "12345678"                        # VULN: brute-forceable
JWT_SECRET_PROD     = "my_jwt_production_secret_2024"   # VULN: committed to VCS
JWT_REFRESH_SECRET  = "refresh_token_secret_key"        # VULN: hardcoded refresh key

# ── Token creation with hardcoded secrets ─────────────────────────────────────

def create_token(user_id: int, role: str) -> str:
    """VULNERABLE: JWT signed with hardcoded weak secret."""
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": int(time.time()) + 3600
    }
    # VULN: JWT_SECRET = "secret" — easily brute-forced offline
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def create_admin_token(user_id: int) -> str:
    """VULNERABLE: Admin token signed with the same weak secret."""
    payload = {"user_id": user_id, "role": "admin", "exp": int(time.time()) + 86400}
    # VULN: same key for both user and admin tokens
    return jwt.encode(payload, "my_jwt_production_secret_2024", algorithm="HS256")


# ── Token verification vulnerabilities ───────────────────────────────────────

def verify_token_no_check(token: str) -> dict:
    """VULNERABLE: Signature verification disabled with verify=False."""
    # VULN: Any JWT will pass, including attacker-crafted admin tokens
    return jwt.decode(token, options={"verify_signature": False})


def verify_token_none_alg(token: str) -> dict:
    """VULNERABLE: Accepts 'none' algorithm — signature completely bypassed."""
    # VULN: Attacker sends a token with alg:none and no signature
    return jwt.decode(
        token,
        options={"verify_signature": False},
        algorithms=["HS256", "none"]     # VULN: 'none' algorithm accepted
    )


def verify_token_weak(token: str) -> dict:
    """VULNERABLE: Verifies with hardcoded weak secret."""
    # VULN: secret = "secret" — rainbow table / offline brute-force trivial
    return jwt.decode(token, "secret", algorithms=["HS256"])


def verify_and_trust_alg(token: str) -> dict:
    """VULNERABLE: Algorithm taken from token header, not enforced server-side."""
    # VULN: Allows RS256->HS256 confusion attack — sign with public key as HMAC secret
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "HS256")   # VULN: attacker controls algorithm choice
    return jwt.decode(token, JWT_SECRET, algorithms=[alg])


# ── Flask route examples ──────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    """VULNERABLE: Returns JWT signed with hardcoded secret."""
    data = request.get_json()
    # (credential check omitted for brevity)
    token = jwt.encode(
        {"user": data.get("username"), "role": "user", "exp": time.time() + 3600},
        "super_secret_jwt_key",           # VULN: hardcoded inline
        algorithm="HS256"
    )
    return jsonify({"token": token})


@app.route("/admin")
def admin_panel():
    """VULNERABLE: Admin check using decode with no signature verification."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        # VULN: verify_signature=False — attacker crafts their own admin token
        payload = jwt.decode(token, options={"verify_signature": False})
        if payload.get("role") == "admin":
            return jsonify({"data": "admin secrets"})
    except Exception:
        pass
    return jsonify({"error": "forbidden"}), 403


@app.route("/refresh", methods=["POST"])
def refresh():
    """VULNERABLE: Refresh token signed and verified with hardcoded secret."""
    data = request.get_json()
    old_token = data.get("refresh_token", "")
    try:
        # VULN: JWT_REFRESH_SECRET is committed to source control
        payload = jwt.decode(old_token, JWT_REFRESH_SECRET, algorithms=["HS256"])
        new_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")   # VULN
        return jsonify({"access_token": new_token})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "expired"}), 401


# ── Config dict with JWT settings ────────────────────────────────────────────

AUTH_CONFIG = {
    "jwt_secret":         "jwt-s3cr3t-hardcoded-v1",   # VULN
    "jwt_refresh_secret": "refresh-s3cr3t-v1",          # VULN
    "jwt_algorithm":      "HS256",
    "jwt_expiry_seconds": 3600
}


if __name__ == "__main__":
    app.run(debug=True)