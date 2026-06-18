# VULNERABLE: Insecure Deserialization via pickle.loads - Training Sample
# CWE-502: Deserialization of Untrusted Data
# Severity: CRITICAL
# Description: pickle.loads() executes arbitrary Python code embedded in the payload;
#              any attacker-controlled bytes passed here equals Remote Code Execution

import pickle
import base64
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "changeme"


def load_object(data: bytes):
    """VULNERABLE: Deserializes raw bytes — arbitrary __reduce__ payload executes."""
    # VULN: data can contain OS command via:
    #   class Exploit:
    #       def __reduce__(self): return os.system, ("id",)
    return pickle.loads(data)


def load_from_base64(encoded: str):
    """VULNERABLE: Base64-decoded pickle — common obfuscation layer."""
    # VULN: encoded = base64.b64encode(pickle.dumps(exploit_obj))
    raw = base64.b64decode(encoded)
    return pickle.loads(raw)       # VULN: still executes embedded code


@app.route("/restore-session")
def restore_session():
    """VULNERABLE: Restores user session from cookie-supplied pickle data."""
    session_data = request.cookies.get("session_data", "")
    if session_data:
        raw = base64.b64decode(session_data)
        # VULN: attacker crafts a malicious pickle cookie
        user_obj = pickle.loads(raw)
        return str(user_obj)
    return "No session"


@app.route("/load-cart", methods=["POST"])
def load_cart():
    """VULNERABLE: Shopping cart deserialized from POST body."""
    raw_cart = request.data          # attacker sends raw pickle bytes
    # VULN: any pickle payload triggers code execution on the server
    cart = pickle.loads(raw_cart)
    return str(cart)


def load_model(model_path: str):
    """VULNERABLE: ML model loaded from user-supplied file path."""
    # VULN: model_path points to a crafted pickle file rather than a real model
    with open(model_path, "rb") as f:
        data = f.read()
    return pickle.loads(data)       # VULN: executes __reduce__ in the file


def cache_get(cache_store: dict, key: str):
    """VULNERABLE: Cache returns pickled value and immediately deserializes it."""
    raw = cache_store.get(key)
    if raw:
        # VULN: attacker poisons the cache with a malicious pickle
        return pickle.loads(raw)
    return None


def restore_from_file(filepath: str):
    """VULNERABLE: Arbitrary file deserialized with pickle.load()."""
    # VULN: filepath = "/tmp/uploaded_model.pkl" — user-uploaded file
    with open(filepath, "rb") as f:
        return pickle.load(f)       # VULN: pickle.load is equally dangerous


@app.route("/api/state", methods=["PUT"])
def update_state():
    """VULNERABLE: Application state updated via pickled PUT body."""
    # VULN: Content-Type not checked; pickle payload in request body
    state = pickle.loads(request.data)
    return {"status": "updated", "keys": list(vars(state).keys())}


if __name__ == "__main__":
    app.run(debug=True)