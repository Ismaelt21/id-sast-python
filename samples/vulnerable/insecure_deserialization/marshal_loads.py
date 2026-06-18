# VULNERABLE: Insecure Deserialization via marshal.loads - Training Sample
# CWE-502: Deserialization of Untrusted Data
# Severity: CRITICAL
# Description: marshal.loads() can deserialize arbitrary Python code objects,
#              enabling remote code execution when given attacker-controlled data

import marshal
import base64
import struct
from flask import Flask, request

app = Flask(__name__)


def deserialize_code(data: bytes):
    """VULNERABLE: Deserializes a Python code object from raw bytes."""
    # VULN: data can encode a compiled code object that imports os and runs system()
    code_obj = marshal.loads(data)
    return code_obj


def execute_remote_code(encoded: str):
    """VULNERABLE: Decodes base64, deserializes code object, then executes it."""
    raw = base64.b64decode(encoded)
    # VULN: attacker sends compiled bytecode that runs arbitrary commands
    code = marshal.loads(raw)
    exec(code)   # double vulnerability: insecure deserialization + exec


def load_plugin_bytecode(plugin_path: str):
    """VULNERABLE: Loads .pyc-style bytecode from user-supplied path."""
    # VULN: plugin_path points to attacker-controlled .pyc file
    with open(plugin_path, "rb") as f:
        # Skip the .pyc magic number and timestamp (first 16 bytes for Python 3.8+)
        f.read(16)
        raw = f.read()
    code = marshal.loads(raw)   # VULN: arbitrary code object
    exec(code)


@app.route("/run-script", methods=["POST"])
def run_script():
    """VULNERABLE: Receives marshal-encoded code object via POST and executes it."""
    raw = request.data   # attacker sends marshal-encoded code
    # VULN: no validation of the code object before deserialization
    code = marshal.loads(raw)
    exec(code)
    return "executed"


def deserialize_from_cache(cache: dict, key: str):
    """VULNERABLE: Cache stores marshal-serialized code objects."""
    raw = cache.get(key)
    if raw:
        # VULN: attacker poisons cache entry with malicious bytecode
        code = marshal.loads(raw)
        return eval(code)   # VULN: eval of deserialized code object
    return None


def load_compiled_template(template_bytes: bytes):
    """VULNERABLE: Compiled template loaded as a code object."""
    # VULN: template_bytes can contain anything — not restricted to template logic
    code = marshal.loads(template_bytes)
    namespace = {}
    exec(code, namespace)   # VULN: executes in restricted namespace but still dangerous
    return namespace.get("render", lambda: "")()


def restore_function(serialized: bytes):
    """VULNERABLE: Reconstructs a callable from serialized data."""
    # VULN: serialized encodes a function code object with malicious body
    code_obj = marshal.loads(serialized)
    # Creating a function from an attacker-controlled code object
    import types
    func = types.FunctionType(code_obj, globals())
    return func()   # VULN: calls attacker-defined function


@app.route("/api/compute", methods=["POST"])
def compute():
    """VULNERABLE: Base64-encoded marshal payload from API client."""
    payload = request.json.get("bytecode", "")
    raw = base64.urlsafe_b64decode(payload + "==")
    # VULN: no integrity check before deserialization
    code = marshal.loads(raw)
    result = eval(code)
    return {"result": str(result)}


if __name__ == "__main__":
    app.run(debug=True)