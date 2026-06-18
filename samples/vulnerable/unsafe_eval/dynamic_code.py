# VULNERABLE: Dynamic Code Execution - Training Sample
# CWE-95: Code Injection via compile/importlib/types/ast.literal_eval misuse
# Severity: CRITICAL
# Description: Various lesser-known dynamic code execution sinks that bypass
#              naive eval/exec detection in SAST tools

import ast
import importlib
import importlib.util
import types
import sys
import os
from flask import Flask, request, jsonify

app = Flask(__name__)


# ── compile() + exec() chain ─────────────────────────────────────────────────

def compile_and_run(source: str):
    """VULNERABLE: compile() then exec() — same risk as exec(source) directly."""
    # VULN: source = "import os; os.system('id')"
    code_obj = compile(source, "<user>", "exec")
    exec(code_obj)   # VULN: compiled code object executed


def compile_and_eval(expr: str):
    """VULNERABLE: compile() in 'eval' mode then eval()."""
    # VULN: expr = "__import__('os').system('whoami')"
    code_obj = compile(expr, "<user>", "eval")
    return eval(code_obj)   # VULN


# ── importlib dynamic import ──────────────────────────────────────────────────

def dynamic_import(module_name: str):
    """VULNERABLE: Imports arbitrary module by user-supplied name."""
    # VULN: module_name = "os" → gives access to os.system
    # VULN: module_name = "subprocess" → subprocess.call
    return importlib.import_module(module_name)


def load_module_from_path(module_name: str, file_path: str):
    """VULNERABLE: Loads arbitrary .py file as a module — RCE via file upload."""
    # VULN: file_path = "/tmp/uploaded_evil.py" — runs on import
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)   # VULN: executes module-level code
    return module


def load_from_source(name: str, source_code: str):
    """VULNERABLE: Creates a module from source string and executes it."""
    # VULN: source_code is attacker-controlled
    module = types.ModuleType(name)
    exec(source_code, module.__dict__)   # VULN: exec in module namespace
    sys.modules[name] = module
    return module


# ── types.FunctionType from code object ──────────────────────────────────────

def make_function_from_source(source: str, func_name: str):
    """VULNERABLE: Creates callable from user-supplied source code."""
    # VULN: source can define any function body including os.system calls
    ns = {}
    exec(source, ns)   # VULN
    return ns.get(func_name)


def reconstruct_function(code_obj, globs: dict = None):
    """VULNERABLE: Builds a callable directly from a code object."""
    # VULN: code_obj can be deserialized from attacker data (e.g. marshal)
    if globs is None:
        globs = globals()
    func = types.FunctionType(code_obj, globs)
    return func()   # VULN: executes attacker code


# ── ast.literal_eval misuse ───────────────────────────────────────────────────

def safe_looking_eval(user_input: str):
    """DECEPTIVE: Uses ast.literal_eval — actually safe for literals BUT
    here the result is passed to exec(), negating the safety."""
    # VULN: Pattern where developer chains ast.literal_eval with exec
    try:
        value = ast.literal_eval(user_input)   # safe on its own
    except (ValueError, SyntaxError):
        value = user_input
    # VULN: then passes to exec — attacker uses a string literal "import os;os.system('id')"
    if isinstance(value, str):
        exec(value)   # VULN: string literal from ast.literal_eval still executed
    return value


# ── __import__ built-in ───────────────────────────────────────────────────────

def get_module_attr(module_name: str, attr_name: str):
    """VULNERABLE: __import__ + getattr with user-controlled names."""
    # VULN: module_name="os", attr_name="system" → returns os.system
    mod = __import__(module_name)   # VULN
    return getattr(mod, attr_name)   # VULN


# ── Flask endpoints ────────────────────────────────────────────────────────────

@app.route("/plugin/load", methods=["POST"])
def load_plugin():
    """VULNERABLE: Loads and executes a plugin from an uploaded path."""
    path = request.json.get("path", "")
    name = request.json.get("name", "plugin")
    # VULN: path = "/tmp/malicious_plugin.py"
    try:
        mod = load_module_from_path(name, path)
        init = getattr(mod, "initialize", None)
        if callable(init):
            init()   # VULN: calls attacker-defined initialize()
        return jsonify({"status": "loaded"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/eval/compile", methods=["POST"])
def eval_compile():
    """VULNERABLE: Compiles and evaluates code submitted via API."""
    src = request.json.get("source", "")
    mode = request.json.get("mode", "eval")   # VULN: mode from request
    code = compile(src, "<api>", mode)        # VULN
    return jsonify({"result": str(eval(code))})   # VULN


if __name__ == "__main__":
    app.run(debug=True)