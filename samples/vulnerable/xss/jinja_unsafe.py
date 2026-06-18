# VULNERABLE: Jinja2 Unsafe Rendering - XSS and Server-Side Template Injection
# CWE-79 / CWE-94: XSS and Code Injection via Template Engine
# Severity: CRITICAL
# Description: Marking user input as Markup() bypasses Jinja2 auto-escaping;
#              render_template_string with user data enables SSTI leading to RCE

from flask import Flask, request, render_template_string
from jinja2 import Environment, BaseLoader
import markupsafe

app = Flask(__name__)


@app.route("/greet")
def greet():
    """VULNERABLE: User input marked safe — disables Jinja2 auto-escaping."""
    name = request.args.get("name", "guest")
    # VULN: Markup() tells Jinja2 not to escape — XSS possible
    safe_name = markupsafe.Markup(name)
    template = "<p>Hello, {{ name }}!</p>"
    return render_template_string(template, name=safe_name)


@app.route("/render")
def render():
    """VULNERABLE: User input used as the template string — SSTI to RCE."""
    tmpl = request.args.get("template", "Hello World")
    # VULN: tmpl = "{{config.items()}}" leaks config
    # VULN: tmpl = "{{''.__class__.__mro__[1].__subclasses__()}}" chains to RCE
    return render_template_string(tmpl)


@app.route("/report")
def report():
    """VULNERABLE: User-controlled title directly in template with | safe filter."""
    title = request.args.get("title", "My Report")
    template = f"""
    <html>
    <head><title>{{ title }}</title></head>
    <body>
      <h1>{{ title | safe }}</h1>
    </body>
    </html>
    """
    # VULN: | safe filter suppresses escaping — XSS in both title and h1
    return render_template_string(template, title=title)


@app.route("/email-preview")
def email_preview():
    """VULNERABLE: Email body from POST is rendered as a Jinja template."""
    body = request.form.get("body", "")
    # VULN: SSTI — attacker submits {{ ''.__class__.__mro__[1].__subclasses__() }}
    template = "<div>" + body + "</div>"
    return render_template_string(template)


def custom_template_engine(user_template: str, context: dict):
    """VULNERABLE: Creates a raw Jinja2 Environment from string without sandboxing."""
    env = Environment(loader=BaseLoader())
    # VULN: SandboxedEnvironment NOT used — full Python access available
    tmpl = env.from_string(user_template)
    return tmpl.render(**context)


@app.route("/widget")
def widget():
    """VULNERABLE: Widget HTML built from query params with | safe."""
    color = request.args.get("color", "blue")
    label = request.args.get("label", "Click Me")
    # VULN: label = '<img src=x onerror=alert(1)>' injected into | safe context
    template = """
    <button style="background:{{ color }}" onclick="action()">
        {{ label | safe }}
    </button>
    """
    return render_template_string(template, color=color, label=label)


@app.route("/invoice")
def invoice():
    """VULNERABLE: Template built via format() string then passed to Jinja."""
    company = request.args.get("company", "ACME")
    # VULN: Python format() substitution happens before Jinja rendering —
    #       attacker injects Jinja tags in 'company' which then get evaluated
    raw = "<html><body><h1>Invoice for {company}</h1></body></html>".format(
        company=company
    )
    return render_template_string(raw)   # VULN: injected tags now in template


@app.route("/notification")
def notification():
    """VULNERABLE: Autoescape disabled in custom environment."""
    env = Environment(autoescape=False, loader=BaseLoader())  # VULN: autoescape=False
    message = request.args.get("msg", "")
    tmpl = env.from_string(f"<div class='alert'>{ message }</div>")
    return tmpl.render()


if __name__ == "__main__":
    app.run(debug=True)