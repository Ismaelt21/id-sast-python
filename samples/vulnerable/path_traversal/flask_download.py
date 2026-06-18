# VULNERABLE: Path Traversal in Flask Download Endpoint - Training Sample
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# Severity: HIGH
# Description: Flask routes serve files based on user-supplied names without restriction

import os
from flask import Flask, request, send_file, abort, jsonify

app = Flask(__name__)
UPLOAD_FOLDER = "/var/www/uploads"
REPORT_FOLDER = "/app/reports"


@app.route("/download")
def download():
    """VULNERABLE: filename query param used directly in send_file."""
    filename = request.args.get("file", "")
    # VULN: ?file=../../etc/passwd serves system files
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    return send_file(filepath)


@app.route("/report/<path:report_name>")
def get_report(report_name):
    """VULNERABLE: Flask path converter <path:> allows slashes — traversal possible."""
    # VULN: /report/../../../etc/shadow — Flask path converter passes slashes
    full_path = os.path.join(REPORT_FOLDER, report_name)
    if not os.path.exists(full_path):
        abort(404)
    return send_file(full_path)


@app.route("/preview")
def preview():
    """VULNERABLE: Returns raw file content as JSON without path check."""
    doc = request.args.get("doc", "")
    # VULN: doc = "../../app/config/secrets.py"
    path = UPLOAD_FOLDER + os.sep + doc
    try:
        with open(path) as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        abort(404)


@app.route("/static-file")
def static_file():
    """VULNERABLE: Uses Flask's send_from_directory improperly with full path join."""
    name = request.args.get("name", "index.html")
    # VULN: send_file is used instead of send_from_directory, bypassing directory checks
    return send_file(os.path.join("/app/static", name))


@app.route("/user/<int:user_id>/file")
def user_file(user_id):
    """VULNERABLE: User can download files from other users' directories."""
    filename = request.args.get("name", "")
    # VULN: user can set name=../2/secret.txt to read another user's files
    path = os.path.join("/data/users", str(user_id), filename)
    return send_file(path)


@app.route("/export")
def export():
    """VULNERABLE: Format and name params both injectable."""
    name = request.args.get("name", "export")
    fmt = request.args.get("format", "csv")
    # VULN: name = "../../etc/passwd" or fmt = "py" to expose source
    path = f"/app/exports/{name}.{fmt}"
    with open(path, "rb") as f:
        return f.read()


@app.route("/media")
def media():
    """VULNERABLE: Resolves symlinks — symlink attack vector."""
    fname = request.args.get("f", "")
    # VULN: attacker plants a symlink pointing to /etc/shadow
    resolved = os.path.realpath(os.path.join(UPLOAD_FOLDER, fname))
    # Missing: check that resolved still starts with UPLOAD_FOLDER
    with open(resolved, "rb") as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True)