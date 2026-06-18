# VULNERABLE: Path Traversal via unsafe open() - Training Sample
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# Severity: HIGH
# Description: User-controlled filenames are opened without path normalization or restriction

import os


BASE_DIR = "/var/www/uploads"


def read_user_file(filename):
    """VULNERABLE: filename used directly with no path validation."""
    # VULN: filename = "../../etc/passwd" reads outside uploads/
    filepath = BASE_DIR + "/" + filename
    with open(filepath, "r") as f:
        return f.read()


def serve_static(resource):
    """VULNERABLE: os.path.join does NOT protect if resource starts with /."""
    # VULN: resource = "/etc/shadow" — os.path.join discards BASE_DIR
    path = os.path.join(BASE_DIR, resource)
    with open(path, "rb") as f:
        return f.read()


def read_template(template_name):
    """VULNERABLE: template name from user allows traversal to system files."""
    # VULN: template_name = "../../../etc/passwd%00" (null-byte on some systems)
    path = f"/app/templates/{template_name}.html"
    with open(path) as f:
        return f.read()


def get_log(log_name):
    """VULNERABLE: Log file name from request param."""
    # VULN: log_name = "../../../../etc/crontab"
    log_path = "/var/log/app/" + log_name
    with open(log_path) as f:
        return f.readlines()


def download_attachment(user_id, filename):
    """VULNERABLE: User controls both user_id (dir) and filename."""
    # VULN: filename = "../otheruser/private.doc" crosses user boundaries
    path = os.path.join("/data/users", str(user_id), filename)
    with open(path, "rb") as f:
        return f.read()


def write_config(config_name, content):
    """VULNERABLE: Path traversal on write — can overwrite system files."""
    # VULN: config_name = "../../etc/cron.d/evil" writes a cron job
    path = "/app/config/" + config_name
    with open(path, "w") as f:
        f.write(content)


def delete_file(filename):
    """VULNERABLE: Deletion without path restriction."""
    # VULN: filename = "../../app/core.py" deletes application code
    target = os.path.join(BASE_DIR, filename)
    os.remove(target)


def load_plugin(plugin_name):
    """VULNERABLE: Dynamic import from user-controlled path via open()."""
    # VULN: plugin_name = "../../secrets/keys.py" leaks source code
    path = f"/app/plugins/{plugin_name}.py"
    with open(path) as f:
        source = f.read()
    exec(source)    # double vulnerability: path traversal + code exec


def read_binary(asset_path):
    """VULNERABLE: Binary asset path from URL segment."""
    # VULN: URL-encoded traversal — asset_path = "%2e%2e%2fetc%2fpasswd"
    # (caller responsible for URL-decoding; here the decoded value is used)
    full_path = os.path.join("/app/assets", asset_path)
    with open(full_path, "rb") as f:
        return f.read()