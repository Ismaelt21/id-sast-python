# VULNERABLE: SSRF Targeting Internal APIs - Training Sample
# CWE-918: Server-Side Request Forgery (SSRF)
# Severity: CRITICAL
# Description: Demonstrates SSRF targeting cloud metadata, internal microservices,
#              and private admin endpoints via various HTTP client libraries

import requests
import http.client
import socket


# ── Cloud metadata endpoints ──────────────────────────────────────────────────

def get_aws_metadata(path):
    """VULNERABLE: Fetches AWS EC2 metadata using user-supplied path."""
    # VULN: path = "iam/security-credentials/my-role" leaks AWS keys
    url = "http://169.254.169.254/latest/meta-data/" + path
    resp = requests.get(url, timeout=2)
    return resp.text


def get_gcp_metadata(path):
    """VULNERABLE: GCP metadata server query with user-controlled path."""
    # VULN: path = "instance/service-accounts/default/token"
    url = "http://metadata.google.internal/computeMetadata/v1/" + path
    resp = requests.get(url, headers={"Metadata-Flavor": "Google"})
    return resp.text


def get_azure_metadata(path):
    """VULNERABLE: Azure IMDS query with attacker-controlled path."""
    # VULN: path = "instance?api-version=2021-02-01" leaks subscription info
    url = "http://169.254.169.254/metadata/" + path
    resp = requests.get(url, headers={"Metadata": "true"})
    return resp.json()


# ── Internal microservice SSRF ────────────────────────────────────────────────

def call_internal_service(service_name, endpoint):
    """VULNERABLE: Constructs internal service URL from user input."""
    # VULN: service_name = "payments" + endpoint = "/admin/refund-all"
    # Maps to http://payments.internal/admin/refund-all
    url = f"http://{service_name}.internal/{endpoint}"
    return requests.get(url).json()


def forward_to_microservice(base_url, path, headers):
    """VULNERABLE: Gateway proxy with user-controlled target."""
    # VULN: base_url = "http://auth-service:8080" + path = "/admin/users"
    resp = requests.get(base_url.rstrip("/") + "/" + path.lstrip("/"), headers=headers)
    return resp.text


# ── Database / cache SSRF ─────────────────────────────────────────────────────

def probe_redis(host, port=6379):
    """VULNERABLE: Raw socket connection to internal Redis — SSRF via socket."""
    # VULN: attacker specifies host=localhost to interact with Redis
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((host, int(port)))
    s.send(b"KEYS *\r\n")
    data = s.recv(4096)
    s.close()
    return data.decode()


def elastic_search_query(host, index, query_body):
    """VULNERABLE: Elasticsearch query forwarded to internal host."""
    # VULN: host = "localhost:9200" dumps all indices
    conn = http.client.HTTPConnection(host, timeout=3)
    conn.request(
        "GET",
        f"/{index}/_search",
        body=str(query_body),
        headers={"Content-Type": "application/json"}
    )
    resp = conn.getresponse()
    return resp.read().decode()


# ── Admin panel SSRF ──────────────────────────────────────────────────────────

def admin_action(admin_url, action):
    """VULNERABLE: POST to internal admin URL from user input."""
    # VULN: admin_url = "http://admin.internal:8080/shutdown"
    resp = requests.post(admin_url, json={"action": action})
    return resp.status_code


def health_check(target):
    """VULNERABLE: Health-check endpoint pings user-controlled target."""
    # VULN: target = "http://jenkins.internal:8080/exit" triggers Jenkins shutdown
    try:
        r = requests.get(target, timeout=2)
        return r.status_code == 200
    except Exception:
        return False


# ── DNS rebinding / URL parser confusion ──────────────────────────────────────

def fetch_with_redirect_follow(url, max_redirects=10):
    """VULNERABLE: Follows redirects — susceptible to DNS rebinding attack."""
    # VULN: first request resolves to safe IP; after TTL, DNS rebinds to 10.0.0.1
    session = requests.Session()
    session.max_redirects = max_redirects
    resp = session.get(url, allow_redirects=True)
    return resp.text


def bypass_check_via_at(url):
    """VULNERABLE: Naive URL allowlist bypassed by @ in URL."""
    # VULN: url = "http://allowed.com@169.254.169.254/meta-data/"
    # urllib interprets 'allowed.com' as credentials, fetches metadata IP
    resp = requests.get(url)
    return resp.text