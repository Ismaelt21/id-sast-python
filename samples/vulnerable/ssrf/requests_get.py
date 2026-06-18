# VULNERABLE: Server-Side Request Forgery via requests.get - Training Sample
# CWE-918: Server-Side Request Forgery (SSRF)
# Severity: HIGH
# Description: User-supplied URLs are fetched by the server without validation,
#              allowing access to internal services and cloud metadata endpoints

import requests


def fetch_url(url):
    """VULNERABLE: Fetches arbitrary URL supplied by the user."""
    # VULN: url = "http://169.254.169.254/latest/meta-data/" (AWS metadata)
    # VULN: url = "http://internal-service:8080/admin"
    response = requests.get(url)
    return response.text


def preview_link(link):
    """VULNERABLE: Link preview feature fetches attacker-controlled URL."""
    # VULN: link can target redis://localhost:6379 or file:///etc/passwd
    resp = requests.get(link, timeout=5)
    return {"status": resp.status_code, "body": resp.text[:500]}


def import_from_url(data_url):
    """VULNERABLE: Imports CSV/JSON data from user-provided URL."""
    # VULN: data_url = "http://10.0.0.1/internal-data.json"
    response = requests.get(data_url)
    return response.json()


def webhook_test(webhook_url, payload):
    """VULNERABLE: POST to attacker-controlled webhook URL."""
    # VULN: webhook_url = "http://localhost:8080/admin/shutdown"
    resp = requests.post(webhook_url, json=payload)
    return resp.status_code


def avatar_upload_from_url(image_url):
    """VULNERABLE: Downloads avatar from URL — SSRF to internal image store."""
    # VULN: image_url = "http://192.168.1.1/router-config-backup"
    r = requests.get(image_url, stream=True)
    return r.content


def check_site_availability(target_url):
    """VULNERABLE: Availability checker — commonly abused for SSRF port-scanning."""
    # VULN: target_url = "http://localhost:5432" probes internal Postgres port
    try:
        r = requests.get(target_url, timeout=3)
        return {"up": True, "code": r.status_code}
    except Exception as e:
        return {"up": False, "error": str(e)}


def rss_feed_reader(feed_url):
    """VULNERABLE: RSS reader fetches arbitrary URL."""
    # VULN: feed_url = "http://metadata.google.internal/computeMetadata/v1/"
    resp = requests.get(feed_url, headers={"Accept": "application/rss+xml"})
    return resp.text


def pdf_from_url(page_url):
    """VULNERABLE: Headless-print service fetches internal page for PDF generation."""
    # VULN: page_url = "http://admin.internal/users/export"
    resp = requests.get(page_url)
    # (PDF conversion would happen here)
    return resp.content


def translate_page(url, target_lang):
    """VULNERABLE: Translation proxy fetches arbitrary URL then processes body."""
    # VULN: url = "http://10.0.0.250:9200/_cat/indices" (Elasticsearch)
    resp = requests.get(url, params={"lang": target_lang})
    return resp.text


def send_to_slack(slack_webhook, message):
    """VULNERABLE: Slack-style webhook — URL fully attacker-controlled."""
    # VULN: slack_webhook can point to internal HR system to POST data
    requests.post(slack_webhook, json={"text": message})