"""Negative controls for SSRF."""

import requests
from flask import Flask, request
from urllib.parse import urlparse


app = Flask(__name__)
ALLOWED_HOSTS = {"api.example.com", "status.example.com"}


@app.route("/preview/raw")
def preview_remote_resource_vulnerable():
    target_url = request.args.get("url", "")
    response = requests.get(target_url, timeout=3)
    return response.text


@app.route("/preview/safe")
def preview_remote_resource_safe():
    source_key = request.args.get("url", "status")
    allowed_urls = {
        "status": "https://status.example.com/health",
        "api": "https://api.example.com/v1/ping",
    }
    target_url = allowed_urls.get(source_key, "https://status.example.com/health")
    parsed = urlparse(target_url)

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")

    response = requests.get(target_url, timeout=3)
    return response.text


def normalize_feed_url(feed_url: str) -> str:
    """Innocuous helper that only normalizes a URL string."""

    parsed = urlparse(feed_url)
    return parsed.geturl().rstrip("/")
