"""Positive benchmark: SSRF through outbound HTTP and URL fetching."""

import requests
from flask import Flask, request
from urllib.request import urlopen


app = Flask(__name__)


@app.route("/preview")
def preview_remote_resource():
    target_url = request.args.get("url", "")
    response = requests.get(target_url, timeout=3)
    return response.text


@app.route("/import-feed")
def import_feed():
    feed_url = request.args.get("feed", "")

    with urlopen(feed_url) as response:
        return response.read().decode("utf-8")

