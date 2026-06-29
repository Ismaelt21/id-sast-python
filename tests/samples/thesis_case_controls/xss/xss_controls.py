"""Negative controls for reflected XSS."""

from flask import Flask, make_response, render_template_string, request
from html import escape


app = Flask(__name__)


@app.route("/profile/raw")
def profile_preview_vulnerable():
    bio = request.args.get("bio", "")
    html = render_template_string(
        "<article><h1>Profile</h1><p>" + bio + "</p></article>"
    )
    return html


@app.route("/profile/safe")
def profile_preview_safe():
    bio = request.args.get("bio", "")
    safe_bio = escape(bio)
    html = render_template_string(
        "<article><h1>Profile</h1><p>" + safe_bio + "</p></article>"
    )
    return html


def build_banner_text(title: str) -> str:
    """Innocuous helper that formats a label without rendering HTML."""

    return title.strip().title()
