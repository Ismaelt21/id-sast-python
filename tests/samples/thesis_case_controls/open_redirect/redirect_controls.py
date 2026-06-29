"""Negative controls for open redirect."""

from flask import Flask, redirect, request
from urllib.parse import urlparse


app = Flask(__name__)
ALLOWED_PATHS = {"/dashboard", "/profile", "/billing"}


@app.route("/login/raw")
def continue_after_login_vulnerable():
    next_url = request.args.get("next", "/dashboard")
    return redirect(next_url)


@app.route("/login/safe")
def continue_after_login_safe():
    next_url = request.args.get("next", "/dashboard")
    parsed = urlparse(next_url)

    if parsed.scheme or parsed.netloc:
        next_url = "/dashboard"

    if next_url not in ALLOWED_PATHS:
        next_url = "/dashboard"

    return redirect(next_url)


def build_internal_route(name: str) -> str:
    """Innocuous helper that returns a fixed internal route."""

    route_map = {
        "home": "/dashboard",
        "account": "/profile",
    }
    return route_map.get(name, "/dashboard")

