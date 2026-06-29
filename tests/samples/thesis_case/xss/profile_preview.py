"""Positive benchmark: reflected XSS in HTML rendering."""

from flask import Flask, make_response, render_template_string, request


app = Flask(__name__)


@app.route("/profile")
def profile_preview():
    bio = request.args.get("bio", "")
    html = render_template_string(
        "<article><h1>Profile</h1><p>" + bio + "</p></article>"
    )
    return html


@app.route("/banner")
def banner_preview():
    title = request.args.get("title", "guest")
    response = make_response(
        f"<div class='banner'><span>{title}</span></div>"
    )
    response.headers["Content-Type"] = "text/html"
    return response

