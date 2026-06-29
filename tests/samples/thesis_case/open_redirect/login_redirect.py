"""Positive benchmark: open redirect from a login continuation endpoint."""

from flask import Flask, redirect, request


app = Flask(__name__)


@app.route("/login/continue")
def continue_after_login():
    next_url = request.args.get("next", "/dashboard")
    return redirect(next_url)


@app.route("/logout/continue")
def continue_after_logout():
    destination = request.args.get("return", "/")
    return redirect(destination)

