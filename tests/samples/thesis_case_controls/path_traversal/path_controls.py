"""Negative controls for path traversal."""

import os
from pathlib import Path
from flask import Flask, request


app = Flask(__name__)
BASE_DIR = Path("/var/app/uploads")


@app.route("/documents/raw")
def download_document_vulnerable():
    filename = request.args.get("file", "")
    target_path = BASE_DIR / filename

    with open(target_path, "rb") as file_handle:
        return file_handle.read()


@app.route("/documents/safe")
def download_document_safe():
    filename = request.args.get("file", "")
    safe_name = os.path.basename(filename)
    target_path = os.path.abspath(BASE_DIR / safe_name)

    if not target_path.startswith(str(BASE_DIR)):
        raise ValueError("Invalid document path")

    with open(target_path, "rb") as file_handle:
        return file_handle.read()


def build_download_label(filename: str) -> str:
    """Innocuous helper that only formats display text."""

    return filename.replace("_", " ").title()

