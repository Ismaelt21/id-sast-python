"""Positive benchmark: path traversal through filesystem reads and deletes."""

import os
from pathlib import Path
from flask import Flask, request


app = Flask(__name__)
BASE_DIR = Path("/var/app/uploads")


@app.route("/documents/download")
def download_document():
    filename = request.args.get("file", "")
    target_path = BASE_DIR / filename

    with open(target_path, "rb") as file_handle:
        return file_handle.read()


@app.route("/documents/delete")
def delete_cached_document():
    filename = request.args.get("file", "")
    archive_path = f"/var/app/cache/{filename}"

    os.remove(archive_path)
    return {"deleted": filename}

