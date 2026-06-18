# VULNERABLE: Arbitrary File Read - Training Sample
# CWE-22 / CWE-73: External Control of File Name or Path
# Severity: HIGH
# Description: Multiple patterns that allow reading arbitrary files from the filesystem

import os
import glob
import configparser


SAFE_DIR = "/app/data"


def render_page(page_name):
    """VULNERABLE: Template rendering via open() with user-controlled page name."""
    # VULN: page_name = "../../../etc/hostname"
    with open(f"/app/views/{page_name}.txt") as f:
        return f.read()


def load_user_config(username):
    """VULNERABLE: ConfigParser reads attacker-controlled path."""
    # VULN: username = "../../root/.ssh/id_rsa" — config parser reads it as INI
    config = configparser.ConfigParser()
    config.read(f"/home/{username}/.appconfig")
    return dict(config)


def tail_file(filepath, n=20):
    """VULNERABLE: Reads last N lines of a file — path is user-supplied."""
    # VULN: filepath = "/etc/shadow" dumps password hashes
    with open(filepath) as f:
        return f.readlines()[-n:]


def cat_multiple(filenames: list):
    """VULNERABLE: Concatenates multiple user-supplied file paths."""
    output = []
    for name in filenames:
        # VULN: each element can be an absolute path or traversal sequence
        full = os.path.join(SAFE_DIR, name)
        try:
            with open(full) as f:
                output.append(f.read())
        except OSError:
            pass
    return "".join(output)


def glob_files(pattern):
    """VULNERABLE: glob with user-controlled pattern."""
    # VULN: pattern = "/etc/*" returns list of all /etc files
    return glob.glob(pattern)


def read_image_metadata(image_path):
    """VULNERABLE: Opens arbitrary binary file to read first 512 bytes."""
    # VULN: image_path = "/proc/self/mem" — may expose process memory
    with open(image_path, "rb") as f:
        return f.read(512)


def include_snippet(snippet_id):
    """VULNERABLE: Server-Side Include simulation — includes arbitrary file."""
    # VULN: snippet_id = "../../../../etc/crontab"
    base = "/app/snippets/"
    path = base + snippet_id + ".html"
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def read_env_file(env_name):
    """VULNERABLE: Reads .env files by environment name — path not restricted."""
    # VULN: env_name = "../../../../root/.env" leaks secrets from other dirs
    path = f"/app/config/{env_name}.env"
    result = {}
    with open(path) as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                result[k] = v
    return result


def stream_csv(report_path):
    """VULNERABLE: Streams CSV content for download — path fully attacker-controlled."""
    # VULN: report_path = "/etc/passwd" — CSV parser reads colon-delimited passwd file
    import csv
    rows = []
    with open(report_path, newline="") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            rows.append(row)
    return rows


def read_proc(proc_path):
    """VULNERABLE: Reads from /proc filesystem — attacker can access /proc/self/environ."""
    # VULN: proc_path = "self/environ" exposes environment variables including secrets
    full = os.path.join("/proc", proc_path)
    with open(full, "rb") as f:
        return f.read()