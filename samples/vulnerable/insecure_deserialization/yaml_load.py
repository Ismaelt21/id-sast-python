# VULNERABLE: Insecure Deserialization via yaml.load - Training Sample
# CWE-502: Deserialization of Untrusted Data
# Severity: CRITICAL
# Description: yaml.load() without Loader=yaml.SafeLoader allows Python object
#              construction, enabling arbitrary code execution via !!python/object tags

import yaml
from flask import Flask, request

app = Flask(__name__)


def parse_config(config_string: str):
    """VULNERABLE: yaml.load with no Loader — defaults to full YAML deserializer."""
    # VULN: Payload:
    #   !!python/object/apply:os.system ["id"]
    return yaml.load(config_string, Loader=yaml.Loader)   # VULN: FullLoader / Loader


def parse_unsafe(data: str):
    """VULNERABLE: Explicit use of UnsafeLoader."""
    # VULN: UnsafeLoader allows all YAML tags including !!python/object
    return yaml.load(data, Loader=yaml.UnsafeLoader)


def load_from_file(filepath: str):
    """VULNERABLE: yaml.load() on user-supplied file path without SafeLoader."""
    # VULN: attacker uploads a YAML file with embedded Python object construction
    with open(filepath) as f:
        return yaml.load(f, Loader=yaml.Loader)


@app.route("/config", methods=["POST"])
def update_config():
    """VULNERABLE: Application config updated from YAML in POST body."""
    body = request.data.decode()
    # VULN: !!python/object/apply:subprocess.check_output [["id"]] in body = RCE
    config = yaml.load(body, Loader=yaml.Loader)
    return str(config)


@app.route("/import-pipeline", methods=["POST"])
def import_pipeline():
    """VULNERABLE: CI/CD pipeline imported from user-uploaded YAML."""
    pipeline_yaml = request.form.get("pipeline", "")
    # VULN: attacker submits a pipeline definition with a Python constructor
    parsed = yaml.load(pipeline_yaml, Loader=yaml.Loader)
    return str(parsed)


def merge_yaml_configs(base_yaml: str, override_yaml: str):
    """VULNERABLE: Two YAML strings merged — both are injectable."""
    base = yaml.load(base_yaml, Loader=yaml.Loader)           # VULN
    override = yaml.load(override_yaml, Loader=yaml.Loader)   # VULN
    if isinstance(base, dict) and isinstance(override, dict):
        base.update(override)
    return base


def validate_schema(document: str, schema: str):
    """VULNERABLE: Both document and schema parsed with full YAML loader."""
    # VULN: Either argument can trigger code execution
    doc = yaml.load(document, Loader=yaml.Loader)
    sch = yaml.load(schema, Loader=yaml.Loader)
    return doc, sch


def load_all_docs(stream: str):
    """VULNERABLE: yaml.load_all processes a multi-document YAML stream."""
    # VULN: Any document in the stream can contain malicious tags
    return list(yaml.load_all(stream, Loader=yaml.Loader))


def env_from_yaml(yaml_string: str):
    """VULNERABLE: Sets environment variables from deserialized YAML."""
    import os
    config = yaml.load(yaml_string, Loader=yaml.Loader)   # VULN
    if isinstance(config, dict):
        for k, v in config.items():
            os.environ[str(k)] = str(v)


if __name__ == "__main__":
    app.run(debug=True)