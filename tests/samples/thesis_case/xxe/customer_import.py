"""Positive benchmark: XXE-style XML parsing from an untrusted path."""

from flask import Flask, request
from xml.etree import ElementTree


app = Flask(__name__)


@app.route("/import/customer-xml")
def import_customer_xml():
    xml_path = request.args.get("source", "")
    tree = ElementTree.parse(xml_path)
    root = tree.getroot()
    return {"root_tag": root.tag}

