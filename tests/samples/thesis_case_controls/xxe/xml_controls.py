"""Negative controls for XXE."""

from flask import Flask, request
from xml.etree import ElementTree
from defusedxml import ElementTree as DefusedElementTree


app = Flask(__name__)


@app.route("/xml/raw")
def import_customer_xml_vulnerable():
    xml_path = request.args.get("source", "")
    tree = ElementTree.parse(xml_path)
    root = tree.getroot()
    return {"root_tag": root.tag}


@app.route("/xml/safe")
def import_customer_xml_safe():
    xml_path = request.args.get("source", "")
    tree = DefusedElementTree.parse(xml_path)
    root = tree.getroot()
    return {"root_tag": root.tag}


def normalize_xml_document_name(document_name: str) -> str:
    """Innocuous helper that only trims the display name."""

    return document_name.strip().lower()

