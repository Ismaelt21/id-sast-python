"""Benchmark validation for thesis samples.

This suite is intentionally separate from the general sample tests so the
thesis corpus can be run and discussed as its own validation artifact.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.analyzers.taint_analyzer import TaintAnalyzer
from core.analyzers.vulnerability_classifier import VulnerabilityClassifier
from core.parsers.dfg_builder import DFGBuilder


ROOT = Path(__file__).parent / "samples"
POSITIVE = ROOT / "thesis_case"
CONTROLS = ROOT / "thesis_case_controls"


def _scan_file(path: Path) -> list[dict]:
    return _scan_source(path.read_text(encoding="utf-8"))


def _scan_source(code: str) -> list[dict]:
    dfg = DFGBuilder().build_from_code(code)
    findings = TaintAnalyzer(dfg).analyze()
    classifier = VulnerabilityClassifier()
    return [classifier.classify(f).to_dict() for f in findings]


def _extract_function_source(path: Path, function_name: str) -> str:
    code = path.read_text(encoding="utf-8")
    tree = ast.parse(code)

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            start_line = node.lineno
            if node.decorator_list:
                start_line = min(decorator.lineno for decorator in node.decorator_list)
            lines = code.splitlines()
            return "\n".join(lines[start_line - 1 : node.end_lineno])

    raise AssertionError(f"Function '{function_name}' not found in {path}")


def _types(findings: list[dict]) -> set[str]:
    return {f["vulnerability_type"] for f in findings}


SUPPORTED_POSITIVE_CASES = [
    (POSITIVE / "sqli" / "account_lookup.py", "SQL_INJECTION"),
    (POSITIVE / "path_traversal" / "document_service.py", "PATH_TRAVERSAL"),
    (POSITIVE / "ssrf" / "external_fetcher.py", "SSRF"),
    (POSITIVE / "xss" / "profile_preview.py", "XSS"),
]

KNOWN_GAP_POSITIVE_CASES = [
    (POSITIVE / "open_redirect" / "login_redirect.py", "OPEN_REDIRECT"),
    (POSITIVE / "xxe" / "customer_import.py", "XXE"),
]

CONTROL_CASES = [
    (
        CONTROLS / "sqli" / "sql_controls.py",
        "SQL_INJECTION",
        "account_lookup_vulnerable",
        "account_lookup_safe",
        "format_account_slug",
        True,
    ),
    (
        CONTROLS / "path_traversal" / "path_controls.py",
        "PATH_TRAVERSAL",
        "download_document_vulnerable",
        "download_document_safe",
        "build_download_label",
        True,
    ),
    (
        CONTROLS / "ssrf" / "ssrf_controls.py",
        "SSRF",
        "preview_remote_resource_vulnerable",
        "preview_remote_resource_safe",
        "normalize_feed_url",
        True,
    ),
    (
        CONTROLS / "xss" / "xss_controls.py",
        "XSS",
        "profile_preview_vulnerable",
        "profile_preview_safe",
        "build_banner_text",
        True,
    ),
]


KNOWN_GAP_CONTROL_CASES = [
    (
        CONTROLS / "open_redirect" / "redirect_controls.py",
        "OPEN_REDIRECT",
        "continue_after_login_vulnerable",
        "continue_after_login_safe",
        "build_internal_route",
        False,
    ),
    (
        CONTROLS / "xxe" / "xml_controls.py",
        "XXE",
        "import_customer_xml_vulnerable",
        "import_customer_xml_safe",
        "normalize_xml_document_name",
        False,
    ),
]


@pytest.mark.parametrize("sample_path, expected_type", SUPPORTED_POSITIVE_CASES)
def test_positive_benchmark_detects_supported_categories(sample_path, expected_type):
    findings = _scan_file(sample_path)
    assert expected_type in _types(findings), sample_path


@pytest.mark.parametrize("sample_path, expected_type", KNOWN_GAP_POSITIVE_CASES)
def test_positive_benchmark_documents_known_gaps(sample_path, expected_type):
    findings = _scan_file(sample_path)
    if expected_type not in _types(findings):
        pytest.xfail(
            f"Known pipeline gap: {expected_type} is present in the benchmark "
            f"but not yet modeled as a DFG sink."
        )


@pytest.mark.parametrize(
    "sample_path, expected_type, vulnerable_name, safe_name, helper_name, supported",
    CONTROL_CASES,
)
def test_controls_detect_vulnerable_and_keep_safe_clean(
    sample_path,
    expected_type,
    vulnerable_name,
    safe_name,
    helper_name,
    supported,
):
    vulnerable_source = _extract_function_source(sample_path, vulnerable_name)
    safe_source = _extract_function_source(sample_path, safe_name)
    helper_source = _extract_function_source(sample_path, helper_name)
    vulnerable_types = _types(_scan_source(vulnerable_source))
    safe_types = _types(_scan_source(safe_source))
    helper_types = _types(_scan_source(helper_source))

    if supported:
        assert expected_type in vulnerable_types, vulnerable_source
    else:
        if expected_type not in vulnerable_types:
            pytest.xfail(
                f"Known pipeline gap: {expected_type} is present in the "
                f"control benchmark but not yet modeled as a DFG sink."
            )

    assert expected_type not in safe_types, safe_source
    assert expected_type not in helper_types, helper_source


@pytest.mark.parametrize(
    "sample_path, expected_type, vulnerable_name, safe_name, helper_name, supported",
    KNOWN_GAP_CONTROL_CASES,
)
def test_controls_document_known_gaps(
    sample_path,
    expected_type,
    vulnerable_name,
    safe_name,
    helper_name,
    supported,
):
    vulnerable_source = _extract_function_source(sample_path, vulnerable_name)
    safe_source = _extract_function_source(sample_path, safe_name)
    helper_source = _extract_function_source(sample_path, helper_name)
    vulnerable_types = _types(_scan_source(vulnerable_source))
    safe_types = _types(_scan_source(safe_source))
    helper_types = _types(_scan_source(helper_source))

    if expected_type not in vulnerable_types:
        pytest.xfail(
            f"Known pipeline gap: {expected_type} is present in the "
            f"benchmark but not yet modeled as a DFG sink."
        )

    assert expected_type not in safe_types, safe_source
    assert expected_type not in helper_types, helper_source
