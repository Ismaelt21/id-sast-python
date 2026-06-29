"""Standalone runner for the thesis benchmark corpus.

This script avoids the CLI dependency stack so the benchmark can be executed
with the bundled Python runtime even when optional packages such as
``python-dotenv`` or ``pytest`` are not available.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.analyzers.taint_analyzer import TaintAnalyzer
from core.analyzers.vulnerability_classifier import VulnerabilityClassifier
from core.parsers.dfg_builder import DFGBuilder


ROOT = Path(__file__).parent / "samples"
POSITIVE = ROOT / "thesis_case"
CONTROLS = ROOT / "thesis_case_controls"


SUPPORTED_POSITIVE = [
    (POSITIVE / "sqli" / "account_lookup.py", "SQL_INJECTION"),
    (POSITIVE / "path_traversal" / "document_service.py", "PATH_TRAVERSAL"),
    (POSITIVE / "ssrf" / "external_fetcher.py", "SSRF"),
    (POSITIVE / "xss" / "profile_preview.py", "XSS"),
]

KNOWN_GAP_POSITIVE = [
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


def scan_source(code: str) -> list[dict]:
    dfg = DFGBuilder().build_from_code(code)
    findings = TaintAnalyzer(dfg).analyze()
    classifier = VulnerabilityClassifier()
    return [classifier.classify(f).to_dict() for f in findings]


def scan_file(path: Path) -> list[dict]:
    return scan_source(path.read_text(encoding="utf-8"))


def extract_function_source(path: Path, function_name: str) -> str:
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


def types(findings: list[dict]) -> set[str]:
    return {finding["vulnerability_type"] for finding in findings}


def report_case(label: str, expected: str, observed: set[str], status: str) -> None:
    observed_text = ", ".join(sorted(observed)) if observed else "-"
    print(f"{status:8} {label:<42} expected={expected:<16} observed={observed_text}")


def run() -> int:
    failures = 0

    print("POSITIVE BENCHMARK")
    for path, expected in SUPPORTED_POSITIVE:
        observed = types(scan_file(path))
        ok = expected in observed
        report_case(path.relative_to(ROOT).as_posix(), expected, observed, "PASS" if ok else "FAIL")
        if not ok:
            failures += 1

    for path, expected in KNOWN_GAP_POSITIVE:
        observed = types(scan_file(path))
        status = "GAP" if expected not in observed else "PASS"
        report_case(path.relative_to(ROOT).as_posix(), expected, observed, status)

    print()
    print("NEGATIVE CONTROLS")
    for path, expected, vuln_fn, safe_fn, helper_fn, supported in CONTROL_CASES:
        vuln_types = types(scan_source(extract_function_source(path, vuln_fn)))
        safe_types = types(scan_source(extract_function_source(path, safe_fn)))
        helper_types = types(scan_source(extract_function_source(path, helper_fn)))

        if supported:
            vuln_status = "PASS" if expected in vuln_types else "FAIL"
        else:
            vuln_status = "PASS" if expected in vuln_types else "GAP"

        safe_ok = expected not in safe_types
        helper_ok = expected not in helper_types

        report_case(
            f"{path.relative_to(ROOT).as_posix()}::{vuln_fn}",
            expected,
            vuln_types,
            vuln_status,
        )
        report_case(
            f"{path.relative_to(ROOT).as_posix()}::{safe_fn}",
            expected,
            safe_types,
            "PASS" if safe_ok else "FAIL",
        )
        report_case(
            f"{path.relative_to(ROOT).as_posix()}::{helper_fn}",
            expected,
            helper_types,
            "PASS" if helper_ok else "FAIL",
        )

        if (supported and expected not in vuln_types) or not safe_ok or not helper_ok:
            failures += 1

    if failures:
        print(f"\nBenchmark finished with {failures} failing checks.")
        return 1

    print("\nBenchmark finished cleanly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
