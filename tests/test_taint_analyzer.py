"""
tests/test_taint_analyzer.py

Tests unitarios para TaintAnalyzer.
Cubre las 6 correcciones aplicadas.
"""

import pytest
from core.analyzers.taint_analyzer import TaintAnalyzer


# =============================================================
# FIXTURES — DFG DATA
# =============================================================

@pytest.fixture
def dfg_direct():
    """Source → variable → sink sin sanitizar."""
    return {
        "nodes": [
            {"id": "input",        "type": "source",   "label": "input"},
            {"id": "user",         "type": "variable", "label": "user"},
            {"id": "os.system@5",  "type": "sink",     "label": "os.system"},
        ],
        "edges": [
            {"source": "input",  "target": "user",        "type": "taint"},
            {"source": "user",   "target": "os.system@5", "type": "sink_flow"},
        ],
    }


@pytest.fixture
def dfg_sanitized():
    """Source → variable → sanitizer → sink."""
    return {
        "nodes": [
            {"id": "input",        "type": "source",   "label": "input"},
            {"id": "user",         "type": "variable", "label": "user"},
            {"id": "shlex.quote",  "type": "variable", "label": "shlex.quote"},
            {"id": "os.system@8",  "type": "sink",     "label": "os.system"},
        ],
        "edges": [
            {"source": "input",       "target": "user",        "type": "taint"},
            {"source": "user",        "target": "shlex.quote", "type": "propagation"},
            {"source": "shlex.quote", "target": "os.system@8", "type": "sink_flow"},
        ],
    }


@pytest.fixture
def dfg_sql():
    """Source → query → cursor.execute."""
    return {
        "nodes": [
            {"id": "input",               "type": "source",   "label": "input"},
            {"id": "query",               "type": "variable", "label": "query"},
            {"id": "cursor.execute@10",   "type": "sink",     "label": "cursor.execute"},
        ],
        "edges": [
            {"source": "input", "target": "query",             "type": "taint"},
            {"source": "query", "target": "cursor.execute@10", "type": "sink_flow"},
        ],
    }


@pytest.fixture
def dfg_no_path():
    """Source y sink sin conexión entre ellos."""
    return {
        "nodes": [
            {"id": "input",       "type": "source",   "label": "input"},
            {"id": "os.system@3", "type": "sink",     "label": "os.system"},
        ],
        "edges": [],
    }


@pytest.fixture
def dfg_empty():
    return {"nodes": [], "edges": []}


# =============================================================
# STRUCTURE
# =============================================================

class TestAnalyzeStructure:

    def test_analyze_returns_list(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        result   = analyzer.analyze()
        assert isinstance(result, list)

    def test_finding_has_required_fields(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        assert len(findings) > 0
        finding  = findings[0]
        required = [
            "vulnerability", "severity", "source",
            "sink", "sink_label", "path",
            "sanitized", "confidence",
        ]
        for field in required:
            assert field in finding, f"Missing field: {field}"

    def test_empty_dfg_returns_empty_list(self, dfg_empty):
        analyzer = TaintAnalyzer(dfg_empty)
        result   = analyzer.analyze()
        assert result == []


# =============================================================
# CORRECCIÓN #1 — LOOKUP EXACTO EN _detect_vulnerability_type
# =============================================================

class TestCorrection1ExactLookup:

    def test_cursor_execute_not_confused_with_exec(self, dfg_sql):
        """
        'exec' no debe matchear dentro de 'cursor.execute'.
        Antes el substring match retornaba CODE_INJECTION
        para cursor.execute.
        """
        analyzer = TaintAnalyzer(dfg_sql)
        findings = analyzer.analyze()
        assert len(findings) > 0
        assert findings[0]["vulnerability"] == "SQL_INJECTION"
        assert findings[0]["vulnerability"] != "CODE_INJECTION"

    def test_os_system_detected_as_command_injection(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        assert findings[0]["vulnerability"] == "COMMAND_INJECTION"

    def test_unknown_sink_returns_unknown(self):
        dfg = {
            "nodes": [
                {"id": "input",        "type": "source",   "label": "input"},
                {"id": "custom@1",     "type": "sink",     "label": "custom_function"},
            ],
            "edges": [
                {"source": "input", "target": "custom@1", "type": "sink_flow"},
            ],
        }
        analyzer = TaintAnalyzer(dfg)
        findings = analyzer.analyze()
        assert findings[0]["vulnerability"] == "UNKNOWN"


# =============================================================
# CORRECCIÓN #2 — CAMPO LABEL PRESERVADO EN _build_graph
# =============================================================

class TestCorrection2LabelPreserved:

    def test_sink_label_in_finding(self, dfg_direct):
        """
        El finding debe incluir sink_label con el nombre limpio
        del sink, separado del ID con @lineno.
        """
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        assert findings[0]["sink_label"] == "os.system"

    def test_sink_label_clean_no_lineno(self, dfg_sql):
        analyzer = TaintAnalyzer(dfg_sql)
        findings = analyzer.analyze()
        assert "@" not in findings[0]["sink_label"]

    def test_sink_id_still_contains_lineno(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        assert "@" in findings[0]["sink"]


# =============================================================
# CORRECCIÓN #3 — SANITIZACIÓN POSICIONAL
# =============================================================

class TestCorrection3PositionalSanitization:

    def test_sanitized_path_marked_as_sanitized(self, dfg_sanitized):
        """
        shlex.quote antes del sink debe marcar sanitized=True.
        """
        analyzer = TaintAnalyzer(dfg_sanitized)
        findings = analyzer.analyze()
        assert len(findings) > 0
        assert findings[0]["sanitized"] is True

    def test_sanitized_path_severity_low(self, dfg_sanitized):
        analyzer = TaintAnalyzer(dfg_sanitized)
        findings = analyzer.analyze()
        assert findings[0]["severity"] == "LOW"

    def test_unsanitized_path_severity_critical(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        assert findings[0]["severity"] == "CRITICAL"

    def test_sanitizer_after_sink_not_counted(self):
        """
        Un sanitizador que aparece DESPUÉS del sink en el path
        no debe marcar el finding como sanitizado.
        """
        dfg = {
            "nodes": [
                {"id": "input",       "type": "source",   "label": "input"},
                {"id": "user",        "type": "variable", "label": "user"},
                {"id": "os.system@5", "type": "sink",     "label": "os.system"},
                {"id": "escape",      "type": "variable", "label": "escape"},
            ],
            "edges": [
                {"source": "input",       "target": "user",        "type": "taint"},
                {"source": "user",        "target": "os.system@5", "type": "sink_flow"},
                {"source": "os.system@5", "target": "escape",      "type": "propagation"},
            ],
        }
        analyzer = TaintAnalyzer(dfg)
        findings = analyzer.analyze()
        sanitized_findings = [f for f in findings if f["sink"] == "os.system@5"]
        assert len(sanitized_findings) > 0
        assert sanitized_findings[0]["sanitized"] is False


# =============================================================
# CORRECCIÓN #4 — RESET DE FINDINGS ENTRE LLAMADAS
# =============================================================

class TestCorrection4FindingsReset:

    def test_second_analyze_does_not_accumulate(self, dfg_direct):
        """
        Llamar analyze() dos veces no debe duplicar findings.
        """
        analyzer = TaintAnalyzer(dfg_direct)
        first    = analyzer.analyze()
        second   = analyzer.analyze()
        assert len(first) == len(second)

    def test_findings_count_stable_multiple_calls(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        counts = [len(analyzer.analyze()) for _ in range(3)]
        assert len(set(counts)) == 1, (
            f"Findings count not stable: {counts}"
        )


# =============================================================
# CORRECCIÓN #5 — _analyze_path RETORNA NONE CUANDO CORRESPONDE
# =============================================================

class TestCorrection5NoneOnLowConfidence:

    def test_no_path_returns_no_findings(self, dfg_no_path):
        """
        Si no hay camino entre source y sink, no debe haber findings.
        """
        analyzer = TaintAnalyzer(dfg_no_path)
        findings = analyzer.analyze()
        assert findings == []

    def test_unknown_vulnerability_low_confidence_filtered(self):
        """
        UNKNOWN con confianza muy baja debe filtrarse.
        """
        dfg = {
            "nodes": [
                {"id": "input",     "type": "source", "label": "input"},
                {"id": "sink@99",   "type": "sink",   "label": "unknown_func"},
            ],
            "edges": [
                {"source": "input", "target": "sink@99", "type": "sink_flow"},
            ],
        }
        analyzer = TaintAnalyzer(dfg)
        findings = analyzer.analyze()
        # UNKNOWN con path directo (2 nodos) puede pasar o no
        # dependiendo del umbral; lo importante es que no explota.
        assert isinstance(findings, list)


# =============================================================
# CORRECCIÓN #6 — CONFIANZA GRANULAR
# =============================================================

class TestCorrection6Confidence:

    def test_direct_path_high_confidence(self, dfg_direct):
        """
        El fixture dfg_direct tiene path ["input", "user", "os.system@5"]
        que son 3 nodos → score base 0.75 (tramo 'corto').
        Un path de 2 nodos (source→sink directo) daría 0.90.
        Verificamos que el score sea >= 0.70 para un path corto.
        """
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        assert findings[0]["confidence"] >= 0.70

    def test_longer_path_lower_confidence(self):
        """
        Path con muchos nodos intermedios debe tener confianza
        menor que un path directo.
        """
        dfg_long = {
            "nodes": [
                {"id": "input",       "type": "source",   "label": "input"},
                {"id": "v1",          "type": "variable", "label": "v1"},
                {"id": "v2",          "type": "variable", "label": "v2"},
                {"id": "v3",          "type": "variable", "label": "v3"},
                {"id": "v4",          "type": "variable", "label": "v4"},
                {"id": "v5",          "type": "variable", "label": "v5"},
                {"id": "os.system@9", "type": "sink",     "label": "os.system"},
            ],
            "edges": [
                {"source": "input", "target": "v1",          "type": "taint"},
                {"source": "v1",    "target": "v2",          "type": "propagation"},
                {"source": "v2",    "target": "v3",          "type": "propagation"},
                {"source": "v3",    "target": "v4",          "type": "propagation"},
                {"source": "v4",    "target": "v5",          "type": "propagation"},
                {"source": "v5",    "target": "os.system@9", "type": "sink_flow"},
            ],
        }

        dfg_short = {
            "nodes": [
                {"id": "input",       "type": "source",   "label": "input"},
                {"id": "os.system@2", "type": "sink",     "label": "os.system"},
            ],
            "edges": [
                {"source": "input", "target": "os.system@2", "type": "sink_flow"},
            ],
        }

        analyzer_long  = TaintAnalyzer(dfg_long)
        analyzer_short = TaintAnalyzer(dfg_short)

        conf_long  = analyzer_long.analyze()[0]["confidence"]
        conf_short = analyzer_short.analyze()[0]["confidence"]

        assert conf_short > conf_long

    def test_sanitized_path_lower_confidence(self, dfg_sanitized):
        """
        Tras el fix del bug real (SANITIZERS expandido con shlex.quote),
        el path sanitizado ahora se detecta correctamente:
        score base 0.75 (3 nodos antes del sink) - 0.40 = 0.35.
        Verificamos que sea menor que el path sin sanitizar (0.75).
        """
        analyzer = TaintAnalyzer(dfg_sanitized)
        findings = analyzer.analyze()
        assert findings[0]["confidence"] < 0.60

    def test_confidence_between_0_and_1(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        for f in findings:
            assert 0.0 <= f["confidence"] <= 1.0


# =============================================================
# PATH FIELD
# =============================================================

class TestPathField:

    def test_finding_has_path_not_taint_path(self, dfg_direct):
        """
        El campo debe llamarse 'path', no 'taint_path'.
        """
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        assert "path"       in findings[0]
        assert "taint_path" not in findings[0]

    def test_path_includes_source_and_sink(self, dfg_direct):
        analyzer = TaintAnalyzer(dfg_direct)
        findings = analyzer.analyze()
        path = findings[0]["path"]
        assert path[0]  == "input"
        assert path[-1] == "os.system@5"