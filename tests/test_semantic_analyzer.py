"""
tests/test_semantic_analyzer.py

Tests unitarios para SemanticAnalyzer.
Cubre las 6 correcciones aplicadas.
"""

import pytest
from core.analyzers.semantic_analyzer import SemanticAnalyzer, SemanticAnalysisResult


# =============================================================
# FIXTURES
# =============================================================

@pytest.fixture
def analyzer():
    return SemanticAnalyzer()


@pytest.fixture
def dfg_data():
    return {
        "nodes": [
            {"id": "input",        "type": "source",   "label": "input"},
            {"id": "user",         "type": "variable", "label": "user"},
            {"id": "shlex.quote",  "type": "variable", "label": "shlex.quote"},
            {"id": "os.system@5",  "type": "sink",     "label": "os.system"},
        ],
        "edges": [],
    }


@pytest.fixture
def finding_unsafe():
    """Finding sin sanitizar del taint_analyzer corregido."""
    return {
        "vulnerability": "COMMAND_INJECTION",
        "severity":      "CRITICAL",
        "source":        "input",
        "sink":          "os.system@5",
        "sink_label":    "os.system",
        "path":          ["input", "user", "os.system@5"],
        "sanitized":     False,
        "confidence":    0.75,
    }


@pytest.fixture
def finding_sanitized():
    """Finding sanitizado con shlex.quote."""
    return {
        "vulnerability": "COMMAND_INJECTION",
        "severity":      "CRITICAL",
        "source":        "input",
        "sink":          "os.system@5",
        "sink_label":    "os.system",
        "path":          ["input", "user", "shlex.quote", "os.system@5"],
        "sanitized":     True,
        "confidence":    0.35,
    }


@pytest.fixture
def finding_sql():
    """SQL Injection finding."""
    return {
        "vulnerability": "SQL_INJECTION",
        "severity":      "CRITICAL",
        "source":        "input",
        "sink":          "cursor.execute@10",
        "sink_label":    "cursor.execute",
        "path":          ["input", "query", "cursor.execute@10"],
        "sanitized":     False,
        "confidence":    0.90,
    }


# =============================================================
# STRUCTURE
# =============================================================

class TestAnalyzeStructure:

    def test_analyze_returns_result_object(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        assert isinstance(result, SemanticAnalysisResult)

    def test_result_has_all_fields(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        required = [
            "vulnerability_detected",
            "exploitability",
            "semantic_confidence",
            "is_false_positive",
            "mitigation_detected",
            "mitigation_type",
            "contextual_risk",
            "reasoning",
            "requires_ai_validation",
            "metadata",
            "timestamp",
        ]
        d = result.to_dict()
        for field in required:
            assert field in d, f"Missing field: {field}"

    def test_to_dict_returns_dict(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        assert isinstance(result.to_dict(), dict)

    def test_to_dict_is_copy(
        self, analyzer, finding_unsafe, dfg_data
    ):
        """to_dict() debe retornar copia, no referencia mutable."""
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        d1 = result.to_dict()
        d2 = result.to_dict()
        d1["vulnerability_detected"] = not d1["vulnerability_detected"]
        assert d1["vulnerability_detected"] != d2["vulnerability_detected"]


# =============================================================
# CORRECCIÓN #1 — CAMPO 'path' EN LUGAR DE 'taint_path'
# =============================================================

class TestCorrection1PathField:

    def test_sanitizer_in_path_detected(
        self, analyzer, finding_sanitized, dfg_data
    ):
        """
        shlex.quote en 'path' debe detectarse como mitigación.
        Antes se leía 'taint_path' que siempre estaba vacío.
        """
        result = analyzer.analyze(
            finding_sanitized, {}, {}, dfg_data
        )
        assert result.mitigation_detected is True

    def test_no_sanitizer_in_path_not_mitigated(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        assert result.mitigation_detected is False

    def test_empty_path_no_mitigation(self, analyzer, dfg_data):
        finding = {
            "vulnerability": "COMMAND_INJECTION",
            "source":        "input",
            "sink":          "os.system@5",
            "sink_label":    "os.system",
            "path":          [],
            "sanitized":     False,
            "confidence":    0.50,
        }
        result = analyzer.analyze(finding, {}, {}, dfg_data)
        assert result.mitigation_detected is False


# =============================================================
# CORRECCIÓN #2 — CAMPO 'vulnerability' EN LUGAR DE 'vulnerability_type'
# =============================================================

class TestCorrection2VulnerabilityField:

    def test_sql_injection_classified_as_high_exploitability(
        self, analyzer, finding_sql, dfg_data
    ):
        """
        'vulnerability'='SQL_INJECTION' debe producir
        exploitability='HIGH'. Antes leía 'vulnerability_type'
        que no existía y retornaba siempre MEDIUM.
        """
        result = analyzer.analyze(
            finding_sql, {}, {}, dfg_data
        )
        assert result.exploitability == "HIGH"

    def test_command_injection_high_exploitability(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        assert result.exploitability == "HIGH"

    def test_reasoning_uses_vulnerability_field(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        # Tras el fix del bug real, el reasoning incluye el tipo
        # de vulnerabilidad cuando no hay mitigación.
        assert "COMMAND_INJECTION" in result.reasoning
        assert "os.system" in result.reasoning


# =============================================================
# CORRECCIÓN #3 — LOOKUP EXACTO SOBRE LABEL DEL NODO
# =============================================================

class TestCorrection3ExactLabelLookup:

    def test_shlex_quote_detected_as_sanitizer(
        self, analyzer, finding_sanitized, dfg_data
    ):
        """
        'shlex.quote' debe matchear exactamente contra
        KNOWN_SANITIZERS, no con substring sobre el ID.
        """
        result = analyzer.analyze(
            finding_sanitized, {}, {}, dfg_data
        )
        assert result.mitigation_detected is True
        assert result.mitigation_type in (
            "shlex.quote", "sanitized"
        )

    def test_partial_sanitizer_name_not_matched(
        self, analyzer, dfg_data
    ):
        """
        Un nodo con label 'escape_something' no debe matchear
        'escape' por substring.
        """
        finding = {
            "vulnerability": "COMMAND_INJECTION",
            "source":        "input",
            "sink":          "os.system@5",
            "sink_label":    "os.system",
            "path":          ["input", "escape_something", "os.system@5"],
            "sanitized":     False,
            "confidence":    0.70,
        }
        dfg = {
            "nodes": [
                {"id": "input",            "type": "source",   "label": "input"},
                {"id": "escape_something", "type": "variable", "label": "escape_something"},
                {"id": "os.system@5",      "type": "sink",     "label": "os.system"},
            ],
            "edges": [],
        }
        result = analyzer.analyze(finding, {}, {}, dfg)
        assert result.mitigation_detected is False


# =============================================================
# CORRECCIÓN #4 — RESPETA EL CAMPO 'sanitized' DEL TAINT
# =============================================================

class TestCorrection4RespectsSanitizedField:

    def test_sanitized_true_marks_mitigation(
        self, analyzer, finding_sanitized, dfg_data
    ):
        """
        Si el taint_analyzer ya marcó sanitized=True, el
        semantic_analyzer debe respetarlo sin reanalizar.
        """
        result = analyzer.analyze(
            finding_sanitized, {}, {}, dfg_data
        )
        assert result.mitigation_detected is True

    def test_sanitized_false_checks_path(
        self, analyzer, finding_unsafe, dfg_data
    ):
        """
        Si sanitized=False, el analyzer baja al path para
        buscar mitigaciones adicionales.
        """
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        assert result.mitigation_detected is False

    def test_false_positive_when_sanitized(
        self, analyzer, finding_sanitized, dfg_data
    ):
        result = analyzer.analyze(
            finding_sanitized, {}, {}, dfg_data
        )
        assert result.is_false_positive is True

    def test_not_false_positive_when_not_sanitized(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        assert result.is_false_positive is False


# =============================================================
# CORRECCIÓN #5 — REQUIRES_AI_VALIDATION MÁS PRECISO
# =============================================================

class TestCorrection5AIValidationLogic:

    def test_high_confidence_high_exploitability_no_ai(
        self, analyzer, dfg_data
    ):
        """
        HIGH exploitability + confianza >= 0.65 → no necesita IA.
        Es un TP claro.
        """
        finding = {
            "vulnerability": "COMMAND_INJECTION",
            "source":        "input",
            "sink":          "os.system@5",
            "sink_label":    "os.system",
            "path":          ["input", "user", "os.system@5"],
            "sanitized":     False,
            "confidence":    0.90,
        }
        result = analyzer.analyze(finding, {}, {}, dfg_data)
        assert result.requires_ai_validation is False

    def test_medium_exploitability_requires_ai(
        self, analyzer, dfg_data
    ):
        finding = {
            "vulnerability": "OPEN_REDIRECT",
            "source":        "input",
            "sink":          "redirect@3",
            "sink_label":    "redirect",
            "path":          ["input", "url", "redirect@3"],
            "sanitized":     False,
            "confidence":    0.55,
        }
        result = analyzer.analyze(finding, {}, {}, dfg_data)
        assert result.requires_ai_validation is True

    def test_low_confidence_no_mitigation_requires_ai(
        self, analyzer, dfg_data
    ):
        # Bug real #3 corregido: confianza < 0.50 sin mitigación
        # siempre requiere IA, incluso cuando exploitability=HIGH.
        # Antes: HIGH+alta_confianza bloqueaba este caso cuando
        # la confianza era baja (0.30 + 0.20 bonus = 0.50).
        finding = {
            "vulnerability": "COMMAND_INJECTION",
            "source":        "input",
            "sink":          "os.system@5",
            "sink_label":    "os.system",
            "path":          ["input", "os.system@5"],
            "sanitized":     False,
            "confidence":    0.25,  # claramente bajo el umbral 0.50
        }
        result = analyzer.analyze(finding, {}, {}, dfg_data)
        assert result.requires_ai_validation is True


# =============================================================
# CORRECCIÓN #6 — TO_DICT CON ASDICT
# =============================================================

class TestCorrection6ToDictAsdict:

    def test_to_dict_does_not_mutate_result(
        self, analyzer, finding_unsafe, dfg_data
    ):
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        d = result.to_dict()
        original_value = result.vulnerability_detected
        d["vulnerability_detected"] = not original_value
        assert result.vulnerability_detected == original_value

    def test_to_dict_serializable(
        self, analyzer, finding_unsafe, dfg_data
    ):
        import json
        result = analyzer.analyze(
            finding_unsafe, {}, {}, dfg_data
        )
        try:
            json.dumps(result.to_dict())
        except (TypeError, ValueError) as e:
            pytest.fail(f"to_dict() not JSON serializable: {e}")


# =============================================================
# ANALYZE MANY
# =============================================================

class TestAnalyzeMany:

    def test_analyze_many_returns_list(
        self, analyzer, finding_unsafe, finding_sql, dfg_data
    ):
        results = analyzer.analyze_many(
            [finding_unsafe, finding_sql], {}, {}, dfg_data
        )
        assert isinstance(results, list)
        assert len(results) == 2

    def test_analyze_many_each_is_result_object(
        self, analyzer, finding_unsafe, dfg_data
    ):
        results = analyzer.analyze_many(
            [finding_unsafe], {}, {}, dfg_data
        )
        assert isinstance(results[0], SemanticAnalysisResult)

    def test_export_results_serializable(
        self, analyzer, finding_unsafe, dfg_data
    ):
        import json
        results  = analyzer.analyze_many(
            [finding_unsafe], {}, {}, dfg_data
        )
        exported = analyzer.export_results(results)
        assert isinstance(exported, list)
        try:
            json.dumps(exported)
        except (TypeError, ValueError) as e:
            pytest.fail(f"export_results() not JSON serializable: {e}")