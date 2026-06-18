"""
tests/test_pattern_matcher.py

Tests unitarios para PatternMatcher.
Cubre las 3 correcciones aplicadas.
"""

import pytest
from core.analyzers.pattern_matcher import PatternMatcher


# =============================================================
# FIXTURES
# =============================================================

@pytest.fixture
def sqli_finding():
    return {
        "vulnerability": "SQL_INJECTION",
        "severity":      "CRITICAL",
        "source":        "input",
        "sink":          "cursor.execute@10",
        "sink_label":    "cursor.execute",
        "path":          ["input", "VAR_1", "VAR_2", "cursor.execute@10"],
        "sanitized":     False,
        "confidence":    0.75,
    }


@pytest.fixture
def command_finding():
    return {
        "vulnerability": "COMMAND_INJECTION",
        "severity":      "CRITICAL",
        "source":        "input",
        "sink":          "os.system@5",
        "sink_label":    "os.system",
        "path":          ["input", "user", "os.system@5"],
        "sanitized":     False,
        "confidence":    0.90,
    }


@pytest.fixture
def sanitized_finding():
    return {
        "vulnerability": "COMMAND_INJECTION",
        "severity":      "LOW",
        "source":        "input",
        "sink":          "os.system@5",
        "sink_label":    "os.system",
        "path":          ["input", "user", "shlex.quote", "os.system@5"],
        "sanitized":     True,
        "confidence":    0.35,
    }


@pytest.fixture
def sqli_rule():
    return {
        "rule_id":       "RULE_SQLI_001",
        "vulnerability": "SQL_INJECTION",
        "pattern": {
            "source_type":          "input",
            "sink_type":            "SQL_EXECUTION",
            "requires_propagation": True,
        },
    }


@pytest.fixture
def command_rule():
    return {
        "rule_id":       "RULE_CMD_001",
        "vulnerability": "COMMAND_INJECTION",
        "pattern": {
            "source_type":          "input",
            "sink_type":            "COMMAND_EXECUTION",
            "requires_propagation": False,
        },
    }


# =============================================================
# STRUCTURE
# =============================================================

class TestMatchStructure:

    def test_match_returns_dict(self, sqli_finding, sqli_rule):
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert isinstance(result, dict)

    def test_result_has_matches_and_unknown(self, sqli_finding, sqli_rule):
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert "matches"          in result
        assert "unknown_patterns" in result

    def test_matches_is_list(self, sqli_finding, sqli_rule):
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert isinstance(result["matches"], list)

    def test_unknown_patterns_is_list(self, sqli_finding, sqli_rule):
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert isinstance(result["unknown_patterns"], list)

    def test_empty_findings_no_matches(self, sqli_rule):
        matcher = PatternMatcher([], [sqli_rule])
        result  = matcher.match()
        assert result["matches"]          == []
        assert result["unknown_patterns"] == []

    def test_empty_rules_all_unknown(self, sqli_finding):
        matcher = PatternMatcher([sqli_finding], [])
        result  = matcher.match()
        assert len(result["unknown_patterns"]) == 1
        assert result["matches"]               == []


# =============================================================
# CORRECCIÓN #1 — CAMPO 'vulnerability' CORRECTO
# =============================================================

class TestCorrection1VulnerabilityField:

    def test_sqli_finding_matches_sqli_rule(self, sqli_finding, sqli_rule):
        """
        El matching usa 'vulnerability' (no 'vulnerability_type').
        Antes el score era siempre 0.0 porque el campo no existía.
        """
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert len(result["matches"]) == 1

    def test_wrong_vulnerability_type_no_match(self, command_finding, sqli_rule):
        """
        COMMAND_INJECTION no debe matchear SQLI rule.
        """
        matcher = PatternMatcher([command_finding], [sqli_rule])
        result  = matcher.match()
        assert len(result["matches"]) == 0

    def test_match_includes_rule_id(self, sqli_finding, sqli_rule):
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert result["matches"][0]["rule_id"] == "RULE_SQLI_001"

    def test_match_includes_similarity(self, sqli_finding, sqli_rule):
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert "similarity" in result["matches"][0]
        assert 0.0 <= result["matches"][0]["similarity"] <= 1.0


# =============================================================
# CORRECCIÓN #2 — SINK_LABEL EN LUGAR DE SINK CON @LINENO
# =============================================================

class TestCorrection2SinkLabel:

    def test_cursor_execute_matches_sql_execution_alias(
        self, sqli_finding, sqli_rule
    ):
        """
        sink_label='cursor.execute' debe matchear alias
        SQL_EXECUTION correctamente.
        Antes se usaba sink='cursor.execute@10' y el match
        fallaba con el substring.
        """
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert len(result["matches"]) > 0

    def test_os_system_matches_command_execution_alias(
        self, command_finding, command_rule
    ):
        matcher = PatternMatcher([command_finding], [command_rule])
        result  = matcher.match()
        assert len(result["matches"]) > 0

    def test_sink_with_lineno_still_matches_via_label(self, sqli_rule):
        """
        Aunque el finding tenga sink con @lineno, el matching
        usa sink_label y no debe fallar.
        """
        finding = {
            "vulnerability": "SQL_INJECTION",
            "source":        "input",
            "sink":          "cursor.execute@999",
            "sink_label":    "cursor.execute",
            "path":          ["input", "cursor.execute@999"],
            "sanitized":     False,
            "confidence":    0.80,
        }
        matcher = PatternMatcher([finding], [sqli_rule])
        result  = matcher.match()
        assert len(result["matches"]) > 0

    def test_no_sink_label_falls_back_to_sink(self, sqli_rule):
        """
        Si no hay sink_label, debe usar sink como fallback.
        """
        finding = {
            "vulnerability": "SQL_INJECTION",
            "source":        "input",
            "sink":          "cursor.execute",
            "path":          ["input", "cursor.execute"],
            "sanitized":     False,
            "confidence":    0.80,
        }
        matcher = PatternMatcher([finding], [sqli_rule])
        result  = matcher.match()
        assert len(result["matches"]) > 0


# =============================================================
# CORRECCIÓN #3 — RESET ENTRE LLAMADAS A MATCH()
# =============================================================

class TestCorrection3ResetBetweenCalls:

    def test_second_call_does_not_duplicate_matches(
        self, sqli_finding, sqli_rule
    ):
        """
        Llamar match() dos veces no debe acumular resultados.
        """
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        first   = matcher.match()
        second  = matcher.match()
        assert len(first["matches"])  == len(second["matches"])
        assert len(first["unknown_patterns"]) == len(second["unknown_patterns"])

    def test_multiple_calls_stable_results(self, sqli_finding, sqli_rule):
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        counts = [len(matcher.match()["matches"]) for _ in range(4)]
        assert len(set(counts)) == 1, f"Unstable match counts: {counts}"


# =============================================================
# PROPAGATION MATCH
# =============================================================

class TestPropagationMatch:

    def test_propagation_required_and_present(self, sqli_finding, sqli_rule):
        """
        path con 4 nodos satisface requires_propagation=True.
        """
        matcher = PatternMatcher([sqli_finding], [sqli_rule])
        result  = matcher.match()
        assert len(result["matches"]) > 0
        similarity = result["matches"][0]["similarity"]
        assert similarity >= 0.75

    def test_propagation_required_but_short_path(self, sqli_rule):
        finding = {
            "vulnerability": "SQL_INJECTION",
            "source":        "input",
            "sink":          "cursor.execute@1",
            "sink_label":    "cursor.execute",
            "path":          ["input", "cursor.execute@1"],
            "sanitized":     False,
            "confidence":    0.90,
        }
        matcher    = PatternMatcher([finding], [sqli_rule])
        result     = matcher.match()
        similarity = result["matches"][0]["similarity"] if result["matches"] else 0
        # Sin propagation el score es menor (falta el 0.1 bonus)
        assert similarity <= 0.90


# =============================================================
# UNKNOWN PATTERNS
# =============================================================

class TestUnknownPatterns:

    def test_unmatched_finding_in_unknown(self, command_finding, sqli_rule):
        matcher = PatternMatcher([command_finding], [sqli_rule])
        result  = matcher.match()
        assert len(result["unknown_patterns"]) == 1

    def test_unknown_pattern_has_requires_ai_flag(
        self, command_finding, sqli_rule
    ):
        matcher = PatternMatcher([command_finding], [sqli_rule])
        result  = matcher.match()
        unknown = result["unknown_patterns"][0]
        assert unknown["requires_ai_analysis"] is True
        assert unknown["matched"] is False

    def test_multiple_findings_mixed_results(
        self, sqli_finding, command_finding, sqli_rule
    ):
        matcher = PatternMatcher(
            [sqli_finding, command_finding],
            [sqli_rule],
        )
        result = matcher.match()
        assert len(result["matches"])          == 1
        assert len(result["unknown_patterns"]) == 1