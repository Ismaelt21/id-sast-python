"""
tests/test_built_in_rules.py

Tests unitarios para core/rules/built_in_rules.py
"""

import pytest
from core.rules.built_in_rules import (
    BuiltInRule,
    BUILT_IN_RULES,
    get_rule,
    get_all_rules,
    get_rules_by_vulnerability,
    match_rule_by_sink,
    match_rule_by_source,
    export_rules,
)


# =============================================================
# REGISTRY STRUCTURE
# =============================================================

class TestRegistryStructure:

    def test_built_in_rules_is_dict(self):
        assert isinstance(BUILT_IN_RULES, dict)

    def test_built_in_rules_not_empty(self):
        assert len(BUILT_IN_RULES) > 0

    def test_each_value_is_rule_instance(self):
        for key, value in BUILT_IN_RULES.items():
            assert isinstance(value, BuiltInRule), (
                f"Expected BuiltInRule for key '{key}'"
            )

    def test_each_rule_has_required_fields(self):
        required = [
            "rule_id", "name", "vulnerability_type", "cwe_id",
            "severity", "description", "sources", "sinks",
            "sanitizers", "confidence",
        ]
        for key, rule in BUILT_IN_RULES.items():
            for field in required:
                assert hasattr(rule, field), (
                    f"Rule '{key}' missing field '{field}'"
                )

    def test_rule_ids_unique(self):
        ids = [r.rule_id for r in BUILT_IN_RULES.values()]
        assert len(ids) == len(set(ids)), "Rule IDs are not unique"

    def test_confidence_between_0_and_1(self):
        for key, rule in BUILT_IN_RULES.items():
            assert 0.0 <= rule.confidence <= 1.0, (
                f"Rule '{key}' has invalid confidence: {rule.confidence}"
            )

    def test_severity_values_valid(self):
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for key, rule in BUILT_IN_RULES.items():
            assert rule.severity in valid, (
                f"Rule '{key}' has invalid severity: {rule.severity}"
            )

    def test_cwe_format(self):
        for key, rule in BUILT_IN_RULES.items():
            assert rule.cwe_id.startswith("CWE-"), (
                f"Rule '{key}' CWE '{rule.cwe_id}' invalid format"
            )


# =============================================================
# EXPECTED RULES PRESENT
# =============================================================

class TestExpectedRulesPresent:

    def test_sql_injection_rule_exists(self):
        assert "sql_injection_rule" in BUILT_IN_RULES

    def test_command_injection_rule_exists(self):
        assert "command_injection_rule" in BUILT_IN_RULES

    def test_code_injection_rule_exists(self):
        assert "code_injection_rule" in BUILT_IN_RULES

    def test_xss_rule_exists(self):
        assert "xss_rule" in BUILT_IN_RULES

    def test_path_traversal_rule_exists(self):
        assert "path_traversal_rule" in BUILT_IN_RULES

    def test_ssrf_rule_exists(self):
        assert "ssrf_rule" in BUILT_IN_RULES

    def test_deserialization_rule_exists(self):
        assert "deserialization_rule" in BUILT_IN_RULES


# =============================================================
# CORRECCIÓN #9 — SINKS USAN LABELS LIMPIOS
# =============================================================

class TestCorrection9SinkLabels:

    def test_sql_rule_uses_cursor_execute(self):
        """
        La regla SQL debe usar 'cursor.execute', no 'execute'.
        El pattern_matcher hace match exacto contra sink_label.
        """
        rule = BUILT_IN_RULES["sql_injection_rule"]
        assert "cursor.execute" in rule.sinks
        assert "execute" not in rule.sinks

    def test_sql_rule_uses_cursor_executemany(self):
        rule = BUILT_IN_RULES["sql_injection_rule"]
        assert "cursor.executemany" in rule.sinks

    def test_command_rule_uses_full_sink_names(self):
        rule = BUILT_IN_RULES["command_injection_rule"]
        assert "os.system"      in rule.sinks
        assert "subprocess.run" in rule.sinks

    def test_code_rule_uses_eval_and_exec(self):
        rule = BUILT_IN_RULES["code_injection_rule"]
        assert "eval" in rule.sinks
        assert "exec" in rule.sinks

    def test_no_sink_with_lineno(self):
        """Ningún sink en las reglas debe contener @lineno."""
        for key, rule in BUILT_IN_RULES.items():
            for sink in rule.sinks:
                assert "@" not in sink, (
                    f"Rule '{key}' sink '{sink}' contains @lineno"
                )


# =============================================================
# GET_RULE
# =============================================================

class TestGetRule:

    def test_get_existing_rule(self):
        rule = get_rule("sql_injection_rule")
        assert rule is not None
        assert isinstance(rule, BuiltInRule)

    def test_get_nonexistent_rule_returns_none(self):
        assert get_rule("nonexistent_rule") is None

    def test_get_rule_has_correct_vulnerability(self):
        rule = get_rule("sql_injection_rule")
        assert rule.vulnerability_type == "SQL_INJECTION"


# =============================================================
# GET_ALL_RULES
# =============================================================

class TestGetAllRules:

    def test_get_all_rules_returns_list(self):
        rules = get_all_rules()
        assert isinstance(rules, list)

    def test_get_all_rules_not_empty(self):
        rules = get_all_rules()
        assert len(rules) > 0

    def test_get_all_rules_are_builtin_instances(self):
        for rule in get_all_rules():
            assert isinstance(rule, BuiltInRule)

    def test_get_all_rules_count_matches_registry(self):
        assert len(get_all_rules()) == len(BUILT_IN_RULES)


# =============================================================
# GET_RULES_BY_VULNERABILITY
# =============================================================

class TestGetRulesByVulnerability:

    def test_sql_injection_rules(self):
        rules = get_rules_by_vulnerability("SQL_INJECTION")
        assert len(rules) > 0
        assert all(r.vulnerability_type == "SQL_INJECTION" for r in rules)

    def test_command_injection_rules(self):
        rules = get_rules_by_vulnerability("COMMAND_INJECTION")
        assert len(rules) > 0

    def test_xss_rules(self):
        rules = get_rules_by_vulnerability("XSS")
        assert len(rules) > 0

    def test_unknown_vulnerability_empty(self):
        rules = get_rules_by_vulnerability("NONEXISTENT")
        assert rules == []


# =============================================================
# MATCH_RULE_BY_SINK — CORRECCIÓN #11
# =============================================================

class TestMatchRuleBySink:

    def test_cursor_execute_matches_sql_rules(self):
        """
        Corrección #11: match_rule_by_sink usa get_sink() y
        vulnerability_type en lugar de comparar el label contra
        rule.sinks directamente.
        """
        rules = match_rule_by_sink("cursor.execute")
        assert len(rules) > 0
        assert all(r.vulnerability_type == "SQL_INJECTION" for r in rules)

    def test_os_system_matches_command_rules(self):
        rules = match_rule_by_sink("os.system")
        assert len(rules) > 0
        assert all(
            r.vulnerability_type == "COMMAND_INJECTION" for r in rules
        )

    def test_eval_matches_code_injection_rules(self):
        rules = match_rule_by_sink("eval")
        assert len(rules) > 0
        assert all(r.vulnerability_type == "CODE_INJECTION" for r in rules)

    def test_unknown_sink_returns_empty(self):
        rules = match_rule_by_sink("nonexistent_sink")
        assert rules == []

    def test_sink_with_lineno_handled(self):
        """
        Aunque se pase sink@lineno, el método debe funcionar
        o retornar vacío sin explotar.
        """
        rules = match_rule_by_sink("cursor.execute@10")
        assert isinstance(rules, list)


# =============================================================
# MATCH_RULE_BY_SOURCE
# =============================================================

class TestMatchRuleBySource:

    def test_input_matches_multiple_rules(self):
        rules = match_rule_by_source("input")
        assert len(rules) > 0

    def test_request_args_matches_rules(self):
        rules = match_rule_by_source("request.args")
        assert len(rules) > 0

    def test_unknown_source_returns_empty(self):
        rules = match_rule_by_source("nonexistent_source")
        assert rules == []

    def test_matched_rules_are_builtin_instances(self):
        rules = match_rule_by_source("input")
        for rule in rules:
            assert isinstance(rule, BuiltInRule)


# =============================================================
# TO_DICT — CORRECCIÓN #10 asdict
# =============================================================

class TestToDict:

    def test_to_dict_returns_dict(self):
        rule = get_rule("sql_injection_rule")
        assert isinstance(rule.to_dict(), dict)

    def test_to_dict_is_copy(self):
        rule = get_rule("sql_injection_rule")
        d1 = rule.to_dict()
        d2 = rule.to_dict()
        d1["rule_id"] = "MUTATED"
        assert d2["rule_id"] != "MUTATED"

    def test_to_dict_has_required_fields(self):
        rule = get_rule("command_injection_rule")
        d = rule.to_dict()
        for field in ["rule_id", "name", "vulnerability_type",
                      "cwe_id", "severity", "sinks", "sources"]:
            assert field in d


# =============================================================
# EXPORT
# =============================================================

class TestExportRules:

    def test_export_returns_dict(self):
        assert isinstance(export_rules(), dict)

    def test_export_not_empty(self):
        assert len(export_rules()) > 0

    def test_export_values_are_dicts(self):
        for key, value in export_rules().items():
            assert isinstance(value, dict)

    def test_export_serializable(self):
        import json
        try:
            json.dumps(export_rules())
        except (TypeError, ValueError) as e:
            pytest.fail(f"export_rules() not JSON serializable: {e}")