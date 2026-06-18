"""
tests/test_sanitizers.py

Tests unitarios para core/rules/sanitizers.py
"""

import pytest
from core.rules.sanitizers import (
    Sanitizer,
    SANITIZERS,
    is_sanitizer,
    get_sanitizer,
    get_sanitizers_for_vulnerability,
    get_sanitizers_by_category,
    get_sanitizers_by_framework,
    sanitizer_protects_against,
    export_sanitizers,
)


# =============================================================
# REGISTRY STRUCTURE
# =============================================================

class TestRegistryStructure:

    def test_sanitizers_is_dict(self):
        assert isinstance(SANITIZERS, dict)

    def test_sanitizers_not_empty(self):
        assert len(SANITIZERS) > 0

    def test_each_value_is_sanitizer_instance(self):
        for key, value in SANITIZERS.items():
            assert isinstance(value, Sanitizer), (
                f"Expected Sanitizer for key '{key}'"
            )

    def test_each_sanitizer_has_required_fields(self):
        required = ["name", "category", "protects_against",
                    "effectiveness", "description", "examples", "aliases"]
        for key, s in SANITIZERS.items():
            for field in required:
                assert hasattr(s, field), (
                    f"Sanitizer '{key}' missing field '{field}'"
                )

    def test_effectiveness_values_valid(self):
        valid = {"LOW", "MEDIUM", "HIGH"}
        for key, s in SANITIZERS.items():
            assert s.effectiveness in valid, (
                f"Sanitizer '{key}' has invalid effectiveness: {s.effectiveness}"
            )

    def test_protects_against_are_lists(self):
        for key, s in SANITIZERS.items():
            assert isinstance(s.protects_against, list), (
                f"Sanitizer '{key}' protects_against is not a list"
            )

    def test_aliases_are_lists(self):
        for key, s in SANITIZERS.items():
            assert isinstance(s.aliases, list)


# =============================================================
# CORRECCIÓN #6 — execute NO ES SANITIZER
# =============================================================

class TestCorrection6ExecuteNotSanitizer:

    def test_execute_not_sanitizer(self):
        """
        cursor.execute es un SINK, no un sanitizer.
        Antes 'parameterized_queries' tenía name='execute'.
        """
        assert is_sanitizer("execute") is False

    def test_cursor_execute_not_sanitizer(self):
        assert is_sanitizer("cursor.execute") is False

    def test_no_sanitizer_named_execute(self):
        for s in SANITIZERS.values():
            assert s.name != "execute", (
                "No sanitizer should be named 'execute'"
            )


# =============================================================
# CORRECCIÓN #7 — ALIAS escape NO DUPLICADO
# =============================================================

class TestCorrection7EscapeAliasNotDuplicated:

    def test_escape_alias_belongs_to_one_sanitizer(self):
        """
        'escape' era alias de html_escape Y markupsafe_escape.
        Ahora debe pertenecer solo a uno (markupsafe_escape).
        """
        sanitizers_with_escape = [
            key for key, s in SANITIZERS.items()
            if "escape" in s.aliases
        ]
        assert len(sanitizers_with_escape) == 1, (
            f"'escape' alias should belong to exactly one sanitizer, "
            f"found in: {sanitizers_with_escape}"
        )

    def test_escape_belongs_to_markupsafe(self):
        sanitizer = get_sanitizer("escape")
        assert sanitizer is not None
        assert "markupsafe" in sanitizer.name.lower()

    def test_html_escape_accessible_by_full_name(self):
        sanitizer = get_sanitizer("html.escape")
        assert sanitizer is not None
        assert sanitizer.name == "html.escape"

    def test_html_escape_not_accessible_as_escape(self):
        """
        html.escape no debe retornarse cuando se busca 'escape' solo.
        """
        sanitizer = get_sanitizer("escape")
        assert sanitizer.name != "html.escape"


# =============================================================
# IS_SANITIZER
# =============================================================

class TestIsSanitizer:

    def test_html_escape_is_sanitizer(self):
        assert is_sanitizer("html.escape") is True

    def test_markupsafe_escape_is_sanitizer(self):
        assert is_sanitizer("markupsafe.escape") is True

    def test_escape_alias_is_sanitizer(self):
        assert is_sanitizer("escape") is True

    def test_bleach_clean_is_sanitizer(self):
        assert is_sanitizer("bleach.clean") is True

    def test_shlex_quote_is_sanitizer(self):
        assert is_sanitizer("shlex.quote") is True

    def test_secure_filename_is_sanitizer(self):
        assert is_sanitizer("secure_filename") is True

    def test_os_path_abspath_is_sanitizer(self):
        assert is_sanitizer("os.path.abspath") is True

    def test_os_path_normpath_is_sanitizer(self):
        assert is_sanitizer("os.path.normpath") is True

    def test_validators_url_is_sanitizer(self):
        assert is_sanitizer("validators.url") is True

    def test_int_is_sanitizer(self):
        assert is_sanitizer("int") is True

    def test_float_is_sanitizer(self):
        assert is_sanitizer("float") is True

    def test_re_match_is_sanitizer(self):
        assert is_sanitizer("re.match") is True

    def test_re_fullmatch_is_sanitizer(self):
        assert is_sanitizer("re.fullmatch") is True

    def test_yaml_safe_load_is_sanitizer(self):
        assert is_sanitizer("yaml.safe_load") is True

    def test_bindparams_is_sanitizer(self):
        assert is_sanitizer("bindparams") is True

    def test_unknown_function_not_sanitizer(self):
        assert is_sanitizer("my_custom_function") is False

    def test_os_system_not_sanitizer(self):
        assert is_sanitizer("os.system") is False

    def test_eval_not_sanitizer(self):
        assert is_sanitizer("eval") is False


# =============================================================
# GET_SANITIZER
# =============================================================

class TestGetSanitizer:

    def test_get_html_escape(self):
        s = get_sanitizer("html.escape")
        assert s is not None
        assert s.name == "html.escape"

    def test_get_by_alias(self):
        s = get_sanitizer("shlex.quote")
        assert s is not None

    def test_get_unknown_returns_none(self):
        assert get_sanitizer("nonexistent") is None

    def test_get_shlex_quote_category(self):
        s = get_sanitizer("shlex.quote")
        assert s.category == "COMMAND_ESCAPING"

    def test_get_int_cast(self):
        s = get_sanitizer("int")
        assert s is not None
        assert "SQL_INJECTION" in s.protects_against


# =============================================================
# GET_SANITIZERS_FOR_VULNERABILITY
# =============================================================

class TestGetSanitizersForVulnerability:

    def test_xss_sanitizers(self):
        sanitizers = get_sanitizers_for_vulnerability("XSS")
        assert len(sanitizers) > 0
        names = [s.name for s in sanitizers]
        assert any("escape" in n for n in names)

    def test_command_injection_sanitizers(self):
        sanitizers = get_sanitizers_for_vulnerability("COMMAND_INJECTION")
        assert len(sanitizers) > 0
        names = [s.name for s in sanitizers]
        assert "shlex.quote" in names

    def test_sql_injection_sanitizers(self):
        sanitizers = get_sanitizers_for_vulnerability("SQL_INJECTION")
        assert len(sanitizers) > 0

    def test_path_traversal_sanitizers(self):
        sanitizers = get_sanitizers_for_vulnerability("PATH_TRAVERSAL")
        assert len(sanitizers) > 0
        names = [s.name for s in sanitizers]
        assert "secure_filename" in names

    def test_deserialization_sanitizers(self):
        sanitizers = get_sanitizers_for_vulnerability(
            "INSECURE_DESERIALIZATION"
        )
        assert len(sanitizers) > 0
        names = [s.name for s in sanitizers]
        assert "yaml.safe_load" in names

    def test_unknown_vulnerability_empty(self):
        sanitizers = get_sanitizers_for_vulnerability("NONEXISTENT")
        assert sanitizers == []


# =============================================================
# GET_SANITIZERS_BY_CATEGORY
# =============================================================

class TestGetSanitizersByCategory:

    def test_output_encoding_category(self):
        sanitizers = get_sanitizers_by_category("OUTPUT_ENCODING")
        assert len(sanitizers) > 0

    def test_command_escaping_category(self):
        sanitizers = get_sanitizers_by_category("COMMAND_ESCAPING")
        assert len(sanitizers) > 0

    def test_path_sanitization_category(self):
        sanitizers = get_sanitizers_by_category("PATH_SANITIZATION")
        assert len(sanitizers) > 0

    def test_type_casting_category(self):
        sanitizers = get_sanitizers_by_category("TYPE_CASTING")
        assert len(sanitizers) > 0

    def test_sql_parameterization_category(self):
        sanitizers = get_sanitizers_by_category("SQL_PARAMETERIZATION")
        assert len(sanitizers) > 0

    def test_unknown_category_empty(self):
        sanitizers = get_sanitizers_by_category("NONEXISTENT")
        assert sanitizers == []


# =============================================================
# GET_SANITIZERS_BY_FRAMEWORK
# =============================================================

class TestGetSanitizersByFramework:

    def test_flask_sanitizers(self):
        sanitizers = get_sanitizers_by_framework("flask")
        assert len(sanitizers) > 0
        names = [s.name for s in sanitizers]
        assert "secure_filename" in names

    def test_sqlalchemy_sanitizers(self):
        sanitizers = get_sanitizers_by_framework("sqlalchemy")
        assert len(sanitizers) > 0

    def test_unknown_framework_empty(self):
        sanitizers = get_sanitizers_by_framework("rails")
        assert sanitizers == []


# =============================================================
# SANITIZER_PROTECTS_AGAINST
# =============================================================

class TestSanitizerProtectsAgainst:

    def test_shlex_quote_protects_command_injection(self):
        assert sanitizer_protects_against(
            "shlex.quote", "COMMAND_INJECTION"
        ) is True

    def test_html_escape_protects_xss(self):
        assert sanitizer_protects_against("html.escape", "XSS") is True

    def test_html_escape_not_protects_sqli(self):
        assert sanitizer_protects_against(
            "html.escape", "SQL_INJECTION"
        ) is False

    def test_int_protects_sqli(self):
        assert sanitizer_protects_against("int", "SQL_INJECTION") is True

    def test_unknown_sanitizer_returns_false(self):
        assert sanitizer_protects_against(
            "nonexistent", "SQL_INJECTION"
        ) is False

    def test_yaml_safe_load_protects_deserialization(self):
        assert sanitizer_protects_against(
            "yaml.safe_load", "INSECURE_DESERIALIZATION"
        ) is True


# =============================================================
# TO_DICT — CORRECCIÓN #8 asdict
# =============================================================

class TestToDict:

    def test_to_dict_returns_dict(self):
        s = get_sanitizer("html.escape")
        assert isinstance(s.to_dict(), dict)

    def test_to_dict_is_copy(self):
        s = get_sanitizer("html.escape")
        d1 = s.to_dict()
        d2 = s.to_dict()
        d1["name"] = "MUTATED"
        assert d2["name"] != "MUTATED"

    def test_to_dict_has_required_fields(self):
        s = get_sanitizer("shlex.quote")
        d = s.to_dict()
        for field in ["name", "category", "protects_against",
                      "effectiveness", "description", "examples", "aliases"]:
            assert field in d


# =============================================================
# EXPORT
# =============================================================

class TestExportSanitizers:

    def test_export_returns_dict(self):
        assert isinstance(export_sanitizers(), dict)

    def test_export_not_empty(self):
        assert len(export_sanitizers()) > 0

    def test_export_values_are_dicts(self):
        for key, value in export_sanitizers().items():
            assert isinstance(value, dict)

    def test_export_serializable(self):
        import json
        try:
            json.dumps(export_sanitizers())
        except (TypeError, ValueError) as e:
            pytest.fail(f"export_sanitizers() not JSON serializable: {e}")