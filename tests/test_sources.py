"""
tests/test_sources.py

Tests unitarios para core/rules/sources.py
"""

import pytest
from core.rules.sources import (
    Source,
    SOURCES,
    is_source,
    get_source,
    get_sources_by_category,
    get_sources_by_framework,
    export_sources,
)


# =============================================================
# REGISTRY STRUCTURE
# =============================================================

class TestRegistryStructure:

    def test_sources_is_dict(self):
        assert isinstance(SOURCES, dict)

    def test_sources_not_empty(self):
        assert len(SOURCES) > 0

    def test_each_value_is_source_instance(self):
        for key, value in SOURCES.items():
            assert isinstance(value, Source), (
                f"Expected Source instance for key '{key}'"
            )

    def test_each_source_has_required_fields(self):
        required = ["name", "category", "risk", "description",
                    "examples", "aliases"]
        for key, source in SOURCES.items():
            for field in required:
                assert hasattr(source, field), (
                    f"Source '{key}' missing field '{field}'"
                )

    def test_risk_values_valid(self):
        valid_risks = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for key, source in SOURCES.items():
            assert source.risk in valid_risks, (
                f"Source '{key}' has invalid risk: {source.risk}"
            )

    def test_aliases_are_lists(self):
        for key, source in SOURCES.items():
            assert isinstance(source.aliases, list), (
                f"Source '{key}' aliases is not a list"
            )

    def test_examples_are_lists(self):
        for key, source in SOURCES.items():
            assert isinstance(source.examples, list), (
                f"Source '{key}' examples is not a list"
            )


# =============================================================
# CORRECCIÓN #1 — open NO ES SOURCE
# =============================================================

class TestCorrection1OpenNotASource:

    def test_open_not_in_sources(self):
        """
        'open' es un SINK de PATH_TRAVERSAL, no una source.
        Antes aparecía como 'file_read' source.
        """
        assert "file_read" not in SOURCES

    def test_open_not_detectable_as_source(self):
        assert is_source("open") is False


# =============================================================
# CORRECCIÓN #2 — pickle.loads y yaml.load NO SON SOURCES
# =============================================================

class TestCorrection2DeserializationNotSources:

    def test_pickle_loads_not_source(self):
        """
        pickle.loads es un SINK de INSECURE_DESERIALIZATION.
        """
        assert is_source("pickle.loads") is False

    def test_yaml_load_not_source(self):
        """
        yaml.load es un SINK de INSECURE_DESERIALIZATION.
        """
        assert is_source("yaml.load") is False

    def test_no_deserialization_category_in_sources(self):
        categories = {s.category for s in SOURCES.values()}
        assert "DESERIALIZATION" not in categories


# =============================================================
# IS_SOURCE
# =============================================================

class TestIsSource:

    def test_input_is_source(self):
        assert is_source("input") is True

    def test_sys_argv_is_source(self):
        assert is_source("sys.argv") is True

    def test_os_environ_is_source(self):
        assert is_source("os.environ") is True

    def test_os_getenv_is_source_via_alias(self):
        assert is_source("os.getenv") is True

    def test_request_args_is_source(self):
        assert is_source("request.args") is True

    def test_request_args_get_is_source(self):
        assert is_source("request.args.get") is True

    def test_request_form_is_source(self):
        assert is_source("request.form") is True

    def test_request_form_get_is_source(self):
        assert is_source("request.form.get") is True

    def test_request_json_is_source(self):
        assert is_source("request.json") is True

    def test_request_get_json_is_source(self):
        assert is_source("request.get_json") is True

    def test_request_get_is_source(self):
        assert is_source("request.GET") is True

    def test_request_post_is_source(self):
        assert is_source("request.POST") is True

    def test_request_body_is_source(self):
        assert is_source("request.body") is True

    def test_socket_recv_is_source(self):
        assert is_source("socket.recv") is True

    def test_recv_alias_is_source(self):
        assert is_source("recv") is True

    def test_unknown_function_not_source(self):
        assert is_source("my_custom_function") is False

    def test_empty_string_not_source(self):
        assert is_source("") is False

    def test_cursor_execute_not_source(self):
        assert is_source("cursor.execute") is False

    def test_os_system_not_source(self):
        assert is_source("os.system") is False


# =============================================================
# GET_SOURCE
# =============================================================

class TestGetSource:

    def test_get_input_source(self):
        source = get_source("input")
        assert source is not None
        assert source.name == "input"

    def test_get_source_by_alias(self):
        source = get_source("os.getenv")
        assert source is not None
        assert source.category == "ENVIRONMENT"

    def test_get_unknown_returns_none(self):
        source = get_source("nonexistent_function")
        assert source is None

    def test_get_request_args_get(self):
        source = get_source("request.args.get")
        assert source is not None
        assert source.risk == "HIGH"

    def test_get_source_has_framework_when_flask(self):
        source = get_source("request.args")
        assert source is not None
        assert source.framework == "flask"

    def test_get_django_source_has_django_framework(self):
        source = get_source("request.GET")
        assert source is not None
        assert source.framework == "django"


# =============================================================
# GET_SOURCES_BY_CATEGORY
# =============================================================

class TestGetSourcesByCategory:

    def test_user_input_category(self):
        sources = get_sources_by_category("USER_INPUT")
        assert len(sources) > 0
        assert all(s.category == "USER_INPUT" for s in sources)

    def test_http_get_category(self):
        sources = get_sources_by_category("HTTP_GET")
        assert len(sources) > 0

    def test_http_post_category(self):
        sources = get_sources_by_category("HTTP_POST")
        assert len(sources) > 0

    def test_environment_category(self):
        sources = get_sources_by_category("ENVIRONMENT")
        assert len(sources) > 0

    def test_network_category(self):
        sources = get_sources_by_category("NETWORK")
        assert len(sources) > 0

    def test_unknown_category_empty(self):
        sources = get_sources_by_category("NONEXISTENT")
        assert sources == []


# =============================================================
# GET_SOURCES_BY_FRAMEWORK
# =============================================================

class TestGetSourcesByFramework:

    def test_flask_sources(self):
        sources = get_sources_by_framework("flask")
        assert len(sources) > 0
        assert all(s.framework == "flask" for s in sources)

    def test_django_sources(self):
        sources = get_sources_by_framework("django")
        assert len(sources) > 0
        assert all(s.framework == "django" for s in sources)

    def test_fastapi_sources(self):
        sources = get_sources_by_framework("fastapi")
        assert len(sources) > 0

    def test_unknown_framework_empty(self):
        sources = get_sources_by_framework("rails")
        assert sources == []


# =============================================================
# TO_DICT — CORRECCIÓN #3 asdict
# =============================================================

class TestToDict:

    def test_to_dict_returns_dict(self):
        source = get_source("input")
        assert isinstance(source.to_dict(), dict)

    def test_to_dict_is_copy(self):
        """to_dict() no debe retornar referencia mutable."""
        source = get_source("input")
        d1 = source.to_dict()
        d2 = source.to_dict()
        d1["name"] = "MUTATED"
        assert d2["name"] != "MUTATED"

    def test_to_dict_has_all_fields(self):
        source = get_source("input")
        d = source.to_dict()
        for field in ["name", "category", "risk", "description",
                      "examples", "aliases"]:
            assert field in d


# =============================================================
# EXPORT
# =============================================================

class TestExportSources:

    def test_export_returns_dict(self):
        result = export_sources()
        assert isinstance(result, dict)

    def test_export_not_empty(self):
        result = export_sources()
        assert len(result) > 0

    def test_export_values_are_dicts(self):
        result = export_sources()
        for key, value in result.items():
            assert isinstance(value, dict), (
                f"Expected dict for key '{key}'"
            )

    def test_export_serializable(self):
        import json
        result = export_sources()
        try:
            json.dumps(result)
        except (TypeError, ValueError) as e:
            pytest.fail(f"export_sources() not JSON serializable: {e}")