"""
tests/test_sinks.py

Tests unitarios para core/rules/sinks.py
"""

import pytest
from core.rules.sinks import (
    Sink,
    SINKS,
    is_sink,
    get_sink,
    get_sinks_by_vulnerability,
    get_sinks_by_framework,
    export_sinks,
)


# =============================================================
# REGISTRY STRUCTURE
# =============================================================

class TestRegistryStructure:

    def test_sinks_is_dict(self):
        assert isinstance(SINKS, dict)

    def test_sinks_not_empty(self):
        assert len(SINKS) > 0

    def test_each_value_is_sink_instance(self):
        for key, value in SINKS.items():
            assert isinstance(value, Sink), (
                f"Expected Sink instance for key '{key}'"
            )

    def test_each_sink_has_required_fields(self):
        required = ["name", "vulnerability", "cwe",
                    "severity", "description", "examples", "aliases"]
        for key, sink in SINKS.items():
            for field in required:
                assert hasattr(sink, field), (
                    f"Sink '{key}' missing field '{field}'"
                )

    def test_severity_values_valid(self):
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for key, sink in SINKS.items():
            assert sink.severity in valid, (
                f"Sink '{key}' has invalid severity: {sink.severity}"
            )

    def test_cwe_format(self):
        for key, sink in SINKS.items():
            assert sink.cwe.startswith("CWE-"), (
                f"Sink '{key}' CWE '{sink.cwe}' doesn't start with CWE-"
            )

    def test_aliases_are_lists(self):
        for key, sink in SINKS.items():
            assert isinstance(sink.aliases, list), (
                f"Sink '{key}' aliases is not a list"
            )


# =============================================================
# CORRECCIÓN #4 — cursor.execute NO ES AMBIGUO
# =============================================================

class TestCorrection4CursorExecute:

    def test_cursor_execute_is_sink(self):
        """
        El nombre principal debe ser 'cursor.execute', no 'execute'.
        Antes 'execute' solo matcheaba cualquier método .execute().
        """
        assert is_sink("cursor.execute") is True

    def test_cursor_executemany_is_sink(self):
        assert is_sink("cursor.executemany") is True

    def test_execute_alone_not_registered(self):
        """
        'execute' a secas ya no debe ser el nombre principal
        del sink para evitar falsos positivos.
        """
        sink = get_sink("execute")
        if sink is not None:
            # Si existe como alias, debe mapear a SQL_INJECTION
            assert sink.vulnerability == "SQL_INJECTION"

    def test_cursor_execute_maps_to_sql_injection(self):
        sink = get_sink("cursor.execute")
        assert sink is not None
        assert sink.vulnerability == "SQL_INJECTION"

    def test_cursor_execute_cwe_89(self):
        sink = get_sink("cursor.execute")
        assert sink.cwe == "CWE-89"


# =============================================================
# IS_SINK
# =============================================================

class TestIsSink:

    def test_os_system_is_sink(self):
        assert is_sink("os.system") is True

    def test_subprocess_run_is_sink(self):
        assert is_sink("subprocess.run") is True

    def test_subprocess_popen_is_sink(self):
        assert is_sink("subprocess.Popen") is True

    def test_subprocess_call_is_sink(self):
        assert is_sink("subprocess.call") is True

    def test_eval_is_sink(self):
        assert is_sink("eval") is True

    def test_exec_is_sink(self):
        assert is_sink("exec") is True

    def test_open_is_sink(self):
        assert is_sink("open") is True

    def test_requests_get_is_sink(self):
        assert is_sink("requests.get") is True

    def test_requests_post_is_sink(self):
        assert is_sink("requests.post") is True

    def test_pickle_loads_is_sink(self):
        assert is_sink("pickle.loads") is True

    def test_yaml_load_is_sink(self):
        assert is_sink("yaml.load") is True

    def test_render_template_string_is_sink(self):
        assert is_sink("render_template_string") is True

    def test_unknown_function_not_sink(self):
        assert is_sink("my_safe_function") is False

    def test_empty_string_not_sink(self):
        assert is_sink("") is False

    def test_input_not_sink(self):
        assert is_sink("input") is False


# =============================================================
# GET_SINK
# =============================================================

class TestGetSink:

    def test_get_os_system(self):
        sink = get_sink("os.system")
        assert sink is not None
        assert sink.vulnerability == "COMMAND_INJECTION"

    def test_get_eval(self):
        sink = get_sink("eval")
        assert sink is not None
        assert sink.vulnerability == "CODE_INJECTION"

    def test_get_exec(self):
        sink = get_sink("exec")
        assert sink is not None
        assert sink.vulnerability == "CODE_INJECTION"

    def test_exec_and_cursor_execute_different(self):
        """
        exec → CODE_INJECTION
        cursor.execute → SQL_INJECTION
        Deben ser tipos distintos.
        """
        exec_sink    = get_sink("exec")
        execute_sink = get_sink("cursor.execute")
        assert exec_sink.vulnerability    == "CODE_INJECTION"
        assert execute_sink.vulnerability == "SQL_INJECTION"
        assert exec_sink.vulnerability    != execute_sink.vulnerability

    def test_get_unknown_returns_none(self):
        assert get_sink("nonexistent") is None

    def test_get_via_alias(self):
        sink = get_sink("subprocess.Popen")
        assert sink is not None
        assert sink.vulnerability == "COMMAND_INJECTION"

    def test_get_pickle_loads(self):
        sink = get_sink("pickle.loads")
        assert sink is not None
        assert sink.vulnerability == "INSECURE_DESERIALIZATION"
        assert sink.severity      == "CRITICAL"


# =============================================================
# GET_SINKS_BY_VULNERABILITY
# =============================================================

class TestGetSinksByVulnerability:

    def test_sql_injection_sinks(self):
        sinks = get_sinks_by_vulnerability("SQL_INJECTION")
        assert len(sinks) > 0
        assert all(s.vulnerability == "SQL_INJECTION" for s in sinks)

    def test_command_injection_sinks(self):
        sinks = get_sinks_by_vulnerability("COMMAND_INJECTION")
        assert len(sinks) > 0

    def test_code_injection_sinks(self):
        sinks = get_sinks_by_vulnerability("CODE_INJECTION")
        assert len(sinks) > 0
        names = [s.name for s in sinks]
        assert "eval" in names
        assert "exec" in names

    def test_path_traversal_sinks(self):
        sinks = get_sinks_by_vulnerability("PATH_TRAVERSAL")
        assert len(sinks) > 0
        names = [s.name for s in sinks]
        assert "open" in names

    def test_ssrf_sinks(self):
        sinks = get_sinks_by_vulnerability("SSRF")
        assert len(sinks) > 0

    def test_deserialization_sinks(self):
        sinks = get_sinks_by_vulnerability("INSECURE_DESERIALIZATION")
        assert len(sinks) > 0
        names = [s.name for s in sinks]
        assert "pickle.loads" in names
        assert "yaml.load"    in names

    def test_unknown_vulnerability_empty(self):
        sinks = get_sinks_by_vulnerability("NONEXISTENT")
        assert sinks == []


# =============================================================
# GET_SINKS_BY_FRAMEWORK
# =============================================================

class TestGetSinksByFramework:

    def test_flask_sinks(self):
        sinks = get_sinks_by_framework("flask")
        assert len(sinks) > 0
        assert all(s.framework == "flask" for s in sinks)

    def test_sqlalchemy_sinks(self):
        sinks = get_sinks_by_framework("sqlalchemy")
        assert len(sinks) > 0

    def test_unknown_framework_empty(self):
        sinks = get_sinks_by_framework("rails")
        assert sinks == []


# =============================================================
# TO_DICT — CORRECCIÓN #5 asdict
# =============================================================

class TestToDict:

    def test_to_dict_returns_dict(self):
        sink = get_sink("eval")
        assert isinstance(sink.to_dict(), dict)

    def test_to_dict_is_copy(self):
        sink = get_sink("eval")
        d1 = sink.to_dict()
        d2 = sink.to_dict()
        d1["name"] = "MUTATED"
        assert d2["name"] != "MUTATED"

    def test_to_dict_has_required_fields(self):
        sink = get_sink("os.system")
        d = sink.to_dict()
        for field in ["name", "vulnerability", "cwe",
                      "severity", "description", "examples", "aliases"]:
            assert field in d


# =============================================================
# EXPORT
# =============================================================

class TestExportSinks:

    def test_export_returns_dict(self):
        assert isinstance(export_sinks(), dict)

    def test_export_not_empty(self):
        assert len(export_sinks()) > 0

    def test_export_values_are_dicts(self):
        for key, value in export_sinks().items():
            assert isinstance(value, dict)

    def test_export_serializable(self):
        import json
        try:
            json.dumps(export_sinks())
        except (TypeError, ValueError) as e:
            pytest.fail(f"export_sinks() not JSON serializable: {e}")