"""
tests/test_dfg_builder.py

Tests unitarios para DFGBuilder.
Cubre las 5 correcciones aplicadas.
"""

import pytest
from core.parsers.dfg_builder import DFGBuilder


# =============================================================
# FIXTURES
# =============================================================

@pytest.fixture
def builder():
    return DFGBuilder()


# Corrección #1: source → variable simple
CODE_ALIAS = """
raw = input()
user = raw
import os
os.system(user)
"""

# Corrección #2: call embebido en BinOp
CODE_EMBEDDED = """
import os
query = "SELECT * FROM users WHERE id=" + input()
os.system(query)
"""

# Caso básico original
CODE_BASIC = """
import os
user = input()
query = "SELECT * FROM users WHERE id=" + user
os.system(query)
"""

# Corrección #3: double-dispatch
CODE_SINK_IN_ASSIGN = """
import os
result = os.system("ls")
"""

# Corrección #5: reset entre llamadas
CODE_SIMPLE_A = "user = input()"
CODE_SIMPLE_B = "import os\nos.system('ls')"


# =============================================================
# STRUCTURE
# =============================================================

class TestDFGStructure:

    def test_returns_dict(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        assert isinstance(result, dict)

    def test_has_required_keys(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        assert "nodes"             in result
        assert "edges"             in result
        assert "tainted_variables" in result

    def test_nodes_are_list(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        assert isinstance(result["nodes"], list)

    def test_edges_are_list(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        assert isinstance(result["edges"], list)

    def test_tainted_variables_are_list(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        assert isinstance(result["tainted_variables"], list)

    def test_node_has_id_type_label(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        for node in result["nodes"]:
            assert "id"    in node
            assert "type"  in node
            assert "label" in node

    def test_edge_has_source_target_type(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        for edge in result["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "type"   in edge


# =============================================================
# SOURCE DETECTION
# =============================================================

class TestSourceDetection:

    def test_input_detected_as_source(self, builder):
        result = builder.build_from_code("user = input()")
        types = [n["type"] for n in result["nodes"]]
        assert "source" in types

    def test_request_args_get_detected_as_source(self, builder):
        code = "from flask import request\nuser = request.args.get('id')"
        result = builder.build_from_code(code)
        types = [n["type"] for n in result["nodes"]]
        assert "source" in types

    def test_tainted_variable_registered(self, builder):
        result = builder.build_from_code("user = input()")
        assert "user" in result["tainted_variables"]

    def test_source_edge_is_taint(self, builder):
        result = builder.build_from_code("user = input()")
        taint_edges = [e for e in result["edges"] if e["type"] == "taint"]
        assert len(taint_edges) > 0


# =============================================================
# CORRECCIÓN #1 — PROPAGACIÓN NAME → NAME
# =============================================================

class TestCorrection1AliasPropagation:

    def test_alias_variable_detected_as_tainted(self, builder):
        """
        b = a donde a está taintada → b debe quedar taintada.
        Antes se descartaba ast.Name y la propagación se rompía.
        """
        result = builder.build_from_code(CODE_ALIAS)
        assert "user" in result["tainted_variables"]

    def test_alias_propagation_edge_exists(self, builder):
        result = builder.build_from_code(CODE_ALIAS)
        propagation_edges = [
            e for e in result["edges"]
            if e["type"] == "propagation"
        ]
        assert len(propagation_edges) > 0

    def test_alias_chain_reaches_sink(self, builder):
        result = builder.build_from_code(CODE_ALIAS)
        sink_nodes = [n for n in result["nodes"] if n["type"] == "sink"]
        assert len(sink_nodes) > 0


# =============================================================
# CORRECCIÓN #2 — CALLS EMBEBIDOS EN BINOP
# =============================================================

class TestCorrection2EmbeddedCallsInBinOp:

    def test_embedded_source_call_in_binop_detected(self, builder):
        """
        query = "SQL" + input()  →  input() debe detectarse como source.
        Antes _extract_variables() ignoraba ast.Call dentro de BinOp.
        """
        result = builder.build_from_code(CODE_EMBEDDED)
        sources = [n for n in result["nodes"] if n["type"] == "source"]
        assert len(sources) > 0

    def test_embedded_call_taints_target(self, builder):
        result = builder.build_from_code(CODE_EMBEDDED)
        assert "query" in result["tainted_variables"]

    def test_embedded_call_reaches_sink(self, builder):
        result = builder.build_from_code(CODE_EMBEDDED)
        sink_nodes = [n for n in result["nodes"] if n["type"] == "sink"]
        assert len(sink_nodes) > 0


# =============================================================
# CORRECCIÓN #3 — NO DOUBLE-DISPATCH ENTRE ASSIGN Y CALL
# =============================================================

class TestCorrection3NoDoubleDispatch:

    def test_sink_node_not_duplicated(self, builder):
        """
        result = os.system("ls") no debe crear dos nodos sink.
        Antes visit_Assign y visit_Call ambos procesaban el Call.
        """
        result = builder.build_from_code(CODE_SINK_IN_ASSIGN)
        sink_nodes = [n for n in result["nodes"] if n["type"] == "sink"]
        sink_ids   = [n["id"] for n in sink_nodes]
        assert len(sink_ids) == len(set(sink_ids)), (
            f"Duplicate sink nodes found: {sink_ids}"
        )


# =============================================================
# CORRECCIÓN #4 — SINK ID CON LABEL SEPARADO
# =============================================================

class TestCorrection4SinkLabelSeparated:

    def test_sink_node_has_label(self, builder):
        """
        El nodo sink debe tener 'label' con el nombre limpio
        (ej: 'os.system') separado del ID que incluye @lineno.
        """
        result = builder.build_from_code(CODE_BASIC)
        sink_nodes = [n for n in result["nodes"] if n["type"] == "sink"]
        assert len(sink_nodes) > 0
        for sink in sink_nodes:
            assert "label" in sink
            assert "@" not in sink["label"], (
                f"Label should not contain @lineno: {sink['label']}"
            )

    def test_sink_id_contains_lineno(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        sink_nodes = [n for n in result["nodes"] if n["type"] == "sink"]
        for sink in sink_nodes:
            assert "@" in sink["id"], (
                f"ID should contain @lineno: {sink['id']}"
            )

    def test_sink_label_is_clean_name(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        sink_nodes = [n for n in result["nodes"] if n["type"] == "sink"]
        labels = [s["label"] for s in sink_nodes]
        assert any("os.system" in label for label in labels)


# =============================================================
# CORRECCIÓN #5 — RESET ENTRE LLAMADAS
# =============================================================

class TestCorrection5ResetBetweenCalls:

    def test_second_call_does_not_accumulate_nodes(self, builder):
        """
        Reutilizar la instancia no debe acumular nodos de
        análisis anteriores.
        """
        result_a = builder.build_from_code(CODE_SIMPLE_A)
        result_b = builder.build_from_code(CODE_SIMPLE_B)

        node_ids_b = [n["id"] for n in result_b["nodes"]]

        # Los nodos de A (source 'input', variable 'user') no
        # deben aparecer en el resultado de B.
        assert "user" not in node_ids_b

    def test_second_call_tainted_variables_reset(self, builder):
        builder.build_from_code(CODE_SIMPLE_A)
        result = builder.build_from_code(CODE_SIMPLE_B)
        assert "user" not in result["tainted_variables"]

    def test_multiple_calls_independent_results(self, builder):
        r1 = builder.build_from_code(CODE_SIMPLE_A)
        r2 = builder.build_from_code(CODE_SIMPLE_A)
        assert r1["nodes"] == r2["nodes"]
        assert r1["edges"] == r2["edges"]


# =============================================================
# SINK DETECTION
# =============================================================

class TestSinkDetection:

    def test_os_system_detected_as_sink(self, builder):
        result = builder.build_from_code(
            "import os\nos.system('ls')"
        )
        sink_labels = [
            n["label"] for n in result["nodes"]
            if n["type"] == "sink"
        ]
        assert any("os.system" in l for l in sink_labels)

    def test_eval_detected_as_sink(self, builder):
        result = builder.build_from_code("eval(user_input)")
        sink_labels = [
            n["label"] for n in result["nodes"]
            if n["type"] == "sink"
        ]
        assert any("eval" in l for l in sink_labels)

    def test_cursor_execute_detected_as_sink(self, builder):
        result = builder.build_from_code("cursor.execute(query)")
        sink_labels = [
            n["label"] for n in result["nodes"]
            if n["type"] == "sink"
        ]
        assert any("cursor.execute" in l for l in sink_labels)

    def test_sink_flow_edge_exists(self, builder):
        result = builder.build_from_code(CODE_BASIC)
        sink_edges = [
            e for e in result["edges"]
            if e["type"] == "sink_flow"
        ]
        assert len(sink_edges) > 0


# =============================================================
# FULL PIPELINE
# =============================================================

class TestFullFlow:

    def test_basic_taint_flow_complete(self, builder):
        """
        input() → user → query (BinOp) → os.system
        El grafo debe tener source, variables, sink y edges.
        """
        result = builder.build_from_code(CODE_BASIC)

        assert len(result["nodes"]) > 0
        assert len(result["edges"]) > 0
        assert len(result["tainted_variables"]) > 0

        node_types = {n["type"] for n in result["nodes"]}
        assert "source" in node_types
        assert "sink"   in node_types

    def test_no_false_source_without_input(self, builder):
        result = builder.build_from_code("x = 1 + 2")
        sources = [n for n in result["nodes"] if n["type"] == "source"]
        assert len(sources) == 0

    def test_no_tainted_variables_without_source(self, builder):
        result = builder.build_from_code("x = 1 + 2")
        assert result["tainted_variables"] == []