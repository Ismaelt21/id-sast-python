"""
tests/test_graph_model.py

Tests unitarios para core/graph/graph_model.py
Cubre las 4 correcciones aplicadas.
"""

import pytest
from core.graph.graph_model import GraphModel, GraphNode, GraphEdge


# =============================================================
# FIXTURES
# =============================================================

@pytest.fixture
def empty_graph():
    return GraphModel(graph_type="dfg")


@pytest.fixture
def simple_graph():
    g = GraphModel(graph_type="dfg")
    g.add_node("N1", "source",   "USER_INPUT")
    g.add_node("N2", "variable", "query")
    g.add_node("N3", "sink",     "cursor.execute")
    g.add_edge("N1", "N2", "taint")
    g.add_edge("N2", "N3", "sink_flow")
    return g


@pytest.fixture
def disconnected_graph():
    g = GraphModel(graph_type="dfg")
    g.add_node("A", "source", "input")
    g.add_node("B", "sink",   "eval")
    # Sin edges — no hay camino
    return g


# =============================================================
# INIT
# =============================================================

class TestInit:

    def test_default_graph_type(self):
        g = GraphModel()
        assert g.get_graph_type() == "generic"

    def test_custom_graph_type(self):
        g = GraphModel(graph_type="cfg")
        assert g.get_graph_type() == "cfg"

    def test_empty_graph_zero_nodes(self, empty_graph):
        assert empty_graph.node_count() == 0

    def test_empty_graph_zero_edges(self, empty_graph):
        assert empty_graph.edge_count() == 0


# =============================================================
# NODE MANAGEMENT
# =============================================================

class TestNodeManagement:

    def test_add_node_increases_count(self, empty_graph):
        empty_graph.add_node("N1", "source", "input")
        assert empty_graph.node_count() == 1

    def test_add_multiple_nodes(self, empty_graph):
        empty_graph.add_node("N1", "source",   "input")
        empty_graph.add_node("N2", "variable", "user")
        empty_graph.add_node("N3", "sink",     "eval")
        assert empty_graph.node_count() == 3

    def test_get_node_returns_dict(self, simple_graph):
        node = simple_graph.get_node("N1")
        assert isinstance(node, dict)

    def test_get_node_has_id(self, simple_graph):
        node = simple_graph.get_node("N1")
        assert node["id"] == "N1"

    def test_get_node_has_type(self, simple_graph):
        node = simple_graph.get_node("N1")
        assert node["type"] == "source"

    def test_get_node_has_label(self, simple_graph):
        node = simple_graph.get_node("N1")
        assert node["label"] == "USER_INPUT"

    def test_get_nonexistent_node_returns_none(self, simple_graph):
        assert simple_graph.get_node("NONEXISTENT") is None

    def test_get_all_nodes_returns_list(self, simple_graph):
        nodes = simple_graph.get_all_nodes()
        assert isinstance(nodes, list)
        assert len(nodes) == 3

    def test_add_node_with_metadata(self, empty_graph):
        empty_graph.add_node(
            "N1", "source", "input",
            metadata={"line": 5}
        )
        node = empty_graph.get_node("N1")
        assert node["metadata"]["line"] == 5

    def test_add_node_default_metadata_empty(self, empty_graph):
        empty_graph.add_node("N1", "source", "input")
        node = empty_graph.get_node("N1")
        assert node["metadata"] == {}


# =============================================================
# EDGE MANAGEMENT — CORRECCIONES #1 Y #2
# =============================================================

class TestEdgeManagement:

    def test_add_edge_increases_count(self, empty_graph):
        empty_graph.add_node("A", "source", "input")
        empty_graph.add_node("B", "sink",   "eval")
        empty_graph.add_edge("A", "B", "taint")
        assert empty_graph.edge_count() == 1

    def test_get_all_edges_returns_list(self, simple_graph):
        edges = simple_graph.get_all_edges()
        assert isinstance(edges, list)
        assert len(edges) == 2

    def test_edge_has_source_target_type(self, simple_graph):
        """
        Corrección #1 y #2: get_all_edges() lee 'edge_type'
        desde los atributos del grafo, no 'type', y no
        contamina con source/target redundantes.
        """
        for edge in simple_graph.get_all_edges():
            assert "source"   in edge
            assert "target"   in edge
            assert "type"     in edge
            assert "metadata" in edge

    def test_edge_type_not_none(self, simple_graph):
        """
        Corrección #2: antes 'type' era siempre None porque
        se guardaba como 'type' en el dict pero se leía 'type'
        del atributo incorrecto. Ahora usa 'edge_type'.
        """
        for edge in simple_graph.get_all_edges():
            assert edge["type"] is not None, (
                f"Edge type is None: {edge}"
            )

    def test_edge_type_values_correct(self, simple_graph):
        edge_types = {e["type"] for e in simple_graph.get_all_edges()}
        assert "taint"     in edge_types
        assert "sink_flow" in edge_types

    def test_edge_source_and_target_correct(self, simple_graph):
        edges = {
            (e["source"], e["target"]): e["type"]
            for e in simple_graph.get_all_edges()
        }
        assert ("N1", "N2") in edges
        assert ("N2", "N3") in edges

    def test_add_edge_with_metadata(self, empty_graph):
        empty_graph.add_node("A", "source", "input")
        empty_graph.add_node("B", "sink",   "eval")
        empty_graph.add_edge("A", "B", "taint", metadata={"weight": 1})
        edge = empty_graph.get_all_edges()[0]
        assert edge["metadata"]["weight"] == 1

    def test_source_target_not_duplicated_in_attributes(self, simple_graph):
        """
        Corrección #1: add_edge no debe guardar 'source' y
        'target' como atributos del edge (redundante con los
        nodos del grafo de NetworkX).
        Los atributos del edge deben ser solo edge_type y metadata.
        """
        import networkx as nx
        for u, v, attrs in simple_graph.graph.edges(data=True):
            # Los atributos no deben tener 'source' ni 'target'
            # como claves duplicadas de los nodos u, v.
            assert "source" not in attrs or attrs.get("source") is None
            assert "target" not in attrs or attrs.get("target") is None


# =============================================================
# PATHS — CORRECCIÓN #3
# =============================================================

class TestPaths:

    def test_get_all_paths_returns_list(self, simple_graph):
        paths = simple_graph.get_all_paths("N1", "N3")
        assert isinstance(paths, list)

    def test_path_exists(self, simple_graph):
        paths = simple_graph.get_all_paths("N1", "N3")
        assert len(paths) > 0

    def test_path_contains_nodes(self, simple_graph):
        paths = simple_graph.get_all_paths("N1", "N3")
        assert "N1" in paths[0]
        assert "N3" in paths[0]

    def test_no_path_returns_empty_list(self, disconnected_graph):
        paths = disconnected_graph.get_all_paths("A", "B")
        assert paths == []

    def test_nonexistent_source_returns_empty(self, simple_graph):
        """
        Corrección #3: NodeNotFound ahora se captura y
        retorna [] en lugar de propagar la excepción.
        """
        paths = simple_graph.get_all_paths("NONEXISTENT", "N3")
        assert paths == []

    def test_nonexistent_target_returns_empty(self, simple_graph):
        """Corrección #3: mismo caso para el target."""
        paths = simple_graph.get_all_paths("N1", "NONEXISTENT")
        assert paths == []

    def test_both_nonexistent_returns_empty(self, simple_graph):
        paths = simple_graph.get_all_paths("X", "Y")
        assert paths == []


# =============================================================
# SUBGRAPH
# =============================================================

class TestSubgraph:

    def test_extract_subgraph_returns_graph_model(self, simple_graph):
        subgraph = simple_graph.extract_subgraph(["N1", "N2"])
        assert isinstance(subgraph, GraphModel)

    def test_subgraph_has_correct_nodes(self, simple_graph):
        subgraph = simple_graph.extract_subgraph(["N1", "N2"])
        assert subgraph.node_count() == 2

    def test_subgraph_type_includes_subgraph(self, simple_graph):
        subgraph = simple_graph.extract_subgraph(["N1", "N2"])
        assert "subgraph" in subgraph.get_graph_type()

    def test_subgraph_edge_preserved(self, simple_graph):
        subgraph = simple_graph.extract_subgraph(["N1", "N2"])
        assert subgraph.edge_count() == 1


# =============================================================
# SEARCH — CORRECCIÓN #4
# =============================================================

class TestSearch:

    def test_find_nodes_by_type(self, simple_graph):
        sources = simple_graph.find_nodes_by_type("source")
        assert len(sources) == 1
        assert sources[0]["type"] == "source"

    def test_find_nodes_by_type_sink(self, simple_graph):
        sinks = simple_graph.find_nodes_by_type("sink")
        assert len(sinks) == 1

    def test_find_nodes_by_type_unknown(self, simple_graph):
        results = simple_graph.find_nodes_by_type("unknown_type")
        assert results == []

    def test_find_nodes_by_label_fuzzy(self, simple_graph):
        """Modo fuzzy original: label contenido en el atributo."""
        results = simple_graph.find_nodes_by_label("cursor")
        assert len(results) > 0

    def test_find_nodes_by_label_exact(self, simple_graph):
        """
        Corrección #4: modo exacto nuevo.
        'cursor' no debe matchear 'cursor.execute' en modo exacto.
        """
        results = simple_graph.find_nodes_by_label(
            "cursor", exact=True
        )
        assert len(results) == 0

    def test_find_nodes_by_label_exact_full_match(self, simple_graph):
        """'cursor.execute' sí debe matchear en modo exacto."""
        results = simple_graph.find_nodes_by_label(
            "cursor.execute", exact=True
        )
        assert len(results) == 1

    def test_find_nodes_by_label_case_insensitive(self, simple_graph):
        """Tanto fuzzy como exacto son case-insensitive."""
        results_lower = simple_graph.find_nodes_by_label(
            "user_input", exact=True
        )
        results_upper = simple_graph.find_nodes_by_label(
            "USER_INPUT", exact=True
        )
        assert len(results_lower) == len(results_upper)
        assert len(results_lower) == 1


# =============================================================
# SIGNATURE
# =============================================================

class TestSignature:

    def test_get_signature_returns_dict(self, simple_graph):
        sig = simple_graph.get_signature()
        assert isinstance(sig, dict)

    def test_signature_has_required_keys(self, simple_graph):
        sig = simple_graph.get_signature()
        for key in ["graph_type", "node_count", "edge_count",
                    "node_types", "edge_types"]:
            assert key in sig

    def test_signature_node_count_correct(self, simple_graph):
        sig = simple_graph.get_signature()
        assert sig["node_count"] == 3

    def test_signature_edge_count_correct(self, simple_graph):
        sig = simple_graph.get_signature()
        assert sig["edge_count"] == 2

    def test_signature_node_types_sorted(self, simple_graph):
        sig = simple_graph.get_signature()
        assert sig["node_types"] == sorted(sig["node_types"])

    def test_signature_edge_types_not_none(self, simple_graph):
        """
        Corrección #2: edge_types usa 'edge_type' en los atributos,
        por lo que no deben ser None.
        """
        sig = simple_graph.get_signature()
        for et in sig["edge_types"]:
            assert et is not None

    def test_signature_edge_types_correct(self, simple_graph):
        sig = simple_graph.get_signature()
        assert "taint"     in sig["edge_types"]
        assert "sink_flow" in sig["edge_types"]


# =============================================================
# TO_DICT Y FROM_DICT
# =============================================================

class TestSerializationRoundtrip:

    def test_to_dict_returns_dict(self, simple_graph):
        assert isinstance(simple_graph.to_dict(), dict)

    def test_to_dict_has_required_keys(self, simple_graph):
        d = simple_graph.to_dict()
        for key in ["graph_type", "nodes", "edges", "statistics"]:
            assert key in d

    def test_to_dict_statistics_correct(self, simple_graph):
        d = simple_graph.to_dict()
        assert d["statistics"]["nodes"] == 3
        assert d["statistics"]["edges"] == 2

    def test_from_dict_roundtrip(self, simple_graph):
        """from_dict(to_dict()) debe producir un grafo equivalente."""
        d       = simple_graph.to_dict()
        rebuilt = GraphModel.from_dict(d)
        assert rebuilt.node_count() == simple_graph.node_count()
        assert rebuilt.edge_count() == simple_graph.edge_count()

    def test_from_dict_edge_types_preserved(self, simple_graph):
        """
        Corrección #2: el roundtrip to_dict → from_dict debe
        preservar los tipos de edge correctamente.
        """
        d       = simple_graph.to_dict()
        rebuilt = GraphModel.from_dict(d)
        original_types = {
            e["type"] for e in simple_graph.get_all_edges()
        }
        rebuilt_types  = {
            e["type"] for e in rebuilt.get_all_edges()
        }
        assert original_types == rebuilt_types
        assert None not in rebuilt_types

    def test_from_dict_default_graph_type(self):
        rebuilt = GraphModel.from_dict({})
        assert rebuilt.get_graph_type() == "generic"

    def test_to_dict_serializable(self, simple_graph):
        import json
        try:
            json.dumps(simple_graph.to_dict())
        except (TypeError, ValueError) as e:
            pytest.fail(f"to_dict() not JSON serializable: {e}")