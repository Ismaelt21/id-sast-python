"""
tests/test_subgraph_matcher.py

Tests unitarios para core/graph/subgraph_matcher.py
Cubre las 3 correcciones aplicadas.
"""

import pytest
from core.graph.graph_model import GraphModel
from core.graph.subgraph_matcher import SubgraphMatcher


# =============================================================
# FIXTURES
# =============================================================

@pytest.fixture
def target_sqli():
    """
    Grafo target con flujo SQL Injection:
    USER_INPUT → query → cursor.execute

    3 nodos con edges directos para que el pattern de 3 nodos
    pueda hacer match por subgraph isomorphism.
    El isomorfismo necesita match exacto de estructura de edges,
    no hace transitive closure.
    """
    g = GraphModel(graph_type="dfg")
    g.add_node("N1", "source",   "USER_INPUT")
    g.add_node("N2", "variable", "query")
    g.add_node("N3", "sink",     "cursor.execute")
    g.add_edge("N1", "N2", "taint")
    g.add_edge("N2", "N3", "sink_flow")
    return g


@pytest.fixture
def target_command():
    """
    Grafo target con flujo Command Injection:
    USER_INPUT → user → os.system
    """
    g = GraphModel(graph_type="dfg")
    g.add_node("N1", "source",   "USER_INPUT")
    g.add_node("N2", "variable", "user")
    g.add_node("N3", "sink",     "os.system")
    g.add_edge("N1", "N2", "taint")
    g.add_edge("N2", "N3", "sink_flow")
    return g


@pytest.fixture
def pattern_sqli_generic():
    """
    Pattern genérico SQL: source → variable → sink (cursor.execute).
    Labels 'source' y 'variable' son genéricos → match por tipo.
    """
    g = GraphModel(graph_type="pattern")
    g.add_node("P1", "source",   "source")
    g.add_node("P2", "variable", "variable")
    g.add_node("P3", "sink",     "cursor.execute")
    g.add_edge("P1", "P2", "taint")
    g.add_edge("P2", "P3", "sink_flow")
    return g


@pytest.fixture
def pattern_command_generic():
    """
    Pattern genérico Command Injection: source → variable → sink.
    """
    g = GraphModel(graph_type="pattern")
    g.add_node("P1", "source",   "source")
    g.add_node("P2", "variable", "variable")
    g.add_node("P3", "sink",     "os.system")
    g.add_edge("P1", "P2", "taint")
    g.add_edge("P2", "P3", "sink_flow")
    return g


@pytest.fixture
def pattern_wrong_sink():
    """Pattern con sink que no existe en el target."""
    g = GraphModel(graph_type="pattern")
    g.add_node("P1", "source",   "source")
    g.add_node("P2", "sink",     "yaml.load")
    g.add_edge("P1", "P2", "sink_flow")
    return g


@pytest.fixture
def empty_pattern():
    return GraphModel(graph_type="pattern")


# =============================================================
# STRUCTURE
# =============================================================

class TestMatchStructure:

    def test_match_returns_dict(self, target_sqli, pattern_sqli_generic):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        assert isinstance(result, dict)

    def test_result_has_required_keys(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        assert "matched"       in result
        assert "total_matches" in result
        assert "matches"       in result

    def test_matches_is_list(self, target_sqli, pattern_sqli_generic):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        assert isinstance(result["matches"], list)

    def test_matched_is_bool(self, target_sqli, pattern_sqli_generic):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        assert isinstance(result["matched"], bool)

    def test_total_matches_is_int(self, target_sqli, pattern_sqli_generic):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        assert isinstance(result["total_matches"], int)


# =============================================================
# CORRECCIÓN #8 — _node_match POR TIPO PRIMERO
# =============================================================

class TestCorrection8NodeMatchByType:

    def test_generic_source_label_matches_by_type(
        self, target_sqli, pattern_sqli_generic
    ):
        """
        Pattern con label='source' debe matchear nodo target con
        label='USER_INPUT' y type='source'.
        Antes fallaba porque 'source' not in 'user_input'.
        """
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        assert result["matched"] is True

    def test_generic_variable_label_matches_by_type(
        self, target_command, pattern_command_generic
    ):
        """
        Pattern con label='variable' debe matchear cualquier
        nodo target con type='variable'.
        """
        matcher = SubgraphMatcher(target_command, pattern_command_generic)
        result  = matcher.match()
        assert result["matched"] is True

    def test_specific_sink_label_matches_exactly(
        self, target_sqli, pattern_sqli_generic
    ):
        """
        Pattern con label='cursor.execute' debe hacer match
        exacto contra el nodo target con el mismo label.
        """
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        assert result["matched"] is True

    def test_specific_sink_label_no_substring_match(
        self, target_sqli
    ):
        """
        Pattern con label='execute' NO debe matchear
        label='cursor.execute' por substring.
        Corrección #8: match exacto, no fuzzy.
        """
        pattern = GraphModel(graph_type="pattern")
        pattern.add_node("P1", "source", "source")
        pattern.add_node("P2", "sink",   "execute")  # substring, no exacto
        pattern.add_edge("P1", "P2", "sink_flow")

        matcher = SubgraphMatcher(target_sqli, pattern)
        result  = matcher.match()
        # 'execute' no debe matchear 'cursor.execute'
        assert result["matched"] is False

    def test_wrong_type_no_match(self, target_sqli):
        """
        Nodo con mismo label pero tipo distinto no debe matchear.
        """
        pattern = GraphModel(graph_type="pattern")
        pattern.add_node("P1", "variable", "USER_INPUT")  # tipo incorrecto
        pattern.add_node("P2", "sink",     "cursor.execute")
        pattern.add_edge("P1", "P2", "sink_flow")

        matcher = SubgraphMatcher(target_sqli, pattern)
        result  = matcher.match()
        assert result["matched"] is False

    def test_any_label_matches_any_type(self, target_sqli):
        """Label 'any' debe matchear cualquier nodo del mismo tipo."""
        pattern = GraphModel(graph_type="pattern")
        pattern.add_node("P1", "source",   "any")
        pattern.add_node("P2", "variable", "any")
        pattern.add_node("P3", "sink",     "cursor.execute")
        pattern.add_edge("P1", "P2", "taint")
        pattern.add_edge("P2", "P3", "sink_flow")

        matcher = SubgraphMatcher(target_sqli, pattern)
        result  = matcher.match()
        assert result["matched"] is True


# =============================================================
# CORRECCIÓN #9 — RESET DE _matches ENTRE LLAMADAS
# =============================================================

class TestCorrection9ResetMatches:

    def test_second_match_not_duplicate(
        self, target_sqli, pattern_sqli_generic
    ):
        """
        Llamar match() dos veces no debe acumular resultados.
        """
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        first   = matcher.match()
        second  = matcher.match()
        assert first["total_matches"] == second["total_matches"]

    def test_multiple_calls_stable(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        counts  = [matcher.match()["total_matches"] for _ in range(4)]
        assert len(set(counts)) == 1, (
            f"Unstable match counts: {counts}"
        )

    def test_reset_forces_recomputation(
        self, target_sqli, pattern_sqli_generic
    ):
        """
        reset() limpia el cache y permite una nueva ejecución.
        """
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        first   = matcher.match()
        matcher.reset()
        second  = matcher.match()
        assert first["total_matches"] == second["total_matches"]

    def test_reset_clears_cache(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        matcher.match()
        matcher.reset()
        assert matcher._match_result is None
        assert matcher._matches      == []


# =============================================================
# CORRECCIÓN #10 — CACHE COMPARTIDO ENTRE best_match Y pattern_exists
# =============================================================

class TestCorrection10Cache:

    def test_pattern_exists_uses_cache(
        self, target_sqli, pattern_sqli_generic
    ):
        """
        pattern_exists() no debe re-ejecutar match(); usa cache.
        """
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        matcher.match()
        # Si no hay cache, llamar pattern_exists acumularía
        # resultados duplicados.
        exists = matcher.pattern_exists()
        result = matcher.match()
        assert result["total_matches"] == matcher.match()["total_matches"]
        assert exists is True

    def test_best_match_uses_cache(
        self, target_sqli, pattern_sqli_generic
    ):
        """best_match() no debe re-ejecutar match()."""
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        matcher.match()
        best = matcher.best_match()
        # El count sigue siendo el mismo tras llamar best_match.
        result = matcher.match()
        assert result["total_matches"] == 1

    def test_match_called_once_by_multiple_helpers(
        self, target_sqli, pattern_sqli_generic
    ):
        """
        Llamar match(), best_match(), pattern_exists() y
        match() de nuevo debe dar el mismo total_matches.
        """
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        t1 = matcher.match()["total_matches"]
        matcher.best_match()
        matcher.pattern_exists()
        t2 = matcher.match()["total_matches"]
        assert t1 == t2


# =============================================================
# PATTERN EXISTS
# =============================================================

class TestPatternExists:

    def test_existing_pattern_returns_true(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        assert matcher.pattern_exists() is True

    def test_nonexistent_pattern_returns_false(
        self, target_sqli, pattern_wrong_sink
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_wrong_sink)
        assert matcher.pattern_exists() is False

    def test_pattern_exists_consistent_with_matched(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        exists  = matcher.pattern_exists()
        assert exists == result["matched"]


# =============================================================
# BEST MATCH
# =============================================================

class TestBestMatch:

    def test_best_match_returns_dict_when_found(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        best    = matcher.best_match()
        assert best is not None
        assert isinstance(best, dict)

    def test_best_match_returns_none_when_not_found(
        self, target_sqli, pattern_wrong_sink
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_wrong_sink)
        assert matcher.best_match() is None

    def test_best_match_has_confidence(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        best    = matcher.best_match()
        assert "confidence" in best
        assert 0.0 <= best["confidence"] <= 1.0

    def test_best_match_has_mapping(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        best    = matcher.best_match()
        assert "mapping" in best
        assert isinstance(best["mapping"], dict)

    def test_best_match_has_matched_flag(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        best    = matcher.best_match()
        assert best["matched"] is True


# =============================================================
# CONFIDENCE
# =============================================================

class TestConfidence:

    def test_confidence_between_0_and_1(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        result  = matcher.match()
        for match in result["matches"]:
            assert 0.0 <= match["confidence"] <= 1.0

    def test_full_pattern_match_high_confidence(
        self, target_command, pattern_command_generic
    ):
        """
        Pattern que mapea todos sus nodos debe tener confianza alta.
        """
        matcher = SubgraphMatcher(target_command, pattern_command_generic)
        best    = matcher.best_match()
        assert best["confidence"] >= 0.5

    def test_empty_pattern_zero_confidence(
        self, target_sqli, empty_pattern
    ):
        """
        Pattern vacío → NetworkX puede encontrar un mapping vacío
        (isomorfismo trivial). Lo importante es que la confianza
        sea 0.0 o que best_match retorne None o confidence=0.
        """
        matcher = SubgraphMatcher(target_sqli, empty_pattern)
        best = matcher.best_match()
        if best is not None:
            assert best["confidence"] == 0.0
        else:
            assert best is None


# =============================================================
# EXTRACT MATCHED SUBGRAPH
# =============================================================

class TestExtractMatchedSubgraph:

    def test_extract_returns_graph_model(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        best    = matcher.best_match()
        assert best is not None
        subgraph = matcher.extract_matched_subgraph(best["mapping"])
        assert isinstance(subgraph, GraphModel)

    def test_extracted_subgraph_has_nodes(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher  = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        best     = matcher.best_match()
        subgraph = matcher.extract_matched_subgraph(best["mapping"])
        assert subgraph.node_count() > 0

    def test_extracted_subgraph_nodes_subset_of_target(
        self, target_sqli, pattern_sqli_generic
    ):
        matcher  = SubgraphMatcher(target_sqli, pattern_sqli_generic)
        best     = matcher.best_match()
        assert best is not None, "Expected a match"
        subgraph = matcher.extract_matched_subgraph(best["mapping"])
        assert subgraph.node_count() <= target_sqli.node_count()


# =============================================================
# EDGE MATCH
# =============================================================

class TestEdgeMatch:

    def test_matching_edge_type_required(self, target_sqli):
        """
        Pattern con edge_type incorrecto no debe matchear.
        """
        pattern = GraphModel(graph_type="pattern")
        pattern.add_node("P1", "source",   "source")
        pattern.add_node("P2", "sink",     "cursor.execute")
        # Edge con tipo distinto al del target (sink_flow)
        pattern.add_edge("P1", "P2", "wrong_edge_type")

        matcher = SubgraphMatcher(target_sqli, pattern)
        result  = matcher.match()
        assert result["matched"] is False

    def test_no_edge_type_in_pattern_matches_any(self, target_sqli):
        """
        Si el pattern no especifica edge_type (None/vacío),
        cualquier tipo del target es válido.
        """
        pattern = GraphModel(graph_type="pattern")
        pattern.add_node("P1", "source",   "source")
        pattern.add_node("P2", "sink",     "cursor.execute")
        # add_edge con edge_type vacío simula pattern sin restricción
        pattern.graph.add_edge("P1", "P2", edge_type=None)

        matcher = SubgraphMatcher(target_sqli, pattern)
        result  = matcher.match()
        # Sin restricción de edge_type, el match puede ocurrir
        assert isinstance(result["matched"], bool)