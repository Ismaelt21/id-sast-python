import networkx as nx
from networkx.algorithms import isomorphism
from typing import Dict, List, Optional

from core.graph.graph_model import GraphModel


class SubgraphMatcher:
    """
    Realiza matching estructural de subgrafos.

    Detecta si un patron vulnerable existe
    dentro de un grafo mayor.
    """

    def __init__(
        self,
        target_graph:  GraphModel,
        pattern_graph: GraphModel,
    ):

        self.target_graph  = target_graph
        self.pattern_graph = pattern_graph

        self._matches: List[Dict] = []
        self._match_result: Optional[Dict] = None

    # =========================================================
    # MAIN
    # =========================================================

    def match(self) -> Dict:
        """
        Ejecuta subgraph matching con cache.
        """

        if self._match_result is not None:
            return self._match_result

        self._matches = []

        matcher = isomorphism.DiGraphMatcher(
            self.target_graph.graph,
            self.pattern_graph.graph,
            node_match=self._node_match,
            edge_match=self._edge_match,
        )

        for mapping in matcher.subgraph_isomorphisms_iter():

            self._matches.append({
                "matched":    True,
                "mapping":    mapping,
                "confidence": self._calculate_confidence(mapping),
            })

        self._match_result = {
            "matched":       len(self._matches) > 0,
            "total_matches": len(self._matches),
            "matches":       self._matches,
        }

        return self._match_result

    # =========================================================
    # RESET
    # =========================================================

    def reset(self) -> None:
        self._matches      = []
        self._match_result = None

    # =========================================================
    # NODE MATCH
    # =========================================================

    def _node_match(
        self,
        target_attrs:  Dict,
        pattern_attrs: Dict,
    ) -> bool:
        """
        NetworkX DiGraphMatcher(G1=target, G2=pattern) llama:
            node_match(G1_node_attrs, G2_node_attrs)
        es decir:
            node_match(target_attrs, pattern_attrs)

        Reglas:
        1. Tipos deben coincidir.
        2. Label generico en el pattern ("source","sink",
           "variable","any") -> match solo por tipo.
        3. Label especifico en el pattern -> match exacto
           contra el label del target.
        """

        target_type  = target_attrs.get("type",  "")
        pattern_type = pattern_attrs.get("type", "")

        if target_type != pattern_type:
            return False

        pattern_label = pattern_attrs.get("label", "").lower()
        target_label  = target_attrs.get("label",  "").lower()

        generic_labels = {"source", "sink", "variable", "any"}

        if pattern_label in generic_labels:
            return True

        return pattern_label == target_label

    # =========================================================
    # EDGE MATCH
    # =========================================================

    def _edge_match(
        self,
        target_attrs:  Dict,
        pattern_attrs: Dict,
    ) -> bool:
        """
        graph_model guarda el tipo como 'edge_type'.
        Si el pattern no especifica tipo, cualquier tipo vale.
        """

        target_type  = target_attrs.get("edge_type")
        pattern_type = pattern_attrs.get("edge_type")

        if not pattern_type:
            return True

        return target_type == pattern_type

    # =========================================================
    # CONFIDENCE
    # =========================================================

    def _calculate_confidence(self, mapping: Dict) -> float:

        matched_nodes       = len(mapping)
        total_pattern_nodes = self.pattern_graph.node_count()

        if total_pattern_nodes == 0:
            return 0.0

        structural_score = matched_nodes / total_pattern_nodes
        edge_score       = self._edge_similarity()

        return round(
            min((structural_score * 0.7) + (edge_score * 0.3), 1.0),
            2,
        )

    # =========================================================
    # EDGE SIMILARITY
    # =========================================================

    def _edge_similarity(self) -> float:

        target_edge_types = {
            attrs.get("edge_type")
            for _, _, attrs in self.target_graph.graph.edges(data=True)
        }

        pattern_edge_types = {
            attrs.get("edge_type")
            for _, _, attrs in self.pattern_graph.graph.edges(data=True)
        }

        if not pattern_edge_types:
            return 0.0

        intersection = target_edge_types & pattern_edge_types

        return len(intersection) / len(pattern_edge_types)

    # =========================================================
    # BEST MATCH
    # =========================================================

    def best_match(self) -> Optional[Dict]:

        result = self.match()

        if not result["matches"]:
            return None

        return max(
            result["matches"],
            key=lambda x: x["confidence"],
        )

    # =========================================================
    # PATTERN EXISTS
    # =========================================================

    def pattern_exists(self) -> bool:

        return self.match()["matched"]

    # =========================================================
    # EXTRACT MATCHED SUBGRAPH
    # =========================================================

    def extract_matched_subgraph(
        self,
        mapping: Dict,
    ) -> GraphModel:

        return self.target_graph.extract_subgraph(
            list(mapping.keys())
        )