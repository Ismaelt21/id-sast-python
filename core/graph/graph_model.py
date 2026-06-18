from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
import networkx as nx


# =============================================================
# NODE
# =============================================================

@dataclass
class GraphNode:
    """
    Representa un nodo del grafo.
    """

    node_id: str
    node_type: str
    label: str
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id":       self.node_id,
            "type":     self.node_type,
            "label":    self.label,
            "metadata": self.metadata,
        }


# =============================================================
# EDGE
# =============================================================

@dataclass
class GraphEdge:
    """
    Representa una arista del grafo.
    """

    source:    str
    target:    str
    edge_type: str
    metadata:  Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source":   self.source,
            "target":   self.target,
            "type":     self.edge_type,
            "metadata": self.metadata,
        }


# =============================================================
# GRAPH MODEL
# =============================================================

class GraphModel:
    """
    Modelo unificado de grafos.

    Soporta:
    - AST
    - CFG
    - DFG
    - Subgraphs

    Internamente usa NetworkX.
    """

    def __init__(self, graph_type: str = "generic"):

        self.graph_type = graph_type
        self.graph      = nx.DiGraph()

    # =========================================================
    # NODE MANAGEMENT
    # =========================================================

    def add_node(
        self,
        node_id:   str,
        node_type: str,
        label:     str,
        metadata:  Optional[dict] = None,
    ):

        metadata = metadata or {}

        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            metadata=metadata,
        )

        self.graph.add_node(node_id, **node.to_dict())

    def get_node(self, node_id: str) -> Optional[dict]:

        if node_id not in self.graph:
            return None

        return dict(self.graph.nodes[node_id])

    def get_all_nodes(self) -> List[dict]:

        return [
            dict(attrs)
            for _, attrs in self.graph.nodes(data=True)
        ]

    # =========================================================
    # EDGE MANAGEMENT
    # Corrección #1 y #2: add_edge ya no pasa "source" y
    # "target" como atributos del edge (evita contaminar los
    # atributos de NetworkX con claves redundantes). Los
    # atributos guardados son solo "edge_type" y "metadata",
    # con claves que luego get_all_edges lee correctamente.
    # =========================================================

    def add_edge(
        self,
        source:    str,
        target:    str,
        edge_type: str,
        metadata:  Optional[dict] = None,
    ):

        metadata = metadata or {}

        # Corrección #1: guardamos únicamente los atributos
        # propios del edge, sin repetir source/target.
        self.graph.add_edge(
            source,
            target,
            edge_type=edge_type,
            metadata=metadata,
        )

    def get_all_edges(self) -> List[dict]:

        edges = []

        for source, target, attrs in self.graph.edges(data=True):

            edges.append({
                "source":   source,
                "target":   target,
                # Corrección #2: la clave guardada en add_edge
                # es "edge_type", no "type".
                "type":     attrs.get("edge_type"),
                "metadata": attrs.get("metadata", {}),
            })

        return edges

    # =========================================================
    # GRAPH INFO
    # =========================================================

    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def get_graph_type(self) -> str:
        return self.graph_type

    # =========================================================
    # PATHS
    # Corrección #3: capturamos también NodeNotFound, que es
    # la excepción real cuando source o target no existen en
    # el grafo. Antes solo se capturaba NetworkXNoPath.
    # =========================================================

    def get_all_paths(
        self,
        source: str,
        target: str,
    ) -> List[List[str]]:
        """
        Retorna todos los caminos simples entre source y target.
        """

        try:

            return list(
                nx.all_simple_paths(
                    self.graph,
                    source=source,
                    target=target,
                )
            )

        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    # =========================================================
    # SUBGRAPHS
    # =========================================================

    def extract_subgraph(self, node_ids: List[str]) -> "GraphModel":
        """
        Extrae un subgrafo con los nodos indicados.
        """

        subgraph = self.graph.subgraph(node_ids).copy()

        model       = GraphModel(graph_type=f"{self.graph_type}_subgraph")
        model.graph = subgraph

        return model

    # =========================================================
    # SEARCH
    # Corrección #4: find_nodes_by_label ahora soporta modo
    # exacto (exact=True) además del modo fuzzy original.
    # Todo el pipeline trabaja con labels limpios exactos;
    # el modo fuzzy se mantiene para búsquedas exploratorias.
    # =========================================================

    def find_nodes_by_type(self, node_type: str) -> List[dict]:

        return [
            dict(attrs)
            for _, attrs in self.graph.nodes(data=True)
            if attrs.get("type") == node_type
        ]

    def find_nodes_by_label(
        self,
        label: str,
        exact: bool = False,
    ) -> List[dict]:
        """
        Busca nodos por label.

        exact=True  → comparación exacta (case-insensitive).
        exact=False → búsqueda fuzzy: label contenido en el
                      atributo del nodo (comportamiento original).
        """

        label_lower = label.lower()

        results = []

        for _, attrs in self.graph.nodes(data=True):

            node_label = attrs.get("label", "").lower()

            if exact:
                if node_label == label_lower:
                    results.append(dict(attrs))
            else:
                if label_lower in node_label:
                    results.append(dict(attrs))

        return results

    # =========================================================
    # EXPORT
    # =========================================================

    def to_dict(self) -> dict:
        """
        Serialización completa del grafo.
        """

        return {
            "graph_type": self.graph_type,
            "nodes":      self.get_all_nodes(),
            "edges":      self.get_all_edges(),
            "statistics": {
                "nodes": self.node_count(),
                "edges": self.edge_count(),
            },
        }

    # =========================================================
    # IMPORT
    # =========================================================

    @classmethod
    def from_dict(cls, data: dict) -> "GraphModel":

        model = cls(graph_type=data.get("graph_type", "generic"))

        for node in data.get("nodes", []):
            model.add_node(
                node_id=node["id"],
                node_type=node["type"],
                label=node["label"],
                metadata=node.get("metadata", {}),
            )

        for edge in data.get("edges", []):
            model.add_edge(
                source=edge["source"],
                target=edge["target"],
                edge_type=edge["type"],
                metadata=edge.get("metadata", {}),
            )

        return model

    # =========================================================
    # SIGNATURE
    # =========================================================

    def get_signature(self) -> dict:
        """
        Firma compacta del grafo.
        Útil para MongoDB y matching rápido.
        """

        node_types = [
            attrs.get("type")
            for _, attrs in self.graph.nodes(data=True)
        ]

        # Corrección #2: la clave es "edge_type", no "type".
        edge_types = [
            attrs.get("edge_type")
            for _, _, attrs in self.graph.edges(data=True)
        ]

        return {
            "graph_type": self.graph_type,
            "node_count": self.node_count(),
            "edge_count": self.edge_count(),
            "node_types": sorted(set(t for t in node_types if t)),
            "edge_types": sorted(set(t for t in edge_types if t)),
        }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    import json

    graph = GraphModel(graph_type="dfg")

    graph.add_node("N1", "source",   "USER_INPUT")
    graph.add_node("N2", "variable", "query")
    graph.add_node("N3", "sink",     "cursor.execute")

    graph.add_edge("N1", "N2", "taint")
    graph.add_edge("N2", "N3", "sink_flow")

    print(json.dumps(graph.to_dict(), indent=2))
    print(graph.get_signature())
    print(graph.find_nodes_by_label("cursor.execute", exact=True))
    print(graph.get_all_paths("N1", "N3"))