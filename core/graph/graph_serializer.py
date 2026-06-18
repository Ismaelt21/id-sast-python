import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from core.graph.graph_model import GraphModel


class GraphSerializer:
    """
    Serializador de grafos.

    Responsabilidades:
    - Exportar/importar JSON
    - Generar firmas compactas
    - Serializar para MongoDB
    - Preparar grafos para IA
    """

    # =========================================================
    # JSON SERIALIZATION
    # =========================================================

    @staticmethod
    def to_json(
        graph: GraphModel,
        indent: int = 2,
    ) -> str:
        """
        Convierte GraphModel → JSON string.
        """

        return json.dumps(
            graph.to_dict(),
            indent=indent,
        )

    @staticmethod
    def from_json(json_string: str) -> GraphModel:
        """
        Convierte JSON string → GraphModel.
        """

        data = json.loads(json_string)

        return GraphModel.from_dict(data)

    # =========================================================
    # FILE EXPORT
    # Corrección #6: manejo explícito de errores de IO y JSON
    # malformado. Mensajes de error descriptivos en lugar de
    # tracebacks crudos que no indican la causa real.
    # =========================================================

    @staticmethod
    def save_json(
        graph: GraphModel,
        filepath: str,
    ) -> None:
        """
        Guarda grafo como JSON en disco.
        """

        path = Path(filepath)

        try:

            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w", encoding="utf-8") as file:
                json.dump(graph.to_dict(), file, indent=2)

        except OSError as e:
            raise OSError(
                f"Could not write graph to '{filepath}': {e}"
            ) from e

        except TypeError as e:
            raise TypeError(
                f"Graph contains non-serializable data: {e}"
            ) from e

    @staticmethod
    def load_json(filepath: str) -> GraphModel:
        """
        Carga grafo desde JSON en disco.
        """

        path = Path(filepath)

        try:

            with open(path, "r", encoding="utf-8") as file:
                data = json.load(file)

        except FileNotFoundError:
            raise FileNotFoundError(
                f"Graph file not found: '{filepath}'"
            )

        except OSError as e:
            raise OSError(
                f"Could not read graph from '{filepath}': {e}"
            ) from e

        except json.JSONDecodeError as e:
            raise ValueError(
                f"Malformed JSON in '{filepath}': {e}"
            ) from e

        return GraphModel.from_dict(data)

    # =========================================================
    # MONGODB SERIALIZATION
    # Corrección #7: añadido timestamp e _id sugerido para
    # permitir ordenación temporal y deduplicación en MongoDB.
    # =========================================================

    @staticmethod
    def to_mongodb_document(
        graph: GraphModel,
        metadata: Optional[Dict[str, Any]] = None,
        analysis_id: Optional[str] = None,
    ) -> dict:
        """
        Serialización optimizada para MongoDB.

        Corrección #7: incluye timestamp y analysis_id para
        ordenación temporal y deduplicación entre análisis.
        """

        metadata = metadata or {}

        now = datetime.utcnow().isoformat()

        document = {
            "graph_type": graph.get_graph_type(),
            "signature":  graph.get_signature(),
            "nodes":      graph.get_all_nodes(),
            "edges":      graph.get_all_edges(),
            "metadata":   metadata,
            # Corrección #7: campos de auditoría para MongoDB.
            "created_at": now,
        }

        # analysis_id opcional: permite agrupar grafos del
        # mismo análisis sin forzar un _id específico.
        if analysis_id:
            document["analysis_id"] = analysis_id

        return document

    # =========================================================
    # COMPACT SIGNATURE
    # =========================================================

    @staticmethod
    def compact_signature(graph: GraphModel) -> dict:
        """
        Firma compacta del grafo.

        Ideal para:
        - matching rápido
        - deduplicación
        - cache
        """

        signature = graph.get_signature()

        return {
            "graph_type": signature["graph_type"],
            "nodes":      signature["node_count"],
            "edges":      signature["edge_count"],
            "node_types": signature["node_types"],
            "edge_types": signature["edge_types"],
        }

    # =========================================================
    # AI SERIALIZATION
    # Corrección #5: el summary ahora refleja el número real
    # de nodos y edges incluidos en el contexto enviado a la
    # IA, no el total del grafo. Evita que Gemini reciba
    # información contradictoria (summary dice N, contexto
    # tiene menos de N).
    # =========================================================

    @staticmethod
    def to_ai_context(
        graph: GraphModel,
        max_nodes: int = 25,
    ) -> dict:
        """
        Serialización optimizada para IA/Gemini.

        Reduce ruido y tamaño del prompt.

        Corrección #5: summary refleja el conteo real del
        contexto truncado, no el total del grafo completo.
        """

        all_nodes = graph.get_all_nodes()

        # Truncamos si hay más nodos que el límite.
        truncated = len(all_nodes) > max_nodes

        nodes = all_nodes[:max_nodes]

        valid_node_ids = {node["id"] for node in nodes}

        # Solo incluimos edges cuyos dos extremos están en
        # el conjunto de nodos truncado.
        edges = [
            {
                "source": edge["source"],
                "target": edge["target"],
                "type":   edge["type"],
            }
            for edge in graph.get_all_edges()
            if (
                edge["source"] in valid_node_ids
                and edge["target"] in valid_node_ids
            )
        ]

        simplified_nodes = [
            {
                "id":    node["id"],
                "type":  node["type"],
                "label": node["label"],
            }
            for node in nodes
        ]

        return {
            "graph_type": graph.get_graph_type(),

            # Corrección #5: conteos del contexto real enviado.
            "summary": {
                "nodes":     len(simplified_nodes),
                "edges":     len(edges),
                # Indicamos si el grafo fue truncado para que
                # la IA sepa que puede haber más contexto.
                "truncated": truncated,
                "total_nodes": graph.node_count(),
                "total_edges": graph.edge_count(),
            },

            "nodes": simplified_nodes,
            "edges": edges,
        }

    # =========================================================
    # SUBGRAPH EXPORT
    # =========================================================

    @staticmethod
    def export_subgraph_pattern(
        graph: GraphModel,
        vulnerability_type: str,
        confidence: float,
    ) -> dict:
        """
        Exporta subgrafo vulnerable como patrón reutilizable.
        """

        return {
            "vulnerability":   vulnerability_type,
            "confidence":      confidence,
            "graph_signature": graph.get_signature(),
            "pattern": {
                "nodes": graph.get_all_nodes(),
                "edges": graph.get_all_edges(),
            },
        }

    # =========================================================
    # VISUALIZATION EXPORT
    # =========================================================

    @staticmethod
    def to_visualization_format(graph: GraphModel) -> dict:
        """
        Formato compatible con frontend/D3/Cytoscape.
        """

        nodes = [
            {
                "data": {
                    "id":    node["id"],
                    "label": node["label"],
                    "type":  node["type"],
                }
            }
            for node in graph.get_all_nodes()
        ]

        edges = [
            {
                "data": {
                    "id":     f"E{idx}",
                    "source": edge["source"],
                    "target": edge["target"],
                    "type":   edge["type"],
                }
            }
            for idx, edge in enumerate(graph.get_all_edges())
        ]

        return {
            "nodes": nodes,
            "edges": edges,
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

    serializer = GraphSerializer()

    print("=== JSON ===")
    print(serializer.to_json(graph))

    print("\n=== COMPACT SIGNATURE ===")
    print(json.dumps(serializer.compact_signature(graph), indent=2))

    print("\n=== AI CONTEXT ===")
    print(json.dumps(serializer.to_ai_context(graph), indent=2))

    print("\n=== MONGODB DOCUMENT ===")
    print(json.dumps(
        serializer.to_mongodb_document(
            graph,
            metadata={"file": "test.py"},
            analysis_id="analysis_001",
        ),
        indent=2,
    ))

    print("\n=== SAVE / LOAD ===")
    serializer.save_json(graph, "/tmp/test_graph.json")
    loaded = serializer.load_json("/tmp/test_graph.json")
    print(f"Loaded graph type: {loaded.get_graph_type()}")
    print(f"Nodes: {loaded.node_count()}, Edges: {loaded.edge_count()}")