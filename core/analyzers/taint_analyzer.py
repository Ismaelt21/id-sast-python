import networkx as nx


class TaintAnalyzer:
    """
    Realiza Taint Analysis sobre el DFG.

    Detecta:

    SOURCE → PROPAGATION → SINK
    """

    VULNERABILITY_MAP = {
        "os.system":        "COMMAND_INJECTION",
        "eval":             "CODE_INJECTION",
        "exec":             "CODE_INJECTION",
        "cursor.execute":   "SQL_INJECTION",
        "open":             "PATH_TRAVERSAL",
        "send_file":        "PATH_TRAVERSAL",
        "send_from_directory": "PATH_TRAVERSAL",
        "os.remove":        "PATH_TRAVERSAL",
        "os.unlink":        "PATH_TRAVERSAL",
        "pathlib.Path.unlink": "PATH_TRAVERSAL",
        "subprocess.run":   "COMMAND_INJECTION",
        "DANGEROUS_SINK":   "UNKNOWN_DANGEROUS_FLOW",
    }

    # Bug real #4/#5/#7: set expandido para incluir todos los
    # sanitizadores definidos en sanitizers.py. El set anterior
    # solo tenía 4 entradas y fallaba con shlex.quote, markupsafe,
    # secure_filename, etc., causando que paths sanitizados no
    # se marcaran correctamente y la penalización de confianza
    # no se aplicara.
    SANITIZERS = {
        # HTML / XSS
        "escape",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        # Command injection
        "shlex.quote",
        # Path traversal
        "secure_filename",
        "os.path.abspath",
        "os.path.normpath",
        # SQL
        "bindparams",
        "filter",
        # URL / SSRF
        "validators.url",
        # Type casting
        "int",
        "float",
        # Regex
        "re.match",
        "re.fullmatch",
        # Deserialization
        "yaml.safe_load",
        # XML
        "defusedxml",
        # Normalizer alias
        "SANITIZER",
    }

    # Umbral mínimo de confianza para reportar un finding.
    # Paths con confianza por debajo de este valor se descartan.
    MIN_CONFIDENCE = 0.15

    def __init__(self, dfg_data: dict):

        self.nodes = dfg_data["nodes"]
        self.edges = dfg_data["edges"]

        self.graph = nx.DiGraph()

        # Corrección #4: findings se inicializa aquí y se
        # resetea en cada llamada a analyze().
        self.findings = []

        self._build_graph()

    # =========================================================
    # GRAPH BUILDING
    # Corrección #2: ahora guardamos el campo 'label' en el
    # nodo para desacoplarlo del ID con @lineno.
    # =========================================================

    def _build_graph(self):

        for node in self.nodes:

            self.graph.add_node(
                node["id"],
                type=node["type"],
                # Corrección #2: preservamos el label limpio
                # que exporta dfg_builder (ej: "os.system")
                # separado del ID (ej: "os.system@5").
                label=node.get("label", node["id"]),
            )

        for edge in self.edges:

            self.graph.add_edge(
                edge["source"],
                edge["target"],
                type=edge["type"],
            )

    # =========================================================
    # MAIN ANALYSIS
    # Corrección #4: reset de findings al inicio de cada
    # llamada para evitar acumulación entre invocaciones.
    # =========================================================

    def analyze(self):

        self.findings = []

        sources = self._get_nodes_by_type("source")
        sinks   = self._get_nodes_by_type("sink")

        for source in sources:

            for sink in sinks:

                try:

                    paths = list(
                        nx.all_simple_paths(
                            self.graph,
                            source=source,
                            target=sink,
                        )
                    )

                    for path in paths:

                        # Corrección #5: _analyze_path puede
                        # retornar None; solo añadimos si hay
                        # finding real.
                        finding = self._analyze_path(path, sink)

                        if finding is not None:
                            self.findings.append(finding)

                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        return self.findings

    # =========================================================
    # PATH ANALYSIS
    # =========================================================

    def _analyze_path(self, path: list, sink: str):

        # -------------------------------------------------
        # Corrección #3: verificamos sanitización mirando
        # el LABEL de cada nodo del path, y además
        # comprobamos que el sanitizador esté posicionado
        # ANTES del sink en el camino (no en una rama
        # independiente). Un sanitizador después del sink
        # no protege nada.
        # -------------------------------------------------

        is_sanitized = self._path_is_sanitized(path, sink)

        vulnerability_type = self._detect_vulnerability_type(sink)

        severity = self._calculate_severity(
            vulnerability_type,
            is_sanitized,
        )

        confidence = self._calculate_confidence(
            path,
            is_sanitized,
        )

        # Corrección #5: descartamos findings con confianza
        # demasiado baja o tipo completamente desconocido sin
        # suficiente señal.
        if confidence < self.MIN_CONFIDENCE:
            return None

        if vulnerability_type == "UNKNOWN" and confidence < 0.4:
            return None

        return {
            "vulnerability":    vulnerability_type,
            "severity":         severity,
            "source":           path[0],
            "sink":             sink,
            # Corrección #4: incluimos el label limpio del
            # sink en el finding para facilitar reporting.
            "sink_label":       self._node_label(sink),
            "path":             path,
            "sanitized":        is_sanitized,
            "confidence":       confidence,
        }

    # =========================================================
    # SANITIZER CHECK
    # Corrección #3: lookup exacto sobre label del nodo, y
    # verificación posicional (el sanitizador debe aparecer
    # antes del sink en el path).
    # =========================================================

    def _path_is_sanitized(self, path: list, sink: str) -> bool:

        # El path completo es [source, ..., sink].
        # Solo nos interesan los nodos intermedios antes del sink.
        nodes_before_sink = path[:-1]

        for node_id in nodes_before_sink:

            label = self._node_label(node_id)

            # Corrección #1 aplicada aquí también: comparación
            # exacta contra el set de sanitizadores, no substring.
            if label in self.SANITIZERS:
                return True

        return False

    # =========================================================
    # HELPERS
    # =========================================================

    def _get_nodes_by_type(self, node_type: str) -> list:

        return [
            node
            for node, attrs in self.graph.nodes(data=True)
            if attrs.get("type") == node_type
        ]

    def _node_label(self, node_id: str) -> str:
        """
        Corrección #2: devuelve el label limpio del nodo
        (ej: "os.system") en lugar del ID con @lineno.
        """

        attrs = self.graph.nodes.get(node_id, {})

        return attrs.get("label", node_id)

    def _detect_vulnerability_type(self, sink: str) -> str:
        """
        Corrección #1: lookup EXACTO sobre el label del sink,
        no substring sobre el ID. Esto evita que "exec" matchee
        dentro de "cursor.execute" o similares.
        """

        sink_label = self._node_label(sink)

        # Primero intentamos match exacto (caso normal).
        if sink_label in self.VULNERABILITY_MAP:
            return self.VULNERABILITY_MAP[sink_label]

        # Fallback: si el label no matchea exactamente,
        # probamos substring solo como último recurso y
        # retornamos UNKNOWN si tampoco hay match.
        for pattern, vuln_type in self.VULNERABILITY_MAP.items():
            if pattern in sink_label:
                return vuln_type

        return "UNKNOWN"

    def _calculate_severity(
        self,
        vulnerability_type: str,
        sanitized: bool,
    ) -> str:

        if sanitized:
            return "LOW"

        severity_map = {
            "SQL_INJECTION":            "CRITICAL",
            "COMMAND_INJECTION":        "CRITICAL",
            "CODE_INJECTION":           "CRITICAL",
            "XSS":                      "HIGH",
            "PATH_TRAVERSAL":           "HIGH",
            "UNKNOWN_DANGEROUS_FLOW":   "MEDIUM",
        }

        return severity_map.get(vulnerability_type, "MEDIUM")

    def _calculate_confidence(
        self,
        path: list,
        sanitized: bool,
    ) -> float:
        """
        Corrección #6: cálculo más granular que distingue
        mejor entre paths directos, cortos y largos.

        Escala base:
          - Path directo (2 nodos: source → sink):    0.90
          - Path corto   (3 nodos):                   0.75
          - Path medio   (4-5 nodos):                 0.60
          - Path largo   (6+ nodos):                  0.45

        Penalización por sanitización: -0.40
        El resultado siempre queda en [0.0, 1.0].
        """

        n = len(path)

        if n <= 2:
            score = 0.90
        elif n == 3:
            score = 0.75
        elif n <= 5:
            score = 0.60
        else:
            score = 0.45

        if sanitized:
            score -= 0.40

        return round(max(0.0, min(score, 1.0)), 2)


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    import json

    # ---------------------------------------------------------
    # Caso 1: path directo sin sanitizar → CRITICAL
    # ---------------------------------------------------------

    dfg_direct = {
        "nodes": [
            {"id": "input",           "type": "source",   "label": "input"},
            {"id": "user",            "type": "variable", "label": "user"},
            {"id": "os.system@5",     "type": "sink",     "label": "os.system"},
        ],
        "edges": [
            {"source": "input",       "target": "user",           "type": "taint"},
            {"source": "user",        "target": "os.system@5",    "type": "sink_flow"},
        ],
    }

    # ---------------------------------------------------------
    # Caso 2: path con sanitizador → LOW
    # ---------------------------------------------------------

    dfg_sanitized = {
        "nodes": [
            {"id": "input",           "type": "source",   "label": "input"},
            {"id": "user",            "type": "variable", "label": "user"},
            {"id": "escape",          "type": "variable", "label": "escape"},
            {"id": "os.system@8",     "type": "sink",     "label": "os.system"},
        ],
        "edges": [
            {"source": "input",       "target": "user",           "type": "taint"},
            {"source": "user",        "target": "escape",         "type": "propagation"},
            {"source": "escape",      "target": "os.system@8",    "type": "sink_flow"},
        ],
    }

    # ---------------------------------------------------------
    # Caso 3: sink cursor.execute no confundido con exec
    # (verifica corrección #1)
    # ---------------------------------------------------------

    dfg_sql = {
        "nodes": [
            {"id": "input",               "type": "source",   "label": "input"},
            {"id": "query",               "type": "variable", "label": "query"},
            {"id": "cursor.execute@10",   "type": "sink",     "label": "cursor.execute"},
        ],
        "edges": [
            {"source": "input",   "target": "query",              "type": "taint"},
            {"source": "query",   "target": "cursor.execute@10",  "type": "sink_flow"},
        ],
    }

    for label, dfg in [
        ("CASO 1: directo",         dfg_direct),
        ("CASO 2: sanitizado",      dfg_sanitized),
        ("CASO 3: cursor.execute",  dfg_sql),
    ]:
        print(f"\n=== {label} ===")
        analyzer = TaintAnalyzer(dfg)
        print(json.dumps(analyzer.analyze(), indent=2))
