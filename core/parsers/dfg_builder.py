import ast
import networkx as nx


class DFGBuilder(ast.NodeVisitor):
    """
    Construye un Data Flow Graph (DFG)
    para análisis SAST.

    Detecta:

    - Sources
    - Variables
    - Transformations
    - Sinks
    """

    SOURCES = {
        "input",
        "USER_INPUT",
        "request.args.get",
        "request.form.get",
    }

    SINKS = {
        "eval",
        "exec",
        "os.system",
        "subprocess.run",
        "cursor.execute",
        "open",
        "send_file",
        "send_from_directory",
        "os.remove",
        "os.unlink",
        "pathlib.Path.unlink",
        "requests.get",
        "requests.post",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "http.client.HTTPConnection",
        "render_template_string",
        "make_response",
        "DANGEROUS_SINK",
    }

    SANITIZERS = {
        "escape",
        "html.escape",
        "bleach.clean",
        "SANITIZER",
    }

    def __init__(self):

        self._reset()

    # =========================================================
    # RESET
    # Corrección #5: reset explícito entre llamadas para evitar
    # que graph y variable_origins acumulen estado de análisis
    # previos cuando se reutiliza la instancia.
    # =========================================================

    def _reset(self):

        self.graph = nx.DiGraph()

        self.variable_origins = {}

        self.current_function = None

        # Control interno para evitar double-dispatch entre
        # visit_Assign → generic_visit → visit_Call.
        # Corrección #3.
        self._processing_assign = False

    # =========================================================
    # MAIN
    # =========================================================

    def build_from_code(self, code: str):

        self._reset()

        tree = ast.parse(code)

        self.visit(tree)

        return self.export_graph()

    # =========================================================
    # FUNCTIONS
    # =========================================================

    def visit_FunctionDef(self, node):

        self.current_function = node.name

        for arg in node.args.args:
            self._add_node(arg.arg, "source")
            self.variable_origins[arg.arg] = "tainted"

        for decorator in getattr(node, "decorator_list", []):
            self.visit(decorator)

        for stmt in getattr(node, "body", []):
            self.visit(stmt)

        if getattr(node, "returns", None):
            self.visit(node.returns)

    def visit_With(self, node):
        self._visit_with_items(node)

    def visit_AsyncWith(self, node):
        self._visit_with_items(node)

    # =========================================================
    # ASSIGNMENTS
    # =========================================================

    def visit_Assign(self, node):

        # Corrección #3: marcamos que estamos dentro de un
        # Assign para que visit_Call no procese el mismo Call
        # como sink de forma independiente.
        self._processing_assign = True

        targets = [
            t.id
            for t in node.targets
            if isinstance(t, ast.Name)
        ]

        value = node.value

        # -------------------------------------------------
        # CASO 1: Asignación desde un Call
        # user = request.args.get("id")
        # user = os.system(...)   ← sink en RHS
        # -------------------------------------------------

        if isinstance(value, ast.Call):

            call_name = self._get_call_name(value)

            if call_name in self.SOURCES:

                for target in targets:

                    self._add_node(call_name, "source")
                    self._add_node(target, "variable")

                    self.graph.add_edge(
                        call_name,
                        target,
                        type="taint",
                    )

                    self.variable_origins[target] = "tainted"

            # Corrección #2: calls dentro del valor que son
            # sinks también deben propagarse al target.
            elif call_name in self.SINKS:

                sink_id = self._sink_id(call_name, value.lineno)

                self._add_node(sink_id, "sink", label=call_name)

                for arg in value.args:
                    self._flow_arg_to_node(arg, sink_id, "sink_flow")

                for target in targets:

                    self._add_node(target, "variable")

                    self.graph.add_edge(
                        sink_id,
                        target,
                        type="propagation",
                    )

        # -------------------------------------------------
        # CASO 2: Asignación desde una variable simple
        # Corrección #1: antes se descartaba ast.Name,
        # rompiendo la propagación de taint entre variables.
        # b = a   →  si a está taintada, b también lo está.
        # -------------------------------------------------

        elif isinstance(value, ast.Name):

            source_var = value.id

            for target in targets:

                self._add_node(source_var, "variable")
                self._add_node(target, "variable")

                self.graph.add_edge(
                    source_var,
                    target,
                    type="propagation",
                )

                if self.variable_origins.get(source_var) == "tainted":
                    self.variable_origins[target] = "tainted"

        # -------------------------------------------------
        # CASO 3: Asignación desde BinOp
        # query = "SELECT * FROM users WHERE id=" + user
        # Corrección #2: también detectamos calls embebidos
        # dentro del BinOp, no sólo ast.Name.
        # -------------------------------------------------

        elif isinstance(value, (ast.BinOp, ast.JoinedStr)):

            variables_used = self._extract_variables(value)

            # Corrección #2: extraer calls embebidos en el BinOp
            embedded_calls = self._extract_calls(value)

            for call_node in embedded_calls:

                call_name = self._get_call_name(call_node)

                if call_name in self.SOURCES:

                    synthetic = f"_src_{call_name}_{call_node.lineno}"

                    self._add_node(call_name, "source")
                    self._add_node(synthetic, "variable")

                    self.graph.add_edge(
                        call_name,
                        synthetic,
                        type="taint",
                    )

                    self.variable_origins[synthetic] = "tainted"

                    variables_used.append(synthetic)

            for source_var in variables_used:

                for target in targets:

                    self._add_node(source_var, "variable")
                    self._add_node(target, "variable")

                    self.graph.add_edge(
                        source_var,
                        target,
                        type="propagation",
                    )

                    if (
                        self.variable_origins.get(source_var)
                        == "tainted"
                    ):
                        self.variable_origins[target] = "tainted"

        # generic_visit para descender al resto del árbol
        self._processing_assign = False

        self.generic_visit(node)

    # =========================================================
    # SINK DETECTION
    # Corrección #3: sólo procesa calls como sinks cuando NO
    # estamos dentro de un visit_Assign, evitando el
    # double-dispatch que genera nodos duplicados.
    # =========================================================

    def visit_Call(self, node):

        if self._processing_assign:
            self.generic_visit(node)
            return

        call_name = self._get_call_name(node)

        if call_name in self.SINKS:

            # Corrección #4: separamos ID interno (único y
            # estable) del label legible. El ID sigue
            # incluyendo lineno para unicidad entre múltiples
            # llamadas al mismo sink, pero el label queda
            # limpio para búsquedas exactas en TaintAnalyzer.
            sink_id = self._sink_id(call_name, node.lineno)

            self._add_node(sink_id, "sink", label=call_name)

            for arg in node.args:
                self._flow_arg_to_node(arg, sink_id, "sink_flow")

        self.generic_visit(node)

    # =========================================================
    # HELPERS
    # =========================================================

    def _add_node(self, node_id: str, node_type: str, label: str = None):
        """
        Añade un nodo al grafo sólo si no existe ya.
        El label separado del ID resuelve la Corrección #4.
        """

        if not self.graph.has_node(node_id):

            self.graph.add_node(
                node_id,
                type=node_type,
                label=label or node_id,
            )

    def _sink_id(self, call_name: str, lineno: int) -> str:
        """
        Corrección #4: genera un ID interno único por sink.
        El TaintAnalyzer puede usar el atributo 'label'
        para lookup exacto en lugar del substring '@'.
        """

        return f"{call_name}@{lineno}"

    def _flow_arg_to_node(self, arg_node, target_id: str, edge_type: str):
        """
        Conecta todas las variables de un argumento al nodo destino.
        """

        variables = self._extract_variables(arg_node)

        for var in variables:

            self._add_node(var, "variable")

            self.graph.add_edge(
                var,
                target_id,
                type=edge_type,
            )

    def _get_call_name(self, node):

        if isinstance(node.func, ast.Name):
            return node.func.id

        elif isinstance(node.func, ast.Attribute):
            return self._resolve_attribute(node.func)

        return "unknown"

    def _visit_with_items(self, node):
        for item in getattr(node, "items", []):
            self.visit(item.context_expr)
            if item.optional_vars:
                self.visit(item.optional_vars)

        for stmt in getattr(node, "body", []):
            self.visit(stmt)

    def _resolve_attribute(self, node):

        parts = []

        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value

        if isinstance(node, ast.Name):
            parts.append(node.id)

        return ".".join(reversed(parts))

    def _extract_variables(self, node) -> list:
        """
        Extrae todos los ast.Name dentro de un nodo AST.
        """

        return [
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name)
        ]

    def _extract_calls(self, node) -> list:
        """
        Corrección #2: extrae todos los ast.Call embebidos
        dentro de un nodo AST (p.ej. dentro de un BinOp).
        """

        return [
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
        ]

    # =========================================================
    # EXPORT
    # =========================================================

    def export_graph(self):

        nodes = [
            {
                "id": node_id,
                "type": attrs.get("type"),
                # Corrección #4: exportamos label separado del ID
                "label": attrs.get("label", node_id),
            }
            for node_id, attrs in self.graph.nodes(data=True)
        ]

        edges = [
            {
                "source": source,
                "target": target,
                "type": attrs.get("type"),
            }
            for source, target, attrs in self.graph.edges(data=True)
        ]

        return {
            "nodes": nodes,
            "edges": edges,
            "tainted_variables": [
                var
                for var, state in self.variable_origins.items()
                if state == "tainted"
            ],
        }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    # Caso 1: source → variable simple → sink (original)
    sample_basic = """
import os

user = input()
query = "SELECT * FROM users WHERE id=" + user
os.system(query)
"""

    # Caso 2: propagación variable → variable (corrección #1)
    sample_alias = """
import os

raw = input()
user = raw
os.system(user)
"""

    # Caso 3: call embebido en BinOp (corrección #2)
    sample_embedded = """
import os

query = "SELECT * FROM users WHERE id=" + input()
os.system(query)
"""

    builder = DFGBuilder()

    import json

    print("=== CASO 1: básico ===")
    print(json.dumps(builder.build_from_code(sample_basic), indent=2))

    print("\n=== CASO 2: alias variable ===")
    print(json.dumps(builder.build_from_code(sample_alias), indent=2))

    print("\n=== CASO 3: call embebido en BinOp ===")
    print(json.dumps(builder.build_from_code(sample_embedded), indent=2))
