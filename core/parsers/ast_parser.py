import ast
from pathlib import Path


class ASTParser(ast.NodeVisitor):
    """
    AST Parser para análisis SAST.

    Responsabilidades:
    - Parsear código Python
    - Extraer estructura semántica
    - Generar metadata reutilizable
    - Servir de base para CFG/DFG/Taint Analysis
    """

    # =========================================================
    # INIT
    # =========================================================

    def __init__(self):

        self._reset()

    # =========================================================
    # RESET
    # =========================================================

    def _reset(self):

        self.nodes = []

        self.imports = []

        self.functions = []

        self.classes = []

        self.calls = []

        self.assignments = []

        self.control_flow = []

        self.returns = []

    # =========================================================
    # MAIN
    # =========================================================

    def parse(self, code: str, filename: str = "<memory>"):

        """
        Método principal utilizado por todo el pipeline.
        """

        self._reset()

        return self.parse_code(code, filename)

    def parse_file(self, file_path: str):

        path = Path(file_path)

        if not path.exists():

            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        code = path.read_text(
            encoding="utf-8"
        )

        return self.parse(
            code,
            str(path)
        )

    def parse_code(
        self,
        code: str,
        filename: str = "<memory>"
    ):

        tree = ast.parse(
            code,
            filename=filename
        )

        self.visit(tree)

        # =====================================================
        # COMPATIBILIDAD CON TESTS
        # =====================================================

        ifs = [
            x for x in self.control_flow
            if x["type"] == "if"
        ]

        fors = [
            x for x in self.control_flow
            if x["type"] == "for"
        ]

        whiles = [
            x for x in self.control_flow
            if x["type"] == "while"
        ]

        return {

            # -------------------------------------------------
            # Metadata
            # -------------------------------------------------

            "file": filename,

            "nodes": self.nodes,

            # -------------------------------------------------
            # AST Components
            # -------------------------------------------------

            "imports": self.imports,

            "functions": self.functions,

            "classes": self.classes,

            "calls": self.calls,

            "assignments": self.assignments,

            "control_flow": self.control_flow,

            "returns": self.returns,

            # -------------------------------------------------
            # Compatibilidad con tests
            # -------------------------------------------------

            "ifs": ifs,

            "fors": fors,

            "whiles": whiles,

            # -------------------------------------------------
            # Raw AST
            # -------------------------------------------------

            "raw_ast": ast.dump(
                tree,
                indent=2
            )
        }

    # =========================================================
    # IMPORTS
    # =========================================================

    def visit_Import(self, node):

        for alias in node.names:

            self.imports.append({
                "type": "import",

                "module": alias.name,

                "alias": alias.asname,

                "line": node.lineno
            })

        self.generic_visit(node)

    def visit_ImportFrom(self, node):

        self.imports.append({
            "type": "from_import",

            "module": node.module,

            "names": [
                n.name for n in node.names
            ],

            "line": node.lineno
        })

        self.generic_visit(node)

    # =========================================================
    # FUNCTIONS
    # =========================================================

    def visit_FunctionDef(self, node):

        function_returns = (
            self._extract_returns(node)
        )

        self.functions.append({

            "name": node.name,

            "args": [
                arg.arg
                for arg in node.args.args
            ],

            "line": node.lineno,

            "returns": function_returns
        })

        self.generic_visit(node)

    # =========================================================
    # CLASSES
    # =========================================================

    def visit_ClassDef(self, node):

        self.classes.append({

            "name": node.name,

            "line": node.lineno,

            "bases": [

                base.id
                if isinstance(base, ast.Name)
                else ast.dump(base)

                for base in node.bases
            ]
        })

        self.generic_visit(node)

    # =========================================================
    # CALLS
    # =========================================================

    def visit_Call(self, node):

        function_name = (
            self._get_call_name(node)
        )

        self.calls.append({

            # Arquitectura interna
            "function": function_name,

            # Compatibilidad tests
            "name": function_name,

            "line": node.lineno,

            "args": [
                self._safe_dump(arg)
                for arg in node.args
            ]
        })

        self.generic_visit(node)

    # =========================================================
    # ASSIGNMENTS
    # =========================================================

    def visit_Assign(self, node):

        targets = []

        for target in node.targets:

            if isinstance(target, ast.Name):

                targets.append(target.id)

            else:

                targets.append(
                    ast.dump(target)
                )

        self.assignments.append({

            # Compatibilidad tests
            "target": (
                targets[0]
                if targets else None
            ),

            # Arquitectura interna
            "targets": targets,

            "value": self._safe_dump(
                node.value
            ),

            "line": node.lineno
        })

        self.generic_visit(node)

    # =========================================================
    # RETURNS
    # =========================================================

    def visit_Return(self, node):

        self.returns.append({

            "value": (
                self._safe_dump(node.value)
                if node.value else None
            ),

            "line": node.lineno
        })

        self.generic_visit(node)

    # =========================================================
    # CONTROL FLOW
    # =========================================================

    def visit_If(self, node):

        self.control_flow.append({

            "type": "if",

            "condition": self._safe_dump(
                node.test
            ),

            "line": node.lineno
        })

        self.generic_visit(node)

    def visit_For(self, node):

        self.control_flow.append({

            "type": "for",

            "target": self._safe_dump(
                node.target
            ),

            "iter": self._safe_dump(
                node.iter
            ),

            "line": node.lineno
        })

        self.generic_visit(node)

    def visit_While(self, node):

        self.control_flow.append({

            "type": "while",

            "condition": self._safe_dump(
                node.test
            ),

            "line": node.lineno
        })

        self.generic_visit(node)

    # =========================================================
    # HELPERS
    # =========================================================

    def _get_call_name(self, node):

        """
        Obtiene el nombre completo de la función.

        Ej:
            print
            os.system
            db.execute
        """

        if isinstance(node.func, ast.Name):

            return node.func.id

        elif isinstance(node.func, ast.Attribute):

            return self._resolve_attribute(
                node.func
            )

        return "unknown"

    def _resolve_attribute(self, node):

        parts = []

        while isinstance(
            node,
            ast.Attribute
        ):

            parts.append(node.attr)

            node = node.value

        if isinstance(node, ast.Name):

            parts.append(node.id)

        return ".".join(
            reversed(parts)
        )

    def _extract_returns(
        self,
        function_node
    ):

        returns = []

        for node in ast.walk(function_node):

            if isinstance(node, ast.Return):

                returns.append(

                    self._safe_dump(node.value)
                    if node.value else None
                )

        return returns

    def _safe_dump(self, node):

        try:

            return ast.dump(node)

        except Exception:

            return str(node)


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    sample_code = """
import os
from flask import request

def test():
    user = request.args.get("id")
    os.system(user)
"""

    parser = ASTParser()

    result = parser.parse(sample_code)

    import json

    print(
        json.dumps(
            result,
            indent=2
        )
    )