import ast
import re
from copy import deepcopy


class ASTNormalizer(ast.NodeTransformer):

    """
    Normalizador central del SAST.

    Responsabilidades:
    - Abstraer variables
    - Abstraer literals
    - Detectar patterns
    - Estandarizar sinks/sources
    - Reducir variabilidad semántica
    """

    SOURCE_PATTERNS = {
        "input",
        "request.args.get",
        "request.form.get",
        "request.GET.get",
        "request.POST.get",
        "os.getenv",
    }

    SINK_PATTERNS = {
        "os.system",
        "subprocess.run",
        "subprocess.Popen",
        "eval",
        "exec",
        "cursor.execute",
    }

    SANITIZER_PATTERNS = {
        "escape",
        "html.escape",
        "bleach.clean",
        "int",
        "str",
    }

    SQL_KEYWORDS = {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "FROM",
        "WHERE"
    }

    def __init__(self):

        super().__init__()

        self.variable_map = {}

        self.variable_counter = 1

    # =========================================================
    # MAIN PIPELINE METHOD
    # =========================================================

    def normalize(self, ast_data: dict):

        """
        Método principal utilizado por el pipeline.
        """

        normalized = deepcopy(ast_data)

        # -----------------------------------------------------
        # IMPORTS
        # -----------------------------------------------------

        normalized["imports"] = [
            self._normalize_import(i)
            for i in ast_data.get("imports", [])
        ]

        # -----------------------------------------------------
        # FUNCTIONS
        # -----------------------------------------------------

        normalized["functions"] = [
            self._normalize_function(f)
            for f in ast_data.get("functions", [])
        ]

        # -----------------------------------------------------
        # CALLS
        # -----------------------------------------------------

        normalized["calls"] = [
            self._normalize_call(c)
            for c in ast_data.get("calls", [])
        ]

        # -----------------------------------------------------
        # ASSIGNMENTS
        # -----------------------------------------------------

        normalized["assignments"] = [
            self._normalize_assignment(a)
            for a in ast_data.get("assignments", [])
        ]

        # -----------------------------------------------------
        # CONTROL FLOW
        # -----------------------------------------------------

        normalized["ifs"] = ast_data.get("ifs", [])

        normalized["fors"] = ast_data.get("fors", [])

        normalized["whiles"] = ast_data.get("whiles", [])

        normalized["returns"] = ast_data.get("returns", [])

        return normalized

    # =========================================================
    # IMPORTS
    # =========================================================

    def _normalize_import(self, import_data):

        return {
            **import_data,
            "module": import_data["module"].lower()
        }

    # =========================================================
    # FUNCTIONS
    # =========================================================

    def _normalize_function(self, function_data):

        return {
            **function_data,
            "name": function_data["name"].lower()
        }

    # =========================================================
    # CALLS
    # =========================================================

    def _normalize_call(self, call_data):

        original_name = call_data["name"]

        normalized_name = self._normalize_call_name(
            original_name
        )

        return {
            **call_data,
            "name": normalized_name
        }

    # =========================================================
    # ASSIGNMENTS
    # =========================================================

    def _normalize_assignment(self, assignment):

        target = assignment.get("target", "VAR")

        value = assignment.get("value", "")

        normalized_target = self._normalize_variable(
            target
        )

        normalized_value = self._normalize_string(
            value
        )

        return {
            **assignment,
            "target": normalized_target,
            "value": normalized_value
        }

    # =========================================================
    # VARIABLE NORMALIZATION
    # =========================================================

    def _normalize_variable(self, variable_name):

        if variable_name not in self.variable_map:

            self.variable_map[
                variable_name
            ] = f"VAR_{self.variable_counter}"

            self.variable_counter += 1

        return self.variable_map[variable_name]

    # =========================================================
    # STRING NORMALIZATION
    # =========================================================

    def _normalize_string(self, value):

        if not isinstance(value, str):
            return value

        upper = value.upper()

        # SQL
        if any(
            keyword in upper
            for keyword in self.SQL_KEYWORDS
        ):
            return "SQL_STRING"

        # URL
        if re.match(r"^https?://", value):
            return "URL"

        # GENERIC STRING
        return "STRING"

    # =========================================================
    # CALL NAME NORMALIZATION
    # =========================================================

    def _normalize_call_name(self, function_name):

        if function_name in self.SOURCE_PATTERNS:
            return "USER_INPUT"

        if function_name in self.SINK_PATTERNS:
            return "DANGEROUS_SINK"

        if function_name in self.SANITIZER_PATTERNS:
            return "SANITIZER"

        return function_name