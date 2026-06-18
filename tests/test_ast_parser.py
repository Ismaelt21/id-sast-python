"""
tests/test_ast_parser.py

Tests unitarios para ASTParser.
"""

import pytest
from core.parsers.ast_parser import ASTParser


# =============================================================
# FIXTURES
# =============================================================

@pytest.fixture
def parser():
    return ASTParser()


SIMPLE_CODE = """
import os
from flask import request

def vulnerable(user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return query

class MyClass(object):
    pass

x = 1
y = x + 2

if x > 0:
    pass

for i in range(10):
    pass

while x > 0:
    break
"""

EMPTY_CODE = ""

CODE_WITH_IMPORTS = """
import os
import sys
from flask import request, render_template
from pathlib import Path
"""

CODE_WITH_CALLS = """
os.system("ls")
eval(user_input)
cursor.execute(query)
request.args.get("id")
"""


# =============================================================
# PARSE RETURNS EXPECTED KEYS
# =============================================================

class TestParseStructure:

    def test_parse_returns_dict(self, parser):
        result = parser.parse(SIMPLE_CODE)
        assert isinstance(result, dict)

    def test_parse_contains_required_keys(self, parser):
        result = parser.parse(SIMPLE_CODE)
        required = [
            "file", "nodes", "imports", "functions",
            "classes", "calls", "assignments",
            "control_flow", "returns",
            "ifs", "fors", "whiles", "raw_ast",
        ]
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_parse_file_defaults_to_memory(self, parser):
        result = parser.parse(SIMPLE_CODE)
        assert result["file"] == "<memory>"

    def test_parse_file_with_custom_filename(self, parser):
        result = parser.parse(SIMPLE_CODE, filename="test.py")
        assert result["file"] == "test.py"

    def test_parse_empty_code(self, parser):
        result = parser.parse(EMPTY_CODE)
        assert result["imports"]     == []
        assert result["functions"]   == []
        assert result["classes"]     == []
        assert result["calls"]       == []
        assert result["assignments"] == []

    def test_raw_ast_is_string(self, parser):
        result = parser.parse(SIMPLE_CODE)
        assert isinstance(result["raw_ast"], str)
        assert len(result["raw_ast"]) > 0


# =============================================================
# IMPORTS
# =============================================================

class TestImports:

    def test_detects_simple_import(self, parser):
        result = parser.parse(CODE_WITH_IMPORTS)
        modules = [i["module"] for i in result["imports"]]
        assert "os" in modules
        assert "sys" in modules

    def test_detects_from_import(self, parser):
        result = parser.parse(CODE_WITH_IMPORTS)
        from_imports = [
            i for i in result["imports"]
            if i["type"] == "from_import"
        ]
        assert len(from_imports) > 0

    def test_from_import_has_module(self, parser):
        result = parser.parse(CODE_WITH_IMPORTS)
        flask_import = next(
            (i for i in result["imports"] if i["module"] == "flask"),
            None,
        )
        assert flask_import is not None
        assert "request" in flask_import["names"]

    def test_import_has_line_number(self, parser):
        result = parser.parse(CODE_WITH_IMPORTS)
        for imp in result["imports"]:
            assert "line" in imp
            assert isinstance(imp["line"], int)
            assert imp["line"] > 0

    def test_import_alias_none_when_absent(self, parser):
        result = parser.parse("import os")
        imp = result["imports"][0]
        assert imp["alias"] is None

    def test_import_alias_captured(self, parser):
        result = parser.parse("import numpy as np")
        imp = result["imports"][0]
        assert imp["alias"] == "np"


# =============================================================
# FUNCTIONS
# =============================================================

class TestFunctions:

    def test_detects_function(self, parser):
        result = parser.parse(SIMPLE_CODE)
        names = [f["name"] for f in result["functions"]]
        assert "vulnerable" in names

    def test_function_has_args(self, parser):
        result = parser.parse(SIMPLE_CODE)
        fn = next(f for f in result["functions"] if f["name"] == "vulnerable")
        assert "user_id" in fn["args"]

    def test_function_has_line(self, parser):
        result = parser.parse(SIMPLE_CODE)
        for fn in result["functions"]:
            assert "line" in fn
            assert isinstance(fn["line"], int)

    def test_function_returns_extracted(self, parser):
        result = parser.parse(SIMPLE_CODE)
        fn = next(f for f in result["functions"] if f["name"] == "vulnerable")
        assert isinstance(fn["returns"], list)

    def test_no_args_function(self, parser):
        result = parser.parse("def foo(): pass")
        fn = result["functions"][0]
        assert fn["args"] == []


# =============================================================
# CLASSES
# =============================================================

class TestClasses:

    def test_detects_class(self, parser):
        result = parser.parse(SIMPLE_CODE)
        names = [c["name"] for c in result["classes"]]
        assert "MyClass" in names

    def test_class_has_bases(self, parser):
        result = parser.parse(SIMPLE_CODE)
        cls = next(c for c in result["classes"] if c["name"] == "MyClass")
        assert "object" in cls["bases"]

    def test_class_has_line(self, parser):
        result = parser.parse(SIMPLE_CODE)
        for cls in result["classes"]:
            assert "line" in cls
            assert isinstance(cls["line"], int)


# =============================================================
# CALLS
# =============================================================

class TestCalls:

    def test_detects_calls(self, parser):
        result = parser.parse(CODE_WITH_CALLS)
        names = [c["name"] for c in result["calls"]]
        assert "os.system" in names
        assert "eval" in names

    def test_call_has_line(self, parser):
        result = parser.parse(CODE_WITH_CALLS)
        for call in result["calls"]:
            assert "line" in call
            assert isinstance(call["line"], int)

    def test_call_has_args(self, parser):
        result = parser.parse(CODE_WITH_CALLS)
        for call in result["calls"]:
            assert "args" in call
            assert isinstance(call["args"], list)

    def test_call_name_and_function_consistent(self, parser):
        result = parser.parse(CODE_WITH_CALLS)
        for call in result["calls"]:
            assert call["name"] == call["function"]

    def test_method_call_resolved(self, parser):
        result = parser.parse("cursor.execute(query)")
        names = [c["name"] for c in result["calls"]]
        assert "cursor.execute" in names


# =============================================================
# ASSIGNMENTS
# =============================================================

class TestAssignments:

    def test_detects_assignment(self, parser):
        result = parser.parse("x = 1")
        assert len(result["assignments"]) == 1

    def test_assignment_target(self, parser):
        result = parser.parse("x = 1")
        assert result["assignments"][0]["target"] == "x"

    def test_assignment_has_value(self, parser):
        result = parser.parse("x = 1")
        assert "value" in result["assignments"][0]

    def test_assignment_has_targets_list(self, parser):
        result = parser.parse("x = 1")
        assert "targets" in result["assignments"][0]
        assert isinstance(result["assignments"][0]["targets"], list)

    def test_assignment_has_line(self, parser):
        result = parser.parse("x = 1\ny = 2")
        for a in result["assignments"]:
            assert "line" in a


# =============================================================
# CONTROL FLOW
# =============================================================

class TestControlFlow:

    def test_detects_if(self, parser):
        result = parser.parse(SIMPLE_CODE)
        assert len(result["ifs"]) > 0
        assert all(i["type"] == "if" for i in result["ifs"])

    def test_detects_for(self, parser):
        result = parser.parse(SIMPLE_CODE)
        assert len(result["fors"]) > 0
        assert all(f["type"] == "for" for f in result["fors"])

    def test_detects_while(self, parser):
        result = parser.parse(SIMPLE_CODE)
        assert len(result["whiles"]) > 0
        assert all(w["type"] == "while" for w in result["whiles"])

    def test_control_flow_compatibility(self, parser):
        result = parser.parse(SIMPLE_CODE)
        total = (
            len(result["ifs"])
            + len(result["fors"])
            + len(result["whiles"])
        )
        assert len(result["control_flow"]) == total

    def test_if_has_condition(self, parser):
        result = parser.parse("if x > 0:\n    pass")
        assert "condition" in result["ifs"][0]

    def test_for_has_iter(self, parser):
        result = parser.parse("for i in range(10):\n    pass")
        assert "iter" in result["fors"][0]

    def test_while_has_condition(self, parser):
        result = parser.parse("while True:\n    break")
        assert "condition" in result["whiles"][0]


# =============================================================
# RETURNS
# =============================================================

class TestReturns:

    def test_detects_return(self, parser):
        result = parser.parse("def f():\n    return 1")
        assert len(result["returns"]) > 0

    def test_return_none(self, parser):
        result = parser.parse("def f():\n    return")
        assert result["returns"][0]["value"] is None

    def test_return_has_line(self, parser):
        result = parser.parse("def f():\n    return 1")
        assert "line" in result["returns"][0]


# =============================================================
# RESET BETWEEN CALLS
# =============================================================

class TestReset:

    def test_parse_resets_state(self, parser):
        parser.parse("import os\nimport sys")
        result = parser.parse("import json")
        modules = [i["module"] for i in result["imports"]]
        assert "os"   not in modules
        assert "sys"  not in modules
        assert "json" in modules

    def test_parse_file_resets_state(self, parser):
        parser.parse("def foo(): pass")
        result = parser.parse("def bar(): pass")
        names = [f["name"] for f in result["functions"]]
        assert "foo" not in names
        assert "bar" in names