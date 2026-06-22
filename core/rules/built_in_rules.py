"""
built_in_rules.py

Reglas vulnerables predefinidas para PY-SAST.

Estas reglas representan patrones conocidos de:
- taint flow
- subgraphs vulnerables
- combinaciones SOURCE -> SINK
- ausencia de sanitización

Estas reglas son utilizadas por:
- pattern_matcher.py
- subgraph_matcher.py
- taint_analyzer.py
- semantic_analyzer.py

IMPORTANTE:
Los valores en 'sinks' deben ser exactamente los labels
limpios que exporta dfg_builder (sin @lineno) y que están
registrados en sinks.py. El pattern_matcher hace match
exacto contra estos valores.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional

from core.rules.sinks import get_sink, get_sinks_by_vulnerability
from core.rules.sources import get_source


# =============================================================
# RULE MODEL
# =============================================================

@dataclass
class BuiltInRule:
    """
    Modelo de regla vulnerable.
    """

    rule_id: str
    name: str
    vulnerability_type: str
    cwe_id: str
    severity: str
    description: str
    sources: List[str]
    sinks: List[str]
    sanitizers: List[str]
    required_nodes: List[str]
    required_edges: List[str]
    dangerous_patterns: List[str]
    safe_patterns: List[str]
    confidence: float
    examples: List[str]

    # Corrección #10: asdict() en lugar de __dict__.
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================
# BUILT-IN RULES
# Corrección #9: los valores en 'sinks' ahora usan los labels
# limpios exactos (sin @lineno), consistentes con sinks.py y
# con el label que exporta dfg_builder. El pattern_matcher
# hace match exacto sobre sink_label contra estos valores.
# =============================================================

BUILT_IN_RULES: Dict[str, BuiltInRule] = {

    # =========================================================
    # SQL INJECTION
    # =========================================================

    "sql_injection_rule": BuiltInRule(
        rule_id="RULE-001",
        name="SQL Injection Pattern",
        vulnerability_type="SQL_INJECTION",
        cwe_id="CWE-89",
        severity="CRITICAL",
        description=(
            "Detects user-controlled input flowing into SQL "
            "execution without parameterization."
        ),
        sources=[
            "input",
            "request.args",
            "request.args.get",
            "request.form",
            "request.form.get",
            "request.GET",
            "request.POST",
        ],
        # Corrección #9: "execute" → "cursor.execute" y
        # "executemany" → "cursor.executemany", consistentes
        # con sinks.py y el label limpio del dfg_builder.
        sinks=[
            "cursor.execute",
            "cursor.executemany",
            "text",
        ],
        sanitizers=[
            "bindparams",
            "filter",
        ],
        required_nodes=[
            "SOURCE",
            "VARIABLE",
            "CONCAT",
            "SQL_QUERY",
            "SINK",
        ],
        required_edges=[
            "SOURCE_TO_VARIABLE",
            "VARIABLE_TO_QUERY",
            "QUERY_TO_SINK",
        ],
        dangerous_patterns=[
            "string_concat_sql",
            "fstring_sql",
            "format_sql",
        ],
        safe_patterns=[
            "parameterized_query",
        ],
        confidence=0.95,
        examples=[
            "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
        ]
    ),

    # =========================================================
    # COMMAND INJECTION
    # =========================================================

    "command_injection_rule": BuiltInRule(
        rule_id="RULE-002",
        name="Command Injection Pattern",
        vulnerability_type="COMMAND_INJECTION",
        cwe_id="CWE-78",
        severity="CRITICAL",
        description=(
            "Detects untrusted input reaching shell execution."
        ),
        sources=[
            "input",
            "request.args",
            "request.args.get",
            "request.form",
            "sys.argv",
        ],
        sinks=[
            "os.system",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
        ],
        sanitizers=[
            "shlex.quote",
        ],
        required_nodes=[
            "SOURCE",
            "COMMAND_STRING",
            "SINK",
        ],
        required_edges=[
            "SOURCE_TO_COMMAND",
            "COMMAND_TO_SINK",
        ],
        dangerous_patterns=[
            "shell_concat",
            "dynamic_command",
        ],
        safe_patterns=[
            "quoted_command",
        ],
        confidence=0.98,
        examples=[
            "os.system('ping ' + host)"
        ]
    ),

    # =========================================================
    # CODE INJECTION
    # =========================================================

    "code_injection_rule": BuiltInRule(
        rule_id="RULE-003",
        name="Code Injection Pattern",
        vulnerability_type="CODE_INJECTION",
        cwe_id="CWE-94",
        severity="CRITICAL",
        description=(
            "Detects untrusted data executed dynamically."
        ),
        sources=[
            "input",
            "request.args",
            "request.args.get",
            "request.form",
        ],
        sinks=[
            "eval",
            "exec",
        ],
        sanitizers=[],
        required_nodes=[
            "SOURCE",
            "CODE_STRING",
            "SINK",
        ],
        required_edges=[
            "SOURCE_TO_CODE",
            "CODE_TO_SINK",
        ],
        dangerous_patterns=[
            "dynamic_eval",
            "dynamic_exec",
        ],
        safe_patterns=[],
        confidence=0.99,
        examples=[
            "eval(user_input)"
        ]
    ),

    # =========================================================
    # XSS
    # =========================================================

    "xss_rule": BuiltInRule(
        rule_id="RULE-004",
        name="Cross Site Scripting Pattern",
        vulnerability_type="XSS",
        cwe_id="CWE-79",
        severity="HIGH",
        description=(
            "Detects user-controlled HTML rendered without escaping."
        ),
        sources=[
            "request.args",
            "request.args.get",
            "request.form",
            "request.GET",
            "request.POST",
        ],
        sinks=[
            "render_template_string",
        ],
        sanitizers=[
            "html.escape",
            "markupsafe.escape",
            "escape",
            "bleach.clean",
        ],
        required_nodes=[
            "SOURCE",
            "HTML_CONTENT",
            "SINK",
        ],
        required_edges=[
            "SOURCE_TO_HTML",
            "HTML_TO_SINK",
        ],
        dangerous_patterns=[
            "unsafe_render",
            "dynamic_html",
        ],
        safe_patterns=[
            "escaped_html",
        ],
        confidence=0.90,
        examples=[
            "render_template_string(user_html)"
        ]
    ),

    # =========================================================
    # PATH TRAVERSAL
    # =========================================================

    "path_traversal_rule": BuiltInRule(
        rule_id="RULE-005",
        name="Path Traversal Pattern",
        vulnerability_type="PATH_TRAVERSAL",
        cwe_id="CWE-22",
        severity="HIGH",
        description=(
            "Detects user-controlled filesystem paths."
        ),
        sources=[
            "input",
            "request.args",
            "request.args.get",
            "request.GET",
        ],
        sinks=[
            "open",
            "send_file",
            "send_from_directory",
            "os.remove",
            "os.unlink",
            "pathlib.Path.unlink",
        ],
        sanitizers=[
            "secure_filename",
            "os.path.abspath",
            "os.path.normpath",
        ],
        required_nodes=[
            "SOURCE",
            "FILE_PATH",
            "SINK",
        ],
        required_edges=[
            "SOURCE_TO_PATH",
            "PATH_TO_SINK",
        ],
        dangerous_patterns=[
            "../",
            "..\\",
        ],
        safe_patterns=[
            "normalized_path",
        ],
        confidence=0.88,
        examples=[
            "open(user_path)"
        ]
    ),

    # =========================================================
    # SSRF
    # =========================================================

    "ssrf_rule": BuiltInRule(
        rule_id="RULE-006",
        name="Server Side Request Forgery Pattern",
        vulnerability_type="SSRF",
        cwe_id="CWE-918",
        severity="HIGH",
        description=(
            "Detects user-controlled URLs used in outbound requests."
        ),
        sources=[
            "request.args",
            "request.args.get",
            "request.GET",
            "request.form",
        ],
        sinks=[
            "requests.get",
            "requests.post",
            "urllib.request.urlopen",
            "urllib.request.urlretrieve",
            "http.client.HTTPConnection",
        ],
        sanitizers=[
            "validators.url",
        ],
        required_nodes=[
            "SOURCE",
            "URL",
            "SINK",
        ],
        required_edges=[
            "SOURCE_TO_URL",
            "URL_TO_SINK",
        ],
        dangerous_patterns=[
            "internal_ip",
            "localhost_access",
        ],
        safe_patterns=[
            "validated_url",
        ],
        confidence=0.87,
        examples=[
            "requests.get(user_url)"
        ]
    ),

    # =========================================================
    # INSECURE DESERIALIZATION
    # =========================================================

    "deserialization_rule": BuiltInRule(
        rule_id="RULE-007",
        name="Insecure Deserialization Pattern",
        vulnerability_type="INSECURE_DESERIALIZATION",
        cwe_id="CWE-502",
        severity="CRITICAL",
        description=(
            "Detects unsafe deserialization of untrusted data."
        ),
        sources=[
            "request.body",
            "request.data",
            "socket.recv",
            "recv",
        ],
        sinks=[
            "pickle.loads",
            "yaml.load",
        ],
        sanitizers=[
            "yaml.safe_load",
        ],
        required_nodes=[
            "SOURCE",
            "SERIALIZED_DATA",
            "SINK",
        ],
        required_edges=[
            "SOURCE_TO_DATA",
            "DATA_TO_SINK",
        ],
        dangerous_patterns=[
            "unsafe_pickle",
            "unsafe_yaml",
        ],
        safe_patterns=[
            "safe_yaml",
        ],
        confidence=0.97,
        examples=[
            "pickle.loads(user_data)"
        ]
    ),
}


# =============================================================
# RULE LOOKUP
# =============================================================

def get_rule(rule_name: str) -> Optional[BuiltInRule]:

    return BUILT_IN_RULES.get(rule_name)


def get_all_rules() -> List[BuiltInRule]:

    return list(BUILT_IN_RULES.values())


def get_rules_by_vulnerability(
    vulnerability_type: str,
) -> List[BuiltInRule]:

    return [
        rule
        for rule in BUILT_IN_RULES.values()
        if rule.vulnerability_type == vulnerability_type
    ]


# =============================================================
# MATCH RULE BY SINK
# Corrección #11: ahora acepta el label limpio del sink y
# delega en sinks.py para resolución, evitando duplicar
# lógica de matching y siendo robusto ante IDs con @lineno.
# =============================================================

def match_rule_by_sink(sink_label: str) -> List[BuiltInRule]:
    """
    Busca reglas compatibles con un sink dado su label limpio.

    Corrección #11: en lugar de comparar sink_label contra
    rule.sinks con 'in' directo (que fallaba con IDs @lineno),
    ahora verifica si el label está registrado en sinks.py y
    busca reglas cuya vulnerability_type coincida con la del
    sink. Esto desacopla las reglas del formato interno del ID.
    """

    sink_obj = get_sink(sink_label)

    if not sink_obj:
        return []

    return get_rules_by_vulnerability(sink_obj.vulnerability)


def match_rule_by_source(source_name: str) -> List[BuiltInRule]:
    """
    Busca reglas compatibles con un source dado.
    """

    matches = []

    for rule in BUILT_IN_RULES.values():

        if source_name in rule.sources:
            matches.append(rule)

    return matches


# =============================================================
# EXPORT
# =============================================================

def export_rules() -> Dict[str, Any]:

    return {
        key: value.to_dict()
        for key, value in BUILT_IN_RULES.items()
    }
