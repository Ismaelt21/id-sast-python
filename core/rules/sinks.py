"""
sinks.py

Define todas las operaciones peligrosas (SINKS)
para el motor de Taint Analysis de PY-SAST.

Un SINK es cualquier operación crítica donde
datos no confiables pueden causar una vulnerabilidad.

Responsabilidades:
- Identificar sinks peligrosos
- Clasificar vulnerabilidades
- Asociar CWE
- Facilitar taint analysis
- Facilitar semantic analysis
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


# =============================================================
# SINK MODEL
# =============================================================

@dataclass
class Sink:
    """
    Modelo de sink peligroso.
    """

    name: str
    vulnerability: str
    cwe: str
    severity: str
    description: str
    examples: List[str]
    aliases: List[str]
    framework: Optional[str] = None

    # Corrección #5: asdict() en lugar de __dict__.
    def to_dict(self) -> Dict:
        return asdict(self)


# =============================================================
# SINKS REGISTRY
# =============================================================

SINKS: Dict[str, Sink] = {

    # =========================================================
    # SQL INJECTION
    # Corrección #4: nombre principal cambiado de "execute"
    # (ambiguo, matchea cualquier método .execute()) a
    # "cursor.execute", consistente con el label limpio que
    # exporta dfg_builder y consume vulnerability_classifier.
    # =========================================================

    "sqlite_execute": Sink(
        name="cursor.execute",
        vulnerability="SQL_INJECTION",
        cwe="CWE-89",
        severity="CRITICAL",
        description="Raw SQL execution via cursor",
        examples=[
            "cursor.execute(query)"
        ],
        aliases=[
            "cursor.execute",
            "cursor.executemany",
        ]
    ),

    "sqlalchemy_text": Sink(
        name="text",
        vulnerability="SQL_INJECTION",
        cwe="CWE-89",
        severity="HIGH",
        description="Dynamic SQLAlchemy text query",
        examples=[
            "text(user_query)"
        ],
        aliases=[
            "text",
        ],
        framework="sqlalchemy"
    ),

    # =========================================================
    # COMMAND INJECTION
    # =========================================================

    "os_system": Sink(
        name="os.system",
        vulnerability="COMMAND_INJECTION",
        cwe="CWE-78",
        severity="CRITICAL",
        description="OS command execution",
        examples=[
            "os.system(user_input)"
        ],
        aliases=[
            "os.system",
        ]
    ),

    "subprocess_run": Sink(
        name="subprocess.run",
        vulnerability="COMMAND_INJECTION",
        cwe="CWE-78",
        severity="CRITICAL",
        description="Subprocess execution",
        examples=[
            "subprocess.run(cmd, shell=True)"
        ],
        aliases=[
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
        ]
    ),

    # =========================================================
    # CODE INJECTION
    # =========================================================

    "eval": Sink(
        name="eval",
        vulnerability="CODE_INJECTION",
        cwe="CWE-94",
        severity="CRITICAL",
        description="Dynamic code execution",
        examples=[
            "eval(user_input)"
        ],
        aliases=[
            "eval",
        ]
    ),

    "exec": Sink(
        name="exec",
        vulnerability="CODE_INJECTION",
        cwe="CWE-94",
        severity="CRITICAL",
        description="Python exec execution",
        examples=[
            "exec(user_code)"
        ],
        aliases=[
            "exec",
        ]
    ),

    # =========================================================
    # PATH TRAVERSAL
    # =========================================================

    "open": Sink(
        name="open",
        vulnerability="PATH_TRAVERSAL",
        cwe="CWE-22",
        severity="HIGH",
        description="File access with user-controlled path",
        examples=[
            "open(user_path)"
        ],
        aliases=[
            "open",
        ]
    ),

    "send_file": Sink(
        name="send_file",
        vulnerability="PATH_TRAVERSAL",
        cwe="CWE-22",
        severity="HIGH",
        description="File sending without path restriction",
        examples=[
            "send_file(path)"
        ],
        aliases=[
            "send_file",
        ],
        framework="flask"
    ),

    "send_from_directory": Sink(
        name="send_from_directory",
        vulnerability="PATH_TRAVERSAL",
        cwe="CWE-22",
        severity="HIGH",
        description="Directory file sending",
        examples=[
            "send_from_directory(base, filename)"
        ],
        aliases=[
            "send_from_directory",
        ],
        framework="flask"
    ),

    "os_remove": Sink(
        name="os.remove",
        vulnerability="PATH_TRAVERSAL",
        cwe="CWE-22",
        severity="HIGH",
        description="File deletion using user-controlled path",
        examples=[
            "os.remove(path)"
        ],
        aliases=[
            "os.remove",
            "os.unlink",
            "pathlib.Path.unlink",
        ]
    ),

    # =========================================================
    # SSRF
    # =========================================================

    "requests_get": Sink(
        name="requests.get",
        vulnerability="SSRF",
        cwe="CWE-918",
        severity="HIGH",
        description="Outbound HTTP GET request",
        examples=[
            "requests.get(url)"
        ],
        aliases=[
            "requests.get",
        ]
    ),

    "requests_post": Sink(
        name="requests.post",
        vulnerability="SSRF",
        cwe="CWE-918",
        severity="HIGH",
        description="Outbound HTTP POST request",
        examples=[
            "requests.post(url)"
        ],
        aliases=[
            "requests.post",
            "requests.put",
            "requests.delete",
        ]
    ),

    "urllib_urlopen": Sink(
        name="urllib.request.urlopen",
        vulnerability="SSRF",
        cwe="CWE-918",
        severity="HIGH",
        description="Remote URL fetch via urllib",
        examples=[
            "urllib.request.urlopen(url)"
        ],
        aliases=[
            "urllib.request.urlopen",
        ]
    ),

    "urllib_urlretrieve": Sink(
        name="urllib.request.urlretrieve",
        vulnerability="SSRF",
        cwe="CWE-918",
        severity="HIGH",
        description="Remote file download via urllib",
        examples=[
            "urllib.request.urlretrieve(url, path)"
        ],
        aliases=[
            "urllib.request.urlretrieve",
        ]
    ),

    "http_connection": Sink(
        name="http.client.HTTPConnection",
        vulnerability="SSRF",
        cwe="CWE-918",
        severity="HIGH",
        description="Outbound HTTP connection",
        examples=[
            "http.client.HTTPConnection(host)"
        ],
        aliases=[
            "http.client.HTTPConnection",
        ]
    ),

    # =========================================================
    # XSS
    # =========================================================

    "jinja_render": Sink(
        name="render_template_string",
        vulnerability="XSS",
        cwe="CWE-79",
        severity="HIGH",
        description="Dynamic HTML rendering",
        examples=[
            "render_template_string(user_html)"
        ],
        aliases=[
            "render_template_string",
        ],
        framework="flask"
    ),

    "flask_make_response": Sink(
        name="make_response",
        vulnerability="XSS",
        cwe="CWE-79",
        severity="HIGH",
        description="HTML response built from user-controlled data",
        examples=[
            "make_response(f'<p>{user}</p>')"
        ],
        aliases=[
            "make_response",
        ],
        framework="flask"
    ),

    # =========================================================
    # DESERIALIZATION
    # =========================================================

    "pickle_loads": Sink(
        name="pickle.loads",
        vulnerability="INSECURE_DESERIALIZATION",
        cwe="CWE-502",
        severity="CRITICAL",
        description="Unsafe pickle deserialization",
        examples=[
            "pickle.loads(data)"
        ],
        aliases=[
            "pickle.loads",
        ]
    ),

    "yaml_load": Sink(
        name="yaml.load",
        vulnerability="INSECURE_DESERIALIZATION",
        cwe="CWE-502",
        severity="CRITICAL",
        description="Unsafe YAML deserialization",
        examples=[
            "yaml.load(data)"
        ],
        aliases=[
            "yaml.load",
        ]
    ),

    # =========================================================
    # LDAP INJECTION
    # =========================================================

    "ldap_search": Sink(
        name="ldap.search_s",
        vulnerability="LDAP_INJECTION",
        cwe="CWE-90",
        severity="HIGH",
        description="LDAP query execution",
        examples=[
            "conn.search_s(base, scope, filter)"
        ],
        aliases=[
            "search_s",
            "ldap.search_s",
        ]
    ),

    # =========================================================
    # XXE
    # =========================================================

    "xml_parse": Sink(
        name="xml.etree.ElementTree.parse",
        vulnerability="XXE",
        cwe="CWE-611",
        severity="HIGH",
        description="Unsafe XML parsing",
        examples=[
            "etree.parse(data)"
        ],
        aliases=[
            "xml.parse",
            "etree.parse",
            "minidom.parse",
        ]
    ),

    # =========================================================
    # OPEN REDIRECT
    # =========================================================

    "redirect": Sink(
        name="redirect",
        vulnerability="OPEN_REDIRECT",
        cwe="CWE-601",
        severity="MEDIUM",
        description="User controlled redirect",
        examples=[
            "redirect(next_url)"
        ],
        aliases=[
            "redirect",
        ],
        framework="flask"
    ),
}


# =============================================================
# SINK LOOKUP
# =============================================================

def is_sink(function_name: str) -> bool:
    """
    Verifica si una función es sink.
    Comparación exacta: primero por name, luego por aliases.
    """

    for sink in SINKS.values():

        if function_name == sink.name:
            return True

        if function_name in sink.aliases:
            return True

    return False


# =============================================================
# GET SINK
# =============================================================

def get_sink(function_name: str) -> Optional[Sink]:
    """
    Obtiene sink por nombre o alias.
    """

    for sink in SINKS.values():

        if function_name == sink.name:
            return sink

        if function_name in sink.aliases:
            return sink

    return None


# =============================================================
# FILTER BY VULNERABILITY
# =============================================================

def get_sinks_by_vulnerability(vulnerability: str) -> List[Sink]:

    return [
        s for s in SINKS.values()
        if s.vulnerability == vulnerability
    ]


# =============================================================
# FILTER BY FRAMEWORK
# =============================================================

def get_sinks_by_framework(framework: str) -> List[Sink]:

    return [
        s for s in SINKS.values()
        if s.framework == framework
    ]


# =============================================================
# EXPORT
# =============================================================

def export_sinks() -> Dict:

    return {
        key: value.to_dict()
        for key, value in SINKS.items()
    }
