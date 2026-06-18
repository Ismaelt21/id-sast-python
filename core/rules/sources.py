"""
sources.py

Define todas las fuentes de datos NO confiables (tainted sources)
para el motor de Taint Analysis de PY-SAST.

Una SOURCE es cualquier entrada controlada parcial o totalmente
por un usuario, sistema externo o entorno no confiable.

Responsabilidades:
- Identificar entradas tainted
- Clasificar tipos de source
- Proveer matching rápido
- Facilitar análisis semántico
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


# =============================================================
# SOURCE MODEL
# =============================================================

@dataclass
class Source:
    """
    Modelo de source tainted.
    """

    name: str
    category: str
    risk: str
    description: str
    examples: List[str]
    aliases: List[str]
    framework: Optional[str] = None

    # Corrección #3: asdict() genera copia profunda, evitando
    # devolver referencia mutable al estado interno del objeto.
    def to_dict(self) -> Dict:
        return asdict(self)


# =============================================================
# SOURCES REGISTRY
# =============================================================

SOURCES: Dict[str, Source] = {

    # =========================================================
    # PYTHON INPUT
    # =========================================================

    "python_input": Source(
        name="input",
        category="USER_INPUT",
        risk="HIGH",
        description="Python console input",
        examples=[
            "input()"
        ],
        aliases=[
            "input",
        ]
    ),

    "sys_argv": Source(
        name="sys.argv",
        category="CLI_ARGUMENT",
        risk="MEDIUM",
        description="Command line arguments",
        examples=[
            "sys.argv[1]"
        ],
        aliases=[
            "sys.argv",
        ]
    ),

    "os_environ": Source(
        name="os.environ",
        category="ENVIRONMENT",
        risk="MEDIUM",
        description="Environment variables",
        examples=[
            "os.environ['TOKEN']"
        ],
        aliases=[
            "os.environ",
            "os.getenv",
        ]
    ),

    # =========================================================
    # FLASK
    # =========================================================

    "flask_request_args": Source(
        name="request.args",
        category="HTTP_GET",
        risk="HIGH",
        description="Flask GET parameters",
        examples=[
            "request.args.get('id')"
        ],
        aliases=[
            "request.args",
            "request.args.get",
        ],
        framework="flask"
    ),

    "flask_request_form": Source(
        name="request.form",
        category="HTTP_POST",
        risk="HIGH",
        description="Flask POST form data",
        examples=[
            "request.form['username']"
        ],
        aliases=[
            "request.form",
            "request.form.get",
        ],
        framework="flask"
    ),

    "flask_request_json": Source(
        name="request.json",
        category="JSON_BODY",
        risk="HIGH",
        description="Flask JSON body",
        examples=[
            "request.json"
        ],
        aliases=[
            "request.json",
            "request.get_json",
        ],
        framework="flask"
    ),

    "flask_request_headers": Source(
        name="request.headers",
        category="HTTP_HEADERS",
        risk="MEDIUM",
        description="Flask request headers",
        examples=[
            "request.headers.get('X-API-KEY')"
        ],
        aliases=[
            "request.headers",
        ],
        framework="flask"
    ),

    "flask_request_cookies": Source(
        name="request.cookies",
        category="COOKIES",
        risk="MEDIUM",
        description="Flask cookies",
        examples=[
            "request.cookies.get('session')"
        ],
        aliases=[
            "request.cookies",
        ],
        framework="flask"
    ),

    # =========================================================
    # DJANGO
    # =========================================================

    "django_get": Source(
        name="request.GET",
        category="HTTP_GET",
        risk="HIGH",
        description="Django GET params",
        examples=[
            "request.GET.get('id')"
        ],
        aliases=[
            "request.GET",
        ],
        framework="django"
    ),

    "django_post": Source(
        name="request.POST",
        category="HTTP_POST",
        risk="HIGH",
        description="Django POST params",
        examples=[
            "request.POST.get('username')"
        ],
        aliases=[
            "request.POST",
        ],
        framework="django"
    ),

    "django_body": Source(
        name="request.body",
        category="RAW_BODY",
        risk="HIGH",
        description="Raw request body",
        examples=[
            "request.body"
        ],
        aliases=[
            "request.body",
        ],
        framework="django"
    ),

    "django_headers": Source(
        name="request.headers",
        category="HTTP_HEADERS",
        risk="MEDIUM",
        description="HTTP headers",
        examples=[
            "request.headers.get('Authorization')"
        ],
        aliases=[
            "request.headers",
        ],
        framework="django"
    ),

    # =========================================================
    # FASTAPI
    # =========================================================

    "fastapi_query": Source(
        name="Query",
        category="HTTP_GET",
        risk="HIGH",
        description="FastAPI query params",
        examples=[
            "Query(...)"
        ],
        aliases=[
            "Query",
        ],
        framework="fastapi"
    ),

    "fastapi_body": Source(
        name="Body",
        category="JSON_BODY",
        risk="HIGH",
        description="FastAPI request body",
        examples=[
            "Body(...)"
        ],
        aliases=[
            "Body",
        ],
        framework="fastapi"
    ),

    "fastapi_header": Source(
        name="Header",
        category="HTTP_HEADERS",
        risk="MEDIUM",
        description="FastAPI headers",
        examples=[
            "Header(...)"
        ],
        aliases=[
            "Header",
        ],
        framework="fastapi"
    ),

    # =========================================================
    # NETWORK INPUTS
    # =========================================================

    "socket_recv": Source(
        name="socket.recv",
        category="NETWORK",
        risk="HIGH",
        description="Socket network input",
        examples=[
            "socket.recv(1024)"
        ],
        aliases=[
            "recv",
            "socket.recv",
        ]
    ),

    # =========================================================
    # FILE INPUTS
    # Corrección #1: 'open' eliminado como source. Es un sink
    # de PATH_TRAVERSAL en sinks.py. Tenerlo en ambos lados
    # rompía la dirección del flujo taint.
    # =========================================================

    # =========================================================
    # DESERIALIZATION INPUTS
    # Corrección #2: pickle.loads y yaml.load eliminados como
    # sources. Son sinks de INSECURE_DESERIALIZATION. El dato
    # peligroso llega a ellos desde request.body o socket.recv,
    # no sale de ellos hacia otros sinks.
    # =========================================================
}


# =============================================================
# SOURCE LOOKUP
# =============================================================

def is_source(function_name: str) -> bool:
    """
    Verifica si una función es source.
    Comparación exacta: primero por name, luego por aliases.
    """

    for source in SOURCES.values():

        if function_name == source.name:
            return True

        if function_name in source.aliases:
            return True

    return False


# =============================================================
# GET SOURCE
# =============================================================

def get_source(function_name: str) -> Optional[Source]:
    """
    Obtiene source por nombre o alias.
    """

    for source in SOURCES.values():

        if function_name == source.name:
            return source

        if function_name in source.aliases:
            return source

    return None


# =============================================================
# FILTER BY CATEGORY
# =============================================================

def get_sources_by_category(category: str) -> List[Source]:

    return [
        s for s in SOURCES.values()
        if s.category == category
    ]


# =============================================================
# FILTER BY FRAMEWORK
# =============================================================

def get_sources_by_framework(framework: str) -> List[Source]:

    return [
        s for s in SOURCES.values()
        if s.framework == framework
    ]


# =============================================================
# EXPORT
# =============================================================

def export_sources() -> Dict:

    return {
        key: value.to_dict()
        for key, value in SOURCES.items()
    }