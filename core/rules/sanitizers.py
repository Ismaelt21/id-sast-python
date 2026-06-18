"""
sanitizers.py

Define funciones y mecanismos de sanitización conocidos
para PY-SAST.

Un sanitizer es cualquier función/proceso que:
- valide
- escape
- filtre
- encodee
- parametrice

datos potencialmente peligrosos antes de llegar
a un sink crítico.

Responsabilidades:
- Detectar mitigaciones
- Reducir falsos positivos
- Ayudar al semantic analyzer
- Mejorar confidence scoring
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


# =============================================================
# SANITIZER MODEL
# =============================================================

@dataclass
class Sanitizer:
    """
    Modelo de sanitizer.
    """

    name: str
    category: str
    protects_against: List[str]
    effectiveness: str
    description: str
    examples: List[str]
    aliases: List[str]
    framework: Optional[str] = None

    # Corrección #8: asdict() en lugar de __dict__.
    def to_dict(self) -> Dict:
        return asdict(self)


# =============================================================
# SANITIZERS REGISTRY
# =============================================================

SANITIZERS: Dict[str, Sanitizer] = {

    # =========================================================
    # SQL INJECTION
    # Corrección #6: eliminado "parameterized_queries" con
    # name="execute". cursor.execute es un SINK, no un
    # sanitizer. El mecanismo seguro es el uso de placeholders
    # (bindparams, prepared statements), no la función execute
    # en sí misma.
    # =========================================================

    "sqlalchemy_bindparams": Sanitizer(
        name="bindparams",
        category="SQL_PARAMETERIZATION",
        protects_against=[
            "SQL_INJECTION",
        ],
        effectiveness="HIGH",
        description=(
            "SQLAlchemy bind parameters. Separates SQL structure "
            "from data, preventing injection."
        ),
        examples=[
            "text(query).bindparams(id=user_id)"
        ],
        aliases=[
            "bindparams",
        ],
        framework="sqlalchemy"
    ),

    "django_orm": Sanitizer(
        name="filter",
        category="SQL_PARAMETERIZATION",
        protects_against=[
            "SQL_INJECTION",
        ],
        effectiveness="HIGH",
        description="Django ORM parameterized queries",
        examples=[
            "User.objects.filter(id=user_id)"
        ],
        aliases=[
            "filter",
            "exclude",
            "get",
        ],
        framework="django"
    ),

    # =========================================================
    # XSS
    # Corrección #7: alias "escape" estaba duplicado entre
    # html_escape y markupsafe_escape causando comportamiento
    # no determinista en is_sanitizer(). Ahora cada sanitizer
    # tiene aliases exclusivos. "escape" queda solo en
    # markupsafe_escape porque es su nombre canónico de import
    # (from markupsafe import escape). html.escape se accede
    # siempre con el nombre completo.
    # =========================================================

    "html_escape": Sanitizer(
        name="html.escape",
        category="OUTPUT_ENCODING",
        protects_against=[
            "XSS",
        ],
        effectiveness="HIGH",
        description="Python stdlib HTML escaping",
        examples=[
            "html.escape(user_input)"
        ],
        aliases=[
            "html.escape",
        ]
    ),

    "markupsafe_escape": Sanitizer(
        name="markupsafe.escape",
        category="OUTPUT_ENCODING",
        protects_against=[
            "XSS",
        ],
        effectiveness="HIGH",
        description="MarkupSafe escaping used by Jinja2",
        examples=[
            "from markupsafe import escape",
            "escape(user_html)",
        ],
        aliases=[
            "markupsafe.escape",
            "escape",
        ]
    ),

    "bleach_clean": Sanitizer(
        name="bleach.clean",
        category="HTML_SANITIZATION",
        protects_against=[
            "XSS",
        ],
        effectiveness="HIGH",
        description="HTML sanitization allowing safe tags",
        examples=[
            "bleach.clean(user_html)"
        ],
        aliases=[
            "bleach.clean",
        ]
    ),

    # =========================================================
    # COMMAND INJECTION
    # =========================================================

    "shlex_quote": Sanitizer(
        name="shlex.quote",
        category="COMMAND_ESCAPING",
        protects_against=[
            "COMMAND_INJECTION",
        ],
        effectiveness="HIGH",
        description=(
            "Shell-escapes a string so it is safe to use as a "
            "single argument in a shell command."
        ),
        examples=[
            "shlex.quote(user_input)"
        ],
        aliases=[
            "shlex.quote",
        ]
    ),

    # =========================================================
    # PATH TRAVERSAL
    # =========================================================

    "secure_filename": Sanitizer(
        name="secure_filename",
        category="PATH_SANITIZATION",
        protects_against=[
            "PATH_TRAVERSAL",
        ],
        effectiveness="HIGH",
        description="Sanitizes filenames, strips path separators",
        examples=[
            "secure_filename(filename)"
        ],
        aliases=[
            "secure_filename",
        ],
        framework="flask"
    ),

    "path_abspath": Sanitizer(
        name="os.path.abspath",
        category="PATH_NORMALIZATION",
        protects_against=[
            "PATH_TRAVERSAL",
        ],
        effectiveness="MEDIUM",
        description=(
            "Resolves path to absolute form. Must be combined "
            "with an allowlist check to be fully effective."
        ),
        examples=[
            "os.path.abspath(user_path)"
        ],
        aliases=[
            "os.path.abspath",
            "os.path.normpath",
        ]
    ),

    # =========================================================
    # SSRF
    # =========================================================

    "url_validation": Sanitizer(
        name="validators.url",
        category="URL_VALIDATION",
        protects_against=[
            "SSRF",
        ],
        effectiveness="MEDIUM",
        description=(
            "URL format validation. Effectiveness is MEDIUM "
            "because format-valid URLs can still target internal "
            "resources; pair with an allowlist."
        ),
        examples=[
            "validators.url(user_url)"
        ],
        aliases=[
            "validators.url",
        ]
    ),

    # =========================================================
    # INPUT VALIDATION
    # =========================================================

    "int_cast": Sanitizer(
        name="int",
        category="TYPE_CASTING",
        protects_against=[
            "SQL_INJECTION",
            "COMMAND_INJECTION",
        ],
        effectiveness="MEDIUM",
        description=(
            "Casting to int raises ValueError on non-numeric "
            "input, effectively blocking most injection payloads."
        ),
        examples=[
            "int(user_id)"
        ],
        aliases=[
            "int",
        ]
    ),

    "float_cast": Sanitizer(
        name="float",
        category="TYPE_CASTING",
        protects_against=[
            "SQL_INJECTION",
        ],
        effectiveness="LOW",
        description="Float casting for numeric validation",
        examples=[
            "float(user_value)"
        ],
        aliases=[
            "float",
        ]
    ),

    "regex_validation": Sanitizer(
        name="re.match",
        category="INPUT_VALIDATION",
        protects_against=[
            "SQL_INJECTION",
            "XSS",
            "COMMAND_INJECTION",
        ],
        effectiveness="MEDIUM",
        description=(
            "Regex validation. Effectiveness depends entirely "
            "on the pattern used; overly permissive patterns "
            "may not block injection."
        ),
        examples=[
            "re.match(r'^[a-zA-Z0-9]+$', user_input)"
        ],
        aliases=[
            "re.match",
            "re.fullmatch",
        ]
    ),

    # =========================================================
    # SAFE DESERIALIZATION
    # =========================================================

    "yaml_safe_load": Sanitizer(
        name="yaml.safe_load",
        category="SAFE_DESERIALIZATION",
        protects_against=[
            "INSECURE_DESERIALIZATION",
        ],
        effectiveness="HIGH",
        description=(
            "Safe YAML loader that does not construct arbitrary "
            "Python objects."
        ),
        examples=[
            "yaml.safe_load(data)"
        ],
        aliases=[
            "yaml.safe_load",
        ]
    ),

    # =========================================================
    # XML SAFE PARSING
    # =========================================================

    "defusedxml": Sanitizer(
        name="defusedxml",
        category="SAFE_XML",
        protects_against=[
            "XXE",
        ],
        effectiveness="HIGH",
        description=(
            "Drop-in replacement for stdlib XML parsers that "
            "disables dangerous XML features (entity expansion, "
            "DTD processing)."
        ),
        examples=[
            "from defusedxml import ElementTree",
            "ElementTree.parse(data)",
        ],
        aliases=[
            "defusedxml",
        ]
    ),
}


# =============================================================
# SANITIZER LOOKUP
# =============================================================

def is_sanitizer(function_name: str) -> bool:
    """
    Verifica si una función es sanitizer.
    Comparación exacta: primero por name, luego por aliases.
    """

    for sanitizer in SANITIZERS.values():

        if function_name == sanitizer.name:
            return True

        if function_name in sanitizer.aliases:
            return True

    return False


# =============================================================
# GET SANITIZER
# =============================================================

def get_sanitizer(function_name: str) -> Optional[Sanitizer]:
    """
    Obtiene sanitizer por nombre o alias.
    """

    for sanitizer in SANITIZERS.values():

        if function_name == sanitizer.name:
            return sanitizer

        if function_name in sanitizer.aliases:
            return sanitizer

    return None


# =============================================================
# GET BY VULNERABILITY
# =============================================================

def get_sanitizers_for_vulnerability(
    vulnerability: str,
) -> List[Sanitizer]:

    return [
        s for s in SANITIZERS.values()
        if vulnerability in s.protects_against
    ]


# =============================================================
# GET BY CATEGORY
# =============================================================

def get_sanitizers_by_category(category: str) -> List[Sanitizer]:

    return [
        s for s in SANITIZERS.values()
        if s.category == category
    ]


# =============================================================
# GET BY FRAMEWORK
# =============================================================

def get_sanitizers_by_framework(framework: str) -> List[Sanitizer]:

    return [
        s for s in SANITIZERS.values()
        if s.framework == framework
    ]


# =============================================================
# CHECK PROTECTION
# =============================================================

def sanitizer_protects_against(
    sanitizer_name: str,
    vulnerability: str,
) -> bool:
    """
    Verifica si un sanitizer protege contra
    una vulnerabilidad específica.
    """

    sanitizer = get_sanitizer(sanitizer_name)

    if not sanitizer:
        return False

    return vulnerability in sanitizer.protects_against


# =============================================================
# EXPORT
# =============================================================

def export_sanitizers() -> Dict:

    return {
        key: value.to_dict()
        for key, value in SANITIZERS.items()
    }