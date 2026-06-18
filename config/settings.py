"""
settings.py

Configuración centralizada para id-sast-python.

Responsabilidades:
- Cargar variables de entorno
- Centralizar configuración global
- Evitar hardcoded values
- Compartir settings entre módulos
- Gestionar feature flags

IMPORTANTE:
Todos los módulos deben importar Settings
en lugar de usar os.getenv() directamente.
"""

import os
from pathlib import Path

from dotenv import load_dotenv


# =============================================================
# LOAD ENV
# =============================================================

# Raíz del proyecto: dos niveles arriba de config/settings.py
BASE_DIR = Path(__file__).resolve().parent.parent

# Cargamos el .env desde la raíz del proyecto.
load_dotenv(BASE_DIR / ".env")


# =============================================================
# HELPERS
# =============================================================

def _resolve_path(env_key: str, default: Path) -> Path:
    """
    Corrección #1 y #5: resuelve una ruta de entorno
    siempre contra BASE_DIR si es relativa, evitando que
    rutas como './storage' dependan del CWD del proceso.

    - Si la variable de entorno no está definida → usa default.
    - Si la ruta es absoluta → la usa tal cual.
    - Si la ruta es relativa → la resuelve contra BASE_DIR.
    """

    raw = os.getenv(env_key)

    if not raw:
        return default

    path = Path(raw)

    if path.is_absolute():
        return path

    # Corrección #1: rutas relativas se anclan a BASE_DIR,
    # no al CWD del proceso en ejecución.
    return BASE_DIR / path


def _int_env(env_key: str, default: int) -> int:
    """
    Corrección #4: convierte variable de entorno a int con
    manejo explícito de ValueError. Si el valor no es un
    entero válido, usa el default y emite un warning en lugar
    de explotar en tiempo de import.
    """

    raw = os.getenv(env_key)

    if raw is None:
        return default

    try:
        return int(raw)

    except ValueError:
        print(
            f"[Settings] WARNING: '{env_key}' has invalid "
            f"integer value '{raw}'. Using default: {default}."
        )
        return default


def _bool_env(env_key: str, default: bool) -> bool:
    """
    Convierte variable de entorno a bool de forma segura.
    """

    raw = os.getenv(env_key)

    if raw is None:
        return default

    return raw.lower() == "true"


# =============================================================
# SETTINGS
# =============================================================

class Settings:

    # =========================================================
    # APP
    # =========================================================

    APP_NAME    = os.getenv("APP_NAME",    "id-sast-python")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    VERSION     = "1.0.0"

    DEBUG = _bool_env("DEBUG", False)

    # =========================================================
    # PATHS
    # Corrección #1 y #5: todas las rutas se resuelven contra
    # BASE_DIR usando _resolve_path(), eliminando la
    # dependencia del CWD del proceso.
    # =========================================================

    BASE_DIR = BASE_DIR

    STORAGE_DIR = _resolve_path(
        "STORAGE_DIR",
        BASE_DIR / "storage",
    )

    REPORTS_DIR = _resolve_path(
        "REPORTS_DIR",
        BASE_DIR / "reports" / "output",
    )

    RULE_CACHE_DIR = _resolve_path(
        "RULE_CACHE_DIR",
        BASE_DIR / "storage" / "rules",
    )

    TEMP_DIR = _resolve_path(
        "TEMP_DIR",
        BASE_DIR / "storage" / "temp",
    )

    # =========================================================
    # GEMINI
    # =========================================================

    GOOGLE_GEMINI_API_KEY = os.getenv("GOOGLE_GEMINI_API_KEY")

    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

    USE_GEMINI          = _bool_env("USE_GEMINI",          True)
    ENABLE_AI_ANALYSIS  = _bool_env("ENABLE_AI_ANALYSIS",  True)

    # =========================================================
    # MONGODB
    # =========================================================

    MONGODB_URI    = os.getenv("MONGODB_URI")
    MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "id_sast_python")

    MONGODB_RULES_COLLECTION    = os.getenv(
        "MONGODB_RULES_COLLECTION",    "security_rules"
    )
    MONGODB_ANALYSIS_COLLECTION = os.getenv(
        "MONGODB_ANALYSIS_COLLECTION", "analyses"
    )
    MONGODB_SCANS_COLLECTION = os.getenv(
        "MONGODB_SCANS_COLLECTION", "scans"
    )

    USE_PERSISTENCE = _bool_env("USE_PERSISTENCE", True)

    # =========================================================
    # ANALYSIS ENGINE
    # Corrección #4: todos los int se leen con _int_env()
    # para manejar valores inválidos en el .env sin explotar
    # en tiempo de import.
    # =========================================================

    ANALYSIS_TIMEOUT = _int_env("ANALYSIS_TIMEOUT", 30)
    MAX_FILE_SIZE    = _int_env("MAX_FILE_SIZE",    1_000_000)
    MAX_AST_DEPTH    = _int_env("MAX_AST_DEPTH",    100)
    MAX_GRAPH_NODES  = _int_env("MAX_GRAPH_NODES",  10_000)

    # Corrección #7: MAX_GRAPH_EDGES documentado aquí con su
    # clave de entorno para que sea visible y configurable.
    MAX_GRAPH_EDGES  = _int_env("MAX_GRAPH_EDGES",  50_000)

    # =========================================================
    # FEATURE FLAGS
    # =========================================================

    ENABLE_CFG               = _bool_env("ENABLE_CFG",               True)
    ENABLE_DFG               = _bool_env("ENABLE_DFG",               True)
    ENABLE_SEMANTIC_ANALYSIS = _bool_env("ENABLE_SEMANTIC_ANALYSIS",  True)
    ENABLE_TAINT_ANALYSIS    = _bool_env("ENABLE_TAINT_ANALYSIS",     True)
    ENABLE_SUBGRAPH_MATCHING = _bool_env("ENABLE_SUBGRAPH_MATCHING",  True)
    ENABLE_RULE_GENERATION   = _bool_env("ENABLE_RULE_GENERATION",    True)

    # =========================================================
    # REPORTS
    # =========================================================

    EXPORT_JSON    = _bool_env("EXPORT_JSON",    True)
    EXPORT_HTML    = _bool_env("EXPORT_HTML",    True)
    EXPORT_CONSOLE = _bool_env("EXPORT_CONSOLE", True)

    # =========================================================
    # LOGGING
    # =========================================================

    LOG_LEVEL       = os.getenv("LOG_LEVEL", "INFO")
    VERBOSE_LOGGING = _bool_env("VERBOSE_LOGGING", True)

    # =========================================================
    # PERFORMANCE
    # =========================================================

    MAX_WORKERS = _int_env("MAX_WORKERS", 4)

    # =========================================================
    # SECURITY
    # =========================================================

    ALLOWED_EXTENSIONS = {".py"}

    BLOCKED_DIRECTORIES = {
        ".git",
        "__pycache__",
        "venv",
        ".venv",
        "node_modules",
    }

    # =========================================================
    # AI PROMPT LIMITS
    # =========================================================

    MAX_PROMPT_CHARS   = _int_env("MAX_PROMPT_CHARS",   25_000)
    MAX_SUBGRAPH_NODES = _int_env("MAX_SUBGRAPH_NODES", 50)

    # =========================================================
    # INITIALIZE DIRECTORIES
    # Corrección #2: ya NO se llama automáticamente al
    # importar el módulo. El scanner o main.py lo invocan
    # explícitamente al arrancar, evitando efectos secundarios
    # en tests unitarios y otros importadores.
    # =========================================================

    @classmethod
    def initialize_directories(cls) -> None:
        """
        Crea los directorios necesarios para el proyecto.
        Debe llamarse explícitamente desde main.py o scanner.py,
        no se ejecuta automáticamente al importar.
        """

        dirs = [
            cls.STORAGE_DIR,
            cls.REPORTS_DIR,
            cls.RULE_CACHE_DIR,
            cls.TEMP_DIR,
        ]

        for directory in dirs:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                print(
                    f"[Settings] WARNING: Could not create "
                    f"directory '{directory}': {e}"
                )

    # =========================================================
    # VALIDATE
    # Corrección #3: retorna lista estructurada de errores
    # en lugar de mezclarlos en un solo string. El caller
    # puede inspeccionar qué falló y decidir qué deshabilitar.
    # =========================================================

    @classmethod
    def validate(cls) -> list:
        """
        Valida la configuración crítica.

        Corrección #3: retorna lista de strings con los
        errores encontrados en lugar de lanzar ValueError
        con todo mezclado. El caller decide cómo manejarlos.

        Retorna lista vacía si todo está correcto.
        """

        errors = []

        if cls.USE_PERSISTENCE and not cls.MONGODB_URI:
            errors.append(
                "MONGODB_URI is not configured but "
                "USE_PERSISTENCE=true. Set MONGODB_URI in .env "
                "or disable persistence with USE_PERSISTENCE=false."
            )

        if cls.USE_GEMINI and not cls.GOOGLE_GEMINI_API_KEY:
            errors.append(
                "GOOGLE_GEMINI_API_KEY is not configured but "
                "USE_GEMINI=true. Set GOOGLE_GEMINI_API_KEY in .env "
                "or disable AI with USE_GEMINI=false."
            )

        return errors

    @classmethod
    def validate_or_raise(cls) -> None:
        """
        Versión estricta de validate() que lanza ValueError
        si hay errores. Útil para entornos de producción donde
        una configuración incompleta no debe continuar.
        """

        errors = cls.validate()

        if errors:
            raise ValueError(
                "Settings validation failed:\n"
                + "\n".join(f"  - {e}" for e in errors)
            )

    # =========================================================
    # SUMMARY
    # Corrección #6: summary completo con todos los flags
    # que el scanner usa activamente.
    # =========================================================

    @classmethod
    def summary(cls) -> dict:
        """
        Resumen completo de la configuración activa.
        Útil para debugging y logging al arrancar el scanner.
        """

        return {
            # App
            "app_name":    cls.APP_NAME,
            "version":     cls.VERSION,
            "environment": cls.ENVIRONMENT,
            "debug":       cls.DEBUG,

            # Paths
            "base_dir":        str(cls.BASE_DIR),
            "reports_dir":     str(cls.REPORTS_DIR),
            "storage_dir":     str(cls.STORAGE_DIR),
            "rule_cache_dir":  str(cls.RULE_CACHE_DIR),
            "temp_dir":        str(cls.TEMP_DIR),

            # Integrations
            "use_gemini":       cls.USE_GEMINI,
            "gemini_model":     cls.GEMINI_MODEL,
            "use_persistence":  cls.USE_PERSISTENCE,
            "mongodb_database": cls.MONGODB_DB_NAME,

            # Analysis engine
            "analysis_timeout": cls.ANALYSIS_TIMEOUT,
            "max_file_size":    cls.MAX_FILE_SIZE,
            "max_ast_depth":    cls.MAX_AST_DEPTH,
            "max_graph_nodes":  cls.MAX_GRAPH_NODES,
            "max_graph_edges":  cls.MAX_GRAPH_EDGES,

            # Feature flags
            "enable_cfg":               cls.ENABLE_CFG,
            "enable_dfg":               cls.ENABLE_DFG,
            "enable_taint_analysis":    cls.ENABLE_TAINT_ANALYSIS,
            "enable_semantic_analysis": cls.ENABLE_SEMANTIC_ANALYSIS,
            "enable_subgraph_matching": cls.ENABLE_SUBGRAPH_MATCHING,
            "enable_rule_generation":   cls.ENABLE_RULE_GENERATION,
            "enable_ai_analysis":       cls.ENABLE_AI_ANALYSIS,

            # Reports
            "export_json":    cls.EXPORT_JSON,
            "export_html":    cls.EXPORT_HTML,
            "export_console": cls.EXPORT_CONSOLE,

            # Performance
            "max_workers": cls.MAX_WORKERS,

            # Logging
            "log_level":       cls.LOG_LEVEL,
            "verbose_logging": cls.VERBOSE_LOGGING,
        }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    import json

    # Validación
    errors = Settings.validate()

    if errors:
        print("[Settings] Configuration warnings:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("[Settings] Configuration OK")

    # Resumen
    print("\n[Settings] Summary:")
    print(json.dumps(Settings.summary(), indent=2))

    # Verificar que las rutas se resuelven contra BASE_DIR
    print(f"\n[Settings] BASE_DIR    : {Settings.BASE_DIR}")
    print(f"[Settings] REPORTS_DIR : {Settings.REPORTS_DIR}")
    print(f"[Settings] STORAGE_DIR : {Settings.STORAGE_DIR}")
