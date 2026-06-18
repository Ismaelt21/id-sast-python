"""
cli/scanner.py

CLI Interface para id-sast-python.

Responsabilidades:
- Interpretar comandos CLI
- Ejecutar scans
- Mostrar help
- Gestionar flags
- UX de terminal
- Punto de entrada profesional

Ejemplos:

python cli/scanner.py scan ./project
python cli/scanner.py scan ./project --no-ai
python cli/scanner.py rules --list
python cli/scanner.py rules --stats
python cli/scanner.py analysis --stats
python cli/scanner.py mongo
"""

import argparse
import sys
from pathlib import Path

from config.settings import Settings


class CLI:
    """
    Command Line Interface para id-sast-python.
    """

    # =========================================================
    # INIT
    # Corrección #7: no instanciamos PySAST ni repositorios
    # en __init__. Cada comando los crea solo si los necesita,
    # evitando inicializar el pipeline completo para comandos
    # que no escanean.
    # =========================================================

    def __init__(self):

        # Corrección #1: importamos MongoDB (nombre correcto)
        # aquí en lugar de al nivel de módulo para que el
        # import error sea claro y localizado.
        from database.mongodb import MongoDB

        self._MongoDB = MongoDB

    # =========================================================
    # MAIN
    # =========================================================

    def run(self) -> None:

        parser = argparse.ArgumentParser(
            prog="id-sast-python",
            description="id-sast-python - Python Static Application Security Testing",
        )

        subparsers = parser.add_subparsers(dest="command")

        # -------------------------------------------------
        # SCAN COMMAND
        # -------------------------------------------------

        scan_parser = subparsers.add_parser(
            "scan",
            help="Scan a Python project for vulnerabilities",
        )

        scan_parser.add_argument(
            "path",
            help="Path to the Python project or file to scan",
        )

        scan_parser.add_argument(
            "--no-ai",
            action="store_true",
            help="Disable Gemini AI analysis",
        )

        scan_parser.add_argument(
            "--json-only",
            action="store_true",
            help="Generate only JSON report",
        )

        scan_parser.add_argument(
            "--html-only",
            action="store_true",
            help="Generate only HTML report",
        )

        scan_parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose output",
        )

        # -------------------------------------------------
        # RULES COMMAND
        # -------------------------------------------------

        rules_parser = subparsers.add_parser(
            "rules",
            help="Manage stored security rules",
        )

        rules_parser.add_argument(
            "--list",
            action="store_true",
            help="List all stored rules",
        )

        rules_parser.add_argument(
            "--stats",
            action="store_true",
            help="Show rules statistics",
        )

        # -------------------------------------------------
        # ANALYSIS COMMAND
        # -------------------------------------------------

        analysis_parser = subparsers.add_parser(
            "analysis",
            help="Manage stored analyses",
        )

        analysis_parser.add_argument(
            "--stats",
            action="store_true",
            help="Show analysis statistics",
        )

        # -------------------------------------------------
        # MONGO COMMAND
        # -------------------------------------------------

        subparsers.add_parser(
            "mongo",
            help="Show MongoDB connection status",
        )

        # -------------------------------------------------
        # PARSE
        # -------------------------------------------------

        args = parser.parse_args()

        if not args.command:
            parser.print_help()
            sys.exit(0)

        # -------------------------------------------------
        # DISPATCH
        # Corrección #8: KeyboardInterrupt capturado en el
        # nivel más alto para cerrar recursos limpiamente.
        # -------------------------------------------------

        try:

            if args.command == "scan":
                self._scan_command(args)

            elif args.command == "rules":
                self._rules_command(args, rules_parser)

            elif args.command == "analysis":
                self._analysis_command(args, analysis_parser)

            elif args.command == "mongo":
                self._mongo_command()

        except KeyboardInterrupt:

            print("\n[id-sast-python] Scan interrupted by user.")
            sys.exit(0)

    # =========================================================
    # SCAN COMMAND
    # =========================================================

    def _scan_command(self, args) -> None:
        """
        Ejecuta el scan de un proyecto Python.
        """

        project_path = Path(args.path).resolve()

        # Corrección #9: validaciones de path más completas.
        if not project_path.exists():
            print(f"[ERROR] Path not found: {project_path}")
            sys.exit(1)

        if not project_path.is_dir():
            print(
                f"[ERROR] Path is not a directory: {project_path}\n"
                f"        Provide a directory containing Python files."
            )
            sys.exit(1)

        py_files = list(project_path.rglob("*.py"))

        if not py_files:
            print(
                f"[ERROR] No Python files found in: {project_path}\n"
                f"        Make sure the directory contains .py files."
            )
            sys.exit(1)

        print(f"\n[id-sast-python] Scanning: {project_path}")
        print(f"[id-sast-python] Python files found: {len(py_files)}")

        # Corrección #4: en lugar de mutar Settings, pasamos
        # los flags como parámetros al scanner. Esto garantiza
        # que módulos que ya leyeron Settings no se vean
        # afectados por cambios tardíos en atributos de clase.
        use_ai      = not args.no_ai
        json_only   = getattr(args, "json_only",  False)
        html_only   = getattr(args, "html_only",  False)
        verbose     = getattr(args, "verbose",    False)

        # Corrección #7: PySAST se instancia solo aquí,
        # cuando realmente se necesita.
        from engine.pysast import PySAST

        scanner = PySAST(
            use_ai    = use_ai,
            verbose   = verbose,
            json_only = json_only,
            html_only = html_only,
        )

        # Corrección #5: el scan gestiona su propia conexión
        # MongoDB internamente a través de PySAST, de forma
        # consistente con los demás comandos.
        try:
            scanner.scan_project(str(project_path))

        except Exception as e:
            print(f"[ERROR] Scan failed: {e}")

            if Settings.DEBUG:
                import traceback
                traceback.print_exc()

            sys.exit(1)

    # =========================================================
    # RULES COMMAND
    # =========================================================

    def _rules_command(self, args, parser) -> None:
        """
        Gestiona las reglas almacenadas en MongoDB.

        Corrección #10: si no se pasa ningún flag, muestra
        el help del subcomando en lugar de conectar y no
        hacer nada.
        """

        if not args.list and not args.stats:
            parser.print_help()
            return

        # Corrección #3: conectamos antes de instanciar
        # los repositorios para que get_collection() no
        # lance ConnectionError.
        mongo = self._MongoDB()

        if not mongo.connect():
            print("[ERROR] Could not connect to MongoDB.")
            sys.exit(1)

        try:

            from database.rule_repository import RuleRepository

            repo = RuleRepository(mongo)

            if args.list:

                rules = repo.get_all_rules()

                print(f"\n[Rules] Total: {len(rules)}\n")

                if not rules:
                    print("  No rules stored yet.")
                    return

                for rule in rules:
                    validated = "✓" if rule.get("validated") else "○"
                    print(
                        f"  [{validated}] {rule.get('pattern_name', 'unnamed')} "
                        f"— {rule.get('vulnerability', 'UNKNOWN')} "
                        f"(confidence: {rule.get('confidence', 0):.2f})"
                    )

            elif args.stats:

                stats = repo.get_statistics()

                print("\n[Rules Statistics]\n")

                for key, value in stats.items():
                    print(f"  {key}: {value}")

        finally:
            # Corrección #2: método correcto es disconnect().
            mongo.disconnect()

    # =========================================================
    # ANALYSIS COMMAND
    # =========================================================

    def _analysis_command(self, args, parser) -> None:
        """
        Gestiona los análisis almacenados en MongoDB.

        Corrección #10: muestra help si no se pasa ningún flag.
        """

        if not args.stats:
            parser.print_help()
            return

        # Corrección #3: conectamos antes de instanciar.
        mongo = self._MongoDB()

        if not mongo.connect():
            print("[ERROR] Could not connect to MongoDB.")
            sys.exit(1)

        try:

            from database.analysis_repository import AnalysisRepository

            repo = AnalysisRepository(mongo)

            stats = repo.get_statistics()

            print("\n[Analysis Statistics]\n")

            for key, value in stats.items():
                print(f"  {key}: {value}")

        finally:
            # Corrección #2: método correcto es disconnect().
            mongo.disconnect()

    # =========================================================
    # MONGO COMMAND
    # Corrección #6: usa get_status() con ping() real en lugar
    # de imprimir "Connected: True" hardcodeado.
    # =========================================================

    def _mongo_command(self) -> None:
        """
        Muestra el estado real de la conexión MongoDB.
        """

        mongo = self._MongoDB()

        connected = mongo.connect()

        try:

            status = mongo.get_status()

            print("\n[MongoDB Status]\n")
            print(f"  Connected        : {status['connected']}")
            print(f"  Healthy (ping)   : {status['healthy']}")
            print(f"  Database         : {status['database']}")
            print(f"  TLS              : {status['tls']}")
            print(f"  URI configured   : {status['uri_configured']}")
            print(f"  Rules collection : {Settings.MONGODB_RULES_COLLECTION}")
            print(f"  Analysis coll.   : {Settings.MONGODB_ANALYSIS_COLLECTION}")

            if connected:
                mongo.create_indexes()
                print("\n  [OK] Indexes verified.")

        except Exception as e:
            print(f"[MongoDB ERROR] {e}")

            if Settings.DEBUG:
                import traceback
                traceback.print_exc()

        finally:
            # Corrección #2: método correcto es disconnect().
            mongo.disconnect()


# =============================================================
# ENTRYPOINT
# =============================================================

def main() -> None:

    # Inicializamos directorios al arrancar el CLI.
    # Corrección #2 de settings.py: initialize_directories()
    # ya no se llama automáticamente al importar Settings,
    # así que lo hacemos explícitamente aquí.
    Settings.initialize_directories()

    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
