"""
console_report.py

Console Report Generator para PY-SAST.

Responsabilidades:
- Mostrar findings en terminal
- Mostrar estadísticas
- Mostrar resumen del scan
- Colorear severidades
- Facilitar debugging
- Facilitar uso CLI

IMPORTANTE:
Este módulo NO detecta vulnerabilidades.
Solo presenta resultados en consola.
"""

from datetime import datetime
from typing import Dict, List


class ConsoleReport:
    """
    Reporte CLI para terminal.
    """

    # =========================================================
    # ANSI COLORS
    # =========================================================

    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    MAGENTA = "\033[95m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

    # =========================================================
    # MAIN
    # =========================================================

    def generate(
        self,
        project_name:  str,
        scanned_files: List[str],
        findings:      List[Dict],
    ) -> None:
        """
        Genera reporte completo en consola.
        """

        self._print_banner()
        self._print_project_info(project_name, scanned_files)
        self._print_statistics(findings)
        self._print_findings(findings)
        self._print_footer()

    # =========================================================
    # BANNER
    # =========================================================

    def _print_banner(self) -> None:

        print(
            f"\n{self.CYAN}{self.BOLD}"
            f"========================================"
        )
        print("           PY-SAST REPORT")
        print(
            f"========================================"
            f"{self.RESET}\n"
        )

    # =========================================================
    # PROJECT INFO
    # =========================================================

    def _print_project_info(
        self,
        project_name:  str,
        scanned_files: List[str],
    ) -> None:

        # Corrección #3: fallback seguro para el entorno en
        # lugar de acceder directamente a Settings.ENVIRONMENT,
        # que puede no estar inicializado.
        try:
            from config.settings import Settings
            environment = Settings.ENVIRONMENT
        except Exception:
            environment = "unknown"

        print(f"{self.BOLD}Project:{self.RESET}       {project_name}")
        print(f"{self.BOLD}Files Scanned:{self.RESET} {len(scanned_files)}")
        print(f"{self.BOLD}Generated:{self.RESET}     {datetime.utcnow().isoformat()}")
        print(f"{self.BOLD}Environment:{self.RESET}   {environment}")
        print()

    # =========================================================
    # STATISTICS
    # =========================================================

    def _print_statistics(self, findings: List[Dict]) -> None:

        # Corrección #4: eliminado "INFO" porque ningún
        # componente del pipeline genera esa severidad.
        # Evita mostrar una línea siempre en 0 que confunde.
        severity_stats = {
            "CRITICAL": 0,
            "HIGH":     0,
            "MEDIUM":   0,
            "LOW":      0,
        }

        for finding in findings:

            severity = finding.get("severity", "LOW")

            if severity in severity_stats:
                severity_stats[severity] += 1

        print(f"{self.BOLD}Statistics:{self.RESET}")
        print(f"  Total Findings : {len(findings)}")
        print(f"  {self.RED}CRITICAL{self.RESET}       : {severity_stats['CRITICAL']}")
        print(f"  {self.RED}HIGH    {self.RESET}       : {severity_stats['HIGH']}")
        print(f"  {self.YELLOW}MEDIUM  {self.RESET}       : {severity_stats['MEDIUM']}")
        print(f"  {self.GREEN}LOW     {self.RESET}       : {severity_stats['LOW']}")
        print()

    # =========================================================
    # FINDINGS
    # =========================================================

    def _print_findings(self, findings: List[Dict]) -> None:

        if not findings:
            print(
                f"{self.GREEN}No vulnerabilities detected.{self.RESET}\n"
            )
            return

        print(f"{self.BOLD}Findings:{self.RESET}\n")

        for index, finding in enumerate(findings, start=1):
            self._print_single_finding(index, finding)

    # =========================================================
    # SINGLE FINDING
    # =========================================================

    def _print_single_finding(
        self,
        index:   int,
        finding: Dict,
    ) -> None:

        severity = finding.get("severity", "LOW")

        # Corrección #1: campo correcto es 'vulnerability',
        # no 'vulnerability_type'.
        vulnerability_type = finding.get("vulnerability", "UNKNOWN")

        file_path   = finding.get("file",        "unknown")
        line        = finding.get("line",         "?")
        description = finding.get("description", "No description")
        source      = finding.get("source",      "unknown")
        confidence  = finding.get("confidence",  0)

        # Corrección #2: preferimos sink_label (label limpio
        # sin @lineno); fallback a sink si no existe.
        sink = finding.get("sink_label") or finding.get("sink", "unknown")

        color = self._severity_color(severity)

        print(
            f"{color}{self.BOLD}"
            f"[{index}] {severity} - {vulnerability_type}"
            f"{self.RESET}"
        )
        print(f"  File        : {file_path}")
        print(f"  Line        : {line}")
        print(f"  Source      : {source}")
        print(f"  Sink        : {sink}")
        print(f"  Confidence  : {confidence}")
        print(f"  Description : {description}")
        print()

    # =========================================================
    # SEVERITY COLOR
    # =========================================================

    def _severity_color(self, severity: str) -> str:

        mapping = {
            "CRITICAL": self.RED,
            "HIGH":     self.RED,
            "MEDIUM":   self.YELLOW,
            "LOW":      self.GREEN,
        }

        return mapping.get(severity, self.WHITE)

    # =========================================================
    # FOOTER
    # =========================================================

    def _print_footer(self) -> None:

        print(f"{self.CYAN}{'=' * 40}")
        print("        Scan Completed")
        print(f"{'=' * 40}{self.RESET}\n")

    # =========================================================
    # QUICK SUMMARY
    # =========================================================

    def quick_summary(self, findings: List[Dict]) -> None:
        """
        Resumen compacto de una línea.
        """

        criticals = sum(
            1 for f in findings
            if f.get("severity") == "CRITICAL"
        )
        highs = sum(
            1 for f in findings
            if f.get("severity") == "HIGH"
        )

        print(
            f"{self.BOLD}[SUMMARY]{self.RESET} "
            f"Critical: {criticals} | "
            f"High: {highs} | "
            f"Total: {len(findings)}"
        )

    # =========================================================
    # DEBUG FINDING
    # =========================================================

    def debug_finding(self, finding: Dict) -> None:
        """
        Debug completo de un finding.
        """

        import pprint

        print(f"{self.MAGENTA}{self.BOLD}[DEBUG FINDING]{self.RESET}")
        pprint.pprint(finding, indent=4)


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    findings = [
        {
            "vulnerability": "COMMAND_INJECTION",
            "severity":      "CRITICAL",
            "source":        "input",
            "sink":          "os.system@5",
            "sink_label":    "os.system",
            "confidence":    0.90,
            "description":   "Untrusted input reaches os.system",
            "file":          "app.py",
            "line":          5,
        },
        {
            "vulnerability": "SQL_INJECTION",
            "severity":      "CRITICAL",
            "source":        "request.args.get",
            "sink":          "cursor.execute@12",
            "sink_label":    "cursor.execute",
            "confidence":    0.95,
            "description":   "Untrusted input reaches cursor.execute",
            "file":          "db.py",
            "line":          12,
        },
    ]

    report = ConsoleReport()
    report.generate(
        project_name="test-project",
        scanned_files=["app.py", "db.py"],
        findings=findings,
    )
    report.quick_summary(findings)