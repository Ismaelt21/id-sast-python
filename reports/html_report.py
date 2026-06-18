"""
html_report.py

HTML Report Generator para PY-SAST.

Responsabilidades:
- Generar reportes HTML visuales
- Mostrar findings organizados
- Mostrar severidades
- Mostrar estadísticas
- Exportar reportes profesionales

IMPORTANTE:
Este módulo NO detecta vulnerabilidades.
Solo renderiza resultados.
"""

import html as html_lib
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class HTMLReport:
    """
    Generador HTML para PY-SAST.
    """

    # =========================================================
    # INIT
    # Corrección #5 y #6: output_dir siempre es Path,
    # y se crea si no existe antes de escribir.
    # =========================================================

    def __init__(self, output_dir: str = None):

        # Corrección #5: convertimos a Path explícitamente
        # para que el operador / funcione siempre.
        try:
            from config.settings import Settings
            default_dir = Settings.REPORTS_DIR
        except Exception:
            default_dir = "./reports/output"

        self.output_dir = Path(output_dir or default_dir)

    # =========================================================
    # MAIN
    # =========================================================

    def generate(
        self,
        report_data: Dict,
        filename:    str = None,
    ) -> str:
        """
        Genera reporte HTML completo y lo guarda en disco.
        """

        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename  = f"py_sast_report_{timestamp}.html"

        output_path = self.output_dir / filename

        # Corrección #6: creamos el directorio si no existe.
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise OSError(
                f"Could not create output directory "
                f"'{output_path.parent}': {e}"
            ) from e

        html_content = self._build_html(report_data)

        try:
            output_path.write_text(html_content, encoding="utf-8")
        except OSError as e:
            raise OSError(
                f"Could not write HTML report to '{output_path}': {e}"
            ) from e

        return str(output_path)

    # =========================================================
    # BUILD HTML
    # =========================================================

    def _build_html(self, report_data: Dict) -> str:
        """
        Construye el HTML completo del reporte.
        """

        findings  = report_data.get("findings",   [])
        stats     = report_data.get("statistics", {})
        project   = report_data.get("project",    {})
        metadata  = report_data.get("metadata",   {})

        findings_html = self._build_findings(findings)

        # Corrección #7: los valores de project y metadata
        # se escapan antes de interpolar en el template.
        project_name  = self._esc(project.get("name", "Unknown"))
        total_files   = self._esc(str(project.get("total_files", 0)))
        generated_at  = self._esc(metadata.get("generated_at", ""))
        year          = datetime.utcnow().year

        severity = stats.get("severity", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PY-SAST Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #f5f7fa;
    margin: 0;
    padding: 0;
    color: #222;
}}
header {{
    background: #111827;
    color: white;
    padding: 25px;
}}
header h1 {{ margin: 0; }}
.container {{ padding: 20px; }}
.card {{
    background: white;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0px 2px 10px rgba(0,0,0,0.08);
}}
.stats {{
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}}
.stat-box {{
    flex: 1;
    min-width: 150px;
    padding: 20px;
    border-radius: 10px;
    color: white;
    text-align: center;
    font-size: 20px;
    font-weight: bold;
}}
.critical {{ background: #dc2626; }}
.high     {{ background: #ea580c; }}
.medium   {{ background: #ca8a04; }}
.low      {{ background: #16a34a; }}
.finding {{
    border-left: 6px solid #ccc;
    padding: 15px;
    margin-bottom: 15px;
    background: #fafafa;
    border-radius: 6px;
}}
.finding.CRITICAL {{ border-color: #dc2626; }}
.finding.HIGH     {{ border-color: #ea580c; }}
.finding.MEDIUM   {{ border-color: #ca8a04; }}
.finding.LOW      {{ border-color: #16a34a; }}
.label {{ font-weight: bold; }}
footer {{
    margin-top: 40px;
    padding: 20px;
    text-align: center;
    background: #111827;
    color: white;
}}
pre {{
    background: #1f2937;
    color: #f9fafb;
    padding: 10px;
    border-radius: 5px;
    overflow-x: auto;
}}
</style>
</head>
<body>

<header>
    <h1>PY-SAST Security Report</h1>
    <p>Generated at: {generated_at}</p>
</header>

<div class="container">

    <div class="card">
        <h2>Project Information</h2>
        <p><span class="label">Project:</span> {project_name}</p>
        <p><span class="label">Files Scanned:</span> {total_files}</p>
    </div>

    <div class="card">
        <h2>Statistics</h2>
        <div class="stats">
            <div class="stat-box critical">CRITICAL<br>{severity.get("CRITICAL", 0)}</div>
            <div class="stat-box high">HIGH<br>{severity.get("HIGH", 0)}</div>
            <div class="stat-box medium">MEDIUM<br>{severity.get("MEDIUM", 0)}</div>
            <div class="stat-box low">LOW<br>{severity.get("LOW", 0)}</div>
        </div>
    </div>

    <div class="card">
        <h2>Findings</h2>
        {findings_html}
    </div>

</div>

<footer>PY-SAST &copy; {year}</footer>

</body>
</html>"""

    # =========================================================
    # BUILD FINDINGS
    # =========================================================

    def _build_findings(self, findings: List[Dict]) -> str:
        """
        Renderiza findings como bloques HTML.

        Corrección #7: todos los valores del finding se
        escapan con html.escape() antes de interpolar en el
        template, previniendo XSS en el reporte generado.

        Corrección #8: campo correcto es 'vulnerability'.
        Corrección #9: preferimos 'sink_label' sobre 'sink'.
        """

        if not findings:
            return "<p>No vulnerabilities detected.</p>"

        blocks = []

        for finding in findings:

            severity = self._esc(finding.get("severity", "LOW"))

            # Corrección #8: clave correcta del pipeline.
            vuln_type   = self._esc(finding.get("vulnerability", "UNKNOWN"))

            description = self._esc(finding.get("description", "No description"))
            file_path   = self._esc(finding.get("file",        "unknown"))
            line        = self._esc(str(finding.get("line",    "?")))
            source      = self._esc(finding.get("source",      "unknown"))
            confidence  = self._esc(str(finding.get("confidence", 0)))

            # Corrección #9: preferimos sink_label.
            sink = self._esc(
                finding.get("sink_label") or finding.get("sink", "unknown")
            )

            # Corrección #7: el código también se escapa para
            # evitar que snippets con < > & rompan el HTML.
            code = self._esc(finding.get("code", ""))

            cwe  = self._esc(finding.get("cwe_id", ""))
            recommendation = self._esc(
                finding.get("recommendation", "")
            )

            blocks.append(f"""
<div class="finding {severity}">
    <h3>[{severity}] {vuln_type}</h3>
    <p><span class="label">Description:</span> {description}</p>
    <p><span class="label">File:</span> {file_path}</p>
    <p><span class="label">Line:</span> {line}</p>
    <p><span class="label">Source:</span> {source}</p>
    <p><span class="label">Sink:</span> {sink}</p>
    <p><span class="label">Confidence:</span> {confidence}</p>
    {f'<p><span class="label">CWE:</span> {cwe}</p>' if cwe else ""}
    {f'<p><span class="label">Recommendation:</span> {recommendation}</p>' if recommendation else ""}
    {f"<pre>{code}</pre>" if code else ""}
</div>""")

        return "\n".join(blocks)

    # =========================================================
    # ESCAPE HELPER
    # Corrección #7: método centralizado para escapar valores
    # antes de interpolarlos en el HTML del reporte.
    # =========================================================

    @staticmethod
    def _esc(value: str) -> str:
        """
        Escapa caracteres HTML especiales.
        Previene XSS en el reporte generado.
        """
        return html_lib.escape(str(value), quote=True)

    # =========================================================
    # MINIMAL REPORT
    # =========================================================

    def generate_minimal(self, findings: List[Dict]) -> str:
        """
        HTML minimalista con total de findings.
        """

        total = len(findings)

        return f"""<!DOCTYPE html>
<html>
<body>
<h1>PY-SAST Minimal Report</h1>
<p>Total Findings: {total}</p>
</body>
</html>"""


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    report_data = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat(),
        },
        "project": {
            "name":        "test-project",
            "total_files": 3,
        },
        "statistics": {
            "severity": {
                "CRITICAL": 1,
                "HIGH":     1,
                "MEDIUM":   0,
                "LOW":      0,
            }
        },
        "findings": [
            {
                "vulnerability":  "COMMAND_INJECTION",
                "severity":       "CRITICAL",
                "source":         "input",
                "sink":           "os.system@5",
                "sink_label":     "os.system",
                "confidence":     0.90,
                "description":    "Untrusted input reaches os.system",
                "file":           "app.py",
                "line":           5,
                "cwe_id":         "CWE-78",
                "recommendation": "Avoid shell execution with user input.",
                # Corrección #7: este valor debería escaparse.
                "code":           "os.system(user_input)  # <dangerous>",
            },
        ],
    }

    reporter = HTMLReport(output_dir="/tmp/sast_reports")
    path     = reporter.generate(report_data)
    print(f"Report saved to: {path}")