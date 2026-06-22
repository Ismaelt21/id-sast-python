"""
json_report.py

JSON Report Generator para PY-SAST.

Responsabilidades:
- Exportar findings en JSON
- Estandarizar estructura de salida
- Preparar datos para HTML reports
- Preparar datos para APIs
- Preparar datasets IA
- Exportar metadata y estadísticas

IMPORTANTE:
Este módulo NO detecta vulnerabilidades.
Solo serializa resultados.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class JSONReport:
    """
    Generador de reportes JSON.
    """

    # =========================================================
    # INIT
    # Corrección #12: output_dir siempre es Path, igual que
    # corregimos en html_report.py.
    # =========================================================

    def __init__(self, output_dir: str = None):

        # Corrección #12: convertimos a Path explícitamente.
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
        project_name:    str,
        scanned_files:   List[str],
        findings:        List[Dict],
        ast_data:        Optional[Dict] = None,
        cfg_data:        Optional[Dict] = None,
        dfg_data:        Optional[Dict] = None,
        ai_analysis:     Optional[List[Dict]] = None,
        generated_rules: Optional[List[Dict]] = None,
        matched_rules:   Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Genera estructura JSON completa del reporte.
        """

        findings        = findings        or []
        ai_analysis     = ai_analysis     or []
        generated_rules = generated_rules or []
        matched_rules   = matched_rules   or []
        enriched_findings = self._enrich_findings(findings)

        # Corrección #14: intentamos importar settings con
        # fallback seguro.
        try:
            from config.settings import Settings
            version     = Settings.VERSION
            environment = Settings.ENVIRONMENT
        except Exception:
            version     = "unknown"
            environment = "unknown"

        return {
            "metadata": {
                "tool":         "PY-SAST",
                "version":      version,
                "generated_at": datetime.utcnow().isoformat(),
                "environment":  environment,
            },
            "project": {
                "name":          project_name,
                "scanned_files": scanned_files,
                "total_files":   len(scanned_files),
            },
            "statistics": self._build_statistics(enriched_findings),
            "findings":         enriched_findings,
            "ai_analysis":      ai_analysis,
            "generated_rules":  generated_rules,
            "matched_rules":    matched_rules,
            "graphs": {
                "ast": self._graph_summary(ast_data),
                "cfg": self._graph_summary(cfg_data),
                "dfg": self._graph_summary(dfg_data),
            },
        }

    # =========================================================
    # SAVE
    # Corrección #11: manejo explícito de errores de IO y
    # datos no serializables. Mismo patrón que aplicamos en
    # graph_serializer.save_json.
    # =========================================================

    def save(
        self,
        report:   Dict,
        filename: str = None,
    ) -> str:
        """
        Guarda reporte JSON en disco.
        """

        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename  = f"py_sast_report_{timestamp}.json"

        output_path = self.output_dir / filename

        # Corrección #12: creamos el directorio si no existe.
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise OSError(
                f"Could not create output directory "
                f"'{output_path.parent}': {e}"
            ) from e

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(
                    report,
                    f,
                    indent=4,
                    ensure_ascii=False,
                    # Corrección #14: serializa datetime objects
                    # automáticamente en lugar de explotar con
                    # TypeError cuando findings vienen de MongoDB.
                    default=self._json_default,
                )

        except OSError as e:
            raise OSError(
                f"Could not write JSON report to '{output_path}': {e}"
            ) from e

        except TypeError as e:
            raise TypeError(
                f"Report contains non-serializable data: {e}"
            ) from e

        return str(output_path)

    # =========================================================
    # EXPORT FINDINGS ONLY
    # Corrección #11: mismo manejo de errores que save().
    # =========================================================

    def export_findings(
        self,
        findings: List[Dict],
        filename: str = None,
    ) -> str:
        """
        Export simplificado solo de findings.
        """

        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename  = f"findings_{timestamp}.json"

        output_path = self.output_dir / filename

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise OSError(
                f"Could not create output directory "
                f"'{output_path.parent}': {e}"
            ) from e

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(
                    findings,
                    f,
                    indent=4,
                    ensure_ascii=False,
                    default=self._json_default,
                )

        except OSError as e:
            raise OSError(
                f"Could not write findings to '{output_path}': {e}"
            ) from e

        return str(output_path)

    # =========================================================
    # BUILD STATISTICS
    # Corrección #10: campo correcto es 'vulnerability',
    # no 'vulnerability_type'. El counter ya no acumula
    # todo en "UNKNOWN".
    # =========================================================

    def _build_statistics(self, findings: List[Dict]) -> Dict:
        """
        Construye estadísticas de severidad y tipo de
        vulnerabilidad desde los findings.
        """

        severity_counter = {
            "CRITICAL": 0,
            "HIGH":     0,
            "MEDIUM":   0,
            "LOW":      0,
        }

        vulnerability_counter: Dict[str, int] = {}

        for finding in findings:

            severity = finding.get("severity", "LOW")

            # Corrección #10: clave correcta del pipeline.
            vulnerability = (
                finding.get("vulnerability_type")
                or finding.get("vulnerability")
                or "UNKNOWN"
            )
            line = finding.get("line")
            if line is None:
                line = finding.get("sink_location")

            if severity in severity_counter:
                severity_counter[severity] += 1

            vulnerability_counter[vulnerability] = (
                vulnerability_counter.get(vulnerability, 0) + 1
            )

            if line is not None:
                finding.setdefault("line", line)

        return {
            "total_findings":  len(findings),
            "severity":        severity_counter,
            "vulnerabilities": vulnerability_counter,
        }

    # =========================================================
    # GRAPH SUMMARY
    # =========================================================

    def _graph_summary(self, graph_data: Optional[Dict]) -> Dict:
        """
        Resumen compacto de un grafo.
        """

        if not graph_data:
            return {"available": False}

        return {
            "available": True,
            "nodes":     len(graph_data.get("nodes", [])),
            "edges":     len(graph_data.get("edges", [])),
        }

    # =========================================================
    # FINDING ENRICHMENT
    # =========================================================

    def _enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Normaliza cada finding y agrega contexto de código.

        El JSON pasa a ser la fuente canónica para el HTML:
        - line
        - start_line
        - end_line
        - code_snippet
        - code_context
        """

        enriched: List[Dict] = []
        for finding in findings:
            item = dict(finding)
            line = item.get("line")
            if line is None:
                line = item.get("sink_location")
            if line is not None:
                item["line"] = line

            code_context = self._build_code_context(item)
            if code_context:
                item["code_context"] = code_context
                item["start_line"] = code_context[0]["line_number"]
                item["end_line"] = code_context[-1]["line_number"]
                item["code_snippet"] = "\n".join(
                    f"{line_item['line_number']:>4} | {line_item['content']}"
                    for line_item in code_context
                )
            else:
                item.setdefault("start_line", line)
                item.setdefault("end_line", line)
                item.setdefault("code_snippet", "")
                item.setdefault("code_context", [])

            enriched.append(item)

        return enriched

    def _build_code_context(self, finding: Dict) -> List[Dict[str, Any]]:
        file_path = finding.get("file")
        line = finding.get("line")

        if not file_path or line is None:
            return []

        try:
            source = Path(file_path).read_text(encoding="utf-8")
        except OSError:
            return []

        lines = source.splitlines()
        if not lines:
            return []

        try:
            line_no = int(line)
        except (TypeError, ValueError):
            return []

        start = max(1, line_no - 2)
        end = min(len(lines), line_no + 2)

        context: List[Dict[str, Any]] = []
        for current in range(start, end + 1):
            context.append(
                {
                    "line_number": current,
                    "content": lines[current - 1],
                    "is_target": current == line_no,
                }
            )

        return context

    # =========================================================
    # EXPORT AI DATASET
    # =========================================================

    def export_ai_training_dataset(
        self,
        generated_rules: List[Dict],
        filename:        str = None,
    ) -> str:
        """
        Exporta dataset para entrenamiento IA.
        """

        dataset = [
            {
                "input": {
                    "source":    rule.get("source_pattern"),
                    "sink":      rule.get("sink_pattern"),
                    "signature": rule.get("taint_signature"),
                },
                "output": {
                    "vulnerability_type": rule.get("vulnerability_type"),
                    "risk":               rule.get("risk"),
                },
            }
            for rule in generated_rules
        ]

        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename  = f"ai_dataset_{timestamp}.json"

        output_path = self.output_dir / filename

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(
                    dataset,
                    f,
                    indent=4,
                    ensure_ascii=False,
                    default=self._json_default,
                )

        except OSError as e:
            raise OSError(
                f"Could not write AI dataset to '{output_path}': {e}"
            ) from e

        return str(output_path)

    # =========================================================
    # LOAD
    # Corrección #13: manejo de FileNotFoundError y
    # JSONDecodeError igual que graph_serializer.load_json.
    # =========================================================

    def load(self, report_path: str) -> Dict:
        """
        Carga reporte JSON desde disco.
        """

        path = Path(report_path)

        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)

        except FileNotFoundError:
            raise FileNotFoundError(
                f"Report file not found: '{report_path}'"
            )

        except OSError as e:
            raise OSError(
                f"Could not read report from '{report_path}': {e}"
            ) from e

        except json.JSONDecodeError as e:
            raise ValueError(
                f"Malformed JSON in '{report_path}': {e}"
            ) from e

    # =========================================================
    # MINIMAL REPORT
    # =========================================================

    def generate_minimal(self, findings: List[Dict]) -> Dict:
        """
        Reporte compacto con solo los findings.
        """

        return {
            "generated_at":  datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "findings":       findings,
        }

    # =========================================================
    # JSON DEFAULT SERIALIZER
    # Corrección #14: convierte tipos no serializables que
    # pueden llegar desde MongoDB (datetime) u otros orígenes
    # en lugar de explotar con TypeError.
    # =========================================================

    @staticmethod
    def _json_default(obj: Any) -> Any:
        """
        Serializer de fallback para json.dump.

        Maneja:
        - datetime → ISO 8601 string
        - set      → list
        - Cualquier otro objeto → str(obj)
        """

        if isinstance(obj, datetime):
            return obj.isoformat()

        if isinstance(obj, set):
            return list(obj)

        return str(obj)


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    reporter = JSONReport(output_dir="/tmp/sast_reports")

    findings = [
        {
            "vulnerability": "COMMAND_INJECTION",
            "severity":      "CRITICAL",
            "source":        "input",
            "sink":          "os.system@5",
            "sink_label":    "os.system",
            "confidence":    0.90,
            "sanitized":     False,
            "path":          ["input", "user", "os.system@5"],
            # Simula datetime de MongoDB
            "timestamp":     datetime.utcnow(),
        },
    ]

    report = reporter.generate(
        project_name="test-project",
        scanned_files=["app.py", "db.py"],
        findings=findings,
    )

    path = reporter.save(report)
    print(f"Report saved to: {path}")

    loaded = reporter.load(path)
    print(f"Total findings loaded: {loaded['statistics']['total_findings']}")
    print(f"Vulnerability counter: {loaded['statistics']['vulnerabilities']}")
