from datetime import datetime
from typing import List, Optional
import os
import uuid

from database.mongodb import MongoDB


class AnalysisRepository:
    """
    Repository para almacenar resultados de análisis SAST.

    Responsabilidades:
    - Guardar scans
    - Consultar análisis
    - Obtener estadísticas
    - Exportar findings

    NO maneja:
    - reglas
    - IA
    - parsing
    """

    def __init__(self, mongodb: MongoDB):

        self.mongodb = mongodb

        # Corrección #8: nombre de colección leído desde env
        # en lugar de hardcodeado como string literal.
        self.collection = self.mongodb.get_collection(
            os.getenv("MONGODB_ANALYSIS_COLLECTION", "analyses")
        )

    # =========================================================
    # SAVE
    # =========================================================

    def save_analysis(
        self,
        project_name:    str,
        scanned_files:   int,
        vulnerabilities: List[dict],
        metadata:        Optional[dict] = None,
    ) -> str:
        """
        Guarda resultado completo del scan.

        Corrección #7: validación básica de inputs antes de
        persistir para evitar documentos con datos basura que
        rompen las queries de estadísticas.
        """

        # Corrección #7: validaciones de entrada.
        if not project_name or not project_name.strip():
            raise ValueError("project_name cannot be empty.")

        if not isinstance(scanned_files, int) or scanned_files < 0:
            raise ValueError(
                "scanned_files must be a non-negative integer."
            )

        if not isinstance(vulnerabilities, list):
            raise ValueError("vulnerabilities must be a list.")

        scan_id = f"SCAN_{uuid.uuid4().hex[:12]}"

        severity_count = self._count_severities(vulnerabilities)

        analysis_document = {
            "scan_id":                scan_id,
            "project_name":           project_name.strip(),
            "timestamp":              datetime.utcnow(),
            "scanned_files":          scanned_files,
            "total_vulnerabilities":  len(vulnerabilities),
            "severity_summary":       severity_count,
            "vulnerabilities":        vulnerabilities,
            "metadata":               metadata or {},
            "version":                "1.0.0",
        }

        self.collection.insert_one(analysis_document)

        print(f"[AnalysisRepository] Analysis saved: {scan_id}")

        return scan_id

    # =========================================================
    # GETTERS
    # =========================================================

    def get_all_analyses(self) -> List[dict]:
        """
        Retorna todos los análisis ordenados por timestamp.
        """

        return list(
            self.collection.find({}, {"_id": 0}).sort("timestamp", -1)
        )

    def get_analysis_by_id(self, scan_id: str) -> Optional[dict]:
        """
        Busca análisis por ID.
        """

        return self.collection.find_one(
            {"scan_id": scan_id},
            {"_id": 0},
        )

    def get_analyses_by_project(self, project_name: str) -> List[dict]:
        """
        Retorna análisis de un proyecto específico.
        """

        return list(
            self.collection.find(
                {"project_name": project_name},
                {"_id": 0},
            ).sort("timestamp", -1)
        )

    # =========================================================
    # VULNERABILITY QUERIES
    # =========================================================

    def get_analyses_by_vulnerability(
        self,
        vulnerability_type: str,
    ) -> List[dict]:
        """
        Busca análisis que contengan cierto tipo de vulnerabilidad.
        """

        return list(
            self.collection.find(
                {"vulnerabilities.vulnerability": vulnerability_type},
                {"_id": 0},
            )
        )

    def get_critical_analyses(self) -> List[dict]:
        """
        Obtiene análisis con vulnerabilidades críticas.
        """

        return list(
            self.collection.find(
                {"severity_summary.CRITICAL": {"$gt": 0}},
                {"_id": 0},
            )
        )

    # =========================================================
    # STATISTICS
    # Corrección #5: reemplazamos el patrón N+1 (traer todos
    # los documentos a memoria y sumar en Python) por un
    # aggregation pipeline que calcula todo en MongoDB en un
    # solo round-trip.
    # =========================================================

    def get_statistics(self) -> dict:
        """
        Estadísticas generales del repositorio.

        Corrección #5: aggregation pipeline en lugar de
        get_all_analyses() + bucle Python. Escala a miles de
        análisis sin traer documentos completos a memoria.
        """

        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_scans": {"$sum": 1},
                    "total_vulnerabilities": {
                        "$sum": "$total_vulnerabilities"
                    },
                    "critical": {"$sum": "$severity_summary.CRITICAL"},
                    "high":     {"$sum": "$severity_summary.HIGH"},
                    "medium":   {"$sum": "$severity_summary.MEDIUM"},
                    "low":      {"$sum": "$severity_summary.LOW"},
                }
            }
        ]

        result = list(self.collection.aggregate(pipeline))

        if not result:
            return {
                "total_scans":                      0,
                "total_vulnerabilities":            0,
                "severity_totals": {
                    "CRITICAL": 0,
                    "HIGH":     0,
                    "MEDIUM":   0,
                    "LOW":      0,
                },
                "average_vulnerabilities_per_scan": 0,
            }

        row           = result[0]
        total_scans   = row.get("total_scans", 0)
        total_vulns   = row.get("total_vulnerabilities", 0)

        return {
            "total_scans":            total_scans,
            "total_vulnerabilities":  total_vulns,
            "severity_totals": {
                "CRITICAL": row.get("critical", 0),
                "HIGH":     row.get("high",     0),
                "MEDIUM":   row.get("medium",   0),
                "LOW":      row.get("low",      0),
            },
            "average_vulnerabilities_per_scan": round(
                total_vulns / total_scans, 2
            ) if total_scans > 0 else 0,
        }

    # =========================================================
    # EXPORT
    # Corrección #6: export_findings ahora usa 'sink_label'
    # cuando está disponible (label limpio sin @lineno),
    # consistente con los cambios en taint_analyzer y
    # vulnerability_classifier.
    # =========================================================

    def export_findings(self) -> List[dict]:
        """
        Export simplificado de findings para reporting.

        Corrección #6: expone sink_label en lugar de sink con
        @lineno, manteniendo consistencia con el pipeline.
        """

        analyses = self.get_all_analyses()

        exported = []

        for analysis in analyses:

            for vuln in analysis.get("vulnerabilities", []):

                exported.append({
                    "scan_id":      analysis["scan_id"],
                    "project_name": analysis["project_name"],
                    "vulnerability": vuln.get("vulnerability"),
                    "severity":     vuln.get("severity"),
                    "confidence":   vuln.get("confidence"),
                    "source":       vuln.get("source"),
                    # Corrección #6: preferimos sink_label;
                    # fallback a sink si no existe.
                    "sink":         (
                        vuln.get("sink_label")
                        or vuln.get("sink")
                    ),
                    "path":         vuln.get("path"),
                    "sanitized":    vuln.get("sanitized"),
                    "timestamp":    analysis["timestamp"],
                })

        return exported

    # =========================================================
    # DELETE
    # =========================================================

    def delete_analysis(self, scan_id: str) -> bool:
        """
        Elimina un análisis por ID.
        """

        result = self.collection.delete_one({"scan_id": scan_id})

        return result.deleted_count > 0

    # =========================================================
    # HELPERS
    # =========================================================

    def _count_severities(
        self,
        vulnerabilities: List[dict],
    ) -> dict:
        """
        Cuenta vulnerabilidades por nivel de severidad.
        """

        summary = {
            "CRITICAL": 0,
            "HIGH":     0,
            "MEDIUM":   0,
            "LOW":      0,
        }

        for vuln in vulnerabilities:

            severity = vuln.get("severity", "LOW")

            if severity in summary:
                summary[severity] += 1

        return summary


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    from database.mongodb import MongoDB

    mongo = MongoDB()
    mongo.connect()

    repo = AnalysisRepository(mongo)

    findings = [
        {
            "vulnerability": "SQL_INJECTION",
            "severity":      "CRITICAL",
            "source":        "input",
            "sink":          "cursor.execute@10",
            "sink_label":    "cursor.execute",
            "path": [
                "input",
                "VAR_1",
                "VAR_2",
                "cursor.execute@10",
            ],
            "sanitized":  False,
            "confidence": 0.95,
        }
    ]

    scan_id = repo.save_analysis(
        project_name="test-project",
        scanned_files=5,
        vulnerabilities=findings,
        metadata={"scanner": "id-sast-python", "language": "python"},
    )

    print(repo.get_statistics())
    print(repo.export_findings())

    mongo.disconnect()
