from __future__ import annotations

import copy
import os
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from api.schemas import ScanRequest
from config.settings import Settings
from database.mongodb import MongoDB
from database.scan_repository import ScanRepository
from engine.pysast import PySAST


class ScanService:
    """
    Orchestrates a Python scan and exposes a service-level scan contract.
    """

    def __init__(self) -> None:
        self._repository = ScanRepository(MongoDB())

    def run_scan(self, request: ScanRequest) -> Dict[str, Any]:
        project_path = Path(request.project_path).expanduser().resolve()

        if not project_path.exists():
            raise FileNotFoundError(f"Path not found: {project_path}")

        if not project_path.is_dir():
            raise ValueError(f"Path is not a directory: {project_path}")

        previous_use_persistence = Settings.USE_PERSISTENCE
        Settings.USE_PERSISTENCE = bool(request.persist)

        try:
            scanner = PySAST(
                use_ai=request.use_ai,
                verbose=request.verbose,
                json_only=request.json_only,
                html_only=request.html_only,
            )

            report = scanner.scan_project(str(project_path))

        finally:
            Settings.USE_PERSISTENCE = previous_use_persistence

        scan_id = f"SCAN_{uuid.uuid4().hex[:12]}"

        statistics = report.get("statistics", {})
        severity = statistics.get("severity", {})
        project = report.get("project", {})
        findings = report.get("findings", [])

        scan_document = {
            "scan_id": scan_id,
            "status": "completed",
            "project_name": project.get("name", project_path.name),
            "project_path": str(project_path),
            "files_scanned": project.get("total_files", len(project.get("scanned_files", []))),
            "findings_count": statistics.get("total_findings", len(findings)),
            "critical": severity.get("CRITICAL", 0),
            "high": severity.get("HIGH", 0),
            "medium": severity.get("MEDIUM", 0),
            "low": severity.get("LOW", 0),
            "reports": {
                "json": report.get("reports", {}).get("json"),
                "html": report.get("reports", {}).get("html"),
            },
            "findings": findings,
            "report": report,
        }

        self._repository.save_scan(
            copy.deepcopy(scan_document),
            persist=request.persist,
        )

        return scan_document

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self._repository.get_scan(scan_id)
