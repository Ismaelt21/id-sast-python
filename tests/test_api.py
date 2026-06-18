from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api import app as api_app
from api.schemas import ScanRequest


class _StubScanService:
    def run_scan(self, request: ScanRequest):
        project_name = Path(request.project_path).name
        return {
            "scan_id": "SCAN_test_001",
            "status": "completed",
            "project_name": project_name,
            "files_scanned": 1,
            "findings_count": 2,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "reports": {"json": None, "html": None},
            "findings": [{"id": "F1"}, {"id": "F2"}],
            "report": {"project": {"name": project_name}},
        }

    def get_scan(self, scan_id: str):
        if scan_id != "SCAN_test_001":
            return None
        return {
            "scan_id": scan_id,
            "status": "completed",
            "project_name": "demo",
            "files_scanned": 1,
            "findings_count": 2,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "reports": {"json": None, "html": None},
            "findings": [{"id": "F1"}, {"id": "F2"}],
            "report": {"scan_id": scan_id},
        }


def test_health_endpoint():
    client = TestClient(api_app.app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["service"] == "id-sast-python"


def test_version_endpoint():
    client = TestClient(api_app.app)
    response = client.get("/version")
    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "id-sast-python"
    assert "version" in payload


def test_scan_endpoint_returns_expected_contract(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(api_app, "scan_service", _StubScanService())
    client = TestClient(api_app.app)

    response = client.post(
        "/scan",
        json={
            "project_path": str(tmp_path / "demo"),
            "use_ai": False,
            "persist": False,
            "json_only": True,
            "html_only": False,
            "verbose": False,
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["scan_id"] == "SCAN_test_001"
    assert payload["status"] == "completed"
    assert payload["findings_count"] == 2
    assert payload["critical"] == 1
    assert payload["high"] == 1


def test_get_scan_endpoint_returns_404_when_missing(monkeypatch):
    monkeypatch.setattr(api_app, "scan_service", _StubScanService())
    client = TestClient(api_app.app)
    response = client.get("/scan/SCAN_missing")
    assert response.status_code == 404

