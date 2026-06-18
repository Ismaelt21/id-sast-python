from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    project_path: str = Field(..., description="Absolute or relative path to a Python project")
    use_ai: bool = Field(default=True, description="Enable Gemini-assisted analysis")
    persist: bool = Field(default=True, description="Persist the scan result")
    json_only: bool = Field(default=False, description="Export JSON only")
    html_only: bool = Field(default=False, description="Export HTML only")
    verbose: bool = Field(default=False, description="Enable verbose logging")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    project_name: str
    files_scanned: int
    findings_count: int
    critical: int
    high: int
    medium: int
    low: int
    reports: Dict[str, Optional[str]]
    findings: List[Dict[str, Any]]
    report: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str

