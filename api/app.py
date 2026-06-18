from __future__ import annotations

from fastapi import FastAPI, HTTPException

from api.schemas import HealthResponse, ScanRequest, ScanResponse
from config.settings import Settings
from service.scan_service import ScanService


Settings.initialize_directories()

app = FastAPI(
    title=Settings.APP_NAME,
    version=Settings.VERSION,
    description="id-sast-python microservice",
)

scan_service = ScanService()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=Settings.APP_NAME,
        version=Settings.VERSION,
    )


@app.get("/version")
def version() -> dict:
    return {
        "service": Settings.APP_NAME,
        "version": Settings.VERSION,
        "environment": Settings.ENVIRONMENT,
    }


@app.post("/scan", response_model=ScanResponse)
def run_scan(request: ScanRequest) -> ScanResponse:
    try:
        return scan_service.run_scan(request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/scan/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str) -> ScanResponse:
    scan = scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(**scan)

