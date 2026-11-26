"""FastAPI entrypoint for Bug Hunter Lab backend."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db.database import get_finding, get_scan, init_db, list_findings, list_scans
from app.models.scan import ScanCreateRequest
from app.models.target import TargetValidateRequest, TargetValidateResponse
from app.security.target_validator import validate_and_resolve_target
from app.services.scan_runner import execute_scan


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db(settings.database_path)
    yield


app = FastAPI(
    title="Bug Hunter Lab API",
    version="0.2.1",
    description="Evidence-first web vulnerability scanner backend with SSRF-hardened target validation and SQLite scan history.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health() -> dict[str, object]:
    """Liveness and capability endpoint."""
    init_db(settings.database_path)
    return {
        "status": "ok",
        "service": "bug-hunter-lab-backend",
        "phase": 3,
        "database": "sqlite",
        "port_policy": "Standard web ports only (80 for HTTP, 443 for HTTPS)",
    }


@app.post(
    "/api/targets/validate",
    response_model=TargetValidateResponse,
    responses={
        400: {"model": TargetValidateResponse, "description": "Malformed URL, unsupported scheme, or DNS failure"},
        403: {"model": TargetValidateResponse, "description": "Prohibited destination or missing authorization"},
    },
)
def validate_target(payload: TargetValidateRequest) -> JSONResponse:
    """
    Validate, normalize, DNS-resolve, and authorize a target URL.
    Does NOT create a scan record.
    """
    result = validate_and_resolve_target(
        payload.url,
        authorized=payload.authorized,
    )

    body = TargetValidateResponse(
        valid=result.valid,
        allowed=result.allowed,
        normalized_url=result.normalized_url,
        hostname=result.hostname,
        scheme=result.scheme if result.scheme in ("http", "https") else None,
        port=result.port,
        resolved_ips=result.resolved_ips,
        error_code=result.error_code,
        reason=result.reason,
    )

    return JSONResponse(status_code=result.http_status, content=body.model_dump())


@app.get("/api/scans")
def get_scans() -> dict[str, object]:
    """Return real scan records persisted in SQLite (excludes sample data)."""
    init_db(settings.database_path)
    scans = list_scans(settings.database_path, include_sample=False)
    return {"scans": scans, "total": len(scans)}


@app.post("/api/scans")
def create_scan(payload: ScanCreateRequest) -> JSONResponse:
    """
    Validate target + authorization and execute the unified scan orchestrator
    across the selected security modules, persisting scan & findings in SQLite.
    """
    init_db(settings.database_path)
    validation, scan, findings = execute_scan(
        raw_url=payload.target,
        checks=list(payload.checks),
        authorized=payload.authorized,
        db_path=settings.database_path,
    )

    if scan is None:
        rejected = TargetValidateResponse(
            valid=validation.valid,
            allowed=validation.allowed,
            normalized_url=validation.normalized_url,
            hostname=validation.hostname,
            scheme=validation.scheme if validation.scheme in ("http", "https") else None,
            port=validation.port,
            resolved_ips=validation.resolved_ips,
            error_code=validation.error_code,
            reason=validation.reason,
        )
        return JSONResponse(status_code=validation.http_status, content=rejected.model_dump())

    return JSONResponse(status_code=201, content={"scan": scan, "findings": findings})


@app.get("/api/scans/{scan_id}")
def get_scan_by_id(scan_id: str) -> dict[str, object]:
    """Return one persisted scan record from SQLite."""
    init_db(settings.database_path)
    scan = get_scan(settings.database_path, scan_id)
    if not scan or scan.get("isSample"):
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {"scan": scan}


@app.get("/api/scans/{scan_id}/findings")
def get_scan_findings(scan_id: str) -> dict[str, object]:
    """Return persisted findings for one scan from SQLite."""
    init_db(settings.database_path)
    scan = get_scan(settings.database_path, scan_id)
    if not scan or scan.get("isSample"):
        raise HTTPException(status_code=404, detail="Scan record not found.")
    findings = list_findings(settings.database_path, scan_id=scan_id, include_sample=False)
    return {"findings": findings}


@app.get("/api/findings")
def get_all_findings() -> dict[str, object]:
    """Return all real findings persisted in SQLite."""
    init_db(settings.database_path)
    findings = list_findings(settings.database_path, include_sample=False)
    return {"findings": findings}


@app.get("/api/findings/{finding_id}")
def get_finding_by_id(finding_id: str) -> dict[str, object]:
    """Return one real finding persisted in SQLite."""
    init_db(settings.database_path)
    finding = get_finding(settings.database_path, finding_id)
    if not finding or finding.get("sample"):
        raise HTTPException(status_code=404, detail="Finding record not found.")
    return {"finding": finding}
