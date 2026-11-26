"""Unified scan orchestrator connecting target validation, SafeHttpSession, the 4 security modules, and SQLite."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.config import settings
from app.db.database import get_next_sequence, insert_findings, insert_scan, update_scan
from app.scanners.base import MODULE_NAMES, CheckId, ModuleExecutionResult
from app.scanners.cookies import scan_cookies
from app.scanners.headers import scan_headers
from app.scanners.injection import scan_injection
from app.scanners.paths import PathProbeSpec, scan_paths
from app.security.target_validator import ResolverFn, TargetValidationResult, validate_and_resolve_target
from app.services.safe_http import SafeHttpClient, SafeHttpError, SafeHttpResponse, ScanHttpSession

ALL_CHECKS: tuple[CheckId, ...] = ("headers", "cookies", "paths", "injection")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _stage_title(check: CheckId) -> tuple[str, str]:
    titles: dict[CheckId, tuple[str, str]] = {
        "headers": ("Inspecting HTTP headers", "Checking CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy."),
        "cookies": ("Analyzing cookie flags", "Inspecting Set-Cookie attributes (Secure, HttpOnly, SameSite) with value redaction."),
        "paths": ("Checking exposed paths", "Comparing safe predefined paths against a non-existent baseline path."),
        "injection": ("Testing injection indicators", "Sending controlled non-destructive GET comparison probes against baseline."),
    }
    return titles[check]


def execute_scan(
    *,
    raw_url: str,
    checks: list[str],
    authorized: bool,
    db_path: Path | None = None,
    resolver: ResolverFn | None = None,
    transport: httpx.BaseTransport | None = None,
    extra_allowed_ports: frozenset[int] | None = None,
    min_interval_seconds: float | None = None,
    max_requests: int | None = None,
    request_timeout: float | None = None,
    path_probes: tuple[PathProbeSpec, ...] | None = None,
) -> tuple[TargetValidationResult, dict[str, Any] | None, list[dict[str, Any]]]:
    """
    Validate target, enforce safe HTTP limits, run the selected scanner modules,
    and persist both scan metadata (including per-module check statuses) and findings.
    """
    validation = validate_and_resolve_target(
        raw_url,
        authorized=authorized,
        resolver=resolver,
        extra_allowed_ports=extra_allowed_ports,
    )
    if not validation.valid or not validation.allowed or not validation.normalized_url:
        return validation, None, []

    target_db = db_path or settings.database_path
    sequence = get_next_sequence(target_db)
    scan_id = f"scan-{uuid.uuid4().hex[:10]}"
    started_at = _utc_now_iso()

    ordered_checks: list[CheckId] = [c for c in ALL_CHECKS if c in set(checks)]
    selected = set(ordered_checks)
    modules: dict[str, str] = {
        check: ("queued" if check in selected else "skipped")
        for check in ALL_CHECKS
    }

    stages: list[dict[str, Any]] = [
        {
            "id": "validate",
            "label": "Validating authorized target",
            "detail": f"Normalized {validation.normalized_url} and verified DNS/SSRF rules.",
            "status": "done",
            "durationMs": 0,
        },
        {
            "id": "baseline-http",
            "label": "Fetching baseline response",
            "detail": "Executing initial IP-pinned GET via SafeHttpClient.",
            "status": "active",
            "durationMs": 0,
        },
    ]
    for check in ordered_checks:
        title, detail = _stage_title(check)
        stages.append(
            {
                "id": f"check-{check}",
                "label": title,
                "detail": detail,
                "status": "pending",
                "durationMs": 0,
            }
        )

    logs: list[dict[str, Any]] = [
        {
            "id": f"{scan_id}-log-0",
            "at": started_at,
            "level": "info",
            "text": (
                f"Target validated: {validation.normalized_url} "
                f"(resolved IPs: {', '.join(validation.resolved_ips)})."
            ),
        }
    ]

    scan: dict[str, Any] = {
        "id": scan_id,
        "sequence": sequence,
        "label": f"Scan {sequence:02d}",
        "target": validation.normalized_url,
        "checks": ordered_checks,
        "status": "running",
        "startedAt": started_at,
        "completedAt": None,
        "progress": 10,
        "currentStageId": "baseline-http",
        "stages": stages,
        "modules": modules,
        "logs": logs,
        "mode": "live",
        "dataSource": "live",
        "rescanOfFindingId": None,
        "verification": None,
        "error": None,
        "requestCount": 0,
        "totalChecks": len(ordered_checks),
        "isSample": False,
        "checkResults": {},
    }
    insert_scan(target_db, scan)

    client = SafeHttpClient(
        resolver=resolver,
        transport=transport,
        request_timeout=request_timeout,
        extra_allowed_ports=extra_allowed_ports,
    )
    session = ScanHttpSession(
        client,
        max_requests=max_requests,
        min_interval_seconds=min_interval_seconds,
    )

    def add_log(level: str, text: str) -> None:
        scan["logs"].append(
            {
                "id": f"{scan_id}-log-{len(scan['logs'])}",
                "at": _utc_now_iso(),
                "level": level,
                "text": text,
            }
        )

    # 1. Fetch initial baseline target response once
    baseline_response: SafeHttpResponse | None = None
    try:
        baseline_response = session.get(validation.normalized_url, authorized=True)
        stages[1]["status"] = "done"
        add_log(
            "success",
            f"Baseline GET {baseline_response.url} returned HTTP {baseline_response.status_code} ({len(baseline_response.body)} bytes) via IP {baseline_response.connected_ip}.",
        )
    except (SafeHttpError, httpx.HTTPError, OSError) as exc:
        err_msg = str(exc) or exc.__class__.__name__
        stages[1]["status"] = "failed"
        for check in ordered_checks:
            modules[check] = "failed"
            scan["checkResults"][check] = ModuleExecutionResult(
                category=check,
                module_name=MODULE_NAMES[check],
                check_status="scan_failed",
                summary=f"Skipped because initial target fetch failed: {err_msg}",
                error=err_msg,
            ).to_check_record()
        for stage in stages[2:]:
            stage["status"] = "failed"
        scan["status"] = "failed"
        scan["completedAt"] = _utc_now_iso()
        scan["progress"] = 10
        scan["currentStageId"] = None
        scan["requestCount"] = session.request_count
        scan["error"] = f"Initial target fetch failed: {err_msg}"
        add_log("error", f"Initial target fetch failed: {err_msg}")
        update_scan(target_db, scan)
        return validation, scan, []

    # 2. Run each selected scanner module independently
    all_findings: list[dict[str, Any]] = []
    failed_modules = 0

    for idx, check in enumerate(ordered_checks):
        stage = stages[2 + idx]
        stage["status"] = "active"
        modules[check] = "running"

        try:
            if check == "headers":
                result = scan_headers(
                    baseline_response.url,
                    session,
                    scan_id=scan_id,
                    baseline_response=baseline_response,
                )
            elif check == "cookies":
                result = scan_cookies(
                    baseline_response.url,
                    session,
                    scan_id=scan_id,
                    baseline_response=baseline_response,
                )
            elif check == "paths":
                kwargs = {"probes": path_probes} if path_probes is not None else {}
                result = scan_paths(
                    baseline_response.url,
                    session,
                    scan_id=scan_id,
                    **kwargs,
                )
            else:
                result = scan_injection(
                    baseline_response.url,
                    session,
                    scan_id=scan_id,
                    root_response=baseline_response,
                )
        except Exception as exc:  # Defensive isolation: one crashed module never marks scan clean
            err_msg = str(exc) or exc.__class__.__name__
            result = ModuleExecutionResult(
                category=check,
                module_name=MODULE_NAMES[check],
                check_status="scan_failed",
                summary=f"Module raised an unexpected error: {err_msg}",
                error=err_msg,
            )

        scan["checkResults"][check] = result.to_check_record()

        if result.check_status == "scan_failed":
            failed_modules += 1
            stage["status"] = "failed"
            modules[check] = "failed"
            add_log("error", f"{result.module_name}: scan_failed — {result.error or result.summary}")
        else:
            stage["status"] = "done"
            modules[check] = "done"
            level = "warn" if result.check_status in ("finding_detected", "inconclusive") else "success"
            add_log("info" if level == "warn" and not result.findings else level, f"{result.module_name} ({result.check_status}): {result.summary}")
            all_findings.extend(result.findings)

    insert_findings(target_db, all_findings)

    scan["completedAt"] = _utc_now_iso()
    scan["currentStageId"] = None
    scan["requestCount"] = session.request_count

    if failed_modules == len(ordered_checks):
        scan["status"] = "failed"
        scan["progress"] = 50
        scan["error"] = "All selected scanner modules failed."
    else:
        scan["status"] = "completed"
        scan["progress"] = 100
        if failed_modules > 0:
            scan["error"] = f"{failed_modules} of {len(ordered_checks)} scanner module(s) failed; partial results recorded."

    update_scan(target_db, scan)
    return validation, scan, all_findings


# Backward-compatible alias for any callers from pre-Phase-3 tests
run_baseline_scan = execute_scan
