"""SQLite persistence for real scans and findings."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any


@contextlib.contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition};")


def init_db(db_path: Path) -> None:
    """Create scans and findings tables if they do not already exist. Starts completely empty."""
    with _connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL,
                label TEXT NOT NULL,
                target TEXT NOT NULL,
                checks_json TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                progress INTEGER NOT NULL,
                current_stage_id TEXT,
                stages_json TEXT NOT NULL,
                modules_json TEXT NOT NULL,
                logs_json TEXT NOT NULL,
                mode TEXT NOT NULL,
                data_source TEXT NOT NULL,
                rescan_of_finding_id TEXT,
                verification_json TEXT,
                error TEXT,
                request_count INTEGER NOT NULL DEFAULT 0,
                total_checks INTEGER NOT NULL DEFAULT 0,
                is_sample INTEGER NOT NULL DEFAULT 0,
                check_results_json TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                category_label TEXT NOT NULL,
                module_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                status TEXT NOT NULL,
                check_status TEXT,
                target_url TEXT,
                target_path TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                summary TEXT NOT NULL,
                impact TEXT NOT NULL,
                severity_rationale TEXT NOT NULL,
                confidence_rationale TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                remediation_json TEXT NOT NULL,
                fix_snippet TEXT,
                fix_language TEXT,
                references_json TEXT NOT NULL,
                verification_json TEXT NOT NULL,
                sample INTEGER NOT NULL DEFAULT 0,
                rescan_count INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """
        )
        _ensure_column(conn, "scans", "check_results_json", "TEXT")
        _ensure_column(conn, "findings", "check_status", "TEXT")
        _ensure_column(conn, "findings", "target_url", "TEXT")


def _row_to_scan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "sequence": row["sequence"],
        "label": row["label"],
        "target": row["target"],
        "checks": json.loads(row["checks_json"]),
        "status": row["status"],
        "startedAt": row["started_at"],
        "completedAt": row["completed_at"],
        "progress": row["progress"],
        "currentStageId": row["current_stage_id"],
        "stages": json.loads(row["stages_json"]),
        "modules": json.loads(row["modules_json"]),
        "logs": json.loads(row["logs_json"]),
        "mode": row["mode"],
        "dataSource": row["data_source"],
        "rescanOfFindingId": row["rescan_of_finding_id"],
        "verification": json.loads(row["verification_json"]) if row["verification_json"] else None,
        "error": row["error"],
        "requestCount": row["request_count"],
        "totalChecks": row["total_checks"],
        "isSample": bool(row["is_sample"]),
        "checkResults": json.loads(row["check_results_json"]) if row["check_results_json"] else {},
    }


def _row_to_finding(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "scanId": row["scan_id"],
        "title": row["title"],
        "category": row["category"],
        "categoryLabel": row["category_label"],
        "moduleName": row["module_name"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "status": row["status"],
        "checkStatus": row["check_status"] or "finding_detected",
        "targetUrl": row["target_url"] or row["target_path"],
        "targetPath": row["target_path"],
        "detectedAt": row["detected_at"],
        "summary": row["summary"],
        "impact": row["impact"],
        "severityRationale": row["severity_rationale"],
        "confidenceRationale": row["confidence_rationale"],
        "evidence": json.loads(row["evidence_json"]),
        "remediation": json.loads(row["remediation_json"]),
        "fixSnippet": row["fix_snippet"],
        "fixLanguage": row["fix_language"],
        "references": json.loads(row["references_json"]),
        "verification": json.loads(row["verification_json"]),
        "sample": bool(row["sample"]),
        "rescanCount": row["rescan_count"],
    }


def get_next_sequence(db_path: Path) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COALESCE(MAX(sequence), 0) AS max_seq FROM scans WHERE is_sample = 0").fetchone()
        return int(row["max_seq"]) + 1 if row else 1


def insert_scan(db_path: Path, scan: dict[str, Any]) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scans (
                id, sequence, label, target, checks_json, status, started_at, completed_at,
                progress, current_stage_id, stages_json, modules_json, logs_json, mode,
                data_source, rescan_of_finding_id, verification_json, error, request_count,
                total_checks, is_sample, check_results_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                scan["id"],
                scan["sequence"],
                scan["label"],
                scan["target"],
                json.dumps(scan["checks"]),
                scan["status"],
                scan["startedAt"],
                scan.get("completedAt"),
                scan["progress"],
                scan.get("currentStageId"),
                json.dumps(scan["stages"]),
                json.dumps(scan["modules"]),
                json.dumps(scan["logs"]),
                scan["mode"],
                scan["dataSource"],
                scan.get("rescanOfFindingId"),
                json.dumps(scan["verification"]) if scan.get("verification") else None,
                scan.get("error"),
                scan.get("requestCount", 0),
                scan.get("totalChecks", len(scan["checks"])),
                1 if scan.get("isSample") else 0,
                json.dumps(scan.get("checkResults", {})),
            ),
        )


def update_scan(db_path: Path, scan: dict[str, Any]) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE scans
            SET status = ?, completed_at = ?, progress = ?, current_stage_id = ?,
                stages_json = ?, modules_json = ?, logs_json = ?, error = ?,
                request_count = ?, verification_json = ?, check_results_json = ?
            WHERE id = ?;
            """,
            (
                scan["status"],
                scan.get("completedAt"),
                scan["progress"],
                scan.get("currentStageId"),
                json.dumps(scan["stages"]),
                json.dumps(scan["modules"]),
                json.dumps(scan["logs"]),
                scan.get("error"),
                scan.get("requestCount", 0),
                json.dumps(scan["verification"]) if scan.get("verification") else None,
                json.dumps(scan.get("checkResults", {})),
                scan["id"],
            ),
        )


def list_scans(db_path: Path, *, include_sample: bool = False) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        if include_sample:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC, sequence DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans WHERE is_sample = 0 ORDER BY started_at DESC, sequence DESC"
            ).fetchall()
        return [_row_to_scan(row) for row in rows]


def get_scan(db_path: Path, scan_id: str) -> dict[str, Any] | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_scan(row) if row else None


def insert_findings(db_path: Path, findings: list[dict[str, Any]]) -> None:
    if not findings:
        return
    with _connect(db_path) as conn:
        for f in findings:
            conn.execute(
                """
                INSERT INTO findings (
                    id, fingerprint, scan_id, title, category, category_label, module_name,
                    severity, confidence, status, check_status, target_url, target_path,
                    detected_at, summary, impact, severity_rationale, confidence_rationale,
                    evidence_json, remediation_json, fix_snippet, fix_language, references_json,
                    verification_json, sample, rescan_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    f["id"],
                    f["fingerprint"],
                    f["scanId"],
                    f["title"],
                    f["category"],
                    f["categoryLabel"],
                    f["moduleName"],
                    f["severity"],
                    f["confidence"],
                    f["status"],
                    f.get("checkStatus", "finding_detected"),
                    f.get("targetUrl", f["targetPath"]),
                    f["targetPath"],
                    f["detectedAt"],
                    f["summary"],
                    f["impact"],
                    f["severityRationale"],
                    f["confidenceRationale"],
                    json.dumps(f["evidence"]),
                    json.dumps(f["remediation"]),
                    f.get("fixSnippet"),
                    f.get("fixLanguage"),
                    json.dumps(f["references"]),
                    json.dumps(f["verification"]),
                    1 if f.get("sample") else 0,
                    f.get("rescanCount", 0),
                ),
            )


def list_findings(
    db_path: Path,
    *,
    scan_id: str | None = None,
    include_sample: bool = False,
) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        clauses: list[str] = []
        params: list[Any] = []
        if not include_sample:
            clauses.append("sample = 0")
        if scan_id is not None:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            f"SELECT * FROM findings {where} ORDER BY detected_at DESC",
            tuple(params),
        ).fetchall()
        return [_row_to_finding(row) for row in rows]


def get_finding(db_path: Path, finding_id: str) -> dict[str, Any] | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return _row_to_finding(row) if row else None
