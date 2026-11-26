"""Shared types, redaction helpers, and finding builders for all four scanner modules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

from app.services.safe_http import SafeHttpResponse

CheckId = Literal["headers", "cookies", "paths", "injection"]
CheckStatus = Literal[
    "finding_detected",
    "no_issue_observed",
    "inconclusive",
    "not_applicable",
    "scan_failed",
]
Severity = Literal["critical", "high", "medium", "low", "informational"]
Confidence = Literal["high", "medium", "low"]

CATEGORY_LABELS: dict[CheckId, str] = {
    "headers": "Header inspector",
    "cookies": "Cookie analyzer",
    "paths": "Exposed path",
    "injection": "Injection tester",
}

MODULE_NAMES: dict[CheckId, str] = {
    "headers": "HTTP Header Inspector",
    "cookies": "Cookie Security Analyzer",
    "paths": "Exposed Path Detector",
    "injection": "Injection Vulnerability Tester",
}

_SENSITIVE_HEADER_KEYS = frozenset({"authorization", "proxy-authorization", "x-api-key"})


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def redact_set_cookie_header(raw_value: str) -> str:
    """
    Preserve cookie name and security attributes while redacting the cookie value.
    Example: 'session=secret123; Path=/; HttpOnly' -> 'session=[REDACTED]; Path=/; HttpOnly'
    """
    parts = [part.strip() for part in raw_value.split(";")]
    if not parts:
        return "[REDACTED]"
    name_val = parts[0]
    if "=" in name_val:
        name, _val = name_val.split("=", 1)
        redacted_first = f"{name.strip()}=[REDACTED]"
    else:
        redacted_first = "[REDACTED]"
    if len(parts) == 1:
        return redacted_first
    return f"{redacted_first}; " + "; ".join(parts[1:])


def redact_secret_lines(text: str, max_lines: int = 12, max_chars: int = 600) -> str:
    """
    Redact potential secret values in KEY=VALUE or JSON-like lines before storing evidence.
    """
    out: list[str] = []
    for line in text.splitlines()[:max_lines]:
        # Redact ENV-style KEY=VALUE values while keeping variable names visible
        env_match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", line)
        if env_match:
            out.append(f"{env_match.group(1)}=[REDACTED]")
        else:
            out.append(line)
    joined = "\n".join(out)
    if len(joined) > max_chars:
        return joined[:max_chars] + "\n...[truncated]"
    return joined


def format_http_request(method: str, url: str, headers: dict[str, str] | None = None) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    if headers:
        for key, value in headers.items():
            if key.lower() == "host":
                continue
            shown = "[REDACTED]" if key.lower() in _SENSITIVE_HEADER_KEYS else value
            lines.append(f"{key}: {shown}")
    return "\n".join(lines)


def format_http_response(
    response: SafeHttpResponse,
    *,
    header_filter: set[str] | None = None,
    body_preview: str | None = None,
) -> str:
    lines = [f"HTTP/1.1 {response.status_code}"]
    for key, value in response.headers:
        lower = key.lower()
        if header_filter is not None and lower not in header_filter:
            continue
        if lower == "set-cookie":
            shown = redact_set_cookie_header(value)
        elif lower in _SENSITIVE_HEADER_KEYS:
            shown = "[REDACTED]"
        else:
            shown = value
        lines.append(f"{key}: {shown}")
    if body_preview:
        lines.append("")
        lines.append(body_preview)
    return "\n".join(lines)


@dataclass
class ModuleExecutionResult:
    """Structured outcome returned by each independent scanner module."""

    category: CheckId
    module_name: str
    check_status: CheckStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    requests_made: int = 0
    summary: str = ""
    observations: list[dict[str, str]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    error: str | None = None

    def to_check_record(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "moduleName": self.module_name,
            "status": self.check_status,
            "findingsCount": len(self.findings),
            "requestsMade": self.requests_made,
            "summary": self.summary,
            "observations": self.observations,
            "limitations": self.limitations,
            "error": self.error,
        }


def build_finding(
    *,
    finding_id: str,
    scan_id: str,
    fingerprint: str,
    category: CheckId,
    target_url: str,
    target_path: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    check_status: CheckStatus,
    summary: str,
    impact: str,
    severity_rationale: str,
    confidence_rationale: str,
    evidence_request: str,
    evidence_response: str,
    remediation: list[str],
    references: list[dict[str, str]],
    evidence_baseline: str | None = None,
    evidence_note: str | None = None,
    evidence_checks: list[dict[str, str]] | None = None,
    evidence_comparison: list[dict[str, str]] | None = None,
    fix_snippet: str | None = None,
    fix_language: str | None = None,
    detected_at: str | None = None,
) -> dict[str, Any]:
    """Build a consistent Finding record matching both Phase 3 spec and frontend schema."""
    timestamp = detected_at or utc_now_iso()
    evidence: dict[str, Any] = {
        "request": evidence_request,
        "response": evidence_response,
    }
    if evidence_baseline is not None:
        evidence["baseline"] = evidence_baseline
    if evidence_note is not None:
        evidence["note"] = evidence_note
    if evidence_checks is not None:
        evidence["checks"] = evidence_checks
    if evidence_comparison is not None:
        evidence["comparison"] = evidence_comparison

    return {
        "id": finding_id,
        "fingerprint": fingerprint,
        "scanId": scan_id,
        "title": title,
        "category": category,
        "categoryLabel": CATEGORY_LABELS[category],
        "moduleName": MODULE_NAMES[category],
        "severity": severity,
        "confidence": confidence,
        "status": "open",
        "checkStatus": check_status,
        "targetUrl": target_url,
        "targetPath": target_path,
        "detectedAt": timestamp,
        "summary": summary,
        "impact": impact,
        "severityRationale": severity_rationale,
        "confidenceRationale": confidence_rationale,
        "evidence": evidence,
        "remediation": remediation,
        "fixSnippet": fix_snippet,
        "fixLanguage": fix_language,
        "references": references,
        "verification": {
            "status": "not-verified",
            "before": evidence_response,
            "note": "Observed during live scan. Run a verification rescan after applying fixes.",
        },
        "sample": False,
        "rescanCount": 0,
    }
