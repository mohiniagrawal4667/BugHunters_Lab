"""Module C — Exposed Path Inspector with random non-existent baseline comparison."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from app.scanners.base import (
    ModuleExecutionResult,
    Severity,
    build_finding,
    format_http_request,
    format_http_response,
    redact_secret_lines,
)
from app.services.safe_http import SafeHttpError, SafeHttpResponse, ScanHttpSession


@dataclass(frozen=True)
class PathProbeSpec:
    path: str
    kind: str  # "public_metadata" | "sensitive_config"
    label: str
    default_severity: Severity


DEFAULT_PATH_PROBES: tuple[PathProbeSpec, ...] = (
    PathProbeSpec("/robots.txt", "public_metadata", "Crawler directives (/robots.txt)", "informational"),
    PathProbeSpec("/.well-known/security.txt", "public_metadata", "Security contact (/.well-known/security.txt)", "informational"),
    PathProbeSpec("/sitemap.xml", "public_metadata", "XML sitemap (/sitemap.xml)", "informational"),
    PathProbeSpec("/.env", "sensitive_config", "Environment configuration file (/.env)", "critical"),
    PathProbeSpec("/.git/HEAD", "sensitive_config", "Git repository HEAD (/.git/HEAD)", "high"),
    PathProbeSpec("/config.json", "sensitive_config", "Application JSON config (/config.json)", "high"),
    PathProbeSpec("/backup/", "sensitive_config", "Backup directory listing (/backup/)", "high"),
    PathProbeSpec("/server-status", "sensitive_config", "Server status endpoint (/server-status)", "medium"),
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(text: str) -> str:
    match = _TITLE_RE.search(text)
    if not match:
        return ""
    return " ".join(match.group(1).split())[:120]


def _normalized_body_hash(body: bytes, probe_path: str) -> str:
    text = body.decode("utf-8", errors="replace")
    normalized = text.replace(probe_path, "")
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _matches_baseline(probe: SafeHttpResponse, baseline: SafeHttpResponse, probe_path: str) -> bool:
    """Detect generic fallback / soft-404 pages returning HTTP 200 (or matching error bodies)."""
    if probe.status_code != baseline.status_code:
        return False

    probe_ct = (probe.first_header("content-type") or "").split(";")[0].strip().lower()
    base_ct = (baseline.first_header("content-type") or "").split(";")[0].strip().lower()
    if probe_ct and base_ct and probe_ct != base_ct:
        return False

    if _normalized_body_hash(probe.body, probe_path) == _normalized_body_hash(baseline.body, urlsplit(baseline.url).path):
        return True

    base_len = len(baseline.body)
    probe_len = len(probe.body)
    tolerance = max(64, int(base_len * 0.08))
    if abs(probe_len - base_len) <= tolerance:
        probe_title = _extract_title(probe.text(4000))
        base_title = _extract_title(baseline.text(4000))
        if probe_title == base_title:
            return True

    return False


def _has_env_signature(text: str) -> bool:
    env_lines = 0
    for line in text.splitlines()[:25]:
        if re.match(r"^\s*[A-Z][A-Z0-9_]{1,40}\s*=\s*\S+", line):
            env_lines += 1
    return env_lines >= 2


def _has_git_head_signature(text: str) -> bool:
    stripped = text.strip()
    return stripped.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-fA-F]{40}", stripped))


def _has_json_config_signature(text: str, content_type: str) -> bool:
    if "json" not in content_type and not text.lstrip().startswith("{"):
        return False
    try:
        parsed = json.loads(text)
        return isinstance(parsed, dict) and len(parsed) > 0
    except ValueError:
        return False


def _has_dir_listing_signature(text: str) -> bool:
    lower = text.lower()
    return "index of /" in lower or "directory listing for" in lower


def _has_server_status_signature(text: str) -> bool:
    lower = text.lower()
    return "apache server status" in lower or "server uptime:" in lower or "total accesses:" in lower


def scan_paths(
    target_url: str,
    session: ScanHttpSession,
    *,
    scan_id: str,
    probes: tuple[PathProbeSpec, ...] = DEFAULT_PATH_PROBES,
) -> ModuleExecutionResult:
    """Inspect a safe, limited set of paths and compare every response against a non-existent baseline."""
    parsed = urlsplit(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    baseline_path = f"/__bhl_nonexistent_{uuid.uuid4().hex[:10]}"
    baseline_url = urljoin(origin, baseline_path)

    requests_made = 0
    try:
        baseline = session.get(baseline_url, authorized=True)
        requests_made += 1 + len(baseline.redirect_chain)
    except (SafeHttpError, httpx.HTTPError, OSError) as exc:
        return ModuleExecutionResult(
            category="paths",
            module_name="Exposed Path Detector",
            check_status="scan_failed",
            requests_made=1,
            summary="Exposed path scan failed because the non-existent baseline request could not complete.",
            error=str(exc) or exc.__class__.__name__,
        )

    base_ct = (baseline.first_header("content-type") or "unknown").split(";")[0].strip()
    base_len = len(baseline.body)
    baseline_text = format_http_response(baseline, header_filter={"content-type", "content-length"})

    findings: list[dict] = []
    fallback_ignored: list[str] = []
    inconclusive_paths: list[str] = []
    failed_probes = 0
    idx = 0

    for spec in probes:
        probe_url = urljoin(origin, spec.path)
        try:
            probe_resp = session.get(probe_url, authorized=True)
            requests_made += 1 + len(probe_resp.redirect_chain)
        except (SafeHttpError, httpx.HTTPError, OSError):
            failed_probes += 1
            continue

        if probe_resp.status_code in (401, 403, 404, 405, 410):
            continue

        if _matches_baseline(probe_resp, baseline, spec.path):
            fallback_ignored.append(spec.path)
            continue

        if probe_resp.status_code != 200:
            continue

        probe_ct = (probe_resp.first_header("content-type") or "unknown").split(";")[0].strip().lower()
        probe_len = len(probe_resp.body)
        body_text = probe_resp.text(8000)

        comparison = [
            {
                "signal": "HTTP status",
                "baseline": str(baseline.status_code),
                "observed": str(probe_resp.status_code),
                "verdict": "warn" if spec.kind == "public_metadata" else "fail",
            },
            {
                "signal": "Content-Type",
                "baseline": base_ct,
                "observed": probe_ct,
                "verdict": "info",
            },
            {
                "signal": "Body length",
                "baseline": f"{base_len} bytes",
                "observed": f"{probe_len} bytes",
                "verdict": "info",
            },
        ]

        req_text = format_http_request("GET", probe_url, probe_resp.request_headers)
        base_req_and_resp = f"{format_http_request('GET', baseline_url)}\n\n{baseline_text}"

        if spec.kind == "public_metadata":
            # Public discovery resources: only report if non-HTML or clear XML/text resource
            if "html" in probe_ct:
                inconclusive_paths.append(spec.path)
                continue
            idx += 1
            preview = "\n".join(body_text.splitlines()[:8])[:400]
            findings.append(
                build_finding(
                    finding_id=f"{scan_id}-path-{idx:02d}",
                    scan_id=scan_id,
                    fingerprint=f"path-public-{spec.path.strip('/.').replace('/', '-')}",
                    category="paths",
                    target_url=probe_url,
                    target_path=spec.path,
                    title=f"Public resource observed at {spec.path}",
                    severity="informational",
                    confidence="high",
                    check_status="finding_detected",
                    summary=f"{spec.path} returned HTTP 200 ({probe_ct}, {probe_len} bytes) distinct from the non-existent baseline ({baseline.status_code}).",
                    impact="Public metadata files such as robots.txt, security.txt, or sitemap.xml are expected on many sites, though Disallow entries can highlight internal paths.",
                    severity_rationale="Rated Informational because this is a standard public metadata resource, not a vulnerability by itself.",
                    confidence_rationale="High confidence: HTTP status, content type, and content differed cleanly from the non-existent baseline.",
                    evidence_request=req_text,
                    evidence_response=format_http_response(
                        probe_resp,
                        header_filter={"content-type", "content-length", "cache-control"},
                        body_preview=preview,
                    ),
                    evidence_baseline=base_req_and_resp,
                    evidence_comparison=comparison,
                    remediation=[
                        f"Review {spec.path} to verify no internal or sensitive administrative paths are unnecessarily listed."
                    ],
                    references=[{"label": "RFC", "value": "RFC 9116 / Robots Exclusion Standard"}],
                )
            )
            continue

        # Sensitive config/exposure probes require content verification, never status 200 alone
        confirmed_marker: str | None = None
        if spec.path == "/.env" and "html" not in probe_ct and _has_env_signature(body_text):
            confirmed_marker = "Environment variable KEY=VALUE entries detected (values redacted)"
        elif spec.path == "/.git/HEAD" and _has_git_head_signature(body_text):
            confirmed_marker = "Git HEAD reference string observed"
        elif spec.path == "/config.json" and _has_json_config_signature(body_text, probe_ct):
            confirmed_marker = "JSON configuration object observed"
        elif spec.path == "/backup/" and _has_dir_listing_signature(body_text):
            confirmed_marker = "Directory listing markers observed"
        elif spec.path == "/server-status" and _has_server_status_signature(body_text):
            confirmed_marker = "Server status telemetry markers observed"

        if confirmed_marker:
            idx += 1
            comparison.append(
                {
                    "signal": "Resource signature",
                    "baseline": "Not present",
                    "observed": confirmed_marker,
                    "verdict": "fail",
                }
            )
            redacted_preview = redact_secret_lines(body_text)
            findings.append(
                build_finding(
                    finding_id=f"{scan_id}-path-{idx:02d}",
                    scan_id=scan_id,
                    fingerprint=f"path-exposed-{spec.path.strip('/.').replace('/', '-')}",
                    category="paths",
                    target_url=probe_url,
                    target_path=spec.path,
                    title=f"{spec.label} appears publicly reachable",
                    severity=spec.default_severity,
                    confidence="high",
                    check_status="finding_detected",
                    summary=f"{spec.path} returned HTTP 200 ({probe_ct}, {probe_len} bytes) differing from baseline {baseline.status_code}, with marker: {confirmed_marker}.",
                    impact="Exposed configuration files, repository metadata, or backup listings can disclose internal structure or credentials.",
                    severity_rationale=f"Rated {spec.default_severity.title()} due to verified content signatures matching {spec.path}.",
                    confidence_rationale="High confidence: distinct from baseline AND matched expected resource signature.",
                    evidence_request=req_text,
                    evidence_response=format_http_response(
                        probe_resp,
                        header_filter={"content-type", "content-length"},
                        body_preview=redacted_preview,
                    ),
                    evidence_baseline=base_req_and_resp,
                    evidence_note="Sensitive values after '=' are redacted automatically; full files are not downloaded.",
                    evidence_comparison=comparison,
                    remediation=[
                        f"Block public access to {spec.path} at the web server or reverse proxy and remove sensitive files from the web root.",
                        "Rotate any credentials or secrets that may have been exposed.",
                    ],
                    fix_snippet="location ~ /\\. {\n    deny all;\n    return 404;\n}",
                    fix_language="nginx",
                    references=[
                        {"label": "OWASP", "value": "A05:2021 - Security Misconfiguration"},
                        {"label": "CWE", "value": "CWE-538 - File and Directory Information Exposure"},
                    ],
                )
            )
        else:
            # HTTP 200 differed from baseline, but lacks expected file signature -> inconclusive!
            inconclusive_paths.append(spec.path)

    limitations = [
        f"Checked {len(probes)} predefined non-destructive paths against random baseline {baseline_path}."
    ]
    if fallback_ignored:
        limitations.append(
            f"Ignored {len(fallback_ignored)} path(s) returning HTTP 200 matching the baseline fallback response ({', '.join(fallback_ignored)})."
        )
    if inconclusive_paths:
        limitations.append(
            f"HTTP 200 on {', '.join(inconclusive_paths)} differed from baseline but lacked expected file signatures and was not flagged as a vulnerability."
        )
    if failed_probes:
        limitations.append(f"{failed_probes} path probe(s) timed out or failed during execution.")

    if failed_probes == len(probes):
        status = "scan_failed"
    elif findings:
        status = "finding_detected"
    elif inconclusive_paths:
        status = "inconclusive"
    else:
        status = "no_issue_observed"

    observations = [
        {
            "label": "Non-existent baseline",
            "value": f"{baseline_path} -> HTTP {baseline.status_code} ({base_ct}, {base_len} bytes)",
            "state": "baseline",
        },
        {
            "label": "Generic fallback (soft-404) ignored",
            "value": ", ".join(fallback_ignored) if fallback_ignored else "None",
            "state": "info",
        },
        {
            "label": "Inconclusive HTTP 200 paths",
            "value": ", ".join(inconclusive_paths) if inconclusive_paths else "None",
            "state": "warn" if inconclusive_paths else "info",
        },
    ]

    return ModuleExecutionResult(
        category="paths",
        module_name="Exposed Path Detector",
        check_status=status,
        findings=findings,
        requests_made=requests_made,
        summary=(
            f"Probed {len(probes)} paths vs baseline HTTP {baseline.status_code}; {len(findings)} finding(s), {len(fallback_ignored)} generic fallback(s) ignored, {len(inconclusive_paths)} inconclusive."
            if findings or inconclusive_paths
            else f"No confirmed exposed resource identified across {len(probes)} paths (baseline HTTP {baseline.status_code}; {len(fallback_ignored)} generic fallback(s) ignored)."
        ),
        observations=observations,
        limitations=limitations,
    )
