"""Module B — Cookie Security Analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.scanners.base import (
    ModuleExecutionResult,
    build_finding,
    format_http_request,
    format_http_response,
    redact_set_cookie_header,
)
from app.services.safe_http import SafeHttpError, SafeHttpResponse, ScanHttpSession

_SESSION_NAME_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "user", "id")
_CSRF_NAME_HINTS = ("csrf", "xsrf")


@dataclass(frozen=True)
class ParsedCookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    path: str | None
    domain: str | None
    redacted_header: str
    malformed: bool = False


def parse_set_cookie(raw_header: str) -> ParsedCookie:
    parts = [part.strip() for part in raw_header.split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return ParsedCookie(
            name="(malformed)",
            secure=False,
            httponly=False,
            samesite=None,
            path=None,
            domain=None,
            redacted_header=redact_set_cookie_header(raw_header),
            malformed=True,
        )

    name, _value = parts[0].split("=", 1)
    cookie_name = name.strip() or "(unnamed)"
    secure = False
    httponly = False
    samesite: str | None = None
    path: str | None = None
    domain: str | None = None

    for attr in parts[1:]:
        if "=" in attr:
            attr_name, attr_val = attr.split("=", 1)
            key = attr_name.strip().lower()
            val = attr_val.strip()
            if key == "samesite":
                samesite = val
            elif key == "path":
                path = val
            elif key == "domain":
                domain = val
        else:
            key = attr.lower()
            if key == "secure":
                secure = True
            elif key == "httponly":
                httponly = True

    return ParsedCookie(
        name=cookie_name,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        path=path,
        domain=domain,
        redacted_header=redact_set_cookie_header(raw_header),
        malformed=cookie_name == "(unnamed)",
    )


def _looks_like_session_cookie(name: str) -> bool:
    lower = name.lower()
    if any(hint in lower for hint in _CSRF_NAME_HINTS):
        return False
    return any(hint in lower for hint in _SESSION_NAME_HINTS)


def scan_cookies(
    target_url: str,
    session: ScanHttpSession,
    *,
    scan_id: str,
    baseline_response: SafeHttpResponse | None = None,
) -> ModuleExecutionResult:
    """Inspect Set-Cookie response headers independently without storing raw cookie values."""
    requests_made = 0
    try:
        if baseline_response is not None:
            response = baseline_response
        else:
            response = session.get(target_url, authorized=True)
            requests_made = 1 + len(response.redirect_chain)
    except (SafeHttpError, httpx.HTTPError, OSError) as exc:
        return ModuleExecutionResult(
            category="cookies",
            module_name="Cookie Security Analyzer",
            check_status="scan_failed",
            requests_made=requests_made or 1,
            summary="Cookie analysis failed because the target could not be fetched safely.",
            error=str(exc) or exc.__class__.__name__,
        )

    raw_cookies = response.header_values("set-cookie")
    if not raw_cookies:
        return ModuleExecutionResult(
            category="cookies",
            module_name="Cookie Security Analyzer",
            check_status="not_applicable",
            findings=[],
            requests_made=requests_made,
            summary="No relevant cookies observed in the target response.",
            observations=[
                {
                    "label": "Set-Cookie headers",
                    "value": "0 observed",
                    "state": "not_applicable",
                }
            ],
            limitations=[
                "Only cookies issued on unauthenticated GET responses to the target URL were inspected; post-login cookies were not tested."
            ],
        )

    final_url = response.url
    parsed_url = urlsplit(final_url)
    path = parsed_url.path or "/"
    req_text = format_http_request("GET", final_url, response.request_headers)
    resp_text = format_http_response(response, header_filter={"set-cookie"})

    findings: list[dict] = []
    malformed_count = 0
    idx = 0

    for raw in raw_cookies:
        cookie = parse_set_cookie(raw)
        if cookie.malformed:
            malformed_count += 1
            continue

        is_session = _looks_like_session_cookie(cookie.name)
        is_csrf = any(hint in cookie.name.lower() for hint in _CSRF_NAME_HINTS)

        missing_flags: list[str] = []
        checks: list[dict[str, str]] = []

        if cookie.secure:
            checks.append({"label": "Secure", "value": "Present", "expected": "Present", "state": "pass"})
        else:
            missing_flags.append("Secure")
            checks.append({"label": "Secure", "value": "Absent", "expected": "Present", "state": "fail"})

        if cookie.httponly:
            checks.append({"label": "HttpOnly", "value": "Present", "expected": "Present", "state": "pass"})
        else:
            if is_csrf:
                checks.append(
                    {
                        "label": "HttpOnly",
                        "value": "Absent (CSRF-named cookie)",
                        "expected": "Present unless JS double-submit CSRF requires reading",
                        "state": "warn",
                    }
                )
            else:
                missing_flags.append("HttpOnly")
                checks.append({"label": "HttpOnly", "value": "Absent", "expected": "Present", "state": "fail"})

        samesite_norm = cookie.samesite.lower() if cookie.samesite else None
        if samesite_norm in ("lax", "strict"):
            checks.append(
                {
                    "label": "SameSite",
                    "value": cookie.samesite or "",
                    "expected": "Lax or Strict",
                    "state": "pass",
                }
            )
        elif samesite_norm == "none":
            if not cookie.secure:
                missing_flags.append("Secure (required with SameSite=None)")
            checks.append(
                {
                    "label": "SameSite",
                    "value": "None",
                    "expected": "Lax or Strict (or None; Secure if cross-site required)",
                    "state": "warn",
                }
            )
        else:
            missing_flags.append("SameSite" if not cookie.samesite else f"Valid SameSite (observed '{cookie.samesite}')")
            checks.append(
                {
                    "label": "SameSite",
                    "value": cookie.samesite or "Absent",
                    "expected": "Lax or Strict",
                    "state": "fail",
                }
            )

        if not missing_flags:
            continue

        idx += 1
        has_critical_attr_gap = ("Secure" in missing_flags or "HttpOnly" in missing_flags)
        severity = "medium" if (is_session and has_critical_attr_gap) else "low"

        findings.append(
            build_finding(
                finding_id=f"{scan_id}-ck-{idx:02d}",
                scan_id=scan_id,
                fingerprint=f"cookie-flags-{cookie.name.lower()}",
                category="cookies",
                target_url=final_url,
                target_path=path,
                title=f"Cookie '{cookie.name}' is missing security flags ({', '.join(missing_flags)})",
                severity=severity,
                confidence="high",
                check_status="finding_detected",
                summary=f"Set-Cookie header for '{cookie.name}' omitted {', '.join(missing_flags)}. Cookie value was redacted.",
                impact=(
                    "Missing Secure allows cookie transmission over plaintext HTTP; missing HttpOnly lets client-side JavaScript read the cookie if XSS occurs; missing SameSite weakens CSRF defense."
                ),
                severity_rationale=(
                    "Rated Medium because the cookie name suggests session/authentication state and lacks Secure or HttpOnly."
                    if severity == "medium"
                    else "Rated Low because cookie purpose is not confirmed as session state or only SameSite/hardening flags are missing."
                ),
                confidence_rationale="High confidence: parsed directly from the observed Set-Cookie header (value redacted).",
                evidence_request=req_text,
                evidence_response=f"{resp_text}\n\nEvaluated cookie:\nSet-Cookie: {cookie.redacted_header}",
                evidence_note="Raw cookie values are intentionally redacted in stored evidence.",
                evidence_checks=checks,
                remediation=[
                    f"Add {'; '.join(missing_flags)} to the '{cookie.name}' Set-Cookie attributes.",
                    "Use SameSite=Lax or SameSite=Strict unless cross-site embedding explicitly requires SameSite=None; Secure.",
                ],
                fix_snippet=f"Set-Cookie: {cookie.name}=<value>; Path={cookie.path or '/'}; Secure; HttpOnly; SameSite=Lax",
                fix_language="http",
                references=[
                    {"label": "OWASP", "value": "Session Management Cheat Sheet"},
                    {"label": "CWE", "value": "CWE-614 / CWE-1004 - Cookie Security Attributes"},
                ],
            )
        )

    if malformed_count and not findings and malformed_count == len(raw_cookies):
        return ModuleExecutionResult(
            category="cookies",
            module_name="Cookie Security Analyzer",
            check_status="inconclusive",
            findings=[],
            requests_made=requests_made,
            summary="Observed Set-Cookie header(s) were malformed and could not be reliably parsed.",
            limitations=["Malformed Set-Cookie syntax prevented attribute verification."],
        )

    status = "finding_detected" if findings else "no_issue_observed"
    summary = (
        f"Analyzed {len(raw_cookies)} Set-Cookie header(s); {len(findings)} cookie issue(s) detected."
        if findings
        else f"No issue observed: all {len(raw_cookies)} Set-Cookie header(s) include Secure, HttpOnly, and safe SameSite flags."
    )
    observations = [
        {
            "label": parse_set_cookie(raw).name,
            "value": redact_set_cookie_header(raw),
            "state": "observed",
        }
        for raw in raw_cookies
    ]

    return ModuleExecutionResult(
        category="cookies",
        module_name="Cookie Security Analyzer",
        check_status=status,
        findings=findings,
        requests_made=requests_made,
        summary=summary,
        observations=observations,
        limitations=[
            "Only Set-Cookie headers returned on unauthenticated GET requests were evaluated."
        ],
    )
