"""Module A — HTTP Security Header Inspector."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from app.scanners.base import (
    ModuleExecutionResult,
    build_finding,
    format_http_request,
    format_http_response,
)
from app.services.safe_http import SafeHttpError, SafeHttpResponse, ScanHttpSession

_HEADER_NAMES = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)

_SAFE_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)
_UNSAFE_REFERRER_POLICIES = frozenset(
    {
        "unsafe-url",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
    }
)


def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_part in csp_value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = [tok.lower() for tok in tokens[1:]]
    return directives


def _evaluate_csp(csp_value: str) -> tuple[bool, list[str]]:
    directives = _parse_csp_directives(csp_value)
    issues: list[str] = []
    script_sources = directives.get("script-src") or directives.get("default-src")
    if script_sources is None:
        issues.append("Neither script-src nor default-src is defined.")
    else:
        if "'unsafe-inline'" in script_sources:
            issues.append("script-src/default-src permits 'unsafe-inline'.")
        if "'unsafe-eval'" in script_sources:
            issues.append("script-src/default-src permits 'unsafe-eval'.")
        if "*" in script_sources:
            issues.append("script-src/default-src uses wildcard '*' source.")
        if "http:" in script_sources:
            issues.append("script-src/default-src allows plaintext 'http:' script loads.")

    if "object-src" not in directives and "default-src" not in directives:
        issues.append("No object-src or default-src restriction defined.")

    return len(issues) == 0, issues


def _parse_hsts_max_age(hsts_value: str) -> int | None:
    match = re.search(r"(?:^|;|\s)max-age\s*=\s*\"?(\d+)\"?", hsts_value, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def scan_headers(
    target_url: str,
    session: ScanHttpSession,
    *,
    scan_id: str,
    baseline_response: SafeHttpResponse | None = None,
) -> ModuleExecutionResult:
    """Inspect real HTTP response security headers on the authorized target."""
    requests_made = 0
    try:
        if baseline_response is not None:
            response = baseline_response
        else:
            response = session.get(target_url, authorized=True)
            requests_made = 1 + len(response.redirect_chain)
    except (SafeHttpError, httpx.HTTPError, OSError) as exc:
        return ModuleExecutionResult(
            category="headers",
            module_name="HTTP Header Inspector",
            check_status="scan_failed",
            requests_made=requests_made or 1,
            summary="HTTP header inspection failed because the target could not be fetched safely.",
            error=str(exc) or exc.__class__.__name__,
        )

    final_url = response.url
    parsed = urlsplit(final_url)
    scheme = parsed.scheme.lower()
    path = parsed.path or "/"
    content_type = (response.first_header("content-type") or "").lower()
    is_html = "text/html" in content_type or "application/xhtml" in content_type

    observed_map = {
        name: response.first_header(name)
        for name in _HEADER_NAMES
    }

    req_text = format_http_request("GET", final_url, response.request_headers)
    header_filter = {name.lower() for name in _HEADER_NAMES} | {"content-type"}
    resp_text = format_http_response(response, header_filter=header_filter)

    findings: list[dict] = []
    idx = 0

    def next_id() -> str:
        nonlocal idx
        idx += 1
        return f"{scan_id}-hdr-{idx:02d}"

    # 1. Content-Security-Policy
    csp = observed_map["Content-Security-Policy"]
    if not csp:
        findings.append(
            build_finding(
                finding_id=next_id(),
                scan_id=scan_id,
                fingerprint="header-csp-missing",
                category="headers",
                target_url=final_url,
                target_path=path,
                title="Content-Security-Policy header is missing",
                severity="medium" if is_html else "low",
                confidence="high",
                check_status="finding_detected",
                summary="The HTTP response did not include a Content-Security-Policy header.",
                impact=(
                    "Without CSP, browsers have no policy restricting where scripts, styles, or frames can be loaded from, increasing the blast radius of any injection bug."
                ),
                severity_rationale=(
                    "Rated Medium on HTML responses (or Low on non-HTML) because missing CSP removes a defense-in-depth browser boundary without proving an XSS flaw exists."
                ),
                confidence_rationale="High confidence: Content-Security-Policy was directly absent from the captured response headers.",
                evidence_request=req_text,
                evidence_response=f"{resp_text}\nContent-Security-Policy: [absent]",
                evidence_checks=[
                    {
                        "label": "Content-Security-Policy",
                        "value": "Absent",
                        "expected": "default-src 'self'; script-src 'self'; object-src 'none'",
                        "state": "fail",
                    }
                ],
                remediation=[
                    "Define a restrictive Content-Security-Policy starting with default-src 'self'; object-src 'none'; base-uri 'self'.",
                    "Avoid 'unsafe-inline' and 'unsafe-eval' in script-src by using nonces or hashes.",
                ],
                fix_snippet="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
                fix_language="http",
                references=[
                    {"label": "OWASP", "value": "Content Security Policy Cheat Sheet"},
                    {"label": "CWE", "value": "CWE-693 - Protection Mechanism Failure"},
                ],
            )
        )
    else:
        csp_strong, csp_issues = _evaluate_csp(csp)
        if not csp_strong:
            findings.append(
                build_finding(
                    finding_id=next_id(),
                    scan_id=scan_id,
                    fingerprint="header-csp-weak",
                    category="headers",
                    target_url=final_url,
                    target_path=path,
                    title="Content-Security-Policy permits unsafe directives",
                    severity="medium",
                    confidence="high",
                    check_status="finding_detected",
                    summary=f"Content-Security-Policy is present but contains weak directives: {' '.join(csp_issues)}",
                    impact="Permissive CSP directives such as 'unsafe-inline', 'unsafe-eval', or wildcards allow inline or untrusted scripts to execute if injection occurs.",
                    severity_rationale="Rated Medium because a weakened CSP fails to block common script injection vectors despite being configured.",
                    confidence_rationale="High confidence: the exact unsafe directive tokens were observed in the response header.",
                    evidence_request=req_text,
                    evidence_response=resp_text,
                    evidence_checks=[
                        {
                            "label": "Content-Security-Policy",
                            "value": csp,
                            "expected": "No 'unsafe-inline', 'unsafe-eval', '*', or http: in script-src",
                            "state": "warn",
                        }
                    ],
                    remediation=[
                        "Remove 'unsafe-inline', 'unsafe-eval', and wildcard '*' from script-src.",
                        "Migrate inline scripts to external files or cryptographic nonces.",
                    ],
                    fix_snippet="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
                    fix_language="http",
                    references=[
                        {"label": "OWASP", "value": "A05:2021 - Security Misconfiguration"},
                        {"label": "CWE", "value": "CWE-693 - Protection Mechanism Failure"},
                    ],
                )
            )

    # 2. Strict-Transport-Security
    hsts = observed_map["Strict-Transport-Security"]
    if scheme == "https":
        if not hsts:
            findings.append(
                build_finding(
                    finding_id=next_id(),
                    scan_id=scan_id,
                    fingerprint="header-hsts-missing",
                    category="headers",
                    target_url=final_url,
                    target_path=path,
                    title="Strict-Transport-Security (HSTS) header is missing",
                    severity="medium",
                    confidence="high",
                    check_status="finding_detected",
                    summary="The HTTPS response did not include a Strict-Transport-Security header.",
                    impact="Without HSTS, clients visiting via HTTP or following downgrade links can be intercepted before upgrading to HTTPS.",
                    severity_rationale="Rated Medium because HTTPS is active, yet browsers are not instructed to enforce HTTPS-only transport on future visits.",
                    confidence_rationale="High confidence: Strict-Transport-Security was absent on an HTTPS response.",
                    evidence_request=req_text,
                    evidence_response=f"{resp_text}\nStrict-Transport-Security: [absent]",
                    evidence_checks=[
                        {
                            "label": "Strict-Transport-Security",
                            "value": "Absent",
                            "expected": "max-age=31536000; includeSubDomains",
                            "state": "fail",
                        }
                    ],
                    remediation=[
                        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses.",
                        "Verify all subdomains support HTTPS before adding includeSubDomains.",
                    ],
                    fix_snippet="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    fix_language="http",
                    references=[
                        {"label": "OWASP", "value": "HTTP Strict Transport Security Cheat Sheet"},
                        {"label": "CWE", "value": "CWE-319 - Cleartext Transmission of Sensitive Information"},
                    ],
                )
            )
        else:
            max_age = _parse_hsts_max_age(hsts)
            if max_age is None or max_age < 15_768_000:
                findings.append(
                    build_finding(
                        finding_id=next_id(),
                        scan_id=scan_id,
                        fingerprint="header-hsts-weak",
                        category="headers",
                        target_url=final_url,
                        target_path=path,
                        title="Strict-Transport-Security has a weak or zero max-age",
                        severity="medium" if max_age == 0 or max_age is None else "low",
                        confidence="high",
                        check_status="finding_detected",
                        summary=f"HSTS header '{hsts}' specifies an insufficient or missing max-age (recommended >= 31536000 seconds).",
                        impact="A zero or very short HSTS max-age expires quickly or disables HTTPS pinning in the browser.",
                        severity_rationale="Rated Medium when max-age=0/missing (disables HSTS) or Low when shorter than 180 days.",
                        confidence_rationale="High confidence: the observed max-age value was directly parsed from the response header.",
                        evidence_request=req_text,
                        evidence_response=resp_text,
                        evidence_checks=[
                            {
                                "label": "Strict-Transport-Security",
                                "value": hsts,
                                "expected": "max-age>=31536000",
                                "state": "warn",
                            }
                        ],
                        remediation=[
                            "Increase max-age to at least 31536000 (1 year) once HTTPS stability is verified."
                        ],
                        fix_snippet="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                        fix_language="http",
                        references=[
                            {"label": "CWE", "value": "CWE-523 - Unprotected Transport of Credentials"},
                        ],
                    )
                )
    else:
        findings.append(
            build_finding(
                finding_id=next_id(),
                scan_id=scan_id,
                fingerprint="header-hsts-http-only",
                category="headers",
                target_url=final_url,
                target_path=path,
                title="Target served over plaintext HTTP (HSTS not enforceable)",
                severity="medium",
                confidence="high",
                check_status="finding_detected",
                summary="The final response was served over unencrypted HTTP; browsers ignore HSTS headers on plaintext HTTP.",
                impact="Traffic over HTTP can be read or tampered with on the network, and HSTS cannot protect clients until HTTPS is enforced.",
                severity_rationale="Rated Medium because unencrypted transport exposes headers, cookies, and page content in transit.",
                confidence_rationale="High confidence: final response scheme after redirects was http://.",
                evidence_request=req_text,
                evidence_response=resp_text,
                evidence_checks=[
                    {
                        "label": "Transport scheme",
                        "value": "http",
                        "expected": "https with HSTS",
                        "state": "fail",
                    }
                ],
                remediation=[
                    "Enable TLS (HTTPS) on the server and redirect HTTP traffic to HTTPS.",
                    "Serve Strict-Transport-Security on HTTPS responses.",
                ],
                fix_snippet="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                fix_language="http",
                references=[
                    {"label": "CWE", "value": "CWE-319 - Cleartext Transmission of Sensitive Information"},
                ],
            )
        )

    # 3. X-Frame-Options (also aware of CSP frame-ancestors)
    xfo = observed_map["X-Frame-Options"]
    csp_directives = _parse_csp_directives(csp) if csp else {}
    has_frame_ancestors = "frame-ancestors" in csp_directives
    if not xfo:
        if not has_frame_ancestors:
            findings.append(
                build_finding(
                    finding_id=next_id(),
                    scan_id=scan_id,
                    fingerprint="header-xfo-missing",
                    category="headers",
                    target_url=final_url,
                    target_path=path,
                    title="Clickjacking protection missing (X-Frame-Options and CSP frame-ancestors absent)",
                    severity="medium" if is_html else "low",
                    confidence="high",
                    check_status="finding_detected",
                    summary="Neither X-Frame-Options nor CSP frame-ancestors was present in the response.",
                    impact="Without framing restrictions, third-party pages can embed the application in an iframe to trick users into unintended clicks.",
                    severity_rationale="Rated Medium on HTML pages when both legacy X-Frame-Options and modern CSP frame-ancestors are absent.",
                    confidence_rationale="High confidence: both framing protection mechanisms were absent from response headers.",
                    evidence_request=req_text,
                    evidence_response=f"{resp_text}\nX-Frame-Options: [absent]",
                    evidence_checks=[
                        {
                            "label": "X-Frame-Options",
                            "value": "Absent",
                            "expected": "DENY or SAMEORIGIN",
                            "state": "fail",
                        }
                    ],
                    remediation=[
                        "Set X-Frame-Options: DENY (or SAMEORIGIN if same-origin framing is required).",
                        "Also configure CSP frame-ancestors 'none' or 'self'.",
                    ],
                    fix_snippet="X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors 'none'",
                    fix_language="http",
                    references=[
                        {"label": "OWASP", "value": "Clickjacking Defense Cheat Sheet"},
                        {"label": "CWE", "value": "CWE-1021 - Improper Restriction of Rendered UI Layers"},
                    ],
                )
            )
    elif xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(
            build_finding(
                finding_id=next_id(),
                scan_id=scan_id,
                fingerprint="header-xfo-weak",
                category="headers",
                target_url=final_url,
                target_path=path,
                title="X-Frame-Options uses an obsolete or invalid value",
                severity="low",
                confidence="high",
                check_status="finding_detected",
                summary=f"X-Frame-Options was set to '{xfo}', which is not DENY or SAMEORIGIN (ALLOW-FROM is deprecated/ignored by modern browsers).",
                impact="Modern browsers ignore non-standard or ALLOW-FROM values, leaving framing unrestricted unless CSP frame-ancestors is set.",
                severity_rationale="Rated Low as a header configuration defect.",
                confidence_rationale="High confidence: exact header value was directly observed.",
                evidence_request=req_text,
                evidence_response=resp_text,
                evidence_checks=[
                    {
                        "label": "X-Frame-Options",
                        "value": xfo,
                        "expected": "DENY or SAMEORIGIN",
                        "state": "warn",
                    }
                ],
                remediation=["Use X-Frame-Options: DENY or SAMEORIGIN alongside CSP frame-ancestors."],
                fix_snippet="X-Frame-Options: SAMEORIGIN",
                fix_language="http",
                references=[{"label": "CWE", "value": "CWE-1021 - Clickjacking"}],
            )
        )

    # 4. X-Content-Type-Options
    xcto = observed_map["X-Content-Type-Options"]
    if not xcto or xcto.strip().lower() != "nosniff":
        findings.append(
            build_finding(
                finding_id=next_id(),
                scan_id=scan_id,
                fingerprint="header-xcto-missing" if not xcto else "header-xcto-weak",
                category="headers",
                target_url=final_url,
                target_path=path,
                title="X-Content-Type-Options: nosniff is missing or misconfigured",
                severity="low",
                confidence="high",
                check_status="finding_detected",
                summary=(
                    "X-Content-Type-Options was absent."
                    if not xcto
                    else f"X-Content-Type-Options was '{xcto}' instead of 'nosniff'."
                ),
                impact="Without nosniff, older browsers or edge cases may MIME-sniff responses away from the declared Content-Type.",
                severity_rationale="Rated Low: this is a defensive browser hardening header.",
                confidence_rationale="High confidence: directly verified in the response headers.",
                evidence_request=req_text,
                evidence_response=resp_text if xcto else f"{resp_text}\nX-Content-Type-Options: [absent]",
                evidence_checks=[
                    {
                        "label": "X-Content-Type-Options",
                        "value": xcto or "Absent",
                        "expected": "nosniff",
                        "state": "fail",
                    }
                ],
                remediation=["Set X-Content-Type-Options: nosniff globally on all HTTP responses."],
                fix_snippet="X-Content-Type-Options: nosniff",
                fix_language="http",
                references=[{"label": "CWE", "value": "CWE-436 - Interpretation Conflict"}],
            )
        )

    # 5. Referrer-Policy
    ref_policy = observed_map["Referrer-Policy"]
    if not ref_policy:
        findings.append(
            build_finding(
                finding_id=next_id(),
                scan_id=scan_id,
                fingerprint="header-referrer-missing",
                category="headers",
                target_url=final_url,
                target_path=path,
                title="Referrer-Policy header is missing",
                severity="low",
                confidence="high",
                check_status="finding_detected",
                summary="The response did not specify an explicit Referrer-Policy header.",
                impact="Without an explicit policy, referrer behavior relies on browser defaults, which can vary across clients.",
                severity_rationale="Rated Low: defensive privacy/hardening header.",
                confidence_rationale="High confidence: Referrer-Policy was absent from the captured headers.",
                evidence_request=req_text,
                evidence_response=f"{resp_text}\nReferrer-Policy: [absent]",
                evidence_checks=[
                    {
                        "label": "Referrer-Policy",
                        "value": "Absent",
                        "expected": "strict-origin-when-cross-origin",
                        "state": "fail",
                    }
                ],
                remediation=["Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive routes)."],
                fix_snippet="Referrer-Policy: strict-origin-when-cross-origin",
                fix_language="http",
                references=[{"label": "CWE", "value": "CWE-116 - Improper Encoding or Escaping"}],
            )
        )
    else:
        tokens = [t.strip().lower() for t in ref_policy.split(",") if t.strip()]
        effective = tokens[-1] if tokens else ""
        if effective in _UNSAFE_REFERRER_POLICIES or (effective and effective not in _SAFE_REFERRER_POLICIES):
            findings.append(
                build_finding(
                    finding_id=next_id(),
                    scan_id=scan_id,
                    fingerprint="header-referrer-weak",
                    category="headers",
                    target_url=final_url,
                    target_path=path,
                    title="Referrer-Policy permits full URL or cross-origin referrer leakage",
                    severity="low",
                    confidence="high",
                    check_status="finding_detected",
                    summary=f"Referrer-Policy was set to '{ref_policy}', which may send full URL paths or query strings to third-party origins.",
                    impact="Query strings or paths containing tokens or internal identifiers can leak in the Referer header to external links.",
                    severity_rationale="Rated Low: potential metadata leakage depending on URL contents.",
                    confidence_rationale="High confidence: exact Referrer-Policy value was observed in response headers.",
                    evidence_request=req_text,
                    evidence_response=resp_text,
                    evidence_checks=[
                        {
                            "label": "Referrer-Policy",
                            "value": ref_policy,
                            "expected": "strict-origin-when-cross-origin or no-referrer",
                            "state": "warn",
                        }
                    ],
                    remediation=["Replace permissive Referrer-Policy with strict-origin-when-cross-origin or no-referrer."],
                    fix_snippet="Referrer-Policy: strict-origin-when-cross-origin",
                    fix_language="http",
                    references=[{"label": "OWASP", "value": "Secure Headers Project"}],
                )
            )

    status = "finding_detected" if findings else "no_issue_observed"
    summary = (
        f"Inspected 5 security headers on {final_url}; {len(findings)} header issue(s) detected."
        if findings
        else f"No issue observed: all 5 inspected security headers are configured on {final_url}."
    )
    observations = [
        {
            "label": name,
            "value": observed_map[name] if observed_map[name] is not None else "[absent]",
            "state": "present" if observed_map[name] is not None else "absent",
        }
        for name in _HEADER_NAMES
    ]

    return ModuleExecutionResult(
        category="headers",
        module_name="HTTP Header Inspector",
        check_status=status,
        findings=findings,
        requests_made=requests_made,
        summary=summary,
        observations=observations,
        limitations=[
            "Evaluates headers on the target URL response only; distinct sub-routes or static asset CDNs were not separately crawled."
        ],
    )
