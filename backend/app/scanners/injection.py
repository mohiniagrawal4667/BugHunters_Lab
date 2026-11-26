"""Module D — Controlled, Non-Destructive Injection Inspector."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.scanners.base import (
    ModuleExecutionResult,
    build_finding,
    format_http_request,
    format_http_response,
)
from app.services.safe_http import SafeHttpError, SafeHttpResponse, ScanHttpSession

_BASELINE_TOKEN = "bhlprobe7391"
_QUOTE_PROBE_TOKEN = "bhlprobe7391'"
_MARKUP_PROBE_TOKEN = "bhlprobe7391<>"

_DB_ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SQLite error", re.compile(r"(sqlite3\.OperationalError|SQLite3::|unrecognized token|near \".*\": syntax error)", re.IGNORECASE)),
    ("MySQL syntax error", re.compile(r"(You have an error in your SQL syntax|MySQL server version for the right syntax|mysqli_sql_exception)", re.IGNORECASE)),
    ("PostgreSQL error", re.compile(r"(PG::SyntaxError|psycopg2\.errors|unterminated quoted string at or near)", re.IGNORECASE)),
    ("SQL Server / ODBC error", re.compile(r"(Unclosed quotation mark after the character string|Microsoft OLE DB Provider|ODBC SQL Server Driver)", re.IGNORECASE)),
    ("Oracle error", re.compile(r"(ORA-00933|ORA-01756|quoted string not properly terminated)", re.IGNORECASE)),
)


def _with_query_param(url: str, param_name: str, param_value: str) -> str:
    parsed = urlsplit(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param_name] = param_value
    new_query = urlencode(params)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", new_query, ""))


def _find_new_db_error(probe_text: str, baseline_text: str) -> str | None:
    for label, pattern in _DB_ERROR_PATTERNS:
        if pattern.search(probe_text) and not pattern.search(baseline_text):
            return label
    return None


def scan_injection(
    target_url: str,
    session: ScanHttpSession,
    *,
    scan_id: str,
    root_response: SafeHttpResponse | None = None,
) -> ModuleExecutionResult:
    """
    Send harmless baseline and syntax comparison probes on GET parameters only.
    Separates input reflection from error-based indicators and inconclusive results.
    """
    parsed = urlsplit(target_url)
    existing_params = parse_qsl(parsed.query, keep_blank_values=True)
    used_default_param = len(existing_params) == 0
    probe_param = existing_params[0][0] if existing_params else "q"

    baseline_url = _with_query_param(target_url, probe_param, _BASELINE_TOKEN)
    quote_url = _with_query_param(target_url, probe_param, _QUOTE_PROBE_TOKEN)
    markup_url = _with_query_param(target_url, probe_param, _MARKUP_PROBE_TOKEN)

    requests_made = 0
    try:
        baseline_resp = session.get(baseline_url, authorized=True)
        requests_made += 1 + len(baseline_resp.redirect_chain)
        quote_resp = session.get(quote_url, authorized=True)
        requests_made += 1 + len(quote_resp.redirect_chain)
        markup_resp = session.get(markup_url, authorized=True)
        requests_made += 1 + len(markup_resp.redirect_chain)
    except (SafeHttpError, httpx.HTTPError, OSError) as exc:
        return ModuleExecutionResult(
            category="injection",
            module_name="Injection Vulnerability Tester",
            check_status="scan_failed",
            requests_made=max(1, requests_made),
            summary="Safe injection check could not complete due to an HTTP request failure.",
            error=str(exc) or exc.__class__.__name__,
        )

    base_text = baseline_resp.text(100_000)
    quote_text = quote_resp.text(100_000)
    markup_text = markup_resp.text(100_000)

    base_len = len(baseline_resp.body)
    quote_len = len(quote_resp.body)
    markup_len = len(markup_resp.body)

    findings: list[dict] = []
    limitations: list[str] = [
        f"Tested only non-destructive GET parameter '{probe_param}' using harmless comparison markers."
    ]
    if used_default_param:
        limitations.append(
            "Target URL had no query parameters, so '?q=' was used as a read-only probe parameter; POST forms and authenticated endpoints were not tested."
        )

    probe_observations = [
        {
            "label": f"Benign baseline ({probe_param}={_BASELINE_TOKEN})",
            "value": f"HTTP {baseline_resp.status_code} ({base_len} bytes)",
            "state": "baseline",
        },
        {
            "label": f"Quote probe ({probe_param}={_QUOTE_PROBE_TOKEN})",
            "value": f"HTTP {quote_resp.status_code} ({quote_len} bytes)",
            "state": "observed",
        },
        {
            "label": f"Markup probe ({probe_param}={_MARKUP_PROBE_TOKEN})",
            "value": f"HTTP {markup_resp.status_code} ({markup_len} bytes)",
            "state": "observed",
        },
    ]

    # 1. Check for database error signature introduced by harmless quote probe
    db_error_label = _find_new_db_error(quote_text, base_text)
    if db_error_label:
        comparison = [
            {"signal": "HTTP status", "baseline": str(baseline_resp.status_code), "observed": str(quote_resp.status_code), "verdict": "fail" if quote_resp.status_code >= 500 else "warn"},
            {"signal": "Body length", "baseline": f"{base_len} bytes", "observed": f"{quote_len} bytes", "verdict": "info"},
            {"signal": "Database error signature", "baseline": "None", "observed": db_error_label, "verdict": "fail"},
        ]
        findings.append(
            build_finding(
                finding_id=f"{scan_id}-inj-01",
                scan_id=scan_id,
                fingerprint=f"injection-db-error-{probe_param}",
                category="injection",
                target_url=quote_url,
                target_path=f"{parsed.path or '/'}?{probe_param}=...",
                title=f"Database error indicator triggered by quote probe on '{probe_param}'",
                severity="high",
                confidence="high" if quote_resp.status_code >= 500 else "medium",
                check_status="finding_detected",
                summary=f"Appending a single quote to '{probe_param}' produced a new '{db_error_label}' message that did not appear in the benign baseline.",
                impact="Unhandled database syntax errors on user-controlled input often indicate string-concatenated SQL queries, though full exploitability was not tested.",
                severity_rationale="Rated High because database error leakage strongly suggests unparameterized query construction.",
                confidence_rationale="High/Medium confidence based on error signature appearing only on the quote probe versus benign baseline.",
                evidence_request=format_http_request("GET", quote_url, quote_resp.request_headers),
                evidence_response=format_http_response(
                    quote_resp,
                    header_filter={"content-type", "content-length"},
                    body_preview="\n".join(quote_text.splitlines()[:10])[:450],
                ),
                evidence_baseline=f"{format_http_request('GET', baseline_url)}\n\n{format_http_response(baseline_resp, header_filter={'content-type', 'content-length'})}",
                evidence_comparison=comparison,
                remediation=[
                    "Use parameterized queries / prepared statements for all database access.",
                    "Disable detailed database exception output in production error responses.",
                ],
                fix_snippet='cursor.execute("SELECT id, name FROM items WHERE name LIKE ?", (f"%{q}%",))',
                fix_language="python",
                references=[
                    {"label": "OWASP", "value": "SQL Injection Prevention Cheat Sheet"},
                    {"label": "CWE", "value": "CWE-89 - SQL Injection"},
                ],
            )
        )
        return ModuleExecutionResult(
            category="injection",
            module_name="Injection Vulnerability Tester",
            check_status="finding_detected",
            findings=findings,
            requests_made=requests_made,
            summary=f"Detected {db_error_label} under controlled quote comparison on '{probe_param}'.",
            observations=probe_observations,
            limitations=limitations,
        )

    # 2. Check for suspicious server status or large response divergence (without DB error text)
    length_delta_ratio = abs(quote_len - base_len) / max(1, base_len)
    if (baseline_resp.status_code < 500 and quote_resp.status_code >= 500) or (
        quote_resp.status_code != baseline_resp.status_code and quote_resp.status_code >= 400
    ) or (length_delta_ratio > 0.35 and abs(quote_len - base_len) > 150):
        comparison = [
            {"signal": "HTTP status", "baseline": str(baseline_resp.status_code), "observed": str(quote_resp.status_code), "verdict": "warn"},
            {"signal": "Body length", "baseline": f"{base_len} bytes", "observed": f"{quote_len} bytes", "verdict": "warn"},
            {"signal": "DB error signature", "baseline": "None", "observed": "None observed", "verdict": "info"},
        ]
        findings.append(
            build_finding(
                finding_id=f"{scan_id}-inj-01",
                scan_id=scan_id,
                fingerprint=f"injection-anomaly-{probe_param}",
                category="injection",
                target_url=quote_url,
                target_path=f"{parsed.path or '/'}?{probe_param}=...",
                title=f"Suspicious response difference under quote probe on '{probe_param}' (inconclusive)",
                severity="medium",
                confidence="low",
                check_status="inconclusive",
                summary=(
                    f"The benign baseline returned HTTP {baseline_resp.status_code} ({base_len} bytes), whereas adding a quote returned HTTP {quote_resp.status_code} ({quote_len} bytes) without an explicit DB error signature."
                ),
                impact="An unhandled exception or parser change may occur on special characters, which warrants source code inspection but is not proof of SQL injection.",
                severity_rationale="Rated Medium with Low confidence because behavioral divergence occurred without database error confirmation.",
                confidence_rationale="Low confidence: status/length shifted under safe probing, but no database error signature was observed and destructive exploitation is not performed.",
                evidence_request=format_http_request("GET", quote_url, quote_resp.request_headers),
                evidence_response=format_http_response(quote_resp, header_filter={"content-type", "content-length"}),
                evidence_baseline=f"{format_http_request('GET', baseline_url)}\n\n{format_http_response(baseline_resp, header_filter={'content-type', 'content-length'})}",
                evidence_comparison=comparison,
                remediation=[
                    f"Inspect server logs and input handling for '{probe_param}' to confirm queries and parsers handle quotes safely."
                ],
                references=[{"label": "CWE", "value": "CWE-20 - Improper Input Validation"}],
            )
        )
        return ModuleExecutionResult(
            category="injection",
            module_name="Injection Vulnerability Tester",
            check_status="inconclusive",
            findings=findings,
            requests_made=requests_made,
            summary=f"Observed suspicious response difference on '{probe_param}' without conclusive DB error evidence.",
            observations=probe_observations,
            limitations=limitations,
        )

    # 3. Check reflection behavior separately from injection!
    raw_markup_reflected = _MARKUP_PROBE_TOKEN in markup_text
    harmless_reflected = _BASELINE_TOKEN in base_text

    if raw_markup_reflected:
        findings.append(
            build_finding(
                finding_id=f"{scan_id}-inj-01",
                scan_id=scan_id,
                fingerprint=f"reflection-unencoded-{probe_param}",
                category="injection",
                target_url=markup_url,
                target_path=f"{parsed.path or '/'}?{probe_param}=...",
                title=f"Unencoded angle-bracket reflection observed on '{probe_param}' (not SQL injection)",
                severity="medium",
                confidence="medium",
                check_status="finding_detected",
                summary=f"Harmless marker '{_MARKUP_PROBE_TOKEN}' was reflected raw without HTML encoding in the response body. No SQL error signatures were observed.",
                impact="Reflected '<>' characters can indicate missing HTML output encoding (potential XSS surface), NOT SQL injection.",
                severity_rationale="Rated Medium because unencoded angle brackets were reflected in the response; actual XSS exploitability depends on context and CSP.",
                confidence_rationale="Medium confidence: raw '<>' reflection was observed, while executable script payloads were intentionally not sent.",
                evidence_request=format_http_request("GET", markup_url, markup_resp.request_headers),
                evidence_response=format_http_response(markup_resp, header_filter={"content-type", "content-length"}),
                evidence_baseline=f"{format_http_request('GET', baseline_url)}\n\n{format_http_response(baseline_resp, header_filter={'content-type', 'content-length'})}",
                evidence_comparison=[
                    {"signal": "Unencoded <> reflection", "baseline": "Benign token only", "observed": f"'{_MARKUP_PROBE_TOKEN}' present verbatim", "verdict": "warn"},
                    {"signal": "DB error signatures", "baseline": "None", "observed": "None", "verdict": "pass"},
                ],
                remediation=[
                    f"HTML-encode user input from '{probe_param}' before rendering it in templates.",
                    "Enforce a strong Content-Security-Policy.",
                ],
                references=[{"label": "CWE", "value": "CWE-79 - Improper Neutralization of Input During Web Page Generation"}],
            )
        )
        return ModuleExecutionResult(
            category="injection",
            module_name="Injection Vulnerability Tester",
            check_status="finding_detected",
            findings=findings,
            requests_made=requests_made,
            summary=f"Unencoded reflection observed on '{probe_param}' (distinguished from SQL injection).",
            observations=probe_observations,
            limitations=limitations,
        )

    if harmless_reflected:
        findings.append(
            build_finding(
                finding_id=f"{scan_id}-inj-01",
                scan_id=scan_id,
                fingerprint=f"reflection-harmless-{probe_param}",
                category="injection",
                target_url=baseline_url,
                target_path=f"{parsed.path or '/'}?{probe_param}=...",
                title=f"Benign query input reflected on '{probe_param}' (not SQL injection)",
                severity="informational",
                confidence="high",
                check_status="finding_detected",
                summary=f"Harmless token '{_BASELINE_TOKEN}' appeared in the response body, while '<>' was encoded/filtered and no database errors occurred.",
                impact="Input reflection alone is normal for search/echo views and does NOT prove SQL injection or XSS when special characters are encoded.",
                severity_rationale="Rated Informational because reflection was observed without unencoded markup or database error signals.",
                confidence_rationale="High confidence: both reflection of the benign token and safe handling of quote/markup probes were directly observed.",
                evidence_request=format_http_request("GET", baseline_url, baseline_resp.request_headers),
                evidence_response=format_http_response(baseline_resp, header_filter={"content-type", "content-length"}),
                evidence_comparison=[
                    {"signal": "Benign reflection", "baseline": "Token sent", "observed": "Reflected in body", "verdict": "info"},
                    {"signal": "Unencoded <>", "baseline": "N/A", "observed": "Encoded or absent", "verdict": "pass"},
                    {"signal": "DB error signatures", "baseline": "None", "observed": "None", "verdict": "pass"},
                ],
                remediation=[
                    "Continue encoding reflected values and using parameterized database queries."
                ],
                references=[{"label": "OWASP", "value": "Input Validation Cheat Sheet"}],
            )
        )
        return ModuleExecutionResult(
            category="injection",
            module_name="Injection Vulnerability Tester",
            check_status="finding_detected",
            findings=findings,
            requests_made=requests_made,
            summary=f"Harmless reflection observed on '{probe_param}' with safe quote/markup handling (not SQLi).",
            observations=probe_observations,
            limitations=limitations,
        )

    # 4. No reflection and no response difference: check if fallback ?q= was ignored by static page
    if used_default_param and root_response is not None and root_response.body == baseline_resp.body:
        limitations.append(
            f"The response for ?{probe_param}={_BASELINE_TOKEN} was byte-for-byte identical to the root page without query parameters, indicating the endpoint may ignore '{probe_param}'."
        )
        return ModuleExecutionResult(
            category="injection",
            module_name="Injection Vulnerability Tester",
            check_status="inconclusive",
            findings=[],
            requests_made=requests_made,
            summary=f"Inconclusive: target ignored fallback parameter '?{probe_param}=' and returned identical static content ({base_len} bytes).",
            observations=probe_observations,
            limitations=limitations,
        )

    return ModuleExecutionResult(
        category="injection",
        module_name="Injection Vulnerability Tester",
        check_status="no_issue_observed",
        findings=[],
        requests_made=requests_made,
        summary=(
            f"No DB errors, status anomalies, or unencoded reflection observed across baseline ({baseline_resp.status_code}, {base_len}B), quote ({quote_resp.status_code}, {quote_len}B), and markup ({markup_resp.status_code}, {markup_len}B) probes."
        ),
        observations=probe_observations,
        limitations=limitations,
    )
