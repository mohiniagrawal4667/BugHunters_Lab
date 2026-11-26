"""Automated Phase 3 tests for all four security modules and the unified scan orchestrator."""

from __future__ import annotations

import socket
import sys
import tempfile
import unittest
from pathlib import Path

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.database import init_db, list_findings, list_scans  # noqa: E402
from app.scanners.cookies import scan_cookies  # noqa: E402
from app.scanners.headers import scan_headers  # noqa: E402
from app.scanners.injection import scan_injection  # noqa: E402
from app.scanners.paths import scan_paths  # noqa: E402
from app.services.safe_http import SafeHttpClient, ScanHttpSession  # noqa: E402
from app.services.scan_runner import execute_scan  # noqa: E402


def fixture_resolver(hostname: str, _port: int) -> list[str]:
    mapping = {
        "hardened-fixture.example": ["93.184.216.34"],
        "vuln-fixture.example": ["93.184.216.34"],
        "spa-fixture.example": ["93.184.216.34"],
        "timeout-fixture.example": ["93.184.216.34"],
        "redirect-ssrf.example": ["93.184.216.34"],
    }
    if hostname not in mapping:
        raise socket.gaierror(f"Unknown host {hostname}")
    return mapping[hostname]


def make_session(handler, *, max_requests: int = 25, timeout: float = 5.0) -> ScanHttpSession:
    client = SafeHttpClient(
        resolver=fixture_resolver,
        transport=httpx.MockTransport(handler),
        request_timeout=timeout,
        connect_timeout=timeout,
    )
    return ScanHttpSession(client, max_requests=max_requests, min_interval_seconds=0.0)


class HeaderScannerTests(unittest.TestCase):
    def test_all_recommended_headers_present(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text="<html><body>Hardened</body></html>",
                headers={
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                },
            )

        res = scan_headers("https://hardened-fixture.example/", make_session(handler), scan_id="s1")
        self.assertEqual(res.check_status, "no_issue_observed")
        self.assertEqual(res.findings, [])

    def test_missing_headers_detected_without_inflating_to_critical(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text="<html><body>Bare</body></html>",
                headers={"Content-Type": "text/html"},
            )

        res = scan_headers("https://vuln-fixture.example/", make_session(handler), scan_id="s2")
        self.assertEqual(res.check_status, "finding_detected")
        fingerprints = {f["fingerprint"] for f in res.findings}
        self.assertEqual(
            fingerprints,
            {
                "header-csp-missing",
                "header-hsts-missing",
                "header-xfo-missing",
                "header-xcto-missing",
                "header-referrer-missing",
            },
        )
        self.assertTrue(all(f["severity"] in ("medium", "low") for f in res.findings))

    def test_weak_header_configurations_detected(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text="<html><body>Weak</body></html>",
                headers={
                    "Content-Type": "text/html",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' *",
                    "Strict-Transport-Security": "max-age=0",
                    "X-Frame-Options": "ALLOW-FROM https://other.example",
                    "X-Content-Type-Options": "invalid",
                    "Referrer-Policy": "unsafe-url",
                },
            )

        res = scan_headers("https://vuln-fixture.example/", make_session(handler), scan_id="s3")
        self.assertEqual(res.check_status, "finding_detected")
        fingerprints = {f["fingerprint"] for f in res.findings}
        self.assertEqual(
            fingerprints,
            {
                "header-csp-weak",
                "header-hsts-weak",
                "header-xfo-weak",
                "header-xcto-weak",
                "header-referrer-weak",
            },
        )


class CookieScannerTests(unittest.TestCase):
    def test_all_expected_flags_present(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text="ok",
                headers=[
                    ("Set-Cookie", "session_id=supersecret123; Path=/; Secure; HttpOnly; SameSite=Lax"),
                ],
            )

        res = scan_cookies("https://hardened-fixture.example/", make_session(handler), scan_id="c1")
        self.assertEqual(res.check_status, "no_issue_observed")
        self.assertEqual(res.findings, [])

    def test_missing_httponly_secure_samesite_and_secret_redaction(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text="ok",
                headers=[
                    ("Set-Cookie", "session=TOP_SECRET_VALUE_999; Path=/; Secure; SameSite=Lax"),
                    ("Set-Cookie", "auth_token=ANOTHER_SECRET_888; Path=/; HttpOnly; SameSite=Strict"),
                    ("Set-Cookie", "prefs=theme_dark; Path=/; Secure; HttpOnly"),
                ],
            )

        res = scan_cookies("https://vuln-fixture.example/", make_session(handler), scan_id="c2")
        self.assertEqual(res.check_status, "finding_detected")
        self.assertEqual(len(res.findings), 3)
        titles = {f["title"] for f in res.findings}
        self.assertTrue(any("session" in t and "HttpOnly" in t for t in titles))
        self.assertTrue(any("auth_token" in t and "Secure" in t for t in titles))
        self.assertTrue(any("prefs" in t and "SameSite" in t for t in titles))

        serialized = str(res.findings)
        self.assertNotIn("TOP_SECRET_VALUE_999", serialized)
        self.assertNotIn("ANOTHER_SECRET_888", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_no_cookies_observed_returns_not_applicable(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="stateless")

        res = scan_cookies("https://hardened-fixture.example/", make_session(handler), scan_id="c3")
        self.assertEqual(res.check_status, "not_applicable")
        self.assertEqual(res.findings, [])

    def test_malformed_cookie_header_handled_without_crash(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok", headers=[("Set-Cookie", "malformed_cookie_without_equals")])

        res = scan_cookies("https://vuln-fixture.example/", make_session(handler), scan_id="c4")
        self.assertEqual(res.check_status, "inconclusive")
        self.assertEqual(res.findings, [])


class ExposedPathScannerTests(unittest.TestCase):
    def test_real_sensitive_and_public_resources_distinguished(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            path = req.url.path
            if path == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /internal/\n", headers={"Content-Type": "text/plain"})
            if path == "/.env":
                return httpx.Response(
                    200,
                    text="APP_ENV=production\nDB_PASSWORD=super_secret_pw\nAPI_KEY=live_key_123\n",
                    headers={"Content-Type": "text/plain"},
                )
            if path == "/.git/HEAD":
                return httpx.Response(200, text="ref: refs/heads/main\n", headers={"Content-Type": "text/plain"})
            return httpx.Response(404, text="<html><title>404</title>Not Found</html>", headers={"Content-Type": "text/html"})

        res = scan_paths("https://vuln-fixture.example/", make_session(handler), scan_id="p1")
        self.assertEqual(res.check_status, "finding_detected")
        by_path = {f["targetPath"]: f for f in res.findings}
        self.assertEqual(by_path["/robots.txt"]["severity"], "informational")
        self.assertEqual(by_path["/.env"]["severity"], "critical")
        self.assertEqual(by_path["/.git/HEAD"]["severity"], "high")
        self.assertNotIn("super_secret_pw", str(by_path["/.env"]))
        self.assertIn("DB_PASSWORD=[REDACTED]", str(by_path["/.env"]))

    def test_generic_404_returns_no_issue_observed(self) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Not Found", headers={"Content-Type": "text/html"})

        res = scan_paths("https://hardened-fixture.example/", make_session(handler), scan_id="p2")
        self.assertEqual(res.check_status, "no_issue_observed")
        self.assertEqual(res.findings, [])

    def test_generic_fallback_returning_http_200_is_not_flagged(self) -> None:
        spa_html = "<!doctype html><html><head><title>App Shell</title></head><body><div id='root'></div></body></html>"

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=spa_html, headers={"Content-Type": "text/html; charset=utf-8"})

        res = scan_paths("https://spa-fixture.example/", make_session(handler), scan_id="p3")
        self.assertEqual(res.check_status, "no_issue_observed")
        self.assertEqual(res.findings, [])

    def test_ambiguous_200_different_from_baseline_without_signature_is_inconclusive(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/.env":
                return httpx.Response(
                    200,
                    text="<html><title>Custom Portal</title><body>Access Notice</body></html>",
                    headers={"Content-Type": "text/html"},
                )
            return httpx.Response(404, text="Not found", headers={"Content-Type": "text/html"})

        res = scan_paths("https://vuln-fixture.example/", make_session(handler), scan_id="p4")
        self.assertEqual(res.check_status, "inconclusive")
        self.assertEqual(res.findings, [])


class InjectionScannerTests(unittest.TestCase):
    def test_harmless_reflection_not_claimed_as_sql_injection(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            q = req.url.params.get("q", "")
            safe_q = q.replace("<", "&lt;").replace(">", "&gt;")
            return httpx.Response(200, text=f"<html><body>Results for {safe_q}</body></html>", headers={"Content-Type": "text/html"})

        res = scan_injection("https://vuln-fixture.example/search?q=hello", make_session(handler), scan_id="i1")
        self.assertEqual(res.check_status, "finding_detected")
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["severity"], "informational")
        self.assertIn("not sql injection", res.findings[0]["title"].lower())

    def test_clean_parameterized_endpoint_with_no_reflection(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            q = req.url.params.get("q", "")
            return httpx.Response(200, text=f"<html><body>0 items matched query length {len(q)}</body></html>")

        res = scan_injection("https://hardened-fixture.example/search?q=init", make_session(handler), scan_id="i2")
        self.assertEqual(res.check_status, "no_issue_observed")
        self.assertEqual(res.findings, [])

    def test_suspicious_response_difference_classified_inconclusive(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            q = req.url.params.get("q", "")
            if "'" in q:
                return httpx.Response(500, text="Internal Server Error")
            return httpx.Response(200, text="Search OK")

        res = scan_injection("https://vuln-fixture.example/search?q=init", make_session(handler), scan_id="i3")
        self.assertEqual(res.check_status, "inconclusive")
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["confidence"], "low")
        self.assertEqual(res.findings[0]["checkStatus"], "inconclusive")

    def test_db_error_signature_detected_on_quote_probe(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            q = req.url.params.get("q", "")
            if "'" in q:
                return httpx.Response(500, text='sqlite3.OperationalError: near "\'": syntax error')
            return httpx.Response(200, text="Search results: 2")

        res = scan_injection("https://vuln-fixture.example/search?q=init", make_session(handler), scan_id="i4")
        self.assertEqual(res.check_status, "finding_detected")
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]["severity"], "high")

    def test_static_page_ignoring_fallback_param_is_inconclusive(self) -> None:
        static_body = b"<html><body>Static landing page</body></html>"
        root_resp = None

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=static_body)

        session = make_session(handler)
        root_resp = session.get("https://hardened-fixture.example/", authorized=True)
        res = scan_injection(
            "https://hardened-fixture.example/",
            session,
            scan_id="i5",
            root_response=root_resp,
        )
        self.assertEqual(res.check_status, "inconclusive")
        self.assertEqual(res.findings, [])


class OrchestratorAndFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "orch_test.db"
        init_db(self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_full_orchestrator_runs_all_four_modules_and_persists_real_findings(self) -> None:
        def vuln_app(req: httpx.Request) -> httpx.Response:
            path = req.url.path
            q = req.url.params.get("q", "")
            if path == "/.env":
                return httpx.Response(200, text="APP_ENV=dev\nSECRET_KEY=topsecret\n", headers={"Content-Type": "text/plain"})
            if path == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /admin\n", headers={"Content-Type": "text/plain"})
            if path == "/search" and "'" in q:
                return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token")
            if path == "/search":
                return httpx.Response(
                    200,
                    text="<html>Search page</html>",
                    headers=[
                        ("Content-Type", "text/html"),
                        ("Set-Cookie", "session=xyz123; Path=/"),
                    ],
                )
            return httpx.Response(404, text="Not found", headers={"Content-Type": "text/html"})

        validation, scan, findings = execute_scan(
            raw_url="https://vuln-fixture.example/search?q=test",
            checks=["headers", "cookies", "paths", "injection"],
            authorized=True,
            db_path=self.db_path,
            resolver=fixture_resolver,
            transport=httpx.MockTransport(vuln_app),
            min_interval_seconds=0.0,
        )
        self.assertTrue(validation.allowed)
        assert scan is not None
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(set(scan["checkResults"].keys()), {"headers", "cookies", "paths", "injection"})
        self.assertGreater(len(findings), 0)
        self.assertEqual(len(list_scans(self.db_path)), 1)
        self.assertEqual(len(list_findings(self.db_path, scan_id=scan["id"])), len(findings))

    def test_timeout_marks_scan_failed(self) -> None:
        def timeout_handler(_req: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Read timed out after 5.0s")

        _val, scan, findings = execute_scan(
            raw_url="https://timeout-fixture.example/",
            checks=["headers", "cookies", "paths", "injection"],
            authorized=True,
            db_path=self.db_path,
            resolver=fixture_resolver,
            transport=httpx.MockTransport(timeout_handler),
            min_interval_seconds=0.0,
        )
        assert scan is not None
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(findings, [])
        self.assertEqual(scan["checkResults"]["headers"]["status"], "scan_failed")

    def test_network_failure_marks_scan_failed(self) -> None:
        def net_err(_req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        _val, scan, findings = execute_scan(
            raw_url="https://timeout-fixture.example/",
            checks=["headers", "cookies"],
            authorized=True,
            db_path=self.db_path,
            resolver=fixture_resolver,
            transport=httpx.MockTransport(net_err),
            min_interval_seconds=0.0,
        )
        assert scan is not None
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(findings, [])

    def test_individual_module_failure_never_marked_passed(self) -> None:
        def partial_fail_handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.startswith("/__bhl_nonexistent_"):
                raise httpx.ReadTimeout("Baseline path timed out")
            return httpx.Response(
                200,
                text="<html>ok</html>",
                headers={
                    "Content-Type": "text/html",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
            )

        _val, scan, _findings = execute_scan(
            raw_url="https://hardened-fixture.example/",
            checks=["headers", "cookies", "paths"],
            authorized=True,
            db_path=self.db_path,
            resolver=fixture_resolver,
            transport=httpx.MockTransport(partial_fail_handler),
            min_interval_seconds=0.0,
        )
        assert scan is not None
        self.assertEqual(scan["modules"]["headers"], "done")
        self.assertEqual(scan["checkResults"]["headers"]["status"], "no_issue_observed")
        self.assertEqual(scan["modules"]["cookies"], "done")
        self.assertEqual(scan["checkResults"]["cookies"]["status"], "not_applicable")
        self.assertEqual(scan["modules"]["paths"], "failed")
        self.assertEqual(scan["checkResults"]["paths"]["status"], "scan_failed")

    def test_invalid_target_rejected_with_no_db_record(self) -> None:
        val, scan, findings = execute_scan(
            raw_url="http://127.0.0.1/admin",
            checks=["headers"],
            authorized=True,
            db_path=self.db_path,
            resolver=fixture_resolver,
            min_interval_seconds=0.0,
        )
        self.assertFalse(val.allowed)
        self.assertIsNone(scan)
        self.assertEqual(findings, [])
        self.assertEqual(list_scans(self.db_path), [])

    def test_redirect_to_prohibited_destination_blocked_and_marked_failed(self) -> None:
        def redirect_handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

        _val, scan, findings = execute_scan(
            raw_url="https://redirect-ssrf.example/",
            checks=["headers", "cookies", "paths", "injection"],
            authorized=True,
            db_path=self.db_path,
            resolver=fixture_resolver,
            transport=httpx.MockTransport(redirect_handler),
            min_interval_seconds=0.0,
        )
        assert scan is not None
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(findings, [])
        self.assertIn("link-local", (scan["error"] or "").lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
