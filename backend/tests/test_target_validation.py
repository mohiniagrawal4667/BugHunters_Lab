"""Automated security and functional tests for Phase 2 target validation and safe HTTP."""

from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

# Ensure backend/ is on sys.path when invoked from repo root or backend/
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.main import validate_target  # noqa: E402
from app.models.target import TargetValidateRequest  # noqa: E402
from app.services.safe_http import (  # noqa: E402
    RedirectLimitError,
    ResponseSizeExceededError,
    SafeHttpClient,
    UnsafeDestinationError,
)


def make_mock_resolver(mapping: dict[str, list[str]]):
    def _resolve(hostname: str, _port: int) -> list[str]:
        if hostname not in mapping:
            raise socket.gaierror(f"Mock DNS failure for {hostname}")
        return mapping[hostname]

    return _resolve


def call_validate_endpoint(url: str, authorized: bool = True) -> tuple[int, dict]:
    """Invoke the FastAPI endpoint handler directly without needing a loopback socketpair."""
    import json

    resp = validate_target(TargetValidateRequest(url=url, authorized=authorized))
    return resp.status_code, json.loads(resp.body.decode("utf-8"))


class TargetValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.public_resolver = make_mock_resolver(
            {
                "example.com": ["93.184.216.34"],
                "owasp.org": ["2606:2800:220:1:248:1893:25c8:1946"],
                "private-dns.example": ["10.20.30.40"],
                "mixed-dns.example": ["93.184.216.34", "192.168.1.50"],
                "metadata-dns.example": ["169.254.169.254"],
            }
        )

    def test_valid_https_url_and_normalization(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", self.public_resolver):
            status, data = call_validate_endpoint("  HTTPS://Example.COM:443/app/login#frag  ", True)
        self.assertEqual(status, 200)
        self.assertTrue(data["valid"])
        self.assertTrue(data["allowed"])
        self.assertEqual(data["normalized_url"], "https://example.com/app/login")
        self.assertEqual(data["hostname"], "example.com")
        self.assertEqual(data["scheme"], "https")
        self.assertEqual(data["port"], 443)
        self.assertEqual(data["resolved_ips"], ["93.184.216.34"])
        self.assertIsNone(data["reason"])

    def test_valid_http_url(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", self.public_resolver):
            status, data = call_validate_endpoint("http://example.com:80", True)
        self.assertEqual(status, 200)
        self.assertTrue(data["valid"])
        self.assertTrue(data["allowed"])
        self.assertEqual(data["normalized_url"], "http://example.com/")
        self.assertEqual(data["scheme"], "http")
        self.assertEqual(data["port"], 80)

    def test_empty_input_rejected(self) -> None:
        for raw in ("", "   \t\n "):
            status, data = call_validate_endpoint(raw, True)
            self.assertEqual(status, 400)
            self.assertFalse(data["valid"])
            self.assertFalse(data["allowed"])
            self.assertEqual(data["error_code"], "EMPTY_URL")

    def test_malformed_urls_rejected(self) -> None:
        malformed = [
            "not-a-url",
            "https://",
            "https://exa mple.com",
            "https://example.com\\@127.0.0.1",
            "https://example..com",
            "https://example.com:99999",
        ]
        for raw in malformed:
            status, data = call_validate_endpoint(raw, True)
            self.assertEqual(status, 400, f"Expected 400 for {raw}")
            self.assertFalse(data["valid"])
            self.assertFalse(data["allowed"])

    def test_unsupported_schemes_rejected(self) -> None:
        for raw in ("ftp://example.com/file", "file:///etc/passwd", "javascript:alert(1)", "gopher://127.0.0.1:70"):
            status, data = call_validate_endpoint(raw, True)
            self.assertEqual(status, 400, f"Expected 400 for {raw}")
            self.assertFalse(data["valid"])
            self.assertFalse(data["allowed"])
            self.assertEqual(data["error_code"], "UNSUPPORTED_SCHEME")

    def test_embedded_credentials_rejected(self) -> None:
        for raw in ("https://admin:secret@example.com", "https://user@example.com/path"):
            status, data = call_validate_endpoint(raw, True)
            self.assertEqual(status, 400)
            self.assertFalse(data["valid"])
            self.assertFalse(data["allowed"])
            self.assertEqual(data["error_code"], "EMBEDDED_CREDENTIALS")

    def test_disallowed_arbitrary_ports_rejected(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", self.public_resolver):
            for raw in ("https://example.com:8443", "http://example.com:22", "https://example.com:80"):
                status, data = call_validate_endpoint(raw, True)
                self.assertEqual(status, 400, f"Expected 400 for {raw}")
                self.assertEqual(data["error_code"], "DISALLOWED_PORT")

    def test_localhost_and_subdomains_rejected(self) -> None:
        for raw in (
            "http://localhost",
            "https://api.localhost/health",
            "http://localhost.",
            "http://localhost.localdomain",
            "http://service.internal",
        ):
            status, data = call_validate_endpoint(raw, True)
            self.assertEqual(status, 403, f"Expected 403 for {raw}")
            self.assertFalse(data["valid"])
            self.assertFalse(data["allowed"])
            self.assertEqual(data["error_code"], "PROHIBITED_DESTINATION")

    def test_loopback_private_link_local_and_reserved_ips_rejected(self) -> None:
        prohibited = [
            "http://127.0.0.1",
            "http://127.0.0.2",
            "http://10.0.0.1",
            "https://172.16.0.10",
            "http://192.168.1.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1",
            "http://0.0.0.0",
            "http://224.0.0.1",
            "http://240.0.0.1",
            "http://[::1]",
            "http://[fe80::1]",
            "http://[fc00::1]",
            "http://[::]",
            "http://[ff02::1]",
            "http://[::ffff:127.0.0.1]",
            "http://[2002:7f00:0001::]",
        ]
        for raw in prohibited:
            status, data = call_validate_endpoint(raw, True)
            self.assertEqual(status, 403, f"Expected 403 for {raw}, got {status}: {data}")
            self.assertFalse(data["valid"])
            self.assertFalse(data["allowed"])
            self.assertEqual(data["resolved_ips"], [])

    def test_obfuscated_ip_hostnames_rejected(self) -> None:
        for raw in ("http://2130706433", "http://0x7f000001", "http://0177.0.0.1", "http://127.1"):
            status, data = call_validate_endpoint(raw, True)
            self.assertEqual(status, 403, f"Expected 403 for {raw}")
            self.assertFalse(data["allowed"])

    def test_ipv6_zone_id_rejected(self) -> None:
        status, data = call_validate_endpoint("http://[fe80::1%eth0]", True)
        self.assertEqual(status, 400)
        self.assertFalse(data["allowed"])

    def test_hostname_resolving_to_private_address_rejected(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", self.public_resolver):
            status, data = call_validate_endpoint("https://private-dns.example/admin", True)
        self.assertEqual(status, 403)
        self.assertFalse(data["valid"])
        self.assertFalse(data["allowed"])
        self.assertEqual(data["resolved_ips"], [])
        self.assertEqual(data["error_code"], "PROHIBITED_DESTINATION")

    def test_hostname_resolving_to_both_public_and_prohibited_rejected(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", self.public_resolver):
            status, data = call_validate_endpoint("https://mixed-dns.example/", True)
        self.assertEqual(status, 403)
        self.assertFalse(data["valid"])
        self.assertFalse(data["allowed"])
        self.assertEqual(data["resolved_ips"], [])
        self.assertEqual(data["error_code"], "PROHIBITED_DESTINATION")

    def test_dns_resolution_failure(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", self.public_resolver):
            status, data = call_validate_endpoint("https://nonexistent.invalid/", True)
        self.assertEqual(status, 400)
        self.assertFalse(data["valid"])
        self.assertFalse(data["allowed"])
        self.assertEqual(data["error_code"], "DNS_RESOLUTION_FAILED")

    def test_authorization_not_confirmed_rejected(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", self.public_resolver):
            status, data = call_validate_endpoint("https://example.com", False)
        self.assertEqual(status, 403)
        self.assertTrue(data["valid"])
        self.assertFalse(data["allowed"])
        self.assertEqual(data["error_code"], "AUTHORIZATION_REQUIRED")
        self.assertIn("authorization", (data["reason"] or "").lower())


class SafeHttpClientTests(unittest.TestCase):
    def test_ip_pinning_and_sni_extension_prevent_dns_rebinding(self) -> None:
        seen_requests: list[httpx.Request] = []
        calls = {"count": 0}

        def rebinding_resolver(_host: str, _port: int) -> list[str]:
            calls["count"] += 1
            return ["93.184.216.34"] if calls["count"] == 1 else ["127.0.0.1"]

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return httpx.Response(200, text="ok")

        client = SafeHttpClient(resolver=rebinding_resolver, transport=httpx.MockTransport(handler))
        resp = client.request("GET", "https://example.com/status", authorized=True)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.connected_ip, "93.184.216.34")
        self.assertEqual(calls["count"], 1)
        self.assertEqual(len(seen_requests), 1)
        req = seen_requests[0]
        self.assertEqual(req.url.host, "93.184.216.34")
        self.assertEqual(req.headers.get("host"), "example.com")
        self.assertEqual(req.extensions.get("sni_hostname"), "example.com")

    def test_redirect_to_prohibited_destination_blocked(self) -> None:
        seen_hosts: list[str] = []
        resolver = make_mock_resolver(
            {
                "example.com": ["93.184.216.34"],
                "internal-alias.example": ["10.0.0.8"],
            }
        )

        def handler(request: httpx.Request) -> httpx.Response:
            seen_hosts.append(request.url.host)
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

        client = SafeHttpClient(resolver=resolver, transport=httpx.MockTransport(handler))
        with self.assertRaises(UnsafeDestinationError):
            client.request("GET", "https://example.com/start", authorized=True)

        self.assertEqual(seen_hosts, ["93.184.216.34"])

        def handler_dns_redirect(request: httpx.Request) -> httpx.Response:
            seen_hosts.append(request.url.host)
            return httpx.Response(302, headers={"Location": "https://internal-alias.example/secret"})

        client2 = SafeHttpClient(resolver=resolver, transport=httpx.MockTransport(handler_dns_redirect))
        with self.assertRaises(UnsafeDestinationError):
            client2.request("GET", "https://example.com/start", authorized=True)
        self.assertEqual(seen_hosts, ["93.184.216.34", "93.184.216.34"])

    def test_redirect_loop_detected(self) -> None:
        resolver = make_mock_resolver({"example.com": ["93.184.216.34"]})

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/a":
                return httpx.Response(302, headers={"Location": "/b"})
            return httpx.Response(302, headers={"Location": "/a"})

        client = SafeHttpClient(resolver=resolver, transport=httpx.MockTransport(handler))
        with self.assertRaises(RedirectLimitError) as ctx:
            client.request("GET", "https://example.com/a", authorized=True)
        self.assertEqual(ctx.exception.code, "REDIRECT_LOOP")

    def test_response_size_limit_enforced(self) -> None:
        resolver = make_mock_resolver({"example.com": ["93.184.216.34"]})

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"A" * 2048)

        client = SafeHttpClient(
            resolver=resolver,
            transport=httpx.MockTransport(handler),
            max_response_bytes=512,
        )
        with self.assertRaises(ResponseSizeExceededError):
            client.request("GET", "https://example.com/large", authorized=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
