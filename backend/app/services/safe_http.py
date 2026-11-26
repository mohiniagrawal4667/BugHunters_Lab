"""Safe, SSRF-hardened HTTP client with IP pinning, validated redirects, throttling, and request budgets."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.config import settings
from app.security.target_validator import (
    ResolverFn,
    TargetValidationResult,
    validate_and_resolve_target,
)

_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_ALLOWED_METHODS = frozenset({"GET", "HEAD"})


class SafeHttpError(Exception):
    """Base error raised when a request violates target security or transport limits."""

    def __init__(self, message: str, *, code: str = "SAFE_HTTP_ERROR") -> None:
        super().__init__(message)
        self.code = code


class UnsafeDestinationError(SafeHttpError):
    """Raised when an initial target or redirect destination is blocked."""


class RedirectLimitError(SafeHttpError):
    """Raised when redirects exceed max_redirects or form a loop."""


class ResponseSizeExceededError(SafeHttpError):
    """Raised when response body exceeds max_response_bytes."""


class RequestBudgetExceededError(SafeHttpError):
    """Raised when a scan exceeds its maximum allowed HTTP request budget."""


@dataclass(frozen=True)
class SafeHttpResponse:
    """Captured response from SafeHttpClient."""

    url: str
    status_code: int
    headers: list[tuple[str, str]]
    body: bytes
    redirect_chain: list[str] = field(default_factory=list)
    connected_ip: str | None = None
    truncated: bool = False
    request_headers: dict[str, str] = field(default_factory=dict)

    def header_values(self, name: str) -> list[str]:
        target = name.lower()
        return [value for key, value in self.headers if key.lower() == target]

    def first_header(self, name: str) -> str | None:
        values = self.header_values(name)
        return values[0] if values else None

    def text(self, max_chars: int = 200_000) -> str:
        return self.body.decode("utf-8", errors="replace")[:max_chars]


def _build_pinned_url(validation: TargetValidationResult, target_ip: str) -> tuple[str, str]:
    """
    Construct a connection URL pinned to a validated IP and the matching Host header.

    Connecting directly to a pre-validated IP prevents DNS rebinding between
    validation and TCP connect, while extensions['sni_hostname'] preserves
    TLS SNI and certificate hostname verification.
    """
    assert validation.normalized_url is not None
    assert validation.hostname is not None
    assert validation.scheme is not None
    assert validation.port is not None

    parsed = urlsplit(validation.normalized_url)
    ip_obj = ipaddress.ip_address(target_ip)
    pinned_host = f"[{ip_obj}]" if isinstance(ip_obj, ipaddress.IPv6Address) else str(ip_obj)
    default_port = 443 if validation.scheme == "https" else 80
    pinned_netloc = f"{pinned_host}:{validation.port}" if validation.port != default_port else pinned_host
    pinned_url = urlunsplit((validation.scheme, pinned_netloc, parsed.path or "/", parsed.query, ""))

    is_host_ipv6 = ":" in validation.hostname
    header_host = f"[{validation.hostname}]" if is_host_ipv6 else validation.hostname
    if validation.port != default_port:
        header_host = f"{header_host}:{validation.port}"

    return pinned_url, header_host


class SafeHttpClient:
    """
    Synchronous non-destructive HTTP client enforcing:
    - GET/HEAD only
    - Pre-connection DNS validation and IP pinning (anti-DNS-rebinding)
    - TLS SNI and certificate validation for the original hostname
    - Manual per-hop redirect validation, loop detection, and hop limit
    - Strict connect/read timeouts and maximum response byte limit
    """

    def __init__(
        self,
        *,
        resolver: ResolverFn | None = None,
        transport: httpx.BaseTransport | None = None,
        max_redirects: int | None = None,
        max_response_bytes: int | None = None,
        request_timeout: float | None = None,
        connect_timeout: float | None = None,
        extra_allowed_ports: frozenset[int] | None = None,
    ) -> None:
        self._resolver = resolver
        self._transport = transport
        self._max_redirects = settings.max_redirects if max_redirects is None else max_redirects
        self._max_response_bytes = (
            settings.max_response_bytes if max_response_bytes is None else max_response_bytes
        )
        self._timeout = httpx.Timeout(
            settings.request_timeout_seconds if request_timeout is None else request_timeout,
            connect=settings.connect_timeout_seconds if connect_timeout is None else connect_timeout,
        )
        self._extra_allowed_ports = extra_allowed_ports

    def _stream_single_hop(
        self,
        client: httpx.Client,
        method: str,
        validation: TargetValidationResult,
        req_headers: dict[str, str],
    ) -> tuple[int, list[tuple[str, str]], bytes, str, dict[str, str]]:
        last_connect_exc: Exception | None = None
        for candidate_ip in validation.resolved_ips:
            pinned_url, host_header = _build_pinned_url(validation, candidate_ip)
            hop_headers = dict(req_headers)
            hop_headers["Host"] = host_header

            extensions: dict[str, object] = {}
            if validation.scheme == "https" and validation.hostname:
                extensions["sni_hostname"] = validation.hostname

            try:
                with client.stream(
                    method,
                    pinned_url,
                    headers=hop_headers,
                    extensions=extensions,
                ) as response:
                    content_length = response.headers.get("content-length")
                    if content_length and content_length.isdigit():
                        if int(content_length) > self._max_response_bytes:
                            raise ResponseSizeExceededError(
                                f"Response Content-Length exceeds {self._max_response_bytes} byte limit.",
                                code="RESPONSE_TOO_LARGE",
                            )

                    chunks: list[bytes] = []
                    total_bytes = 0
                    for chunk in response.iter_bytes():
                        total_bytes += len(chunk)
                        if total_bytes > self._max_response_bytes:
                            raise ResponseSizeExceededError(
                                f"Response body exceeded {self._max_response_bytes} byte limit.",
                                code="RESPONSE_TOO_LARGE",
                            )
                        chunks.append(chunk)

                    return (
                        response.status_code,
                        list(response.headers.multi_items()),
                        b"".join(chunks),
                        candidate_ip,
                        hop_headers,
                    )
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_connect_exc = exc
                continue

        assert last_connect_exc is not None
        raise last_connect_exc

    def request(
        self,
        method: str,
        url: str,
        *,
        authorized: bool = True,
        headers: dict[str, str] | None = None,
    ) -> SafeHttpResponse:
        upper_method = method.upper()
        if upper_method not in _ALLOWED_METHODS:
            raise SafeHttpError(
                f"Method '{upper_method}' is blocked. Only GET and HEAD are permitted.",
                code="UNSUPPORTED_METHOD",
            )

        current_url = url
        visited_urls: set[str] = set()
        redirect_chain: list[str] = []

        with httpx.Client(
            follow_redirects=False,
            timeout=self._timeout,
            transport=self._transport,
        ) as client:
            for hop in range(self._max_redirects + 1):
                validation = validate_and_resolve_target(
                    current_url,
                    authorized=authorized,
                    resolver=self._resolver,
                    extra_allowed_ports=self._extra_allowed_ports,
                )
                if not validation.valid or not validation.allowed or not validation.normalized_url:
                    raise UnsafeDestinationError(
                        validation.reason or "Target URL failed security validation.",
                        code=validation.error_code or "PROHIBITED_DESTINATION",
                    )

                if validation.normalized_url in visited_urls:
                    raise RedirectLimitError(
                        f"Redirect loop detected at {validation.normalized_url}.",
                        code="REDIRECT_LOOP",
                    )
                visited_urls.add(validation.normalized_url)

                if not validation.resolved_ips:
                    raise UnsafeDestinationError(
                        "No validated IP address available for connection.",
                        code="DNS_RESOLUTION_FAILED",
                    )

                req_headers = {"User-Agent": "BugHunterLab/1.0 (authorized-assessment)"}
                if headers:
                    req_headers.update(headers)

                status_code, raw_headers, body, connected_ip, sent_headers = self._stream_single_hop(
                    client,
                    upper_method,
                    validation,
                    req_headers,
                )

                if status_code in _REDIRECT_STATUS_CODES:
                    location = next(
                        (v for k, v in raw_headers if k.lower() == "location"),
                        None,
                    )
                    if location:
                        if hop >= self._max_redirects:
                            raise RedirectLimitError(
                                f"Exceeded maximum redirect limit of {self._max_redirects}.",
                                code="TOO_MANY_REDIRECTS",
                            )
                        redirect_chain.append(validation.normalized_url)
                        current_url = urljoin(validation.normalized_url, location.strip())
                        continue

                return SafeHttpResponse(
                    url=validation.normalized_url,
                    status_code=status_code,
                    headers=raw_headers,
                    body=body,
                    redirect_chain=redirect_chain,
                    connected_ip=connected_ip,
                    request_headers=sent_headers,
                )

        raise RedirectLimitError("Redirect handling exceeded limit.", code="TOO_MANY_REDIRECTS")


class ScanHttpSession:
    """Per-scan throttled and budgeted wrapper around SafeHttpClient."""

    def __init__(
        self,
        client: SafeHttpClient,
        *,
        max_requests: int | None = None,
        min_interval_seconds: float | None = None,
    ) -> None:
        self._client = client
        self.max_requests = settings.max_requests_per_scan if max_requests is None else max_requests
        self.min_interval_seconds = (
            settings.min_request_interval_seconds
            if min_interval_seconds is None
            else min_interval_seconds
        )
        self.request_count = 0
        self._last_request_at: float | None = None

    def request(
        self,
        method: str,
        url: str,
        *,
        authorized: bool = True,
        headers: dict[str, str] | None = None,
    ) -> SafeHttpResponse:
        if self.request_count >= self.max_requests:
            raise RequestBudgetExceededError(
                f"Scan request budget ({self.max_requests} requests) exceeded.",
                code="REQUEST_BUDGET_EXCEEDED",
            )

        if self._last_request_at is not None and self.min_interval_seconds > 0:
            elapsed = time.monotonic() - self._last_request_at
            if elapsed < self.min_interval_seconds:
                time.sleep(self.min_interval_seconds - elapsed)

        self._last_request_at = time.monotonic()
        self.request_count += 1
        response = self._client.request(method, url, authorized=authorized, headers=headers)
        # Count redirect hops toward budget tracking accurately
        if response.redirect_chain:
            self.request_count += len(response.redirect_chain)
        return response

    def get(
        self,
        url: str,
        *,
        authorized: bool = True,
        headers: dict[str, str] | None = None,
    ) -> SafeHttpResponse:
        return self.request("GET", url, authorized=authorized, headers=headers)
