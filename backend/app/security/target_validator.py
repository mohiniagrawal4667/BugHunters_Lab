"""Centralized URL validation, normalization, DNS resolution, and SSRF protection."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from app.config import settings

ResolverFn = Callable[[str, int], Sequence[str]]

_CONTROL_OR_SPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
_NUMERIC_LABEL_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|0[0-7]+|\d+)$")
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".localhost.localdomain",
    ".local",
    ".internal",
    ".arpa",
)
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")
_THIS_NET_NETWORK = ipaddress.IPv4Network("0.0.0.0/8")
_BENCHMARK_NETWORK = ipaddress.IPv4Network("198.18.0.0/15")


@dataclass(frozen=True)
class TargetValidationResult:
    """Internal result of target URL validation and DNS resolution."""

    valid: bool
    allowed: bool
    http_status: int
    normalized_url: str | None = None
    hostname: str | None = None
    scheme: str | None = None
    port: int | None = None
    resolved_ips: list[str] = field(default_factory=list)
    error_code: str | None = None
    reason: str | None = None


def default_dns_resolver(hostname: str, port: int) -> list[str]:
    """Resolve A/AAAA records using the system resolver."""
    infos = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        # Strip IPv6 scope ID if OS ever attaches one
        ip_clean = ip_str.split("%", 1)[0]
        if ip_clean not in ips:
            ips.append(ip_clean)
    return ips


def check_ip_safety(ip_str: str) -> str | None:
    """Return a rejection reason if an IP address is prohibited, else None."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Target resolved to an invalid IP address."

    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None:
            mapped_reason = check_ip_safety(str(ip_obj.ipv4_mapped))
            if mapped_reason:
                return mapped_reason
        if ip_obj.sixtofour is not None:
            sixtofour_reason = check_ip_safety(str(ip_obj.sixtofour))
            if sixtofour_reason:
                return f"Destination uses 6to4 addressing wrapping a prohibited IPv4 address ({sixtofour_reason})"

    if ip_obj.is_unspecified:
        return "Unspecified IP addresses (such as 0.0.0.0 or ::) are prohibited."
    if ip_obj.is_loopback:
        return "Loopback IP addresses (such as 127.0.0.0/8 or ::1) are prohibited."
    if ip_obj.is_link_local:
        return "Link-local IP addresses (such as 169.254.0.0/16 or fe80::/10) are prohibited."
    if ip_obj.is_multicast:
        return "Multicast IP addresses are prohibited."
    if ip_obj.is_private:
        return "Private network IP addresses (RFC 1918 / RFC 4193) are prohibited."
    if ip_obj.is_reserved:
        return "Reserved IP addresses are prohibited."
    if getattr(ip_obj, "is_site_local", False):
        return "Site-local IPv6 addresses are prohibited."

    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj in _CGNAT_NETWORK:
            return "Shared carrier-grade NAT IP addresses (100.64.0.0/10) are prohibited."
        if ip_obj in _THIS_NET_NETWORK:
            return "Source-only network addresses (0.0.0.0/8) are prohibited."
        if ip_obj in _BENCHMARK_NETWORK:
            return "Benchmarking network addresses (198.18.0.0/15) are prohibited."

    if not ip_obj.is_global:
        return "Non-global or special-purpose IP addresses are prohibited."

    return None


def _is_obfuscated_ip_hostname(hostname: str) -> bool:
    """Detect integer, hex, octal, or shorthand IPv4 hostnames (e.g. 2130706433, 0x7f000001, 0177.0.0.1, 127.1)."""
    if ":" in hostname:
        return False
    labels = hostname.split(".")
    if not labels:
        return False
    if not all(_NUMERIC_LABEL_RE.match(label) for label in labels):
        return False
    # If all labels are numeric/hex/octal, only canonical dotted-quad decimal (no leading zeros) is valid IPv4.
    if len(labels) != 4:
        return True
    for label in labels:
        if not label.isdigit():
            return True
        if len(label) > 1 and label.startswith("0"):
            return True
    return False


def _validate_hostname_syntax(ascii_host: str) -> str | None:
    if not ascii_host:
        return "URL must include a valid hostname."
    if ascii_host in _BLOCKED_HOSTNAMES or any(ascii_host.endswith(suffix) for suffix in _BLOCKED_SUFFIXES):
        return f"Hostname '{ascii_host}' refers to localhost or an internal-only domain and is prohibited."
    if _is_obfuscated_ip_hostname(ascii_host):
        return "Non-canonical, integer, octal, or hexadecimal IP hostnames are rejected."
    return None


def _build_normalized_url(
    scheme: str,
    ascii_host: str,
    port: int,
    default_port: int,
    path: str,
    query: str,
    is_ipv6: bool,
) -> str:
    host_part = f"[{ascii_host}]" if is_ipv6 else ascii_host
    port_part = "" if port == default_port else f":{port}"
    netloc = f"{host_part}{port_part}"
    normalized_path = path if path else "/"
    return urlunsplit((scheme, netloc, normalized_path, query, ""))


def validate_and_resolve_target(
    raw_url: str,
    *,
    authorized: bool = True,
    resolver: ResolverFn | None = None,
    extra_allowed_ports: frozenset[int] | None = None,
) -> TargetValidationResult:
    """
    Validate, normalize, and DNS-resolve a user-supplied target URL.

    Security validation runs before authorization confirmation so prohibited or
    malformed URLs are always flagged as invalid/prohibited regardless of consent.
    """
    trimmed = raw_url.strip()
    if not trimmed:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            error_code="EMPTY_URL",
            reason="Enter a target URL to validate.",
        )

    if _CONTROL_OR_SPACE_RE.search(trimmed):
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            error_code="MALFORMED_URL",
            reason="URL contains invalid whitespace or control characters.",
        )

    # Check scheme + authority boundary for backslash smuggling (e.g. https://evil.com\@127.0.0.1)
    if "\\" in trimmed.split("?", 1)[0].split("#", 1)[0]:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            error_code="MALFORMED_URL",
            reason="URL contains backslash characters in the authority or path.",
        )

    try:
        parsed = urlsplit(trimmed)
    except ValueError:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            error_code="MALFORMED_URL",
            reason="The entered value is not a valid URL.",
        )

    scheme = parsed.scheme.lower()
    if not scheme:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            error_code="MALFORMED_URL",
            reason="URL must include an explicit http:// or https:// scheme.",
        )

    if scheme not in ("http", "https"):
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            scheme=scheme,
            error_code="UNSUPPORTED_SCHEME",
            reason=f"Unsupported URL scheme '{scheme}'. Only http and https are allowed.",
        )

    if not parsed.netloc:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            scheme=scheme,
            error_code="MALFORMED_URL",
            reason="URL must include a hostname after the scheme.",
        )

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            scheme=scheme,
            error_code="EMBEDDED_CREDENTIALS",
            reason="Embedded username/password credentials or '@' in URL authority are not allowed.",
        )

    # Reject IPv6 zone IDs such as [fe80::1%eth0]
    if "%" in parsed.netloc:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            scheme=scheme,
            error_code="MALFORMED_URL",
            reason="Percent-encoded characters or IPv6 zone IDs are not permitted in the host.",
        )

    try:
        explicit_port = parsed.port
    except ValueError:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            scheme=scheme,
            error_code="INVALID_PORT",
            reason="URL specifies an invalid port number.",
        )

    raw_hostname = parsed.hostname
    if not raw_hostname:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            scheme=scheme,
            error_code="MALFORMED_URL",
            reason="URL must include a valid hostname.",
        )

    default_port = 443 if scheme == "https" else 80
    port = explicit_port if explicit_port is not None else default_port
    allowed_extra = extra_allowed_ports if extra_allowed_ports is not None else settings.extra_allowed_ports
    if port != default_port and port not in allowed_extra:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=400,
            scheme=scheme,
            port=port,
            error_code="DISALLOWED_PORT",
            reason=(
                f"Port {port} is not permitted for {scheme.upper()} targets. "
                f"Only standard port {default_port} is allowed by default policy."
            ),
        )

    # Detect whether raw_hostname is an IP literal vs DNS domain
    ip_literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ip_literal = ipaddress.ip_address(raw_hostname)
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        ascii_host = str(ip_literal)
        is_ipv6 = isinstance(ip_literal, ipaddress.IPv6Address)
    else:
        stripped_host = raw_hostname.rstrip(".")
        if not stripped_host or ".." in stripped_host:
            return TargetValidationResult(
                valid=False,
                allowed=False,
                http_status=400,
                scheme=scheme,
                error_code="MALFORMED_URL",
                reason="Hostname syntax is invalid.",
            )
        try:
            ascii_host = stripped_host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return TargetValidationResult(
                valid=False,
                allowed=False,
                http_status=400,
                scheme=scheme,
                error_code="MALFORMED_URL",
                reason="Hostname contains invalid internationalized domain characters.",
            )
        is_ipv6 = False

    host_syntax_error = _validate_hostname_syntax(ascii_host)
    if host_syntax_error:
        return TargetValidationResult(
            valid=False,
            allowed=False,
            http_status=403,
            hostname=ascii_host,
            scheme=scheme,
            port=port,
            error_code="PROHIBITED_DESTINATION",
            reason=host_syntax_error,
        )

    normalized_url = _build_normalized_url(
        scheme=scheme,
        ascii_host=ascii_host,
        port=port,
        default_port=default_port,
        path=parsed.path,
        query=parsed.query,
        is_ipv6=is_ipv6,
    )

    if ip_literal is not None:
        resolved_ips = [str(ip_literal)]
    else:
        dns_fn = resolver or default_dns_resolver
        try:
            resolved_ips = list(dict.fromkeys(dns_fn(ascii_host, port)))
        except (socket.gaierror, OSError):
            return TargetValidationResult(
                valid=False,
                allowed=False,
                http_status=400,
                normalized_url=normalized_url,
                hostname=ascii_host,
                scheme=scheme,
                port=port,
                error_code="DNS_RESOLUTION_FAILED",
                reason=f"Could not resolve DNS records for '{ascii_host}'.",
            )

        if not resolved_ips:
            return TargetValidationResult(
                valid=False,
                allowed=False,
                http_status=400,
                normalized_url=normalized_url,
                hostname=ascii_host,
                scheme=scheme,
                port=port,
                error_code="DNS_RESOLUTION_FAILED",
                reason=f"No IP addresses were returned for '{ascii_host}'.",
            )

    for ip_str in resolved_ips:
        ip_reason = check_ip_safety(ip_str)
        if ip_reason is not None:
            # Do not disclose prohibited internal IP addresses in the response payload.
            return TargetValidationResult(
                valid=False,
                allowed=False,
                http_status=403,
                normalized_url=normalized_url,
                hostname=ascii_host,
                scheme=scheme,
                port=port,
                resolved_ips=[],
                error_code="PROHIBITED_DESTINATION",
                reason=ip_reason,
            )

    if not authorized:
        return TargetValidationResult(
            valid=True,
            allowed=False,
            http_status=403,
            normalized_url=normalized_url,
            hostname=ascii_host,
            scheme=scheme,
            port=port,
            resolved_ips=resolved_ips,
            error_code="AUTHORIZATION_REQUIRED",
            reason="Confirm that you own or have explicit authorization to test this target before proceeding.",
        )

    return TargetValidationResult(
        valid=True,
        allowed=True,
        http_status=200,
        normalized_url=normalized_url,
        hostname=ascii_host,
        scheme=scheme,
        port=port,
        resolved_ips=resolved_ips,
    )
