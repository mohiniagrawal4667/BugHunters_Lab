"""Runtime configuration for Bug Hunter Lab backend."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _parse_ports(raw: str | None) -> frozenset[int]:
    """Parse optional extra allowed ports from environment configuration."""
    if not raw:
        return frozenset()
    ports: set[int] = set()
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return frozenset(ports)


def _parse_origins(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return (
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "https://bughunterslab.vercel.app",
        )
    return tuple(origin.strip() for origin in raw.split(",") if origin.strip())


def _default_database_path() -> Path:
    explicit = os.getenv("BHL_DB_PATH")
    if explicit:
        return Path(explicit)
    # Vercel serverless filesystem (/var/task) is read-only; /tmp is writable at runtime.
    if os.getenv("VERCEL"):
        return Path("/tmp/bughunterlab.db")
    return Path(__file__).resolve().parents[1] / "data" / "bughunterlab.db"


@dataclass(frozen=True)
class Settings:
    """Centralized security and HTTP limits for target validation and scanning."""

    cors_origins: tuple[str, ...] = field(
        default_factory=lambda: _parse_origins(os.getenv("BHL_CORS_ORIGINS"))
    )
    # By default only standard web ports (80 for http, 443 for https) are permitted.
    extra_allowed_ports: frozenset[int] = field(
        default_factory=lambda: _parse_ports(os.getenv("BHL_EXTRA_ALLOWED_PORTS"))
    )
    request_timeout_seconds: float = float(os.getenv("BHL_REQUEST_TIMEOUT", "10.0"))
    connect_timeout_seconds: float = float(os.getenv("BHL_CONNECT_TIMEOUT", "5.0"))
    max_response_bytes: int = int(os.getenv("BHL_MAX_RESPONSE_BYTES", str(2 * 1024 * 1024)))
    max_redirects: int = int(os.getenv("BHL_MAX_REDIRECTS", "5"))
    min_request_interval_seconds: float = float(os.getenv("BHL_MIN_REQUEST_INTERVAL", "0.15"))
    max_requests_per_scan: int = int(os.getenv("BHL_MAX_REQUESTS_PER_SCAN", "25"))
    database_path: Path = field(default_factory=_default_database_path)


settings = Settings()
