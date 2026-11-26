"""Pydantic schemas for target validation requests and responses."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class TargetValidateRequest(BaseModel):
    """Input payload for POST /api/targets/validate."""

    url: str = Field(..., description="User-supplied HTTP or HTTPS URL to validate.")
    authorized: bool = Field(
        False,
        description="Explicit user confirmation that they own or have permission to test the target.",
    )


class TargetValidateResponse(BaseModel):
    """Structured target validation response."""

    valid: bool
    allowed: bool
    normalized_url: str | None = None
    hostname: str | None = None
    scheme: Literal["http", "https"] | None = None
    port: int | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    error_code: str | None = None
    reason: str | None = None
    port_policy: str = "Standard web ports only (80 for HTTP, 443 for HTTPS)."
