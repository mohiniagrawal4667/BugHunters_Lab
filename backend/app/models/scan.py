"""Pydantic schemas for scans and findings."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

CheckId = Literal["headers", "cookies", "paths", "injection"]


class ScanCreateRequest(BaseModel):
    """Input payload for POST /api/scans."""

    target: str = Field(..., description="Target HTTP or HTTPS URL to scan.")
    checks: list[CheckId] = Field(..., min_length=1, description="Security check IDs requested.")
    authorized: bool = Field(
        False,
        description="Explicit user confirmation that they own or have permission to test the target.",
    )
