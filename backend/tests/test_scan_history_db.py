"""Automated tests verifying SQLite persistence, empty state, sample exclusion, and scan records."""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import settings  # noqa: E402
from app.db.database import init_db, insert_scan, list_scans  # noqa: E402
from app.main import get_all_findings, get_scan_by_id, get_scans, validate_target  # noqa: E402
from app.models.target import TargetValidateRequest  # noqa: E402
from app.services.scan_runner import execute_scan  # noqa: E402


def mock_resolver(hostname: str, _port: int) -> list[str]:
    mapping = {
        "example.com": ["93.184.216.34"],
        "failing.example": ["93.184.216.34"],
    }
    if hostname not in mapping:
        raise socket.gaierror(f"Unknown host {hostname}")
    return mapping[hostname]


class ScanHistoryDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_bhl.db"
        self.orig_db_path = settings.database_path
        object.__setattr__(settings, "database_path", self.db_path)
        init_db(self.db_path)

    def tearDown(self) -> None:
        object.__setattr__(settings, "database_path", self.orig_db_path)
        self.temp_dir.cleanup()

    def test_1_empty_database_returns_zero_scans_and_findings(self) -> None:
        scans_resp = get_scans()
        findings_resp = get_all_findings()
        self.assertEqual(scans_resp["scans"], [])
        self.assertEqual(scans_resp["total"], 0)
        self.assertEqual(findings_resp["findings"], [])

    def test_2_sample_rows_never_appear_in_real_scan_history(self) -> None:
        insert_scan(
            self.db_path,
            {
                "id": "sample-scan-1",
                "sequence": 1,
                "label": "Sample 01",
                "target": "https://demo-app.example/",
                "checks": ["headers"],
                "status": "completed",
                "startedAt": "2026-01-01T00:00:00Z",
                "completedAt": "2026-01-01T00:00:05Z",
                "progress": 100,
                "currentStageId": None,
                "stages": [],
                "modules": {"headers": "done", "cookies": "skipped", "paths": "skipped", "injection": "skipped"},
                "logs": [],
                "mode": "demo",
                "dataSource": "sample",
                "requestCount": 0,
                "totalChecks": 1,
                "isSample": True,
            },
        )
        self.assertEqual(get_scans()["scans"], [])
        self.assertEqual(get_scans()["total"], 0)
        with self.assertRaises(Exception):
            get_scan_by_id("sample-scan-1")

    def test_3_target_validation_does_not_create_scan_record(self) -> None:
        with patch("app.security.target_validator.default_dns_resolver", mock_resolver):
            resp = validate_target(TargetValidateRequest(url="https://example.com", authorized=True))
        self.assertEqual(resp.status_code, 200)
        payload = json.loads(resp.body.decode("utf-8"))
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["allowed"])
        self.assertEqual(payload["resolved_ips"], ["93.184.216.34"])
        self.assertEqual(get_scans()["total"], 0)

    def test_4_5_6_completed_scan_persisted_and_retrievable_across_reads(self) -> None:
        def ok_transport(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>Example</html>")

        validation, scan, _findings = execute_scan(
            raw_url="  HTTPS://Example.COM/  ",
            checks=["headers", "cookies"],
            authorized=True,
            db_path=self.db_path,
            resolver=mock_resolver,
            transport=httpx.MockTransport(ok_transport),
            min_interval_seconds=0.0,
        )
        self.assertTrue(validation.allowed)
        self.assertIsNotNone(scan)
        assert scan is not None
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["target"], "https://example.com/")
        self.assertEqual(scan["dataSource"], "live")
        self.assertFalse(scan["isSample"])
        self.assertGreaterEqual(scan["requestCount"], 1)

        # Case Records endpoint reads persisted SQLite records
        case_records = get_scans()
        self.assertEqual(case_records["total"], 1)
        self.assertEqual(case_records["scans"][0]["id"], scan["id"])
        self.assertEqual(case_records["scans"][0]["target"], "https://example.com/")

        # Re-read directly from SQLite file (simulating page reload / backend restart)
        reloaded = list_scans(self.db_path, include_sample=False)
        self.assertEqual(len(reloaded), 1)
        self.assertEqual(reloaded[0]["status"], "completed")

    def test_7_failed_scan_persisted_as_failed(self) -> None:
        def failing_transport(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("Timed out connecting to target")

        validation, scan, _findings = execute_scan(
            raw_url="https://failing.example/",
            checks=["headers"],
            authorized=True,
            db_path=self.db_path,
            resolver=mock_resolver,
            transport=httpx.MockTransport(failing_transport),
            min_interval_seconds=0.0,
        )
        self.assertTrue(validation.allowed)
        self.assertIsNotNone(scan)
        assert scan is not None
        self.assertEqual(scan["status"], "failed")
        self.assertIn("Timed out", scan["error"] or "")

        case_records = get_scans()
        self.assertEqual(case_records["total"], 1)
        self.assertEqual(case_records["scans"][0]["status"], "failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
