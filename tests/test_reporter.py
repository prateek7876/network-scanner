"""Tests for report generation (CSV, JSON, HTML)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from netscan.exceptions import ExportError
from netscan.models import PortResult, ScanReport, ScanTarget
from netscan.reporter import export_csv, export_html, export_json


def _sample_report() -> ScanReport:
    """Build a minimal ScanReport for export tests."""
    return ScanReport(
        scan_time="2026-07-30T12:00:00",
        scan_type="quick",
        targets=[
            ScanTarget(
                ip="10.0.0.1",
                hostname="test.local",
                state="up",
                ports=[
                    PortResult(
                        port=22, protocol="tcp", state="open",
                        service="ssh", version="8.2p1",
                        product="OpenSSH",
                    ),
                ],
            ),
        ],
        duration_seconds=2.1,
    )


class TestCsvExport:
    """CSV report generation."""

    def test_export_basic(self) -> None:
        report = _sample_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                         delete=False) as tmp:
            path = tmp.name

        try:
            export_csv(report, path)
            content = Path(path).read_text()
            assert "IP,Hostname,State" in content
            assert "10.0.0.1" in content
            assert "test.local" in content
            assert "ssh" in content
        finally:
            Path(path).unlink(missing_ok=True)

    def test_export_empty_report(self) -> None:
        report = ScanReport(scan_time="now", scan_type="test")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                         delete=False) as tmp:
            path = tmp.name

        try:
            export_csv(report, path)
            content = Path(path).read_text()
            assert "IP" in content
            # Only header row — no data rows
            assert content.strip().count("\n") == 0
        finally:
            Path(path).unlink(missing_ok=True)

    def test_export_permission_error(self) -> None:
        report = _sample_report()
        with pytest.raises(ExportError):
            export_csv(report, "/nonexistent/path/report.csv")


class TestJsonExport:
    """JSON report generation."""

    def test_export_basic(self) -> None:
        report = _sample_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as tmp:
            path = tmp.name

        try:
            export_json(report, path)
            data = json.loads(Path(path).read_text())
            assert data["scan_type"] == "quick"
            assert data["total_hosts"] == 1
            assert data["total_open_ports"] == 1
            assert data["targets"][0]["ip"] == "10.0.0.1"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_export_round_trip(self) -> None:
        """Export and verify the JSON structure."""
        report = _sample_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as tmp:
            path = tmp.name

        try:
            export_json(report, path)
            data = json.loads(Path(path).read_text())
            assert "scan_time" in data
            assert "targets" in data
            port = data["targets"][0]["ports"][0]
            assert port["port"] == 22
            assert port["banner"] is None
        finally:
            Path(path).unlink(missing_ok=True)


class TestHtmlExport:
    """HTML report generation."""

    def test_export_basic(self) -> None:
        report = _sample_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                         delete=False) as tmp:
            path = tmp.name

        try:
            export_html(report, path)
            content = Path(path).read_text()
            assert "<!DOCTYPE html>" in content
            assert "Network Scan Report" in content
            assert "10.0.0.1" in content
            assert "22" in content
        finally:
            Path(path).unlink(missing_ok=True)

    def test_export_empty(self) -> None:
        report = ScanReport(scan_time="now", scan_type="test")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                         delete=False) as tmp:
            path = tmp.name

        try:
            export_html(report, path)
            content = Path(path).read_text()
            assert "<!DOCTYPE html>" in content
        finally:
            Path(path).unlink(missing_ok=True)
