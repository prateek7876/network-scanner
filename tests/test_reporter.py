"""Tests for report generation (CSV, JSON, HTML)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from netscan.exceptions import ExportError
from netscan.models import PortResult, ScanReport, ScanTarget
from netscan.reporter import display_report, export_csv, export_html, export_json


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
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        version="8.2p1",
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as tmp:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as tmp:
            path = tmp.name

        try:
            export_html(report, path)
            content = Path(path).read_text()
            assert "<!DOCTYPE html>" in content
        finally:
            Path(path).unlink(missing_ok=True)


class TestExportErrorPaths:
    """Export failures should raise ExportError."""

    def test_json_permission_error(self) -> None:
        report = _sample_report()
        with pytest.raises(ExportError):
            export_json(report, "/nonexistent/path/report.json")

    def test_html_permission_error(self) -> None:
        report = _sample_report()
        with pytest.raises(ExportError):
            export_html(report, "/nonexistent/path/report.html")


class TestDisplayReport:
    """Terminal report rendering (captured via capsys)."""

    def test_prints_hosts_and_ports(self, capsys, scan_report) -> None:  # type: ignore[no-untyped-def]
        display_report(scan_report)
        out = capsys.readouterr().out

        assert "SCAN RESULTS" in out
        assert "quick" in out
        assert "192.168.1.1" in out
        assert "router.local" in out
        assert "ssh" in out
        assert "http" in out
        assert "1 host(s), 2 open port(s)" in out

    def test_empty_report_warns(self, capsys) -> None:
        report = ScanReport(scan_time="now", scan_type="test")
        display_report(report)
        out = capsys.readouterr().out
        assert "No hosts found" in out

    def test_shows_os_info(self, capsys, scan_target) -> None:  # type: ignore[no-untyped-def]
        scan_target.os_info = {"name": "Linux 2.6.32", "accuracy": 95}
        report = ScanReport(
            scan_time="now",
            scan_type="os-detection",
            targets=[scan_target],
        )
        display_report(report)
        out = capsys.readouterr().out
        assert "Linux 2.6.32" in out
        assert "95%" in out

    def test_shows_banner(self, capsys, scan_target) -> None:  # type: ignore[no-untyped-def]
        scan_target.ports[0].banner = "SSH-2.0-OpenSSH_8.2"
        report = ScanReport(
            scan_time="now",
            scan_type="quick",
            targets=[scan_target],
        )
        display_report(report)
        out = capsys.readouterr().out
        assert "Banner:" in out
        assert "SSH-2.0-OpenSSH_8.2" in out

    def test_no_ports_prints_notice(self, capsys) -> None:
        report = ScanReport(
            scan_time="now",
            scan_type="quick",
            targets=[ScanTarget(ip="10.0.0.1", hostname="h", state="up", ports=[])],
        )
        display_report(report)
        out = capsys.readouterr().out
        assert "No open ports found" in out

    def test_port_state_colours(self, capsys) -> None:
        report = ScanReport(
            scan_time="now",
            scan_type="quick",
            targets=[
                ScanTarget(
                    ip="10.0.0.1",
                    hostname="h",
                    state="up",
                    ports=[
                        PortResult(
                            port=22,
                            protocol="tcp",
                            state="open",
                            service="ssh",
                            version="",
                            product="",
                        ),
                        PortResult(
                            port=443,
                            protocol="tcp",
                            state="filtered",
                            service="https",
                            version="",
                            product="",
                        ),
                        PortResult(
                            port=80,
                            protocol="tcp",
                            state="closed",
                            service="http",
                            version="",
                            product="",
                        ),
                    ],
                )
            ],
        )
        display_report(report)
        out = capsys.readouterr().out
        assert "open" in out
        assert "filtered" in out
        assert "closed" in out

    def test_duration_omitted_when_zero(self, capsys) -> None:
        report = ScanReport(scan_time="now", scan_type="quick", duration_seconds=0.0)
        display_report(report)
        out = capsys.readouterr().out
        assert "Duration:" not in out
