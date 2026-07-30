"""Tests for the netscan domain models."""

from __future__ import annotations

from netscan.models import PortResult, ScanReport, ScanTarget


class TestPortResult:
    """PortResult creation and string representation."""

    def test_minimal_creation(self) -> None:
        port = PortResult(
            port=80, protocol="tcp", state="open",
            service="http", version="", product="",
        )
        assert port.port == 80
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert "80/tcp open" in str(port)

    def test_with_banner(self) -> None:
        port = PortResult(
            port=22, protocol="tcp", state="open",
            service="ssh", version="8.2p1",
            product="OpenSSH", banner="SSH-2.0-OpenSSH_8.2p1",
        )
        assert port.banner == "SSH-2.0-OpenSSH_8.2p1"


class TestScanTarget:
    """ScanTarget properties and filtering."""

    def test_open_ports_filtering(self, scan_target: ScanTarget) -> None:
        assert len(scan_target.open_ports) == 2
        for p in scan_target.open_ports:
            assert p.state == "open"

    def test_filtered_ports(self, scan_target: ScanTarget) -> None:
        # All our sample ports are open
        assert len(scan_target.filtered_ports) == 0

    def test_mixed_ports(self) -> None:
        target = ScanTarget(
            ip="10.0.0.1", hostname="", state="up",
            ports=[
                PortResult(port=80, protocol="tcp", state="open",
                           service="http", version="", product=""),
                PortResult(port=443, protocol="tcp", state="filtered",
                           service="https", version="", product=""),
                PortResult(port=3306, protocol="tcp", state="closed",
                           service="mysql", version="", product=""),
            ],
        )
        assert len(target.open_ports) == 1
        assert target.open_ports[0].port == 80
        assert len(target.filtered_ports) == 1
        assert target.filtered_ports[0].port == 443


class TestScanReport:
    """ScanReport aggregation and serialization."""

    def test_totals(self, scan_report: ScanReport) -> None:
        assert scan_report.total_hosts == 1
        assert scan_report.total_open_ports == 2

    def test_empty_report(self) -> None:
        report = ScanReport(scan_time="now", scan_type="quick")
        assert report.total_hosts == 0
        assert report.total_open_ports == 0

    def test_to_dict(self, scan_report: ScanReport) -> None:
        d = scan_report.to_dict()
        assert d["scan_type"] == "quick"
        assert d["total_hosts"] == 1
        assert d["total_open_ports"] == 2
        assert len(d["targets"]) == 1
        assert d["targets"][0]["ip"] == "192.168.1.1"
        assert d["targets"][0]["ports"][0]["port"] == 22

    def test_to_dict_empty(self) -> None:
        report = ScanReport(scan_time="now", scan_type="test")
        d = report.to_dict()
        assert d["total_hosts"] == 0
        assert d["targets"] == []

    def test_invalid_port_data(self) -> None:
        """Model should handle port data gracefully."""
        target = ScanTarget(
            ip="10.0.0.1", hostname="", state="up", ports=[],
        )
        assert target.open_ports == []
        assert target.filtered_ports == []
