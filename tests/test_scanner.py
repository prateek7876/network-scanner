"""Tests for the scanning engine (with mocked nmap)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from netscan.exceptions import (
    InvalidTargetError,
    NmapNotFoundError,
    ScanError,
)
from netscan.scanner import _build_report, _parse_os_info, _parse_port_data


def test_scanner_init_success() -> None:
    """Scanner should initialise when nmap is available."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.return_value.all_hosts.return_value = []
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        assert scanner is not None


def test_scanner_init_failure() -> None:
    """Scanner should raise NmapNotFoundError when nmap is missing."""
    from nmap.nmap import PortScannerError

    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.side_effect = PortScannerError("nmap not found")
        from netscan.scanner import NetworkScanner

        with pytest.raises(NmapNotFoundError):
            NetworkScanner()


def test_validate_target_empty() -> None:
    """Empty target should fail validation."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.return_value.all_hosts.return_value = []
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        assert scanner.validate_target("") is False
        assert scanner.validate_target("   ") is False
        assert scanner.validate_target(None) is False  # type: ignore[arg-type]


def test_validate_target_suspect_chars() -> None:
    """Targets with suspicious characters should be rejected."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.return_value.all_hosts.return_value = []
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        assert scanner.validate_target("; rm -rf /") is False
        assert scanner.validate_target("$(whoami)") is False
        assert scanner.validate_target("`id`") is False


def test_validate_target_valid() -> None:
    """A valid, reachable target should pass."""
    with patch("nmap.PortScanner"):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        result = scanner.validate_target("192.168.1.1")
        assert result is True


def test_scan_target_empty() -> None:
    """Empty target should raise InvalidTargetError."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.return_value.all_hosts.return_value = []
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        with pytest.raises(InvalidTargetError, match="Target cannot be empty"):
            scanner.scan_target("  ")


def test_scan_target_nmap_error() -> None:
    """If nmap raises, ScanError should be raised."""
    with patch("nmap.PortScanner") as mock_nmap:
        instance = mock_nmap.return_value
        instance.scan.side_effect = RuntimeError("connection timeout")
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        with pytest.raises(ScanError):
            scanner.scan_target("192.168.1.1")


def test_scan_target_success(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """A successful scan should produce a populated ScanReport."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        report = scanner.scan_target("192.168.1.1")

        assert report.total_hosts == 1
        assert report.total_open_ports == 2
        assert report.scan_type == "quick"

        target = report.targets[0]
        assert target.ip == "192.168.1.1"
        assert target.hostname == "test.local"
        assert target.os_info is not None
        assert target.os_info["name"] == "Linux 2.6.32"

        ports = target.ports
        assert len(ports) == 2
        assert ports[0].port == 22
        assert ports[0].service == "ssh"
        assert ports[1].port == 80
        assert ports[1].service == "http"


def test_scan_target_with_os_detection(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """OS detection scan should populate os_info."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        report = scanner.scan_target("192.168.1.1", scan_type="os-detection")
        target = report.targets[0]
        assert target.os_info is not None
        assert target.os_info["name"] == "Linux 2.6.32"
        assert target.os_info["accuracy"] == 95


def test_scan_targets_multi(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """Multi-target scan should process each target."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        report = scanner.scan_targets(
            targets=["10.0.0.1", "10.0.0.2"],
            ports="22,80",
            scan_type="quick",
            max_workers=2,
        )
        # Each mock scan returns the same host, so we get 2 target groups
        assert report.total_hosts >= 1
        assert report.scan_type == "quick"


# ---------------------------------------------------------------------------
# Result-parsing helpers (edge cases)
# ---------------------------------------------------------------------------


def test_parse_os_info_missing_osmatch() -> None:
    """No osmatch data should produce no OS info."""
    assert _parse_os_info({}) is None
    assert _parse_os_info({"osmatch": []}) is None


def test_parse_os_info_malformed_accuracy() -> None:
    """A non-integer accuracy should be swallowed (returns None)."""
    data = {"osmatch": [{"name": "X", "accuracy": "not-an-int"}]}
    assert _parse_os_info(data) is None


def test_parse_port_data_type_error() -> None:
    """Malformed protocols data should produce an empty port list."""
    assert _parse_port_data({"protocols": None}) == []


def test_parse_port_data_missing_ports_key() -> None:
    """A protocol entry without a ports key should be tolerated."""
    data = {"protocols": [{"name": "tcp"}]}
    assert _parse_port_data(data) == []


def test_build_report_string_hostname() -> None:
    """Hostname given as a plain string should be used directly."""
    host_data = {
        "hostname": "plain.host",
        "status": {"state": "up"},
        "protocols": [],
    }
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["10.0.0.9"]
    scanner.__getitem__.return_value = host_data

    report = _build_report(scanner, "quick")
    assert report.targets[0].hostname == "plain.host"
    assert report.targets[0].state == "up"


# ---------------------------------------------------------------------------
# Scanner edge cases
# ---------------------------------------------------------------------------


def test_validate_target_scan_exception() -> None:
    """A failed ping probe should fail validation."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.return_value.scan.side_effect = RuntimeError("nmap failed")
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        assert scanner.validate_target("192.168.1.1") is False


def test_scan_target_show_progress(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """Single-target scan with the rich progress bar enabled."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        report = scanner.scan_target(
            "192.168.1.1",
            ports="22,80",
            scan_type="quick",
            show_progress=True,
        )
        assert report.total_hosts == 1
        assert report.total_open_ports == 2


def test_scan_target_show_progress_error() -> None:
    """Progress-path scan failures should raise ScanError."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.return_value.scan.side_effect = RuntimeError("boom")
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        with pytest.raises(ScanError):
            scanner.scan_target("192.168.1.1", show_progress=True)


def test_scan_targets_skips_blank_targets(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """Blank entries in the target list should be skipped, not scanned."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        report = scanner.scan_targets(
            targets=["", "   ", "10.0.0.1"],
            ports="22",
            scan_type="quick",
        )
        assert report.total_hosts >= 1


def test_scan_targets_collects_scan_errors(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """A failing worker should be collected as an error, not crash the scan."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        with patch.object(
            scanner, "_scan_single", side_effect=ScanError("10.0.0.5", "down")
        ):
            report = scanner.scan_targets(
                targets=["10.0.0.5"],
                ports="22",
                scan_type="quick",
            )
        assert report.total_hosts == 0


def test_scan_targets_collects_unexpected_errors(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """Non-ScanError exceptions from a worker should also be collected."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        with patch.object(
            scanner, "_scan_single", side_effect=RuntimeError("unexpected")
        ):
            report = scanner.scan_targets(
                targets=["10.0.0.6"],
                ports="22",
                scan_type="quick",
            )
        assert report.total_hosts == 0


def test_scan_single_raises_scan_error(mock_nmap_scanner) -> None:  # type: ignore[no-untyped-def]
    """The private single-scan helper should wrap failures in ScanError."""
    with patch("nmap.PortScanner", return_value=mock_nmap_scanner):
        from netscan.scanner import NetworkScanner

        scanner = NetworkScanner()
        scanner._scanner.scan.side_effect = ConnectionError("refused")
        with pytest.raises(ScanError):
            scanner._scan_single("10.0.0.7", "22", "-sV")
