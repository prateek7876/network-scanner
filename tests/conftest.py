"""Shared pytest fixtures and sample data for netscan tests."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from netscan.models import PortResult, ScanReport, ScanTarget

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_PORT_80: dict[str, Any] = {
    "port": 80,
    "state": "open",
    "service": {
        "name": "http",
        "product": "Apache httpd",
        "version": "2.4.41",
        "extrainfo": "(Ubuntu)",
    },
}

SAMPLE_PORT_22: dict[str, Any] = {
    "port": 22,
    "state": "open",
    "service": {
        "name": "ssh",
        "product": "OpenSSH",
        "version": "8.2p1",
        "extrainfo": "protocol 2.0",
    },
}

SAMPLE_PORT_443: dict[str, Any] = {
    "port": 443,
    "state": "filtered",
    "service": {
        "name": "https",
        "product": "",
        "version": "",
        "extrainfo": "",
    },
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def port_result_open() -> PortResult:
    """Return a sample open port result."""
    return PortResult(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        version="2.4.41",
        product="Apache httpd",
    )


@pytest.fixture
def port_result_filtered() -> PortResult:
    """Return a sample filtered port result."""
    return PortResult(
        port=443,
        protocol="tcp",
        state="filtered",
        service="https",
        version="",
        product="",
    )


@pytest.fixture
def scan_target() -> ScanTarget:
    """Return a sample scan target with a couple of ports."""
    return ScanTarget(
        ip="192.168.1.1",
        hostname="router.local",
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
            PortResult(
                port=80,
                protocol="tcp",
                state="open",
                service="http",
                version="2.4.41",
                product="Apache httpd",
            ),
        ],
    )


@pytest.fixture
def scan_report(scan_target: ScanTarget) -> ScanReport:
    """Return a complete sample scan report."""
    return ScanReport(
        scan_time="2026-07-30T12:00:00",
        scan_type="quick",
        targets=[scan_target],
        duration_seconds=5.3,
    )


@pytest.fixture
def mock_nmap_scanner() -> MagicMock:
    """Mock ``nmap.PortScanner`` with canned data.

    The mock returns a dict-like structure mimicking python-nmap output.
    """
    # Build protocol/port structure
    services = [
        {
            "port": 22,
            "state": "open",
            "service": {
                "name": "ssh",
                "product": "OpenSSH",
                "version": "8.2p1",
                "extrainfo": "",
            },
        },
        {
            "port": 80,
            "state": "open",
            "service": {
                "name": "http",
                "product": "Apache httpd",
                "version": "2.4.41",
                "extrainfo": "(Ubuntu)",
            },
        },
    ]

    host_data = {
        "hostname": [{"name": "test.local", "type": "PTR"}],
        "status": {"state": "up"},
        "protocols": [
            {"name": "tcp", "ports": services},
        ],
        "osmatch": [
            {
                "name": "Linux 2.6.32",
                "accuracy": 95,
                "osclass": [
                    {
                        "type": "general purpose",
                        "vendor": "Linux",
                        "osfamily": "Linux",
                        "osgen": "2.6.X",
                    }
                ],
            }
        ],
    }

    scanner = MagicMock()
    scanner.all_hosts.return_value = ["192.168.1.1"]
    scanner.__getitem__.return_value = host_data

    # Make indexing with a string key work
    def getitem(key: str) -> dict[str, Any]:
        return host_data

    scanner.__getitem__.side_effect = getitem

    return scanner


@pytest.fixture
def mock_nmap_not_found() -> MagicMock:
    """Mock nmap import so ``nmap.PortScanner()`` raises."""
    with patch("nmap.PortScanner") as mock:
        mock.side_effect = ImportError("nmap not found")
        yield mock
