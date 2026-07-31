"""Tests for OS and service fingerprinting helpers."""

from __future__ import annotations

import pytest

from netscan.detector import (
    classify_port_state,
    enrich_service_name,
    extract_version_info,
    is_high_value_service,
)


class TestEnrichServiceName:
    """Service name enrichment from generic nmap detections."""

    @pytest.mark.parametrize(
        ("port", "detected", "expected"),
        [
            (22, "unknown", "SSH (detected: unknown)"),
            (80, "", "HTTP (detected: )"),
            (443, "tcpwrapped", "HTTPS (detected: tcpwrapped)"),
            (3306, "unknown", "MySQL (detected: unknown)"),
        ],
    )
    def test_generic_names_get_hint(
        self, port: int, detected: str, expected: str
    ) -> None:
        assert enrich_service_name(port, detected) == expected

    def test_no_hint_returns_detected_name(self) -> None:
        assert enrich_service_name(8081, "unknown") == "unknown"

    def test_known_service_passes_through(self) -> None:
        assert enrich_service_name(22, "ssh") == "ssh"
        assert enrich_service_name(8080, "http-proxy") == "http-proxy"


class TestExtractVersionInfo:
    """Structured version parsing."""

    def test_semver_extraction(self) -> None:
        result = extract_version_info("8.2p1", "OpenSSH")
        assert result["version"] == "8.2p1"
        assert result["major"] == 8
        assert result["minor"] == 2

    def test_single_dot_only(self) -> None:
        result = extract_version_info("1.2.3", "nginx")
        assert result["major"] == 1
        assert result["minor"] == 2

    def test_no_version(self) -> None:
        result = extract_version_info("", "")
        assert result["version"] == ""
        assert result["major"] is None
        assert result["minor"] is None

    def test_non_numeric_version(self) -> None:
        result = extract_version_info("latest", "product")
        assert result["version"] == "latest"
        assert result["major"] is None
        assert result["minor"] is None


class TestIsHighValueService:
    """High-value service detection."""

    @pytest.mark.parametrize(
        "service",
        [
            "ssh",
            "rdp",
            "vnc",
            "telnet",
            "ftp",
            "smb",
            "mssql",
            "mysql",
            "postgresql",
            "oracle",
            "redis",
            "mongodb",
            "ldap",
            "winrm",
        ],
    )
    def test_high_value(self, service: str) -> None:
        assert is_high_value_service(service) is True

    def test_case_insensitive(self) -> None:
        assert is_high_value_service("SSH") is True
        assert is_high_value_service("RdP") is True

    @pytest.mark.parametrize("service", ["http", "https", "dns", "unknown"])
    def test_low_value(self, service: str) -> None:
        assert is_high_value_service(service) is False


class TestClassifyPortState:
    """Port state classification."""

    @pytest.mark.parametrize(
        ("state", "expected"),
        [
            ("open", "open"),
            ("filtered", "filtered"),
            ("unfiltered", "filtered"),
            ("closed", "closed"),
            ("weird", "unknown"),
        ],
    )
    def test_classification(self, state: str, expected: str) -> None:
        assert classify_port_state(state) == expected

    def test_case_and_whitespace_insensitive(self) -> None:
        assert classify_port_state("  OPEN  ") == "open"
        assert classify_port_state("Closed") == "closed"
