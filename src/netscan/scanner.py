"""Core scanning engine wrapping python-nmap."""

from __future__ import annotations

import logging
import re
from typing import Any

import nmap

from netscan.exceptions import NmapNotFoundError, ScanError, InvalidTargetError
from netscan.models import PortResult, ScanReport, ScanTarget

logger = logging.getLogger("netscan.scanner")


def _parse_os_info(host_data: dict[str, Any]) -> dict[str, Any] | None:
    """Extract OS fingerprinting results from nmap host data."""
    try:
        osmatch = host_data.get("osmatch", [])
        if not osmatch:
            return None
        best_match = osmatch[0]
        return {
            "name": best_match.get("name", "unknown"),
            "accuracy": int(best_match.get("accuracy", 0)),
            "type": best_match.get("osclass", [{}])[0].get("type", ""),
            "vendor": best_match.get("osclass", [{}])[0].get("vendor", ""),
            "family": best_match.get("osclass", [{}])[0].get("osfamily", ""),
            "generation": best_match.get("osclass", [{}])[0].get("osgen", ""),
        }
    except (IndexError, KeyError, ValueError, TypeError):
        return None


def _parse_port_data(host_data: dict[str, Any]) -> list[PortResult]:
    """Parse port data from nmap scan results."""
    ports: list[PortResult] = []
    try:
        for proto in host_data.get("protocols", []):
            proto_name = proto.get("name", "tcp")
            for port_entry in proto.get("ports", []):
                port_info = port_entry.get("service", {})
                ports.append(
                    PortResult(
                        port=port_entry.get("port", 0),
                        protocol=proto_name,
                        state=port_entry.get("state", ""),
                        service=port_info.get("name", ""),
                        version=(
                            f"{port_info.get('version', '')}"
                            f" {port_info.get('extrainfo', '')}"
                        ).strip(),
                        product=port_info.get("product", ""),
                        banner=None,
                        extra=port_info.get("extrainfo", ""),
                    )
                )
    except (KeyError, TypeError) as exc:
        logger.warning("Error parsing port data: %s", exc)
    return ports


class NetworkScanner:
    """Advanced port scanner with OS detection and service fingerprinting.

    Usage:
        scanner = NetworkScanner()
        report = scanner.scan_target("192.168.1.1", ports="22,80,443")
        print(report.total_open_ports)
    """

    SCAN_PROFILES: dict[str, str] = {
        "quick": "-sV -T4",
        "full": "-sV -sC -O -T4",
        "stealth": "-sS -T2",
        "os-detection": "-O -T4",
    }

    def __init__(self) -> None:
        """Initialize the nmap scanner engine."""
        try:
            self._scanner = nmap.PortScanner()
            logger.debug("Nmap scanner engine initialized")
        except nmap.PortScannerError:
            raise NmapNotFoundError

    def validate_target(self, target: str) -> bool:
        """Check if a target is reachable and valid.

        Args:
            target: IP address, CIDR range, or hostname.

        Returns:
            True if the target responds to a ping probe.
        """
        if not target or not target.strip():
            return False

        # Basic input sanitisation
        if not re.match(r"^[\w\.\-/:]+$", target.strip()):
            logger.warning("Target contains suspect characters: %s", target)
            return False

        try:
            self._scanner.scan(target.strip(), arguments="-sn")
            return True
        except Exception as exc:
            logger.debug("Target validation failed for %s: %s", target, exc)
            return False

    def scan_target(
        self,
        target: str,
        ports: str = "1-1024",
        scan_type: str = "quick",
    ) -> ScanReport:
        """Run a scan against *target* and return a structured report.

        Args:
            target: IP, CIDR, or range to scan.
            ports: Port specification (e.g. ``"22,80,443"``, ``"1-65535"``).
            scan_type: One of ``"quick"``, ``"full"``, ``"stealth"``,
                       ``"os-detection"``.

        Returns:
            A :class:`ScanReport` containing all results.

        Raises:
            InvalidTargetError: The target was empty or malformed.
            ScanError: The nmap scan itself failed.
        """
        target = target.strip()
        if not target:
            raise InvalidTargetError(target, "Target cannot be empty")

        arguments = self.SCAN_PROFILES.get(scan_type, "-sV")
        logger.info(
            "Starting %s scan on %s (ports=%s, args=%s)",
            scan_type,
            target,
            ports,
            arguments,
        )

        try:
            self._scanner.scan(target, ports, arguments)
        except Exception as exc:
            raise ScanError(target, str(exc))

        report = self._build_report(target, scan_type)

        logger.info(
            "Scan finished: %d host(s), %d open port(s)",
            report.total_hosts,
            report.total_open_ports,
        )
        return report

    def _build_report(self, target: str, scan_type: str) -> ScanReport:
        """Convert raw nmap host data into a ScanReport."""
        import time
        from datetime import datetime, timezone

        scan_targets: list[ScanTarget] = []

        for host in self._scanner.all_hosts():
            host_data = self._scanner[host]

            # nmap.python outputs a dict — convert to our model
            raw = host_data if isinstance(host_data, dict) else {}

            ports = _parse_port_data(raw)
            os_info = _parse_os_info(raw)

            scan_targets.append(
                ScanTarget(
                    ip=host,
                    hostname=raw.get("hostname", [{}])[0].get("name", "")
                    if isinstance(raw.get("hostname"), list)
                    else raw.get("hostname", ""),
                    state=raw.get("status", {}).get("state", "unknown"),
                    os_info=os_info,
                    ports=ports,
                )
            )

        return ScanReport(
            scan_time=datetime.now(timezone.utc).isoformat(),
            scan_type=scan_type,
            targets=scan_targets,
        )
