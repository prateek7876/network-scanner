"""Service and OS fingerprinting utilities.

Provides helper functions to enrich scan results with additional
fingerprint data beyond what python-nmap returns by default.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("netscan.detector")


# Common service-to-port mappings used for fingerprint hints
SERVICE_HINTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9090: "HTTP-Alt",
    27017: "MongoDB",
}


def enrich_service_name(port: int, detected_name: str) -> str:
    """Return an enriched service name when nmap's detection is generic.

    Args:
        port: The port number.
        detected_name: The service name nmap detected.

    Returns:
        A more descriptive name if available, otherwise *detected_name*.
    """
    if detected_name in ("unknown", "", "tcpwrapped"):
        hint = SERVICE_HINTS.get(port)
        if hint:
            logger.debug(
                "Enriched port %d service: %s -> %s", port, detected_name, hint
            )
            return f"{hint} (detected: {detected_name})"
    return detected_name


def extract_version_info(version: str, product: str) -> dict[str, Any]:
    """Parse version/product strings into structured components.

    Args:
        version: Raw version string from nmap.
        product: Raw product name from nmap.

    Returns:
        Dict with ``version``, ``major``, ``minor`` keys.
    """
    result: dict[str, Any] = {
        "version": version or "",
        "major": None,
        "minor": None,
    }

    # Try to extract semver-like version numbers
    if version:
        match = re.search(r"(\d+)\.(\d+)", version)
        if match:
            result["major"] = int(match.group(1))
            result["minor"] = int(match.group(2))

    return result


def is_high_value_service(service: str) -> bool:
    """Check if a service is considered 'high value' for security reporting.

    High-value services are those commonly targeted in attacks.

    Args:
        service: Service name string.

    Returns:
        True if the service is high-value.
    """
    high_value = {
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
    }
    return service.lower() in high_value


def classify_port_state(state: str) -> str:
    """Classify a port state for display/alerting purposes.

    Args:
        state: The raw port state from nmap.

    Returns:
        A color-coded classification: ``"open"``, ``"filtered"``,
        ``"closed"``, or ``"unknown"``.
    """
    state_lower = state.strip().lower()
    if state_lower in ("open",):
        return "open"
    if state_lower in ("filtered", "unfiltered"):
        return "filtered"
    if state_lower in ("closed",):
        return "closed"
    return "unknown"
