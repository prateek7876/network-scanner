"""TCP banner grabbing for open ports.

Attempts to connect to open ports and read service banners to
identify exact software versions.
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from netscan.models import ScanReport

logger = logging.getLogger("netscan.banner")

# Default probe payloads per service
PROBES: dict[str, bytes] = {
    "http": b"GET / HTTP/1.0\r\n\r\n",
    "https": b"GET / HTTP/1.0\r\n\r\n",
    "ssh": b"\r\n",
    "smtp": b"EHLO scan\r\n",
    "ftp": b"\r\n",
    "pop3": b"\r\n",
    "imap": b"\r\n",
    "telnet": b"\r\n",
    "redis": b"PING\r\n",
    "mysql": b"\r\n",
}

DEFAULT_PROBE = b"\r\n"


def _grab_banner(
    host: str,
    port: int,
    service: str = "",
    timeout: float = 3.0,
) -> str | None:
    """Connect to *port* on *host* and read a banner.

    Args:
        host: Target IP address.
        port: Target port.
        service: Detected service name (used to pick a probe).
        timeout: Connection/read timeout seconds.

    Returns:
        The received banner string, or ``None`` on failure.
    """
    probe = PROBES.get(service.lower(), DEFAULT_PROBE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        if probe:
            sock.send(probe)
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return banner if banner else None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def grab_banners(
    report: ScanReport,
    max_workers: int = 10,
    timeout: float = 3.0,
) -> ScanReport:
    """Grab banners for all open ports in *report*.

    Uses a thread pool to scan ports concurrently.

    Args:
        report: Scan report with targets and open ports.
        max_workers: Number of concurrent banner-grab threads.
        timeout: Connection timeout per port.

    Returns:
        The same report with ``banner`` fields populated.

    Raises:
        ScanError: If all banner grabs fail for every port.
    """
    futures: list[Any] = []
    grabbed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for target in report.targets:
            for port in target.ports:
                if port.state != "open":
                    continue
                future = pool.submit(
                    _grab_banner,
                    target.ip,
                    port.port,
                    port.service,
                    timeout,
                )
                futures.append((future, target, port))

        for future, target, port in futures:
            try:
                banner = future.result()
                if banner:
                    port.banner = banner
                    grabbed += 1
                    logger.debug("Banner %s:%d = %s", target.ip, port.port, banner[:60])
            except Exception as exc:
                logger.debug("Banner grab failed %s:%d — %s", target.ip, port.port, exc)

    if grabbed == 0 and any(t.ports for t in report.targets):
        logger.warning("No banners could be retrieved (firewall? no response?)")

    logger.info("Banner grabbing complete: %d banner(s) captured", grabbed)
    return report
