"""Core scanning engine wrapping python-nmap.

Supports multi-threaded scanning of multiple targets and
real-time progress feedback via *rich*.
"""

from __future__ import annotations

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import nmap
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table as RichTable

from netscan.exceptions import InvalidTargetError, NmapNotFoundError, ScanError
from netscan.models import PortResult, ScanReport, ScanTarget

logger = logging.getLogger("netscan.scanner")
_console = Console()


# ---------------------------------------------------------------------------
# Result parsing helpers
# ---------------------------------------------------------------------------

def _parse_os_info(host_data: dict[str, Any]) -> dict[str, Any] | None:
    """Extract OS fingerprinting results from nmap host data."""
    try:
        osmatch = host_data.get("osmatch", [])
        if not osmatch:
            return None
        best = osmatch[0]
        os_class = (best.get("osclass") or [{}])[0]
        return {
            "name": best.get("name", "unknown"),
            "accuracy": int(best.get("accuracy", 0)),
            "type": os_class.get("type", ""),
            "vendor": os_class.get("vendor", ""),
            "family": os_class.get("osfamily", ""),
            "generation": os_class.get("osgen", ""),
        }
    except (IndexError, KeyError, ValueError, TypeError):
        return None


def _parse_port_data(host_data: dict[str, Any]) -> list[PortResult]:
    """Parse port data from nmap scan results."""
    ports: list[PortResult] = []
    try:
        for proto in host_data.get("protocols", []):
            name = proto.get("name", "tcp")
            for p in proto.get("ports", []):
                svc = p.get("service", {})
                ports.append(
                    PortResult(
                        port=p.get("port", 0),
                        protocol=name,
                        state=p.get("state", ""),
                        service=svc.get("name", ""),
                        version=(
                            f"{svc.get('version', '')}"
                            f" {svc.get('extrainfo', '')}"
                        ).strip(),
                        product=svc.get("product", ""),
                        banner=None,
                        extra=svc.get("extrainfo", ""),
                    )
                )
    except (KeyError, TypeError) as exc:
        logger.warning("Error parsing port data: %s", exc)
    return ports


def _build_report(
    scanner: nmap.PortScanner,
    scan_type: str,
) -> ScanReport:
    """Convert raw nmap host data into a ScanReport."""
    targets: list[ScanTarget] = []
    for host in scanner.all_hosts():
        data = scanner[host]
        raw = data if isinstance(data, dict) else {}

        ports = _parse_port_data(raw)
        os_info = _parse_os_info(raw)
        hostname = ""
        hn = raw.get("hostname")
        if isinstance(hn, list) and hn:
            hostname = hn[0].get("name", "")
        elif isinstance(hn, str):
            hostname = hn

        targets.append(
            ScanTarget(
                ip=host,
                hostname=hostname,
                state=raw.get("status", {}).get("state", "unknown"),
                os_info=os_info,
                ports=ports,
            )
        )

    return ScanReport(
        scan_time=datetime.now(timezone.utc).isoformat(),
        scan_type=scan_type,
        targets=targets,
    )


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class NetworkScanner:
    """Advanced port scanner with multi-threading and progress feedback.

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
        """Initialise the nmap scanner engine."""
        try:
            self._scanner = nmap.PortScanner()
            logger.debug("Nmap scanner engine initialised")
        except nmap.PortScannerError:
            raise NmapNotFoundError

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    _SAFE_TARGET_RE = re.compile(r"^[\w\.\-/:]+$")

    def validate_target(self, target: str) -> bool:
        """Check whether *target* is reachable (ping probe).

        Args:
            target: IP address, CIDR range, or hostname.

        Returns:
            ``True`` if the target is valid and responds.
        """
        target = target.strip()
        if not target or not self._SAFE_TARGET_RE.match(target):
            return False
        try:
            self._scanner.scan(target, arguments="-sn")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Single-target scan
    # ------------------------------------------------------------------

    def scan_target(
        self,
        target: str,
        ports: str = "1-1024",
        scan_type: str = "quick",
        show_progress: bool = False,
    ) -> ScanReport:
        """Run a scan against a single target (or CIDR range).

        Args:
            target: IP, CIDR, or range to scan.
            ports: Port spec (e.g. ``"22,80,443"``, ``"1-65535"``).
            scan_type: One of ``"quick"``, ``"full"``, ``"stealth"``,
                       ``"os-detection"``.
            show_progress: Show a live progress bar (doesn't add much
                           for a single target but available for
                           consistency).

        Returns:
            A :class:`ScanReport` with results.

        Raises:
            InvalidTargetError: Empty or malformed target.
            ScanError: The nmap scan failed.
        """
        target = target.strip()
        if not target:
            raise InvalidTargetError(target, "Target cannot be empty")

        arguments = self.SCAN_PROFILES.get(scan_type, "-sV")
        logger.info(
            "Starting %s scan on %s (ports=%s, args=%s)",
            scan_type, target, ports, arguments,
        )

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=_console,
            ) as progress:
                task = progress.add_task(
                    f"Scanning {target} ({ports})…", total=1,
                )
                try:
                    self._scanner.scan(target, ports, arguments)
                except Exception as exc:
                    raise ScanError(target, str(exc))
                progress.update(task, completed=1)
        else:
            try:
                self._scanner.scan(target, ports, arguments)
            except Exception as exc:
                raise ScanError(target, str(exc))

        report = _build_report(self._scanner, scan_type)
        logger.info(
            "Finished: %d host(s), %d open port(s)",
            report.total_hosts, report.total_open_ports,
        )
        return report

    # ------------------------------------------------------------------
    # Multi-target scan (threaded + progress)
    # ------------------------------------------------------------------

    def scan_targets(
        self,
        targets: list[str],
        ports: str = "1-1024",
        scan_type: str = "quick",
        max_workers: int = 10,
    ) -> ScanReport:
        """Scan multiple targets concurrently with a progress bar.

        Each target is dispatched to its own worker thread.

        Args:
            targets: List of IP addresses / hostnames.
            ports: Port spec forwarded to every target scan.
            scan_type: Scan profile name.
            max_workers: Thread-pool size.

        Returns:
            A merged :class:`ScanReport` covering all targets.

        Raises:
            ScanError: If every single target fails.
        """
        arguments = self.SCAN_PROFILES.get(scan_type, "-sV")
        total = len(targets)
        logger.info(
            "Scanning %d target(s) with %d worker(s) …",
            total, max_workers,
        )

        merged_targets: list[ScanTarget] = []
        errors: list[str] = []

        progress_bar = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=_console,
        )

        with progress_bar:
            scan_task = progress_bar.add_task(
                f"Scanning {total} target(s) …", total=total,
            )

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                future_map = {}
                for tgt in targets:
                    tgt = tgt.strip()
                    if not tgt:
                        continue
                    future = pool.submit(self._scan_single, tgt, ports, arguments)
                    future_map[future] = tgt

                for future in as_completed(future_map):
                    tgt = future_map[future]
                    try:
                        result = future.result()
                        if result:
                            merged_targets.extend(result)
                    except ScanError as exc:
                        errors.append(str(exc))
                        logger.warning("Target %s failed: %s", tgt, exc)
                    except Exception as exc:
                        errors.append(f"{tgt}: {exc}")
                        logger.error("Unexpected error for %s: %s", tgt, exc)
                    finally:
                        progress_bar.update(scan_task, advance=1)

        report = ScanReport(
            scan_time=datetime.now(timezone.utc).isoformat(),
            scan_type=scan_type,
            targets=merged_targets,
        )

        logger.info(
            "Multi-target scan complete: %d host(s), %d open port(s)",
            report.total_hosts, report.total_open_ports,
        )

        if errors:
            logger.warning("Errors encountered: %s", "; ".join(errors))
            _console.print(
                f"[yellow]! {len(errors)} target(s) had errors — "
                "check the logs for details[/]"
            )

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_single(
        self,
        target: str,
        ports: str,
        arguments: str,
    ) -> list[ScanTarget] | None:
        """Run nmap against one target and return its parsed targets."""
        try:
            self._scanner.scan(target, ports, arguments)
            report = _build_report(self._scanner, "direct")
            return report.targets
        except Exception as exc:
            raise ScanError(target, str(exc))
