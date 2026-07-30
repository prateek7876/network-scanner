"""Domain models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PortResult:
    """Represents a single port scan result."""

    port: int
    protocol: str
    state: str
    service: str
    version: str
    product: str
    banner: str | None = None
    extra: str = ""

    def __str__(self) -> str:
        return (
            f"{self.port}/{self.protocol} "
            f"{self.state:10} "
            f"{self.service:15} "
            f"{self.version or self.product}"
        )


@dataclass
class ScanTarget:
    """Represents a scanned host and its open ports."""

    ip: str
    hostname: str
    state: str
    os_info: dict[str, Any] | None = None
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        """Return only open ports."""
        return [p for p in self.ports if p.state == "open"]

    @property
    def filtered_ports(self) -> list[PortResult]:
        """Return only filtered ports."""
        return [p for p in self.ports if p.state == "filtered"]


@dataclass
class ScanReport:
    """Complete scan report containing all targets and metadata."""

    scan_time: str
    scan_type: str
    targets: list[ScanTarget] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def total_hosts(self) -> int:
        return len(self.targets)

    @property
    def total_open_ports(self) -> int:
        return sum(len(t.open_ports) for t in self.targets)

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to a dictionary (for JSON export)."""
        return {
            "scan_time": self.scan_time,
            "scan_type": self.scan_type,
            "duration_seconds": self.duration_seconds,
            "total_hosts": self.total_hosts,
            "total_open_ports": self.total_open_ports,
            "targets": [
                {
                    "ip": t.ip,
                    "hostname": t.hostname,
                    "state": t.state,
                    "os": t.os_info,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                            "product": p.product,
                            "banner": p.banner,
                        }
                        for p in t.ports
                    ],
                }
                for t in self.targets
            ],
        }
