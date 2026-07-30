"""
netscan — Advanced Network Scanner
===================================
A professional-grade network scanner with port detection,
service fingerprinting, banner grabbing, and multiple export formats.

Typical usage:
    python -m netscan -t 192.168.1.1
    python -m netscan -t 192.168.1.0/24 -p 1-65535 --threads 20
"""

from netscan.models import PortResult, ScanTarget, ScanReport
from netscan.scanner import NetworkScanner
from netscan.exceptions import (
    NetscanError,
    NmapNotFoundError,
    InvalidTargetError,
    ScanError,
    ExportError,
)

__version__ = "2.0.0"
__author__ = "Prateek Raghuvanshi"
__all__ = [
    "NetworkScanner",
    "PortResult",
    "ScanTarget",
    "ScanReport",
    "NetscanError",
    "NmapNotFoundError",
    "InvalidTargetError",
    "ScanError",
    "ExportError",
]
