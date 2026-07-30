"""Custom exception hierarchy for the netscan package."""


class NetscanError(Exception):
    """Base exception for all netscan errors."""


class NmapNotFoundError(NetscanError):
    """Raised when the nmap binary is not found on the system."""

    def __init__(self) -> None:
        super().__init__(
            "nmap is not installed or not in PATH. "
            "Install it via your package manager: "
            "brew install nmap / apt install nmap / dnf install nmap"
        )


class InvalidTargetError(NetscanError):
    """Raised when the target specification is invalid."""

    def __init__(self, target: str, reason: str = "") -> None:
        msg = f"Invalid target: {target!r}"
        if reason:
            msg += f" — {reason}"
        super().__init__(msg)


class ScanError(NetscanError):
    """Raised when a scan operation fails."""

    def __init__(self, target: str, detail: str = "") -> None:
        msg = f"Scan failed for {target!r}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class ExportError(NetscanError):
    """Raised when report export fails."""

    def __init__(self, fmt: str, detail: str = "") -> None:
        msg = f"Failed to export {fmt.upper()} report"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)
