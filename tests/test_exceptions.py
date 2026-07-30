"""Tests for the custom exception hierarchy."""

from netscan.exceptions import (
    ExportError,
    InvalidTargetError,
    NetscanError,
    NmapNotFoundError,
    ScanError,
)


class TestNetscanError:
    """Base exception and hierarchy."""

    def test_base_exception(self) -> None:
        err = NetscanError("base error")
        assert isinstance(err, Exception)
        assert str(err) == "base error"

    def test_inheritance(self) -> None:
        """All custom exceptions inherit from NetscanError."""
        assert issubclass(NmapNotFoundError, NetscanError)
        assert issubclass(InvalidTargetError, NetscanError)
        assert issubclass(ScanError, NetscanError)
        assert issubclass(ExportError, NetscanError)


class TestNmapNotFoundError:
    def test_message(self) -> None:
        err = NmapNotFoundError()
        assert "nmap is not installed" in str(err).lower()


class TestInvalidTargetError:
    def test_with_reason(self) -> None:
        err = InvalidTargetError("10.0.0.999", "unreachable")
        assert "Invalid target" in str(err)
        assert "10.0.0.999" in str(err)
        assert "unreachable" in str(err)

    def test_minimal(self) -> None:
        err = InvalidTargetError("bad")
        assert "bad" in str(err)


class TestScanError:
    def test_with_detail(self) -> None:
        err = ScanError("10.0.0.1", "connection refused")
        assert "10.0.0.1" in str(err)
        assert "connection refused" in str(err)

    def test_minimal(self) -> None:
        err = ScanError("target")
        assert "target" in str(err)


class TestExportError:
    def test_csv(self) -> None:
        err = ExportError("csv", "permission denied")
        assert "CSV" in str(err)
        assert "permission denied" in str(err)

    def test_minimal(self) -> None:
        err = ExportError("json")
        assert "JSON" in str(err)
