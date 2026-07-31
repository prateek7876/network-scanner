"""Tests for TCP banner grabbing (with mocked sockets)."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from netscan.banner import DEFAULT_PROBE, PROBES, _grab_banner, grab_banners
from netscan.models import PortResult, ScanReport, ScanTarget


def _make_sock(banner: bytes = b"SSH-2.0-OpenSSH_8.2") -> MagicMock:
    """Return a mock socket whose ``recv`` yields *banner*."""
    sock = MagicMock()
    sock.recv.return_value = banner
    return sock


def _report() -> ScanReport:
    """Build a report with open SSH/HTTP ports and a filtered HTTPS port."""
    return ScanReport(
        scan_time="2026-07-30T12:00:00",
        scan_type="quick",
        targets=[
            ScanTarget(
                ip="10.0.0.1",
                hostname="h1",
                state="up",
                ports=[
                    PortResult(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        version="",
                        product="",
                    ),
                    PortResult(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                        version="",
                        product="",
                    ),
                    PortResult(
                        port=443,
                        protocol="tcp",
                        state="filtered",
                        service="https",
                        version="",
                        product="",
                    ),
                ],
            )
        ],
    )


class TestGrabBanner:
    """Single-port banner grabbing over a mocked socket."""

    def test_success(self) -> None:
        sock = _make_sock()
        with patch("netscan.banner.socket.socket", return_value=sock) as mk:
            result = _grab_banner("192.168.1.1", 22)

        assert result == "SSH-2.0-OpenSSH_8.2"
        mk.return_value.settimeout.assert_called_once_with(3.0)
        mk.return_value.connect.assert_called_once_with(("192.168.1.1", 22))
        mk.return_value.send.assert_called_once_with(DEFAULT_PROBE)
        mk.return_value.close.assert_called_once()

    def test_uses_service_specific_probe(self) -> None:
        sock = _make_sock()
        with patch("netscan.banner.socket.socket", return_value=sock):
            _grab_banner("192.168.1.1", 80, service="http")

        sock.send.assert_called_once_with(PROBES["http"])

    def test_unknown_service_uses_default_probe(self) -> None:
        sock = _make_sock()
        with patch("netscan.banner.socket.socket", return_value=sock):
            _grab_banner("192.168.1.1", 9000, service="weird")

        sock.send.assert_called_once_with(DEFAULT_PROBE)

    def test_empty_banner_returns_none(self) -> None:
        sock = _make_sock(b"")
        with patch("netscan.banner.socket.socket", return_value=sock):
            result = _grab_banner("192.168.1.1", 22)

        assert result is None

    def test_timeout_returns_none(self) -> None:
        sock = _make_sock()
        sock.connect.side_effect = socket.timeout("timed out")
        with patch("netscan.banner.socket.socket", return_value=sock):
            assert _grab_banner("192.168.1.1", 22) is None

    def test_connection_refused_returns_none(self) -> None:
        sock = _make_sock()
        sock.connect.side_effect = ConnectionRefusedError
        with patch("netscan.banner.socket.socket", return_value=sock):
            assert _grab_banner("192.168.1.1", 22) is None

    def test_os_error_returns_none(self) -> None:
        sock = _make_sock()
        sock.connect.side_effect = OSError("no route to host")
        with patch("netscan.banner.socket.socket", return_value=sock):
            assert _grab_banner("192.168.1.1", 22) is None

    def test_close_os_error_is_swallowed(self) -> None:
        sock = _make_sock()
        sock.close.side_effect = OSError("bad file descriptor")
        with patch("netscan.banner.socket.socket", return_value=sock):
            assert _grab_banner("192.168.1.1", 22) == "SSH-2.0-OpenSSH_8.2"

    def test_decode_errors_replaced(self) -> None:
        sock = _make_sock(b"\xff\xfe non-utf8 banner")
        with patch("netscan.banner.socket.socket", return_value=sock):
            result = _grab_banner("192.168.1.1", 22)

        assert result is not None
        assert "banner" in result


class TestGrabBanners:
    """Multi-port threaded banner collection."""

    def test_populates_only_open_ports(self) -> None:
        report = _report()

        def fake_grab(host: str, port: int, service: str, timeout: float):
            return f"{service}-banner" if port == 22 else None

        with patch("netscan.banner._grab_banner", side_effect=fake_grab):
            grab_banners(report, max_workers=2, timeout=1.0)

        ports = report.targets[0].ports
        assert ports[0].banner == "ssh-banner"
        assert ports[1].banner is None  # _grab_banner returned None
        assert ports[2].banner is None  # filtered ports are never probed

    def test_skips_non_open_ports(self) -> None:
        report = _report()
        with patch("netscan.banner._grab_banner") as fake:
            grab_banners(report)
        # Only the 2 open ports are submitted
        assert fake.call_count == 2

    def test_future_exception_is_handled(self) -> None:
        report = _report()

        def fake_grab(host: str, port: int, service: str, timeout: float):
            raise RuntimeError("boom")

        with patch("netscan.banner._grab_banner", side_effect=fake_grab):
            grab_banners(report, max_workers=1)

        assert all(p.banner is None for p in report.targets[0].ports)

    def test_no_open_ports_returns_report(self) -> None:
        report = ScanReport(
            scan_time="now",
            scan_type="quick",
            targets=[
                ScanTarget(
                    ip="10.0.0.2",
                    hostname="h2",
                    state="up",
                    ports=[
                        PortResult(
                            port=443,
                            protocol="tcp",
                            state="filtered",
                            service="https",
                            version="",
                            product="",
                        )
                    ],
                )
            ],
        )
        with patch("netscan.banner._grab_banner") as fake:
            result = grab_banners(report)

        fake.assert_not_called()
        assert result is report
        assert result.targets[0].ports[0].banner is None

    def test_end_to_end_through_socket(self) -> None:
        """Real ``_grab_banner`` runs inside the pool against a mock socket."""
        sock = _make_sock()
        report = _report()
        with patch("netscan.banner.socket.socket", return_value=sock):
            grab_banners(report, max_workers=1)

        ports = report.targets[0].ports
        assert ports[0].banner == "SSH-2.0-OpenSSH_8.2"
        assert ports[1].banner == "SSH-2.0-OpenSSH_8.2"
        assert ports[2].banner is None
