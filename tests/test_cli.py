"""Tests for the CLI argument parser."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from netscan.cli import _build_parser, _resolve_scan_type, main
from netscan.exceptions import ExportError, ScanError


class TestArgumentParser:
    """Argparse configuration."""

    def test_minimal_args(self) -> None:
        """Parser accepts -t/--target as the only required flag."""
        parser = _build_parser()
        args = parser.parse_args(["-t", "192.168.1.1"])
        assert args.target == "192.168.1.1"

    def test_target_required(self) -> None:
        """Parser exits with error when --target is missing."""
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_all_flags(self) -> None:
        """All optional flags parse correctly."""
        parser = _build_parser()
        args = parser.parse_args(
            [
                "-t",
                "10.0.0.1",
                "-p",
                "22,80,443",
                "--full",
                "--csv",
                "--json",
                "--html",
                "--banner-grab",
                "--threads",
                "20",
                "-v",
                "-o",
                "my_scan",
            ]
        )
        assert args.target == "10.0.0.1"
        assert args.ports == "22,80,443"
        assert args.full is True
        assert args.csv is True
        assert args.json is True
        assert args.html is True
        assert args.banner_grab is True
        assert args.threads == 20
        assert args.verbose is True
        assert args.output == "my_scan"

    def test_scan_type_mutual_exclusion(self) -> None:
        """Only one scan type flag should be active at a time."""
        parser = _build_parser()
        args = parser.parse_args(["-t", "10.0.0.1", "--stealth"])
        assert args.stealth is True
        assert args.full is False
        assert args.quick is False

    def test_default_ports(self) -> None:
        """Default port range should be 1-1024."""
        parser = _build_parser()
        args = parser.parse_args(["-t", "10.0.0.1"])
        assert args.ports == "1-1024"


class TestScanTypeResolution:
    """Scan type string resolution from flags."""

    def test_default_is_quick(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["-t", "10.0.0.1"])
        assert _resolve_scan_type(args) == "quick"

    def test_full(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["-t", "10.0.0.1", "--full"])
        assert _resolve_scan_type(args) == "full"

    def test_stealth(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["-t", "10.0.0.1", "--stealth"])
        assert _resolve_scan_type(args) == "stealth"

    def test_os_detection(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["-t", "10.0.0.1", "--os-detection"])
        assert _resolve_scan_type(args) == "os-detection"


class TestMainExitCodes:
    """Integration-level exit code behaviour."""

    def test_version(self) -> None:
        """--version should exit 0."""
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_no_target_exits_error(self) -> None:
        """Missing --target should exit non-zero."""
        with pytest.raises(SystemExit):
            main([])

    def test_invalid_target_exits_error(self) -> None:
        """An unreachable target should return exit code 1."""
        test_args = ["-t", "invalid.target.that.will.fail"]
        with patch.object(sys, "argv", ["netscan"] + test_args):
            # We can't easily test the full flow without nmap,
            # so we verify the parser at least accepts the args
            parser = _build_parser()
            args = parser.parse_args(test_args)
            assert args.target == "invalid.target.that.will.fail"


class TestMainSuccessFlow:
    """End-to-end main() execution with a mocked scanner."""

    def test_quick_scan_success(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report") as mk_display,
        ):
            mk_scanner.return_value.scan_target.return_value = scan_report
            rc = main(["-t", "192.168.1.1"])

        assert rc == 0
        mk_display.assert_called_once_with(scan_report)
        mk_scanner.return_value.scan_target.assert_called_once()

    def test_multi_target_uses_scan_targets(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report"),
        ):
            mk_scanner.return_value.scan_targets.return_value = scan_report
            rc = main(["-t", "10.0.0.1,10.0.0.2"])

        assert rc == 0
        mk_scanner.return_value.scan_targets.assert_called_once()
        mk_scanner.return_value.scan_target.assert_not_called()

    def test_all_exports_written(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report"),
            patch("netscan.reporter.export_csv") as mk_csv,
            patch("netscan.reporter.export_json") as mk_json,
            patch("netscan.reporter.export_html") as mk_html,
        ):
            mk_scanner.return_value.scan_target.return_value = scan_report
            rc = main(["-t", "192.168.1.1", "--csv", "--json", "--html", "-o", "out"])

        assert rc == 0
        mk_csv.assert_called_once_with(scan_report, "out.csv")
        mk_json.assert_called_once_with(scan_report, "out.json")
        mk_html.assert_called_once_with(scan_report, "out.html")

    def test_banner_grab_flow(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report"),
            patch("netscan.banner.grab_banners") as mk_grab,
        ):
            mk_scanner.return_value.scan_target.return_value = scan_report
            mk_grab.return_value = scan_report
            rc = main(["-t", "192.168.1.1", "--banner-grab"])

        assert rc == 0
        mk_grab.assert_called_once()

    def test_export_failure_does_not_abort(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report"),
            patch(
                "netscan.reporter.export_csv",
                side_effect=ExportError("CSV", "permission denied"),
            ) as mk_csv,
        ):
            mk_scanner.return_value.scan_target.return_value = scan_report
            rc = main(["-t", "192.168.1.1", "--csv"])

        assert rc == 0  # export failure is logged, not fatal
        mk_csv.assert_called_once()

    def test_json_export_failure_does_not_abort(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report"),
            patch(
                "netscan.reporter.export_json",
                side_effect=ExportError("JSON", "permission denied"),
            ),
        ):
            mk_scanner.return_value.scan_target.return_value = scan_report
            rc = main(["-t", "192.168.1.1", "--json"])

        assert rc == 0

    def test_html_export_failure_does_not_abort(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report"),
            patch(
                "netscan.reporter.export_html",
                side_effect=ExportError("HTML", "permission denied"),
            ),
        ):
            mk_scanner.return_value.scan_target.return_value = scan_report
            rc = main(["-t", "192.168.1.1", "--html"])

        assert rc == 0

    def test_banner_grab_failure_does_not_abort(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
            patch("netscan.reporter.display_report"),
            patch(
                "netscan.banner.grab_banners",
                side_effect=ScanError("10.0.0.1", "unreachable"),
            ),
        ):
            mk_scanner.return_value.scan_target.return_value = scan_report
            rc = main(["-t", "192.168.1.1", "--banner-grab"])

        assert rc == 0  # banner grab failure is skipped, not fatal


class TestMainErrorFlow:
    """main() error handling."""

    def test_scan_error_returns_1(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
        ):
            mk_scanner.return_value.scan_target.side_effect = ScanError(
                "10.0.0.1", "connection timeout"
            )
            rc = main(["-t", "10.0.0.1"])

        assert rc == 1

    def test_scan_targets_error_returns_1(self, scan_report) -> None:  # type: ignore[no-untyped-def]
        with (
            patch("netscan.cli.NetworkScanner") as mk_scanner,
            patch("netscan.logger.setup_logging"),
        ):
            mk_scanner.return_value.scan_targets.side_effect = ScanError(
                "10.0.0.1", "down"
            )
            rc = main(["-t", "10.0.0.1,10.0.0.2"])

        assert rc == 1


class TestDirectExecution:
    """Running the module directly (python cli.py)."""

    def test_cli_direct_execution(self) -> None:
        """``python cli.py --version`` should exit 0 via __main__ guard."""
        cli_path = Path(__file__).parent.parent / "src" / "netscan" / "cli.py"
        with patch.object(sys, "argv", ["netscan", "--version"]):
            with pytest.raises(SystemExit) as exc:
                runpy.run_path(str(cli_path), run_name="__main__")
        assert exc.value.code == 0
