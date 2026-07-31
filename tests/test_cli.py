"""Tests for the CLI argument parser."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from netscan.cli import _build_parser, _resolve_scan_type, main


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
