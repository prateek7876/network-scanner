"""Tests for structured logging configuration."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from netscan.logger import _JsonFormatter, setup_logging


@pytest.fixture(autouse=True)
def _clean_logger() -> None:
    """Remove any configured netscan handlers between tests."""
    yield
    logger = logging.getLogger("netscan")
    logger.handlers.clear()


class TestSetupLogging:
    """Logging configuration behaviour."""

    def test_configures_two_handlers(self, tmp_path: Path) -> None:
        setup_logging(level="INFO", log_dir=str(tmp_path))
        handlers = logging.getLogger("netscan").handlers
        assert len(handlers) == 2  # console + rotating file

    def test_idempotent_on_second_call(self, tmp_path: Path) -> None:
        setup_logging(level="INFO", log_dir=str(tmp_path))
        first = list(logging.getLogger("netscan").handlers)

        setup_logging(level="INFO", log_dir=str(tmp_path))
        assert logging.getLogger("netscan").handlers == first

    def test_json_format_uses_json_formatter(self, tmp_path: Path) -> None:
        setup_logging(level="DEBUG", log_dir=str(tmp_path), log_format="json")
        for handler in logging.getLogger("netscan").handlers:
            assert isinstance(handler.formatter, _JsonFormatter)

    def test_simple_format_uses_text_formatter(self, tmp_path: Path) -> None:
        setup_logging(level="INFO", log_dir=str(tmp_path), log_format="simple")
        for handler in logging.getLogger("netscan").handlers:
            assert not isinstance(handler.formatter, _JsonFormatter)

    def test_creates_log_directory_and_file(self, tmp_path: Path) -> None:
        setup_logging(level="INFO", log_dir=str(tmp_path))
        files = list(tmp_path.iterdir())
        assert files
        assert any(f.name.startswith("netscan_") for f in files)

    def test_invalid_level_falls_back_to_info(self, tmp_path: Path) -> None:
        setup_logging(level="BOGUS", log_dir=str(tmp_path))
        console = logging.getLogger("netscan").handlers[0]
        assert console.level == logging.INFO

    def test_emits_json_records_to_file(self, tmp_path: Path) -> None:
        setup_logging(level="DEBUG", log_dir=str(tmp_path), log_format="json")
        logger = logging.getLogger("netscan")
        logger.info("hello %s", "world")

        for handler in logger.handlers:
            handler.flush()

        log_files = [f for f in tmp_path.iterdir() if f.name.startswith("netscan_")]
        assert log_files
        content = log_files[0].read_text()
        records = [json.loads(line) for line in content.splitlines() if line.strip()]
        assert any(
            r["message"] == "hello world" and r["level"] == "INFO" for r in records
        )


class TestJsonFormatter:
    """JSON log formatter."""

    def test_format(self) -> None:
        record = logging.LogRecord(
            name="netscan.test",
            level=logging.INFO,
            pathname="x.py",
            lineno=1,
            msg="scanned %s",
            args=("host",),
            exc_info=None,
        )
        out = _JsonFormatter().format(record)
        data = json.loads(out)
        assert data["level"] == "INFO"
        assert data["logger"] == "netscan.test"
        assert data["message"] == "scanned host"
        assert "timestamp" in data
