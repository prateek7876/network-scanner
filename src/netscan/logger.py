"""Logging configuration — coloured console output and rotating file logs."""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Literal

_LOG_DIR = "logs"


def setup_logging(
    level: str = "INFO",
    log_dir: str = _LOG_DIR,
    log_format: Literal["simple", "json"] = "simple",
) -> None:
    """Configure the netscan package logger.

    Sets up a console handler and a rotating file handler. Safe to call
    multiple times — subsequent calls are no-ops.

    Args:
        level: One of ``"DEBUG"``, ``"INFO"``, ``"WARNING"``, ``"ERROR"``.
        log_dir: Directory for log files (created if missing).
        log_format: ``"simple"`` for human-readable, ``"json"`` for machine-parsed.
    """
    logger = logging.getLogger("netscan")
    if logger.handlers:
        return  # already configured

    logger.setLevel(logging.DEBUG)

    # Console handler (respects requested level)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    if log_format == "json":
        console.setFormatter(_JsonFormatter())
    else:
        fmt = "%(asctime)s | %(levelname)-8s | %(message)s"
        console.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    logger.addHandler(console)

    # File handler (always DEBUG)
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(log_dir, f"netscan_{timestamp}.log")

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setLevel(logging.DEBUG)
    if log_format == "json":
        file_handler.setFormatter(_JsonFormatter())
    else:
        fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        file_handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(file_handler)

    logger.debug("Logging configured: level=%s, file=%s", level, log_path)


class _JsonFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        import json as _json

        return _json.dumps(
            {
                "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )
