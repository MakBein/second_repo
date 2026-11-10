# xss_security_gui/auto_recon/core_logger.py
"""Structured logger used by AutoReconOrchestrator (RT-style tags)."""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, Optional


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"


class StructuredLogger:
    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: int, message: str, **kwargs: Any) -> None:
        extra = {k: v for k, v in kwargs.items() if k not in ("exc_info",)}
        if extra:
            message = f"{message} | {extra}"
        self._log.log(level, message)

    def info(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.ERROR, message, **kwargs)

    def success(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.INFO, message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        self._emit(logging.DEBUG, message, **kwargs)


def get_logger(name: str) -> StructuredLogger:
    return StructuredLogger(name)
