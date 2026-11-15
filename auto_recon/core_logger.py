# xss_security_gui/auto_recon/core_logger.py
"""
Structured logger used by AutoReconOrchestrator (RT-style tags).

Provides:
    - StructuredLogger
    - EnterpriseLogger (backward compatibility)
    - LogLevel
    - get_logger()
"""

from __future__ import annotations

import logging

from enum import Enum
from typing import Any


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"


class StructuredLogger:

    def __init__(
            self,
            name: str,
    ):
        self._log = logging.getLogger(name)

    def _emit(
            self,
            level: int,
            message: str,
            **kwargs: Any,
    ) -> None:

        extra = {
            k: v
            for k, v in kwargs.items()
            if k != "exc_info"
        }

        if extra:
            message = (
                f"{message} | {extra}"
            )

        self._log.log(
            level,
            message,
        )

    def info(
            self,
            message: str,
            **kwargs: Any,
    ) -> None:

        self._emit(
            logging.INFO,
            message,
            **kwargs,
        )

    def warning(
            self,
            message: str,
            **kwargs: Any,
    ) -> None:

        self._emit(
            logging.WARNING,
            message,
            **kwargs,
        )

    def error(
            self,
            message: str,
            **kwargs: Any,
    ) -> None:

        self._emit(
            logging.ERROR,
            message,
            **kwargs,
        )

    def success(
            self,
            message: str,
            **kwargs: Any,
    ) -> None:

        self._emit(
            logging.INFO,
            message,
            **kwargs,
        )

    def debug(
            self,
            message: str,
            **kwargs: Any,
    ) -> None:

        self._emit(
            logging.DEBUG,
            message,
            **kwargs,
        )


class EnterpriseLogger(StructuredLogger):
    """
    Legacy compatibility layer.

    Used by old AutoRecon modules.
    """

    def __init__(
            self,
            name: str = "AutoRecon",
    ):
        super().__init__(name)

    def log_event(
            self,
            event: str,
            **kwargs: Any,
    ) -> None:

        self.info(
            event,
            **kwargs,
        )

    def log_success(
            self,
            event: str,
            **kwargs: Any,
    ) -> None:

        self.success(
            event,
            **kwargs,
        )

    def log_warning(
            self,
            event: str,
            **kwargs: Any,
    ) -> None:

        self.warning(
            event,
            **kwargs,
        )

    def log_error(
            self,
            event: str,
            **kwargs: Any,
    ) -> None:

        self.error(
            event,
            **kwargs,
        )

    def log_debug(
            self,
            event: str,
            **kwargs: Any,
    ) -> None:

        self.debug(
            event,
            **kwargs,
        )


def get_logger(
        name: str,
) -> EnterpriseLogger:

    return EnterpriseLogger(name)
