# xss_security_gui/dom_parser/__init__.py
"""
DOMParser ULTRA 7.0
Modern asynchronous DOM parser with caching, threading, and ThreatConnector integration
"""

from .parser import DOMParser, DOMParserAsync
from .errors import (
    DOMParserException,
    HTMLSizeExceeded,
    ParseTimeout,
    InvalidHTML,
    RegexInjection,
    ParsingError,
    CacheError,
    PoolExhausted,
)
from .async_executor import AsyncExecutor, BatchProcessor
from .cache import DOMParserCache, L1Cache, L2Cache
from .metrics import MetricsCollector, ProgressTracker, ParseMetrics
from .async_logger import AsyncLogger, BulkLogger, get_async_logger

__all__ = [
    "DOMParser",
    "DOMParserAsync",
    "DOMParserException",
    "HTMLSizeExceeded",
    "ParseTimeout",
    "InvalidHTML",
    "RegexInjection",
    "ParsingError",
    "CacheError",
    "PoolExhausted",
    "AsyncExecutor",
    "BatchProcessor",
    "DOMParserCache",
    "L1Cache",
    "L2Cache",
    "MetricsCollector",
    "ProgressTracker",
    "ParseMetrics",
    "AsyncLogger",
    "BulkLogger",
    "get_async_logger",
]

