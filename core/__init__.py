# xss_security_gui/core/__init__.py
"""
XSS Security GUI - Core Package
Enterprise-grade threat analysis suite v12.0

Components:
- ThreadPoolManager: Async task execution without GUI blocking
- CacheEngine: Intelligent response caching
- ReportGenerator: Professional security reports (HTML/PDF/JSON)
- WAFDetector: Advanced WAF detection & evasion
"""

from .threading_manager import (
    ThreadPoolManager,
    get_thread_pool,
    submit_task,
    wait_for,
    TaskPriority,
)
from .cache_engine import (
    CacheEngine,
    HTTPResponseCache,
    get_cache,
    get_http_cache,
    cache_get,
    cache_set,
    cache_invalidate,
)
from .report_generator import (
    ReportGenerator,
    VulnerabilityReport,
)
from .waf_engine import (
    WAFDetector,
    WAFType,
    HTTPEvasionWrapper,
)

__all__ = [
    # Threading
    "ThreadPoolManager",
    "get_thread_pool",
    "submit_task",
    "wait_for",
    "TaskPriority",
    # Caching
    "CacheEngine",
    "HTTPResponseCache",
    "get_cache",
    "get_http_cache",
    "cache_get",
    "cache_set",
    "cache_invalidate",
    # Reporting
    "ReportGenerator",
    "VulnerabilityReport",
    # WAF
    "WAFDetector",
    "WAFType",
    "HTTPEvasionWrapper",
]
