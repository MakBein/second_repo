# xss_security_gui/dom_parser.py
"""
DOMParser ULTRA 7.0 — Backward Compatibility Layer
Парсер DOM для XSS Security Suite:
- Извлечение форм, скриптов, событий, медиа и др.
- Интеграция с settings.py и ThreatConnector
- Асинхронизация, кэширование, оптимизация производительности

Для нового кода используйте:
    from xss_security_gui.dom_parser import DOMParser, DOMParserAsync
    
Для старого кода остается полная обратная совместимость:
    from xss_security_gui.dom_parser import DOMParser
"""

# Re-export из нового пакета
from xss_security_gui.dom_parser.parser import DOMParser, DOMParserAsync
from xss_security_gui.dom_parser import (
    DOMParserException,
    HTMLSizeExceeded,
    ParseTimeout,
    InvalidHTML,
    AsyncExecutor,
    DOMParserCache,
    MetricsCollector,
    ProgressTracker,
)

__all__ = [
    "DOMParser",
    "DOMParserAsync",
    "DOMParserException",
    "HTMLSizeExceeded",
    "ParseTimeout",
    "InvalidHTML",
    "AsyncExecutor",
    "DOMParserCache",
    "MetricsCollector",
    "ProgressTracker",
]

