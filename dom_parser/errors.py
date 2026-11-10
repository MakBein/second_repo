# xss_security_gui/dom_parser/errors.py
"""
Custom exceptions for DOMParser ULTRA 7.0
"""


class DOMParserException(Exception):
    """Base exception for DOMParser"""
    pass


class HTMLSizeExceeded(DOMParserException):
    """HTML size exceeds configured limit"""
    def __init__(self, size: int, limit: int):
        super().__init__(f"HTML size {size} bytes exceeds limit {limit} bytes")
        self.size = size
        self.limit = limit


class ParseTimeout(DOMParserException):
    """Parsing exceeded time limit"""
    def __init__(self, category: str, timeout: float):
        super().__init__(f"Parsing {category} exceeded timeout {timeout}s")
        self.category = category
        self.timeout = timeout


class InvalidHTML(DOMParserException):
    """HTML content is invalid or malformed"""
    def __init__(self, reason: str):
        super().__init__(f"Invalid HTML: {reason}")
        self.reason = reason


class RegexInjection(DOMParserException):
    """Potential regex injection attempt detected"""
    def __init__(self, pattern: str):
        super().__init__(f"Suspicious regex pattern: {pattern}")
        self.pattern = pattern


class ParsingError(DOMParserException):
    """Generic parsing error"""
    def __init__(self, category: str, error: Exception):
        super().__init__(f"Error parsing {category}: {error}")
        self.category = category
        self.original_error = error


class CacheError(DOMParserException):
    """Cache operation error"""
    def __init__(self, operation: str, error: Exception):
        super().__init__(f"Cache {operation} failed: {error}")
        self.operation = operation
        self.original_error = error


class PoolExhausted(DOMParserException):
    """Object pool exhausted after timeout"""
    def __init__(self, pool_type: str, timeout: float):
        super().__init__(f"{pool_type} pool exhausted after {timeout}s wait")
        self.pool_type = pool_type
        self.timeout = timeout

