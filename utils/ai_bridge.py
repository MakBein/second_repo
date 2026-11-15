"""Asynchronous adapter between GUI findings and the AI risk engine."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from xss_security_gui.ai_core.risk_engine import analyze_security_risk
from xss_security_gui.utils.thread_worker import run_in_thread

_logger = logging.getLogger(__name__)


def analyze_async(
    finding: Any,
    *,
    callback: Callable[[dict[str, Any]], None],
    name: str = "AIAnalysis",
) -> None:
    """Analyze a finding off the UI thread and deliver a compact verdict."""
    if not callable(callback):
        raise TypeError("callback must be callable")

    if isinstance(finding, dict):
        raw_text = json.dumps(finding, ensure_ascii=False, default=str)
        insights = finding.get("js_insights")
        if not isinstance(insights, dict):
            insights = {}
    else:
        raw_text = str(finding)
        insights = {}

    def deliver_error(error: Exception) -> None:
        _logger.warning("Asynchronous AI analysis failed: %s", error)
        callback({
            "summary": f"AI analysis unavailable: {type(error).__name__}",
            "confidence": 0.0,
            "error": str(error),
        })

    def deliver_result(result: dict[str, Any]) -> None:
        verdict = dict(result)
        verdict["summary"] = (
            result.get("llm_summary")
            or f"Risk level: {result.get('risk_level', 'unknown')}"
        )
        verdict["confidence"] = result.get("risk_score", 0.0)
        callback(verdict)

    run_in_thread(
        analyze_security_risk,
        insights,
        raw_text,
        name=name,
        on_success=deliver_result,
        on_error=deliver_error,
    )


__all__ = ["analyze_async"]
