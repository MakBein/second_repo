# xss_security_gui/auto_recon/reporting.py
"""JSON/HTML report writer for AutoReconOrchestrator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from xss_security_gui.settings import LOG_DIR, EXPORT_DIR


class ReportGenerator:
    def __init__(self) -> None:
        self.out_dir = Path(EXPORT_DIR) if EXPORT_DIR else Path(LOG_DIR)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def generate_scan_report(
        self,
        scan_results: List[Dict[str, Any]],
        scan_name: str = "AutoRecon",
        targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "name": scan_name,
            "targets": targets or [],
            "count": len(scan_results),
            "items": scan_results[:500],
        }

    def generate_vulnerability_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target: str = "",
    ) -> Dict[str, Any]:
        return {
            "target": target,
            "count": len(vulnerabilities),
            "items": vulnerabilities[:500],
        }

    def generate_detailed_analysis(
        self,
        scan_results: List[Dict[str, Any]],
        analysis_results: Dict[str, Any],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "user": user_context or {},
            "scan_count": len(scan_results),
            "modules": {k: (len(v) if isinstance(v, list) else 1) for k, v in (analysis_results or {}).items()},
            "analysis": analysis_results or {},
        }

    def save_report(self, report: Dict[str, Any]) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.out_dir / f"autorecon_report_{ts}.json"
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return str(path)

    def generate_html_report(self, report: Dict[str, Any]) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.out_dir / f"autorecon_report_{ts}.html"
        meta = report.get("metadata") or {}
        threat = report.get("threat_summary") or {}
        rows = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in list(threat.items())[:40]
        )
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AutoRecon Report</title>
<style>body{{font-family:Segoe UI,sans-serif;background:#111;color:#ddd;padding:24px}}
table{{border-collapse:collapse}}td,th{{border:1px solid #444;padding:6px 10px}}</style>
</head><body>
<h1>AutoRecon Enterprise Report</h1>
<p>Targets: {", ".join(meta.get("targets") or [])}</p>
<p>Risk: {meta.get("risk_level")} (score {meta.get("risk_score")})</p>
<p>Generated: {meta.get("generated_at")}</p>
<table><tr><th>Key</th><th>Value</th></tr>{rows}</table>
</body></html>"""
        path.write_text(html, encoding="utf-8")
        return str(path)


_GEN: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _GEN
    if _GEN is None:
        _GEN = ReportGenerator()
    return _GEN
