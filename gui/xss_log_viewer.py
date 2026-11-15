# xss_security_gui/gui/xss_log_viewer.py
# ============================================================
# XSS Log Viewer 9.0 — async, risk-aware, paginated, GUI-safe
# ============================================================

import json
import threading
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from collections import Counter, defaultdict

from xss_security_gui.settings import LOG_DIR as BASE_LOG_DIR

# Директория логов
XSS_LOG_DIR: Path = BASE_LOG_DIR / "xss"
XSS_LOG_FILE: Path = XSS_LOG_DIR / "reflected_responses.json"

XSS_LOG_DIR.mkdir(parents=True, exist_ok=True)
_write_lock = threading.Lock()


# ============================================================
# NDJSON Loader 2.0
# ============================================================
def rotate_if_big(path: Path, max_mb: int = 20) -> None:
    """Ротирует файл, если он превышает max_mb мегабайт."""
    try:
        if path.exists() and path.stat().st_size > max_mb * 1024 * 1024:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup = path.with_suffix(path.suffix + f".{ts}.bak")
            path.rename(backup)
    except Exception as e:
        print(f"[XSSLogViewer] Ошибка ротации: {e}")


def load_ndjson(path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Безопасная загрузка NDJSON (lazy, limit)."""
    items: List[Dict[str, Any]] = []
    if not path.exists():
        return items

    try:
        with path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if limit and i >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[XSSLogViewer] Ошибка чтения NDJSON: {e}")

    return items


# ============================================================
# RiskScoreEngine
# ============================================================
def calculate_risk(x: Dict[str, Any]) -> str:
    payload = (x.get("payload") or "").lower()
    url = (x.get("url") or "").lower()

    if "<script>" in payload or "onerror=" in payload or "svg/onload" in payload:
        return "high"
    if "javascript:" in payload or "img src=x onerror" in payload:
        return "medium"
    if "alert(" in payload:
        return "low"
    return "unknown"


# ============================================================
# XSSLogViewer 9.0
# ============================================================
class XSSLogViewer:
    """
    XSSLogViewer 9.0
    ----------------
    • NDJSON loader 2.0
    • RiskScoreEngine
    • SummaryEngine
    • DetailsEngine (пагінація)
    • SearchEngine
    • GUI-safe callback
    """

    def __init__(self, gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.gui_callback = gui_callback

    # ---------------------------------------------------------
    # Safe emit
    # ---------------------------------------------------------
    def _emit(self, key: str, payload: Any) -> None:
        if self.gui_callback:
            try:
                self.gui_callback({key: payload})
            except Exception as e:
                print(f"[XSSLogViewer] Ошибка gui_callback: {e}")

    # ---------------------------------------------------------
    # Load logs
    # ---------------------------------------------------------
    def load(self, path: Path = XSS_LOG_FILE, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        rotate_if_big(path)
        items = load_ndjson(path, limit=limit)

        # Add risk score
        for x in items:
            x["risk"] = calculate_risk(x)

        return items

    # ---------------------------------------------------------
    # SummaryEngine
    # ---------------------------------------------------------
    def summarize(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_category = Counter(x.get("category", "unknown") for x in items)
        by_risk = Counter(x.get("risk", "unknown") for x in items)
        by_url = Counter(x.get("url", "unknown") for x in items)

        return {
            "total": len(items),
            "by_category": dict(by_category),
            "by_risk": dict(by_risk),
            "top_urls": by_url.most_common(10),
        }

    # ---------------------------------------------------------
    # GUI summary
    # ---------------------------------------------------------
    def render_summary(self, limit: int = 5000) -> Dict[str, Any]:
        items = self.load(limit=limit)
        summary = self.summarize(items)

        self._emit("xss_log_summary", summary)
        return summary

    # ---------------------------------------------------------
    # DetailsEngine (pagination)
    # ---------------------------------------------------------
    def render_details(self, page: int = 0, page_size: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self.load()

        # Sort by timestamp
        items.sort(key=lambda x: x.get("_ts", ""), reverse=True)

        # Filter
        if category:
            items = [x for x in items if x.get("category") == category]

        start = page * page_size
        end = start + page_size
        sliced = items[start:end]

        self._emit("xss_log_details", sliced)
        return sliced

    # ---------------------------------------------------------
    # RiskMap
    # ---------------------------------------------------------
    def render_riskmap(self, limit: int = 5000) -> List[Dict[str, Any]]:
        items = self.load(limit=limit)

        matrix = defaultdict(lambda: defaultdict(int))
        for x in items:
            cat = x.get("category", "unknown")
            risk = x.get("risk", "unknown")
            matrix[cat][risk] += 1

        heatmap = []
        for cat, risks in matrix.items():
            for risk, count in risks.items():
                heatmap.append({
                    "category": cat,
                    "risk": risk,
                    "count": count,
                })

        self._emit("xss_log_riskmap", heatmap)
        return heatmap

    # ---------------------------------------------------------
    # SearchEngine
    # ---------------------------------------------------------
    def search(self, keyword: str, limit: int = 5000) -> List[Dict[str, Any]]:
        items = self.load(limit=limit)
        keyword = keyword.lower()

        results = [
            x for x in items
            if keyword in (x.get("url", "").lower())
            or keyword in (x.get("payload", "").lower())
            or keyword in (x.get("full_response", "").lower())
        ]

        self._emit("xss_log_search", results[:200])
        return results[:200]

