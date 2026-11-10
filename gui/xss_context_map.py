# xss_security_gui/gui/xss_context_map.py
# ============================================================
# XSSContextMapTab 9.0 — context-aware, risk-aware, live-mode 2.0
# ============================================================

import json
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any, Optional, Callable
from collections import defaultdict
import time

from xss_security_gui.auto_recon.scanner import load_reflected_responses
from xss_security_gui.utils.threat_sender import (
    enrich_threat_artifact,
    emit_threat_event,
)
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class XSSContextMapTab:
    """
    XSS Context Map 9.0
    -------------------
    • grouping по category + context_type + risk
    • heatmap 2.0 (context × risk)
    • ThreatConnector 9.0 (auto-risk, auto-ts, auto-hash)
    • Live‑режим 2.0 (throttled, safe)
    • GUI‑safe через UIQueueBridge 9.0
    """

    def __init__(
        self,
        ui: UIQueueBridge,
        gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        refresh_interval: float = 3.0,
    ):
        self.ui = ui
        self.gui_callback = gui_callback
        self.refresh_interval = max(0.5, float(refresh_interval))
        self._live_running = False

    # ============================================================
    # Safe GUI emit
    # ============================================================
    def _emit(self, key: str, payload: Any) -> None:
        if not self.gui_callback:
            return
        try:
            self.ui.call_ui(self.gui_callback, {key: payload})
        except Exception as e:
            print(f"[XSSContextMapTab] gui_callback error: {e}")

    # ============================================================
    # Load NDJSON artifacts
    # ============================================================
    def load_data(self) -> List[Dict[str, Any]]:
        try:
            data = load_reflected_responses()
            if not isinstance(data, list):
                print("[XSSContextMapTab] Некорректный формат NDJSON.")
                return []
            return data
        except Exception as e:
            print(f"[XSSContextMapTab] Ошибка загрузки данных: {e}")
            return []

    # ============================================================
    # Build context map (category → entries)
    # ============================================================
    def build_context_map(self, data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        ctx_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for raw in data:
            try:
                entry = enrich_threat_artifact(raw, module_name="XSSContextMap")
                category = entry.get("category", "unknown")
                ctx_map[category].append(entry)

                # ThreatConnector stream
                emit_threat_event(entry)

                # LiveAttackMonitor
                self._emit("xss_context_event", entry)

            except Exception as e:
                print(f"[XSSContextMapTab] normalize error: {e}")

        return dict(ctx_map)

    # ============================================================
    # Heatmap 2.0 (context × risk)
    # ============================================================
    def build_heatmap(self, data: List[Dict[str, Any]]):
        matrix = defaultdict(lambda: defaultdict(int))

        for r in data:
            ctx = (r.get("context") or "unknown").lower()
            risk = (r.get("risk") or "unknown").lower()
            matrix[ctx][risk] += 1

        heatmap = []
        for ctx, risks in matrix.items():
            for risk, count in risks.items():
                heatmap.append({
                    "context": ctx,
                    "risk": risk,
                    "count": count,
                })

        return heatmap

    # ============================================================
    # Main render
    # ============================================================
    def render(self) -> Dict[str, Any]:
        data = self.load_data()

        ctx_map = self.build_context_map(data)
        heatmap = self.build_heatmap(data)

        stats = {
            "total": len(data),
            "categories": len(ctx_map),
            "per_category": {k: len(v) for k, v in ctx_map.items()},
            "top_category": max(ctx_map, key=lambda k: len(ctx_map[k]), default=None),
        }

        payload = {
            "xss_context_map": ctx_map,
            "stats": stats,
            "heatmap": heatmap,
        }

        self._emit("xss_context_map", payload)
        self._emit("xss_heatmap", heatmap)

        return payload

    # ============================================================
    # Live‑mode 2.0
    # ============================================================
    def _live_loop(self):
        while self._live_running:
            try:
                self.render()
            except Exception as e:
                print(f"[XSSContextMapTab] live update error: {e}")
            time.sleep(self.refresh_interval)

    def start_live(self):
        if self._live_running:
            return
        self._live_running = True
        self.ui.post_bg(self._live_loop)

    def stop_live(self):
        self._live_running = False


# ============================================================
# XSSContextMapView — Tkinter-обгортка для XSSContextMapTab
# ============================================================
class XSSContextMapView(ttk.Frame):
    """
    Frame-обгортка навколо логіки XSSContextMapTab (сам контролер не є віджетом).
    За зразком AutoReconDashboardTab: власний UIQueueBridge + Text-вивід +
    кнопки Refresh / Live On / Live Off. Підключається як вкладка sidebar.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self._bridge = UIQueueBridge(self, poll_ms=80)
        self.mapper = XSSContextMapTab(ui=self._bridge, gui_callback=self._on_event)

        self._build_ui()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=6, pady=6)

        ttk.Button(top, text="🔄 Обновить", command=self.refresh).pack(side="left", padx=4)
        ttk.Button(top, text="▶ Live On", command=self.start_live).pack(side="left", padx=4)
        ttk.Button(top, text="⏹ Live Off", command=self.stop_live).pack(side="left", padx=4)
        ttk.Button(top, text="🧹 Очистить", command=self._clear).pack(side="left", padx=4)

        self._status = tk.StringVar(value="Готово")
        ttk.Label(top, textvariable=self._status).pack(side="right", padx=6)

        self.output = tk.Text(self, bg="#111", fg="#0ff", wrap="word", height=28)
        self.output.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self.output.tag_config("TITLE", foreground="#00eaff", font=("Segoe UI", 11, "bold"))
        self.output.tag_config("INFO", foreground="#faad14")

    # ---------------------------------------------------------
    # Actions
    # ---------------------------------------------------------
    def refresh(self):
        self._status.set("Оновлення…")
        self._append("\n[🔄] Оновлення XSS Context Map…\n", "INFO")
        # Не блокуємо GUI — читання NDJSON у фоні.
        self._bridge.post_bg(self.mapper.render)

    def start_live(self):
        self._append("\n[▶] Live-режим увімкнено.\n", "INFO")
        self._status.set("LIVE")
        self.mapper.start_live()

    def stop_live(self):
        self._append("\n[⏹] Live-режим вимкнено.\n", "INFO")
        self._status.set("Готово")
        self.mapper.stop_live()

    def _clear(self):
        self.output.delete("1.0", "end")

    # ---------------------------------------------------------
    # Callback з контролера (отримує {key: payload})
    # ---------------------------------------------------------
    def _on_event(self, data: Dict[str, Any]):
        for key, value in (data or {}).items():
            if key == "stats":
                self._append("\n=== 📊 XSS Context Map ===\n", "TITLE")
                try:
                    self._append(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
                except Exception:
                    self._append(str(value) + "\n")
                self._status.set(f"Артефактів: {value.get('total', '?')}")
            elif key == "heatmap":
                self._append("\n=== 🔥 Heatmap (context × risk) ===\n", "TITLE")
                for row in (value or []):
                    self._append(
                        f"  {row.get('context')} → {row.get('risk')} = {row.get('count')}\n"
                    )

    def _append(self, text: str, tag: Optional[str] = None):
        try:
            if tag:
                self.output.insert("end", text, tag)
            else:
                self.output.insert("end", text)
            self.output.see("end")
        except tk.TclError:
            pass

    # ---------------------------------------------------------
    # Cleanup
    # ---------------------------------------------------------
    def destroy(self):
        try:
            self.mapper.stop_live()
        except Exception:
            pass
        try:
            self._bridge.stop()
        except Exception:
            pass
        super().destroy()

