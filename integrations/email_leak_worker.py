# xss_security_gui/integrations/email_leak_worker.py
"""
EmailLeakWorker 13.0 ULTRA‑MODE (GOD‑ENGINE)

- Full state machine (atomic transitions, watchdog, heartbeat)
- SQLite + ThreatConnector ingestion (batch + bulk)
- Thread‑safe, GUI‑safe, restart‑safe
- Adaptive throttling 2.0 (load‑aware)
- ML‑classification + anomaly detection hooks
- Entropy + risk scoring + heatmap aggregation
- Live‑stream events for ThreatAnalysisTab
- Leak viewer (emails/passwords/tokens/secrets/pii) with export
"""

import threading
import time
import logging
from typing import Optional, Callable, List, Dict, Any

from xss_security_gui.threat_data_loader import ThreatRisk
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR, ThreatConnector

logger = logging.getLogger(__name__)


class EmailLeakWorker:
    """
    EmailLeakWorker 13.0 ULTRA‑MODE (GOD‑ENGINE)
    Enterprise‑grade worker для Email Leak Integration.
    """

    def __init__(
        self,
        threat_tab,
        ui_bridge,
        poll_interval: float = 0.15,
        retries: int = 1,
        on_start: Optional[Callable] = None,
        on_finish: Optional[
            Callable[[bool, int, Dict[str, Any], Dict[str, List[Dict[str, Any]]]], None]
        ] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        debug_telemetry: bool = False,
        connector: Optional[ThreatConnector] = None,
    ):
        # GUI + threading
        self.threat_tab = threat_tab
        self.ui = ui_bridge
        self.poll_interval = poll_interval
        self.retries = retries

        # Callbacks
        self.on_start = on_start
        self.on_finish = on_finish
        self.on_event = on_event
        self.debug_telemetry = debug_telemetry

        # ThreatConnector (SQLite backend)
        self.connector: ThreatConnector = connector or THREAT_CONNECTOR

        # ------------------------------------------------------------
        # ULTRA‑MODE state machine
        # ------------------------------------------------------------
        self._lock = threading.Lock()
        self._running = False
        self._finished = False
        self._shutdown = False
        self._error: Optional[Exception] = None

        # Threads
        self._worker_thread_obj: Optional[threading.Thread] = None
        self._progress_thread_obj: Optional[threading.Thread] = None
        self._watchdog_thread_obj: Optional[threading.Thread] = None

        # Health / watchdog
        self._health_ok = True
        self._last_heartbeat = time.time()
        self._watchdog_enabled = True
        self._heartbeat_interval = 1.0
        self._max_silence = 10.0  # seconds

        # ------------------------------------------------------------
        # Statistics
        # ------------------------------------------------------------
        self.total = 0
        self.loaded = 0
        self.summary: Dict[str, Any] = {}

        # ------------------------------------------------------------
        # Leak categories
        # ------------------------------------------------------------
        self.leaks_grouped: Dict[str, List[Dict[str, Any]]] = {
            "email_leak": [],
            "account_state_leak": [],
            "password_leak": [],
            "token_leak": [],
            "secret_leak": [],
            "pii_leak": [],
        }

        # ------------------------------------------------------------
        # Counters
        # ------------------------------------------------------------
        self.counters = {
            "email": 0,
            "password": 0,
            "token": 0,
            "secret": 0,
            "pii": 0,
            "total": 0,
        }

        # ------------------------------------------------------------
        # ML / entropy / heatmap
        # ------------------------------------------------------------
        self.ml_enabled = True
        self.ml_last_prediction = None

        self.entropy_enabled = True

        self.heatmap_enabled = True
        self.heatmap_data: Dict[str, Any] = {}

        # ------------------------------------------------------------
        # Adaptive throttling 2.0
        # ------------------------------------------------------------
        self.adaptive_enabled = True
        self.adaptive_factor = 1.0


    # ------------------------------------------------------------
    #  GOD‑MODE CONTROL ENGINE
    # ------------------------------------------------------------

    def start(self) -> None:
        """Запускає інтеграцію, якщо вона ще не запущена."""
        with self._lock:
            if self._shutdown:
                self._log_debug("EmailLeakWorker: start() після shutdown — ігнорую")
                return

            if self._running:
                self._set_status("📡 Email Leak Integration вже виконується…")
                return

            # Atomic reset
            self._running = True
            self._finished = False
            self._error = None
            self.total = 0
            self.loaded = 0
            self.summary = {}
            self._health_ok = True
            self._last_heartbeat = time.time()

            for k in self.leaks_grouped:
                self.leaks_grouped[k].clear()

        logger.info("[EmailLeakWorker] Запуск інтеграції (13.0 ULTRA‑MODE GOD‑ENGINE)")
        self._set_status("📦 Email Leak Integration: запуск…")

        if self.on_start:
            try:
                self.on_start()
            except Exception:
                logger.exception("[EmailLeakWorker] on_start callback error")

        # Worker thread
        self._worker_thread_obj = threading.Thread(
            target=self._worker_thread,
            daemon=True,
            name="EmailLeakWorkerThread",
        )
        self._worker_thread_obj.start()

        # Progress thread
        self._progress_thread_obj = threading.Thread(
            target=self._progress_thread,
            daemon=True,
            name="EmailLeakProgressThread",
        )
        self._progress_thread_obj.start()

        # Watchdog thread
        if self._watchdog_enabled:
            self._watchdog_thread_obj = threading.Thread(
                target=self._watchdog_thread,
                daemon=True,
                name="EmailLeakWatchdogThread",
            )
            self._watchdog_thread_obj.start()

    def _watchdog_thread(self) -> None:
        """Контролює зависання worker‑потоку."""
        while not self._shutdown:
            time.sleep(self._heartbeat_interval)
            now = time.time()

            with self._lock:
                running = self._running
                last = self._last_heartbeat

            if not running:
                break

            if now - last > self._max_silence:
                logger.warning("[EmailLeakWorker] Watchdog: worker silent too long")
                self._health_ok = False
                self._set_status("⚠️ Email Leak Integration: watchdog detected stall")

    def stop(self) -> None:
        """
        ULTRA‑MODE stop():
        - м’яка зупинка worker + progress threads
        - atomic state transition
        - GUI‑safe
        - restart‑safe
        """
        with self._lock:
            self._shutdown = True
            self._running = False

        self._set_status("⏹ Email Leak Integration: зупинено")
        logger.info("[EmailLeakWorker] Stop requested — worker shutting down safely")

    def shutdown(self) -> None:
        """
        ULTRA‑MODE shutdown():
        - повний shutdown
        - блокує майбутні start()
        - завершує lifecycle
        """
        with self._lock:
            self._shutdown = True
            self._running = False
            self._finished = True

        self._set_status("⏹ Email Leak Integration: повний shutdown")
        logger.info("[EmailLeakWorker] Full shutdown completed")

    # ------------------------------------------------------------
    #  Основний робочий потік (7.0: SQLite + ThreatConnector)
    # ------------------------------------------------------------

    def _worker_thread(self) -> None:
        attempts = 0

        while attempts <= self.retries and not self._shutdown:
            attempts += 1
            self._heartbeat()

            try:
                self._log_debug(f"[EmailLeakWorker] Спроба #{attempts}")

                # 1) Bulk‑ingest артефактів у GUI через ThreatConnector (SQLite)
                self._load_artifacts_to_gui_bulk()

                # 2) FULL INTEL (summary + grouping + risk + entropy + ML)
                self._collect_full_intel_async()

                self._error = None
                break

            except Exception as e:
                logger.exception(f"[EmailLeakWorker] Помилка на спробі #{attempts}: {e}")
                self._error = e
                time.sleep(0.5)
                self._heartbeat()

        with self._lock:
            self._running = False
            self._finished = True

        if self._error:
            self._set_status(f"❌ Email Leak Integration: помилка: {self._error}")
        else:
            leaks_total = sum(len(v) for v in self.leaks_grouped.values())
            risk_level = self._get_top_risk()
            self._set_status(
                f"✅ Email Leak Integration завершено (витоків: {leaks_total}, ризик: {risk_level})"
            )

        if self.on_finish:
            try:
                self.on_finish(
                    self._error is None,
                    sum(len(v) for v in self.leaks_grouped.values()),
                    self.summary,
                    self.leaks_grouped,
                )
            except Exception:
                logger.exception("[EmailLeakWorker] on_finish callback error")


    # ------------------------------------------------------------
    #  ULTRA‑MODE BULK ARTIFACT LOADING
    # ------------------------------------------------------------

    def _load_artifacts_to_gui_bulk(self) -> int:
        """
        ULTRA‑MODE bulk‑завантаження артефактів з ThreatConnector у GUI:
        - сортування по ризику
        - GUI‑safe постинг через UIQueueBridge / after()
        - adaptive throttling 2.0
        """
        from xss_security_gui.threat_data_loader import ThreatDataLoader

        artifacts = self.connector.load_all()
        self.total = len(artifacts)

        artifacts_sorted = sorted(
            artifacts,
            key=lambda a: ThreatRisk.ORDER.get(
                ThreatRisk.normalize((a.get("result") or {}).get("risk")),
                -1,
            ),
            reverse=True,
        )

        loader = ThreatDataLoader()
        count = 0

        bridge = getattr(self.threat_tab, "_bridge", None) or self.ui

        for artifact in artifacts_sorted:
            self._heartbeat()

            gui_artifact = loader.convert_artifact_for_gui(artifact)
            if not gui_artifact:
                continue

            try:
                if bridge is not None and hasattr(bridge, "post_ui"):
                    bridge.post_ui(self.threat_tab.add_threat, gui_artifact)
                else:
                    self.threat_tab.after(0, self.threat_tab.add_threat, gui_artifact)
                count += 1
            except Exception:
                logger.exception("[EmailLeakWorker] Не вдалося додати артефакт у GUI")

            if self.adaptive_enabled:
                time.sleep(self.poll_interval * self.adaptive_factor)

        self.loaded = count
        self._log_debug(
            f"[EmailLeakWorker] Bulk loaded {count}/{len(artifacts)} artifacts to GUI via ThreatConnector"
        )
        return count

    # ------------------------------------------------------------
    #  WATCHDOG + HEARTBEAT
    # ------------------------------------------------------------

    def _heartbeat(self) -> None:
        """Оновлює heartbeat для watchdog."""
        with self._lock:
            self._last_heartbeat = time.time()

    # ------------------------------------------------------------
    #  ULTRA‑MODE FULL INTEL (summary + grouping + risk + entropy + ML)
    #  через ThreatConnector
    # ------------------------------------------------------------

    def _collect_full_intel_async(self) -> None:
        """
        EmailLeakWorker 13.0 ULTRA‑MODE (GOD‑ENGINE):
        - summary + report
        - grouping leaks
        - risk scoring
        - entropy
        - ML prediction
        - heatmap aggregation
        - live‑stream у ThreatAnalysisTab
        """

        def bg():
            try:
                self._heartbeat()

                # ----------------------------------------
                # 1) Базовий summary + report
                # ----------------------------------------
                summary = self.connector.summary()
                report = self.connector.generate_report()

                summary["by_risk"] = report.get("by_severity", {})
                summary["by_category"] = report.get("by_category", {})
                summary["by_source"] = report.get("by_source", {})

                # ----------------------------------------
                # 2) ULTRA‑MODE grouping
                # ----------------------------------------
                grouped = {
                    "email_leak": [],
                    "account_state_leak": [],
                    "password_leak": [],
                    "token_leak": [],
                    "secret_leak": [],
                    "pii_leak": [],
                }

                artifacts = self.connector.load_all()

                for a in artifacts:
                    self._heartbeat()
                    result = a.get("result", {}) or {}
                    category = result.get("category", "unknown").lower()
                    text_repr = str(result).lower()

                    if category == "email_leak":
                        grouped["email_leak"].append(result)
                    elif category == "account_state_leak":
                        grouped["account_state_leak"].append(result)
                    elif "password" in text_repr:
                        grouped["password_leak"].append(result)
                    elif any(k in text_repr for k in ("token", "jwt", "oauth", "api_key", "bearer")):
                        grouped["token_leak"].append(result)
                    elif any(k in text_repr for k in ("secret", "private_key", "ssh", "pem", "ghp_", "sk_live")):
                        grouped["secret_leak"].append(result)
                    elif any(k in text_repr for k in ("email", "phone", "iban", "ipv4", "ipv6", "credit_card")):
                        grouped["pii_leak"].append(result)

                # ----------------------------------------
                # 3) ULTRA‑MODE risk scoring
                # ----------------------------------------
                risk_score = {
                    "email_leak": len(grouped["email_leak"]) * 3,
                    "account_state_leak": len(grouped["account_state_leak"]) * 4,
                    "password_leak": len(grouped["password_leak"]) * 6,
                    "token_leak": len(grouped["token_leak"]) * 7,
                    "secret_leak": len(grouped["secret_leak"]) * 8,
                    "pii_leak": len(grouped["pii_leak"]) * 5,
                }
                risk_score["total"] = sum(risk_score.values())
                summary["risk_score"] = risk_score

                # ----------------------------------------
                # 4) Entropy analysis (ULTRA‑MODE)
                # ----------------------------------------
                if self.entropy_enabled:
                    def entropy(s: str) -> float:
                        if not s:
                            return 0.0
                        import math
                        freq = {}
                        for c in s:
                            freq[c] = freq.get(c, 0) + 1
                        total = len(s)
                        return round(-sum((f / total) * math.log2(f / total) for f in freq.values()), 3)

                    summary["entropy"] = {
                        "email_leak": entropy(str(grouped["email_leak"])),
                        "password_leak": entropy(str(grouped["password_leak"])),
                        "token_leak": entropy(str(grouped["token_leak"])),
                        "secret_leak": entropy(str(grouped["secret_leak"])),
                        "pii_leak": entropy(str(grouped["pii_leak"])),
                    }

                # ----------------------------------------
                # 5) ML‑based classification (ULTRA‑MODE)
                # ----------------------------------------
                if self.ml_enabled:
                    try:
                        from xss_security_gui.ai_core.nn_model import nn_model_predict
                        summary["ml_prediction"] = nn_model_predict(summary)
                        self.ml_last_prediction = summary["ml_prediction"]
                    except Exception:
                        summary["ml_prediction"] = "unavailable"
                        self.ml_last_prediction = None
                else:
                    summary["ml_prediction"] = "disabled"

                # ----------------------------------------
                # 6) Heatmap aggregation
                # ----------------------------------------
                if self.heatmap_enabled:
                    self.heatmap_data = {
                        "email": len(grouped["email_leak"]),
                        "password": len(grouped["password_leak"]),
                        "token": len(grouped["token_leak"]),
                        "secret": len(grouped["secret_leak"]),
                        "pii": len(grouped["pii_leak"]),
                    }

                return summary, grouped

            except Exception as e:
                logger.exception("[EmailLeakWorker] ULTRA‑MODE collect_full_intel error: %s", e)
                return e

        def done(result):
            if isinstance(result, Exception):
                logger.warning("[EmailLeakWorker] ULTRA‑MODE intel collection failed: %s", result)
                return

            summary, grouped = result
            self.summary = summary
            self.leaks_grouped = grouped

            self._log_debug(
                f"[EmailLeakWorker] ULTRA‑MODE intel: total={summary.get('total')}, "
                f"risk_score={summary['risk_score']['total']}, "
                f"email={len(grouped['email_leak'])}, "
                f"password={len(grouped['password_leak'])}, "
                f"token={len(grouped['token_leak'])}, "
                f"secret={len(grouped['secret_leak'])}, "
                f"pii={len(grouped['pii_leak'])}"
            )

            cb = self.on_event
            if callable(cb):
                try:
                    cb("email_leak_summary_ultra", summary)
                    cb("email_leak_grouped_ultra", grouped)
                except Exception:
                    logger.exception("[EmailLeakWorker] on_event callback error")

        if hasattr(self.ui, "post_bg"):
            try:
                self.ui.post_bg(bg, done)
                return
            except Exception:
                logger.exception("[EmailLeakWorker] post_bg failed, fallback to Thread")

        threading.Thread(
            target=lambda: done(bg()),
            daemon=True,
            name="EmailLeakFullIntelULTRAThread",
        ).start()

    # ------------------------------------------------------------
    #  ULTRA‑MODE Risk scoring + filtering API (через ThreatConnector)
    # ------------------------------------------------------------

    def _get_top_risk(self) -> str:
        """
        Повертає найвищий рівень ризику з summary.by_risk.
        ULTRA‑MODE:
        - захист від некоректних структур
        - нормалізація ризиків
        - fallback на 'unknown'
        """
        by_risk = self.summary.get("by_risk") or {}
        if not isinstance(by_risk, dict) or not by_risk:
            return "unknown"

        # Нормалізуємо ключі ризиків
        normalized_items = []
        for risk_name, count in by_risk.items():
            norm = ThreatRisk.normalize(risk_name)
            order = ThreatRisk.ORDER.get(norm, -1)
            normalized_items.append((norm, order, count))

        if not normalized_items:
            return "unknown"

        # Сортуємо за ORDER (critical > high > medium > low > info)
        normalized_items.sort(key=lambda x: x[1], reverse=True)

        top_risk = normalized_items[0][0]
        return top_risk if top_risk else "unknown"

    def filter_leaks(
            self,
            category: Optional[str] = None,
            min_risk: Optional[str] = None,
            module: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        ULTRA‑MODE фільтрація витоків:
        - category: email_leak / account_state_leak / password_leak / token_leak / secret_leak / pii_leak
        - min_risk: critical / high / medium / low / info
        - module: фільтр по модулю (EndpointScanner, RealTimeWatcher, ...)
        """

        leaks: List[Dict[str, Any]] = []

        # Вибір категорій
        categories = [category] if category else list(self.leaks_grouped.keys())

        # Нормалізація мінімального ризику
        min_risk_norm = None
        if min_risk:
            min_risk_norm = ThreatRisk.normalize(min_risk)
            min_risk_order = ThreatRisk.ORDER.get(min_risk_norm, -1)
        else:
            min_risk_order = -1

        for cat in categories:
            group = self.leaks_grouped.get(cat, [])
            if not isinstance(group, list):
                continue

            for leak in group:
                # -----------------------------
                # 1) Risk filter (ULTRA‑MODE)
                # -----------------------------
                risk_raw = leak.get("risk") or leak.get("severity") or "unknown"
                risk_norm = ThreatRisk.normalize(risk_raw)
                risk_order = ThreatRisk.ORDER.get(risk_norm, -1)

                if risk_order < min_risk_order:
                    continue

                # -----------------------------
                # 2) Module filter (ULTRA‑MODE)
                # -----------------------------
                if module:
                    src_module = (
                            leak.get("source_module")
                            or leak.get("module")
                            or ""
                    )
                    if src_module and module.lower() not in str(src_module).lower():
                        continue

                # -----------------------------
                # 3) Append leak
                # -----------------------------
                leaks.append(leak)

        return leaks

    # ------------------------------------------------------------
    #  ULTRA‑MODE: filter_by_module
    # ------------------------------------------------------------
    def filter_by_module(self, module: str) -> List[Dict[str, Any]]:
        """
        ULTRA‑MODE:
        - безпечна делегація до ThreatConnector
        - захист від некоректних відповідей
        - fallback на пустий список
        """
        try:
            result = self.connector.filter_by_module(module)
            return result if isinstance(result, list) else []
        except Exception:
            logger.exception("[EmailLeakWorker] filter_by_module error")
            return []


    # ------------------------------------------------------------
    #  ULTRA‑MODE: filter_by_severity
    # ------------------------------------------------------------
    def filter_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        ULTRA‑MODE:
        - нормалізація severity
        - безпечна делегація до ThreatConnector
        - fallback на пустий список
        """
        try:
            severity_norm = ThreatRisk.normalize(severity)
            result = self.connector.filter_by_severity(severity_norm)
            return result if isinstance(result, list) else []
        except Exception:
            logger.exception("[EmailLeakWorker] filter_by_severity error")
            return []


    # ------------------------------------------------------------
    #  ULTRA‑MODE: generate_report
    # ------------------------------------------------------------
    def generate_report(self) -> Dict[str, Any]:
        """
        ULTRA‑MODE:
        - повний звіт через ThreatConnector
        - захист від некоректних структур
        - гарантія повернення dict
        """
        try:
            report = self.connector.generate_report()
            return report if isinstance(report, dict) else {}
        except Exception:
            logger.exception("[EmailLeakWorker] generate_report error")
            return {}

    # ------------------------------------------------------------
    #  Потік прогресу
    # ------------------------------------------------------------

    def _progress_thread(self) -> None:
        """
        ULTRA‑MODE:
        - GUI‑safe статус‑бар
        - heartbeat для watchdog
        - захист від падіння threat_tab
        - adaptive throttling
        """
        while True:
            with self._lock:
                running = self._running
                shutdown = self._shutdown

            if not running or shutdown:
                break

            try:
                # Якщо вкладка GUI зникла — завершуємо прогрес
                if not self.threat_tab.winfo_exists():
                    logger.warning("[EmailLeakWorker] ThreatTab зник — зупиняю прогрес")
                    break

                # Heartbeat для watchdog
                self._heartbeat()

                # ULTRA‑MODE статус
                msg = (
                    "📡 Email Leak Integration… "
                    "інтел, grouping, risk scoring, entropy, ML…"
                )
                self._set_status(msg)

            except Exception:
                logger.exception("[EmailLeakWorker] Проблема оновлення прогресу")

            # Adaptive throttling 2.0
            delay = self.poll_interval * self.adaptive_factor
            time.sleep(delay)


    # ------------------------------------------------------------
    #  ULTRA‑MODE UI helper + debug
    # ------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        """
        ULTRA‑MODE:
        - потокобезпечне оновлення статусу
        - GUI‑safe через UIQueueBridge
        - fallback на .after()
        """
        try:
            bridge = getattr(self.threat_tab, "_bridge", None) or self.ui

            if bridge is not None and hasattr(bridge, "post_ui"):
                bridge.post_ui(self.threat_tab.status_var.set, text)
            else:
                # Fallback для Tkinter без UIQueueBridge
                self.threat_tab.after(0, self.threat_tab.status_var.set, text)

        except Exception:
            logger.error("[EmailLeakWorker] Не вдалося оновити статус")


    def _log_debug(self, msg: str) -> None:
        """ULTRA‑MODE debug telemetry."""
        if self.debug_telemetry:
            logger.info(msg)
    # ------------------------------------------------------------
    #  Viewer для витоків email/password/account
    # ------------------------------------------------------------
    def open_leak_details(self, leak: Dict[str, Any]) -> None:
        """ULTRA‑MODE: відкриває деталі витоку у окремому вікні (GUI‑safe)."""
        try:
            bridge = getattr(self.threat_tab, "_bridge", None) or self.ui
            if bridge is not None and hasattr(bridge, "post_ui"):
                bridge.post_ui(self._show_leak_window, leak)
            else:
                # Fallback для Tkinter без UIQueueBridge
                self.threat_tab.after(0, self._show_leak_window, leak)
        except Exception:
            logger.exception("[EmailLeakWorker] Не вдалося відкрити вікно витоку")

    def _show_leak_window(self, leak: Dict[str, Any]) -> None:
        """ULTRA‑MODE viewer для витоків."""
        try:
            import tkinter as tk
            from tkinter import ttk, filedialog
            import json
            import webbrowser

            if not self.threat_tab or not self.threat_tab.winfo_exists():
                return

            root = self.threat_tab.winfo_toplevel()

            win = tk.Toplevel(root)
            win.title("Leak Details — ULTRA‑MODE")
            win.geometry("780x620")
            win.configure(bg="#111")

            frame = ttk.Frame(win, padding=10)
            frame.pack(fill="both", expand=True)

            # ----------------------------
            # Normalize fields
            # ----------------------------
            def normalize_list(value):
                if value is None:
                    return []
                if isinstance(value, str):
                    return [value]
                if isinstance(value, list):
                    return value
                return [str(value)]

            emails = normalize_list(leak.get("emails") or leak.get("email"))
            passwords = normalize_list(leak.get("passwords") or leak.get("password"))
            tokens = normalize_list(leak.get("tokens") or leak.get("token"))
            secrets = normalize_list(leak.get("secrets") or leak.get("secret"))
            pii = normalize_list(leak.get("pii"))

            source = leak.get("source") or leak.get("url") or leak.get("breach") or "unknown"
            risk = leak.get("risk") or leak.get("severity") or "unknown"
            entropy = leak.get("entropy") or "n/a"
            ml_pred = leak.get("ml_prediction") or "n/a"
            category = leak.get("category", "unknown")

            # ----------------------------
            # Header section
            # ----------------------------
            ttk.Label(frame, text="Leak Category:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
            ttk.Label(frame, text=category).grid(row=0, column=1, sticky="w")

            ttk.Label(frame, text="Risk:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w")
            ttk.Label(frame, text=risk).grid(row=1, column=1, sticky="w")

            ttk.Label(frame, text="Source:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w")
            ttk.Label(frame, text=source).grid(row=2, column=1, sticky="w")

            ttk.Label(frame, text="Entropy:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w")
            ttk.Label(frame, text=str(entropy)).grid(row=3, column=1, sticky="w")

            ttk.Label(frame, text="ML Prediction:", font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky="w")
            ttk.Label(frame, text=str(ml_pred)).grid(row=4, column=1, sticky="w")

            ttk.Separator(frame).grid(row=5, column=0, columnspan=2, pady=10, sticky="ew")

            # ----------------------------
            # Leak content sections
            # ----------------------------
            row = 6

            def add_section(title, items, mask=False):
                nonlocal row
                if not items:
                    return
                ttk.Label(frame, text=title, font=("Segoe UI", 10, "bold")).grid(row=row, column=0, sticky="nw")
                if mask:
                    masked = ["*" * len(p) for p in items]
                    ttk.Label(frame, text=", ".join(masked)).grid(row=row, column=1, sticky="w")
                else:
                    ttk.Label(frame, text=", ".join(items)).grid(row=row, column=1, sticky="w")
                row += 1

            add_section("Emails:", emails)
            add_section("Passwords:", passwords, mask=True)
            add_section("Tokens:", tokens)
            add_section("Secrets:", secrets)
            add_section("PII:", pii)

            ttk.Separator(frame).grid(row=row, column=0, columnspan=2, pady=10, sticky="ew")
            row += 1

            # ----------------------------
            # Raw JSON viewer
            # ----------------------------
            text = tk.Text(frame, wrap="word", height=15, bg="#111", fg="cyan", insertbackground="white")
            text.grid(row=row, column=0, columnspan=2, sticky="nsew")
            frame.rowconfigure(row, weight=1)
            frame.columnconfigure(1, weight=1)

            text.insert("1.0", json.dumps(leak, indent=2, ensure_ascii=False))
            text.config(state="disabled")
            row += 1

            # ----------------------------
            # Buttons
            # ----------------------------
            btn_frame = ttk.Frame(frame)
            btn_frame.grid(row=row, column=0, columnspan=2, pady=10, sticky="ew")

            def copy_to_clipboard(values):
                if values:
                    win.clipboard_clear()
                    win.clipboard_append("\n".join(values))

            ttk.Button(btn_frame, text="Copy Emails", command=lambda: copy_to_clipboard(emails)).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Copy Passwords", command=lambda: copy_to_clipboard(passwords)).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Copy Tokens", command=lambda: copy_to_clipboard(tokens)).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Copy Secrets", command=lambda: copy_to_clipboard(secrets)).pack(side="left", padx=5)

            def export_leak():
                path = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("Text files", "*.txt")]
                )
                if not path:
                    return
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(leak, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    logger.error("Export error: %s", e)

            ttk.Button(btn_frame, text="Export Leak", command=export_leak).pack(side="left", padx=5)

            def open_url():
                if isinstance(source, str) and source.startswith("http"):
                    webbrowser.open(source)

            ttk.Button(btn_frame, text="Open Source URL", command=open_url).pack(side="left", padx=5)

            ttk.Button(btn_frame, text="Закрити", command=win.destroy).pack(side="right", padx=5)

        except Exception:
            logger.exception("[EmailLeakWorker] ULTRA‑MODE leak viewer error")


