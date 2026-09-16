# xss_security_gui/threat_tab.py

from __future__ import annotations

import json
import math
import threading
import time
from typing import Any, Dict, List
from datetime import datetime, UTC

import tkinter as tk
from tkinter import ttk, filedialog

from xss_security_gui.auto_recon.user_tracker import get_user_tracker
from xss_security_gui.auto_recon.core_logger import get_logger
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.threat_data_loader import ThreatDataLoader
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.utils.pii_aggregator import (
    PII_FIELD_LABELS,
    aggregate_pii_from_crawler,
    build_email_leak_artifact,
    flatten_email_leak_rows,
    merge_pii_dicts,
    pii_has_data,
)


class ThreatAnalysisTab(ttk.Frame):
    """
    Threat Intel Viewer ULTRA 9.0 + SSRF Burp-Style
    ...
    """

    L1_LIMIT = 500  # GUI-safe limit
    L1_DEBOUNCE_MS = 200

    def __init__(self, parent: tk.Misc, result_queue=None) -> None:
        super().__init__(parent)

        # === Red Team Core Components ===
        self.user_tracker = get_user_tracker()
        self.logger = get_logger("ThreatAnalysisTab")

        # === ThreatConnector reference ===
        self.threat_connector = THREAT_CONNECTOR

        # === LiveAttackMonitor event queue ===
        # GUI передає LIVE_MONITOR_QUEUE глобально
        try:
            from xss_security_gui.threat_analysis.threat_connector import LIVE_MONITOR_QUEUE
            self._event_queue = LIVE_MONITOR_QUEUE
        except Exception:
            self._event_queue = None

        # === Timestamp helper ===
        self._now = lambda: datetime.now(UTC)

        # === Shared queue for CombatCrawler + RealTimeWatcher + GUI ===
        self.result_queue = result_queue

        self.offset = 0
        self.total_count = 0
        self._last_render_ts = 0
        self._reload_lock = threading.Lock()
        self._bridge = UIQueueBridge(self, poll_ms=50)
        self._email_leak_pii: Dict[str, List[str]] = {}
        self._email_leak_rows: List[Dict[str, str]] = []
        self._ssrf_heatmap: Dict[str, int] = {}

        # ============================================================
        # Верхняя панель
        # ============================================================
        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)

        btn_ssrf = ttk.Button(top, text="⚡ SSRF Attack", command=self._attack_ssrf)
        btn_ssrf.pack(side="left", padx=5)

        self.btn_pivot = ttk.Button(top, text="⚡ SSRF Auto‑Pivot", command=self._ssrf_auto_pivot)
        self.btn_pivot.pack(side="left", padx=5)

        ttk.Button(top, text="🔄 Обновить", command=self.reload_summary).pack(side="left", padx=5)
        ttk.Button(top, text="🧹 Очистить", command=self.clear).pack(side="left")
        ttk.Button(top, text="💾 Экспорт JSON", command=self.export_json).pack(side="left", padx=5)

        ttk.Button(top, text="➕ Expand All", command=self.expand_all).pack(side="left", padx=5)
        ttk.Button(top, text="➖ Collapse All", command=self.collapse_all).pack(side="left")
        ttk.Button(top, text="🔥 SSRF Heatmap", command=self.show_ssrf_heatmap).pack(side="left", padx=5)

        ttk.Label(top, text="Модуль:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar()
        self.filter_box = ttk.Combobox(top, textvariable=self.filter_var, width=20, state="readonly")
        self.filter_box.pack(side="left")
        self.filter_box.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

        ttk.Label(top, text="Поиск:").pack(side="left", padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=25)
        search_entry.pack(side="left")
        search_entry.bind("<Return>", lambda e: self.apply_search())
        ttk.Button(top, text="🔍", command=self.apply_search).pack(side="left")

        # 🔍 Статус RealTimeWatcher
        self.watcher_status_var = tk.StringVar(value="RealTimeWatcher: idle")
        ttk.Label(top, textvariable=self.watcher_status_var).pack(side="left", padx=10)

        # Кнопки пагінації
        pag_frame = ttk.Frame(self)
        pag_frame.pack(fill="x", pady=3)

        ttk.Button(pag_frame, text="⬅ Prev 500", command=self.prev_page).pack(side="left", padx=5)
        ttk.Button(pag_frame, text="Next 500 ➡", command=self.next_page).pack(side="left", padx=5)

        self.page_info = tk.StringVar(value="Page 1")
        ttk.Label(pag_frame, textvariable=self.page_info).pack(side="left", padx=10)
        self.after(500, self.reload_summary)

        # ============================================================
        # Summary (верхняя панель)
        # ============================================================
        self.text_widget = tk.Text(self, height=8, bg="#111", fg="#0f0")
        self.text_widget.pack(fill="x", padx=5, pady=5)

        # ============================================================
        # Email Leak / PII
        # ============================================================
        leak_frame = ttk.LabelFrame(self, text="📧 Email Leak / PII")
        leak_frame.pack(fill="both", expand=False, padx=5, pady=(0, 5))

        self.email_leak_summary = tk.StringVar(value="Нет данных — запустите краулинг или RealTimeWatcher")
        ttk.Label(leak_frame, textvariable=self.email_leak_summary).pack(anchor="w", padx=5, pady=2)

        leak_table_frame = ttk.Frame(leak_frame)
        leak_table_frame.pack(fill="both", expand=True, padx=5, pady=2)

        leak_scroll = ttk.Scrollbar(leak_table_frame, orient="vertical")
        leak_scroll.pack(side="right", fill="y")
        self.email_leak_tree = ttk.Treeview(
            leak_table_frame,
            columns=("category", "value", "url"),
            show="headings",
            height=8,
            yscrollcommand=leak_scroll.set,
        )
        self.email_leak_tree.heading("category", text="Категория")
        self.email_leak_tree.heading("value", text="Значение")
        self.email_leak_tree.heading("url", text="Источник (URL)")
        self.email_leak_tree.column("category", width=180, anchor="w")
        self.email_leak_tree.column("value", width=320, anchor="w")
        self.email_leak_tree.column("url", width=280, anchor="w")
        self.email_leak_tree.pack(side="left", fill="both", expand=True)
        leak_scroll.config(command=self.email_leak_tree.yview)
        self.email_leak_tree.tag_configure("critical", foreground="#ff6b6b")
        self.email_leak_tree.tag_configure("high", foreground="#ffb347")
        self.email_leak_tree.tag_configure("info", foreground="#7ec8e3")

        # ============================================================
        # Account Leak / Credentials
        # ============================================================
        account_frame = ttk.LabelFrame(self, text="👤 Account Leak / Credentials")
        account_frame.pack(fill="both", expand=False, padx=5, pady=(0, 5))

        self.account_leak_summary = tk.StringVar(value="Нет данных — запустите сканирование")
        ttk.Label(account_frame, textvariable=self.account_leak_summary).pack(anchor="w", padx=5, pady=2)

        acc_table_frame = ttk.Frame(account_frame)
        acc_table_frame.pack(fill="both", expand=True, padx=5, pady=2)

        acc_scroll = ttk.Scrollbar(acc_table_frame, orient="vertical")
        acc_scroll.pack(side="right", fill="y")

        self.account_leak_tree = ttk.Treeview(
            acc_table_frame,
            columns=("username", "email", "password", "phone", "credit_card", "status", "url", "risk"),
            show="headings",
            height=8,
            yscrollcommand=acc_scroll.set,
        )

        self.account_leak_tree.heading("username", text="Логин")
        self.account_leak_tree.heading("email", text="Email")
        self.account_leak_tree.heading("password", text="Пароль")
        self.account_leak_tree.heading("phone", text="Телефон")
        self.account_leak_tree.heading("credit_card", text="Карта")
        self.account_leak_tree.heading("status", text="Статус")
        self.account_leak_tree.heading("url", text="Источник (URL)")
        self.account_leak_tree.heading("risk", text="Риск")

        self.account_leak_tree.pack(side="left", fill="both", expand=True)
        acc_scroll.config(command=self.account_leak_tree.yview)

        self.account_leak_tree.tag_configure("critical", foreground="#ff4d4d", font=("TkDefaultFont", 9, "bold"))
        self.account_leak_tree.tag_configure("high", foreground="#ff9900")
        self.account_leak_tree.tag_configure("info", foreground="#66ccff")
        self._account_leak_rows: List[Dict[str, str]] = []

        self.scrollbar = ttk.Scrollbar(self, orient="vertical")
        self.scrollbar.pack(side="right", fill="y")

        self.tree = ttk.Treeview(
            self,
            columns=("detail",),
            show="tree headings",
            yscrollcommand=self.scrollbar.set,
        )
        self.tree.heading("#0", text="Ключ")
        self.tree.heading("detail", text="Значение")

        self.tree.column("#0", width=350, anchor="w")
        self.tree.column("detail", width=550, anchor="w")

        self.tree.tag_configure("critical", foreground="#ff4d4d", font=("TkDefaultFont", 9, "bold"))
        self.tree.tag_configure("high", foreground="#ff9900")
        self.tree.tag_configure("info", foreground="#66ccff")

        self.tree.pack(fill="both", expand=True)
        self.scrollbar.config(command=self.tree.yview)

        self.tree.bind("<Control-Return>", lambda e: self._attack_ssrf())
        self.tree.bind("<Control-KP_Enter>", lambda e: self._attack_ssrf())
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Копировать ключ", command=self._copy_selected_key)
        self.menu.add_command(label="Копировать значение", command=self._copy_selected_value)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # ============================================================
        # Статус
        # ============================================================
        self.status_var = tk.StringVar(value="Готово")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status.pack(side="bottom", fill="x")

        # Автообновление при старте
        self.after(500, self.reload_summary)

    # ============================================================
    # RealTimeWatcher status update (thread-safe via UIQueueBridge)
    # ============================================================
    def update_watcher_status(self, status: str) -> None:
        try:
            self.watcher_status_var.set(f"RealTimeWatcher: {status}")
        except Exception:
            pass

    # ============================================================
    # Combat Event Reader — читает события из CombatCrawler
    # ============================================================
    def start_combat_event_reader(self):
        """Запускает поток, который читает события из result_queue."""
        if not self.result_queue:
            return

        def _reader():
            while self.winfo_exists():
                try:
                    event = self.result_queue.get(timeout=0.5)
                except Exception:
                    continue

                try:
                    self._bridge.post_ui(lambda ev=event: self._handle_combat_event(ev))
                except Exception as e:
                    self.status_var.set(f"Ошибка обработки события: {e}")

        threading.Thread(target=_reader, daemon=True).start()

    def _handle_combat_event(self, event: Dict[str, Any]):
        """Обрабатывает события CombatCrawler и добавляет их в Threat Intel."""
        etype = event.get("type")
        data = event.get("data", {})
        ts = event.get("timestamp", time.time())

        # Нормализованный артефакт
        artifact = {
            "module": f"combat::{etype}",
            "target": data.get("target") or "combat",
            "timestamp": ts,
            "category": "combat_event",
            "risk": "info",
            "result": data,
        }

        # Специальные категории
        if etype == "crawl_complete":
            artifact["category"] = "combat_crawl"
            artifact["risk"] = "info"

        elif etype == "analysis_complete":
            artifact["category"] = "combat_analysis"
            artifact["risk"] = "info"

        elif etype == "attacks_complete":
            artifact["category"] = "combat_attacks"
            artifact["risk"] = (
                "high" if data.get("critical_severity", 0) > 0 else
                "medium" if data.get("total_vulnerable", 0) > 0 else
                "info"
            )

        elif etype == "report_saved":
            artifact["category"] = "combat_report"
            artifact["risk"] = "info"

        elif etype == "combat_complete":
            artifact["category"] = "combat_complete"
            artifact["risk"] = "high" if data.get("vulnerability_summary", {}).get("critical", 0) else "info"

        # Добавляем в Threat Intel
        self.add_threat(artifact)

    # ============================================================
    # Вспомогательные методы
    # ============================================================
    def _to_str(self, value: Any) -> str:
        """Безопасное преобразование значения в строку с ограничением длины."""
        try:
            text = str(value)
        except Exception:
            text = repr(value)
        return text if len(text) <= 2000 else text[:2000] + "…"

    def _trim_response(self, text: str, limit: int = 500) -> str:
        """Обрезает raw response до limit символов."""
        if not isinstance(text, str):
            try:
                text = str(text)
            except Exception:
                return "<unprintable response>"
        return text if len(text) <= limit else text[:limit] + "…"

    def _show_context_menu(self, event: tk.Event) -> None:
        selected = self.tree.identify_row(event.y)
        if not selected:
            return
        self.tree.selection_set(selected)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_selected_key(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        key_text = self.tree.item(selected[0], "text")
        self.clipboard_clear()
        self.clipboard_append(key_text)
        self.status_var.set("Ключ скопирован")

    def _copy_selected_value(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        value_text = values[0] if values else ""
        self.clipboard_clear()
        self.clipboard_append(value_text)
        self.status_var.set("Значение скопировано")

    def reload_summary(self) -> None:
        """Safe reload — only loads 500 items."""
        if self._reload_lock.locked():
            return

        self.status_var.set("Загрузка Threat Intel…")
        self._bridge.post_bg(self._reload_worker)

    def _reload_worker(self) -> None:
        with self._reload_lock:
            try:
                # L2: count total
                self.total_count = THREAT_CONNECTOR.count()

                # L1: load only 500 items
                data = THREAT_CONNECTOR.query(
                    limit=self.L1_LIMIT,
                    offset=self.offset,
                    order_by="timestamp",
                    order_desc=True,
                )

                summary = {
                    "entries": data,
                    "total": self.total_count,
                    "offset": self.offset,
                    "limit": self.L1_LIMIT,
                }

                self._bridge.post_ui(self.load_results_safe, summary)

            except Exception as e:
                self._bridge.post_ui(lambda: self._show_error(e))

    def load_results_safe(self, summary: Dict[str, Any]) -> None:
        """Debounced + chunked GUI update (без зависань)."""
        now = time.time()
        if now - self._last_render_ts < (self.L1_DEBOUNCE_MS / 1000):
            self.after(self.L1_DEBOUNCE_MS, lambda: self.load_results_safe(summary))
            return

        self._last_render_ts = now
        self._last_summary = summary

        # Оновити індикатор сторінки
        page = (self.offset // self.L1_LIMIT) + 1
        pages = max(1, math.ceil(self.total_count / self.L1_LIMIT))
        self.page_info.set(f"Page {page} / {pages}")

        # Очистити дерево
        self.tree.delete(*self.tree.get_children())

        entries = summary.get("entries", [])
        if not entries:
            self._render_empty("Нет данных")
            return

        # 🔥 CHUNKED RENDER — рендеримо порціями по 40 елементів
        self._render_entries_chunked(entries, chunk_size=40)

        self.status_var.set(f"Загружено {len(entries)} из {self.total_count}")

    def _render_entries_chunked(self, entries, chunk_size=40, index=0):
        """Порційний рендер артефактів, щоб уникнути зависань GUI."""
        end = index + chunk_size
        chunk = entries[index:end]

        for art in chunk:
            self._render_artifact(art)

        # Якщо ще є елементи — рендеримо наступну порцію
        if end < len(entries):
            self.after(1, lambda: self._render_entries_chunked(entries, chunk_size, end))

    def _render_artifact(self, art: Dict[str, Any]) -> None:
        """Оптимізований рендер одного артефакта (мінімум дочірніх вузлів, без зависань)."""

        if not isinstance(art, dict):
            return

        module = art.get("module", "unknown")
        target = art.get("target", "—")
        result = art.get("result", {}) or {}
        timestamp = art.get("timestamp", "—")

        # 🔥 SSRF Replay потребує URL → беремо з result або target
        url = result.get("url") or target

        severity = result.get("severity", "info")
        category = result.get("category", "unknown")

        tag = (
            "critical" if severity == "critical"
            else "high" if severity == "high"
            else "info"
        )

        # Кореневий вузол — тепер values містить URL
        root = self.tree.insert(
            "",
            "end",
            text=f"{module} → {target}",
            values=(url,),  # 🔥 SSRF Replay працює
            tags=(tag,),
            open=False,
        )

        # Мінімальний рендер — тільки ключові поля
        self.tree.insert(root, "end", text="timestamp", values=(timestamp,))
        self.tree.insert(root, "end", text="risk", values=(severity,))
        self.tree.insert(root, "end", text="category", values=(category,))

        # 🔥 Безпечний summary — без json.dumps (не блокує mainloop)
        try:
            raw = str(result)
        except Exception:
            raw = "<unprintable>"

        if len(raw) > 300:
            raw = raw[:300] + "…"

        self.tree.insert(root, "end", text="summary", values=(raw,))

        # === PII / Account Intelligence ===
        email = art.get("email") or "—"
        password = art.get("password") or "—"
        phone = art.get("phone") or "—"
        credit_card = art.get("credit_card") or "—"

        self.tree.insert(root, "end", text="email", values=(email,))
        self.tree.insert(root, "end", text="password", values=(password,))
        self.tree.insert(root, "end", text="phone", values=(phone,))
        self.tree.insert(root, "end", text="credit_card", values=(credit_card,))

        # Автоматично розкривати critical/high
        if severity in ("critical", "high"):
            self.tree.item(root, open=True)

    def next_page(self):
        if self.offset + self.L1_LIMIT < self.total_count:
            self.offset += self.L1_LIMIT
            self.reload_summary()

    def prev_page(self):
        if self.offset >= self.L1_LIMIT:
            self.offset -= self.L1_LIMIT
            self.reload_summary()

    # ============================================================
    # SSRF Attack Replay (Ctrl+Enter / кнопка)
    # ============================================================

    def _attack_ssrf(self) -> None:
        item = self.tree.focus()
        if not item:
            self.status_var.set("⚠️ Виберіть вузол з SSRF‑URL")
            return

        values = self.tree.item(item, "values")
        if not values:
            self.status_var.set("⚠️ Вузол не містить URL")
            return

        url = values[0].strip()
        if not url or not url.startswith(("http://", "https://")):
            self.status_var.set(f"⚠️ Невалідний SSRF‑URL: {url}")
            return

        tester_tab = self._find_ssrf_tab()
        if tester_tab is None:
            self.status_var.set("⚠️ SSRF Tester вкладка не знайдена")
            return

        self.status_var.set(f"🔍 SSRF атака на {url}...")

        try:
            result = tester_tab.run_attack(url)

            if not result or not isinstance(result, dict):
                self.status_var.set("❌ SSRF атака не повернула коректний результат")
                return

            # 🔥 Додаємо Replay‑вузол під URL
            self._render_ssrf_attack_result(item, result)

            if result.get("risk") in ("critical", "high"):
                self.status_var.set(f"✅ SSRF атака вдалася (risk={result.get('risk')})")
            else:
                self.status_var.set(f"⚠️ SSRF атака виконана (risk={result.get('risk')})")

        except Exception as e:
            self.status_var.set(f"❌ Помилка SSRF: {e}")

    def _find_ssrf_tab(self):
        """
        Пошук SSRFTab серед відкритих вкладок.
        Повертає SSRFTab або None.
        """
        try:
            # self.master.master — це MainWindow
            for tab in self.master.master.tabs.values():
                if hasattr(tab, "run_attack"):  # SSRFTab має run_attack()
                    return tab
        except Exception:
            pass
        return None

    def _render_ssrf_attack_result(self, parent_node, result: dict) -> None:
        """
        Додає результат SSRF‑атаки під вузлом, оптимізовано (мінімум дочірніх вузлів).
        """
        if not result or not isinstance(result, dict):
            return

        risk = result.get("risk", "info")
        tag = "critical" if risk == "critical" else "high" if risk == "high" else "info"

        # 🔥 Додаємо короткий summary замість десятків дочірніх вузлів
        try:
            raw = str(result)
        except Exception:
            raw = "<unprintable>"

        if len(raw) > 400:
            raw = raw[:400] + "…"

        attack_node = self.tree.insert(
            parent_node,
            "end",
            text="⚡ SSRF Attack Result",
            values=(raw,),  # 🔥 тепер SSRF Auto‑Pivot може повторно атакувати
            tags=(tag,),
            open=True,
        )

        # Розкриваємо батьківський вузол
        self.tree.item(parent_node, open=True)

    def _ssrf_auto_pivot(self) -> None:
        """
        SSRF Auto‑Pivoting:
        - знаходить усі вузли з SSRF‑URL (values[0])
        - запускає SSRF‑атаку по кожному
        - додає результати під вузлами
        """
        self.status_var.set("🔍 Пошук SSRF‑URL у дереві…")

        ssrf_nodes: List[str] = []

        def walk(node: str) -> None:
            for child in self.tree.get_children(node):
                vals = self.tree.item(child, "values")
                if vals and isinstance(vals[0], str) and vals[0].startswith(("http://", "https://")):
                    ssrf_nodes.append(child)
                walk(child)

        walk("")  # root

        if not ssrf_nodes:
            self.status_var.set("⚠️ SSRF‑URL не знайдено")
            return

        self.status_var.set(f"⚡ Знайдено {len(ssrf_nodes)} SSRF‑URL → запускаю атаки…")

        tester_tab = self._find_ssrf_tab()
        if tester_tab is None:
            self.status_var.set("❌ SSRF Tester вкладка не знайдена")
            return

        def worker() -> None:
            for node in ssrf_nodes:
                url = self.tree.item(node, "values")[0]
                try:
                    result = tester_tab.run_attack(url)
                    self.after(0, lambda n=node, r=result: self._render_ssrf_attack_result(n, r))
                except Exception as e:
                    self.after(0, lambda: self.status_var.set(f"❌ Помилка SSRF Auto‑Pivot: {e}"))

            self.after(0, lambda: self.status_var.set("✅ SSRF Auto‑Pivot завершено"))

        threading.Thread(target=worker, daemon=True).start()

    # ============================================================
    # Интеграция с Threat Intel (ThreatDataLoader + RealTimeWatcher)
    # ============================================================

    def add_threat(self, threat_data: Dict[str, Any]) -> None:
        """
        Добавляет одну угрозу в список Threat Intel.
        Используется при интеграции с threat_data_loader.py и RealTimeThreatWatcher.
        Ожидает уже нормализованный gui_artifact.
        """
        try:
            if not self.winfo_exists():
                return

            # Обновляем локальный summary (entries)
            summary = self._last_summary or {}
            entries = summary.get("entries", [])
            if not isinstance(entries, list):
                entries = []

            entries.append(threat_data)
            summary["entries"] = entries
            self._last_summary = summary

            # 🔥 Live‑рендер — chunked, безопасный
            self._bridge.post_ui(self.load_results_safe, summary)

            # Email Leak / PII панель
            if threat_data.get("category") == "email_leak" or threat_data.get("email_leak"):
                self._ingest_email_leak_artifact(threat_data)

            # Account Leak
            if threat_data.get("category") == "account_state_leak" or threat_data.get("account_leak"):
                self._ingest_account_leak_artifact(threat_data)

            category = threat_data.get("category", "unknown")
            risk = threat_data.get("risk", "unknown")

            # SSRF Heatmap
            if category in ("ssrf_candidate", "ssrf_attack_result"):
                url = threat_data.get("url")
                if url:
                    self._ssrf_heatmap[url] = self._ssrf_heatmap.get(url, 0) + 1

            # 🔥 Не спамим статус — обновляем только раз в 150 мс
            now = time.time()
            if now - getattr(self, "_last_status_ts", 0) > 0.15:
                self.status_var.set(f"Добавлена угроза: {category} ({risk})")
                self._last_status_ts = now

        except Exception as e:
            self.status_var.set(f"Ошибка добавления угрозы: {e}")

    def _ingest_account_leak_artifact(self, artifact: Dict[str, Any]) -> None:
        leak = artifact.get("account_leak", {})
        if not isinstance(leak, dict):
            return

        accounts = leak.get("accounts", [])
        if not accounts:
            return

        self.account_leak_summary.set(f"Найдено {len(accounts)} аккаунтов")

        self._account_leak_rows = []  # перезаписываем список

        for acc in accounts:
            row = {
                "username": acc.get("username") or "—",
                "email": acc.get("email") or "—",
                "password": acc.get("password") or "—",
                "phone": acc.get("phone") or "—",
                "credit_card": acc.get("credit_card") or "—",
                "status": acc.get("account_status") or "—",
                "url": acc.get("url") or "—",
                "risk": str(acc.get("risk", "info")),
            }
            self._account_leak_rows.append(row)

        self._refresh_account_leak_panel()

    def _refresh_account_leak_panel(self) -> None:
        """Асинхронное, порционное обновление таблицы Account Leak (без зависаний)."""
        rows = list(self._account_leak_rows)

        self.account_leak_tree.delete(*self.account_leak_tree.get_children())

        def render_chunk(i: int) -> None:
            chunk = rows[i:i + 100]  # 🔥 рендеримо по 100 рядків за раз

            for row in chunk:
                risk = row.get("risk", "info")
                tag = (
                    "critical" if risk == "critical"
                    else "high" if risk == "high"
                    else "info"
                )

                self.account_leak_tree.insert(
                    "",
                    "end",
                    values=(
                        row["username"],
                        row["email"],
                        row["password"],
                        row["phone"],
                        row["credit_card"],
                        row["status"],
                        row["url"],
                        row["risk"],
                    ),
                    tags=(tag,),
                )

            # 🔥 Якщо ще є рядки — рендеримо наступну порцію
            if i + 100 < len(rows):
                self.after(1, lambda: render_chunk(i + 100))

        render_chunk(0)

    def show_ssrf_heatmap(self) -> None:
        """Показує теплову карту SSRF у дереві Threat Intel (chunked, без зависань)."""
        self.tree.delete(*self.tree.get_children())

        root = self.tree.insert("", "end", text="🔥 SSRF Heatmap", open=True)

        if not self._ssrf_heatmap:
            self.tree.insert(root, "end", text="→", values=("Немає даних",))
            self.status_var.set("SSRF Heatmap: порожньо")
            return

        sorted_items = sorted(self._ssrf_heatmap.items(), key=lambda x: x[1], reverse=True)

        def render_chunk(i: int) -> None:
            chunk = sorted_items[i:i + 100]  # 🔥 рендеримо по 100 URL за раз

            for url, count in chunk:
                tag = (
                    "critical" if count >= 3
                    else "high" if count == 2
                    else "info"
                )
                self.tree.insert(
                    root,
                    "end",
                    text=url,
                    values=(f"{count} попадань",),
                    tags=(tag,),
                )

            if i + 100 < len(sorted_items):
                self.after(1, lambda: render_chunk(i + 100))

        render_chunk(0)

        self.tree.item(root, open=True)
        self.status_var.set("SSRF Heatmap оновлено")

    def ingest_crawl_result(self, result: Dict[str, Any]) -> None:
        """
        Принимает результат краулера и отображает найденные PII в секции Email Leak.
        Вызывается из main.propagate_crawler_results().
        """
        if not self.winfo_exists() or not isinstance(result, dict):
            return

        pii = aggregate_pii_from_crawler(result)
        if not pii_has_data(pii):
            self.email_leak_summary.set("Краулинг завершён — PII не обнаружены")
            return

        target = (
            result.get("root")
            or result.get("url")
            or (result.get("summary") or {}).get("target")
            or "unknown"
        )
        artifact = build_email_leak_artifact(pii, target_url=str(target), source="crawler")
        if artifact:
            # crawler‑артефакт уже в формате email_leak gui_artifact
            self.add_threat(artifact)
            self.status_var.set(f"Email Leak: найдено {sum(len(v) for v in pii.values())} PII-записей")

    def _ingest_email_leak_artifact(self, artifact: Dict[str, Any]) -> None:
        leak = artifact.get("email_leak", {})
        if not isinstance(leak, dict):
            return

        pii_slice = {
            key: [str(x) for x in (leak.get(key) or []) if str(x).strip()]
            for key in PII_FIELD_LABELS
        }
        self._email_leak_pii = merge_pii_dicts(self._email_leak_pii, pii_slice)

        url = str(artifact.get("url") or "—")
        for row in flatten_email_leak_rows(artifact, source_url=url):
            if not any(
                r.get("field") == row["field"]
                and r.get("value") == row["value"]
                and r.get("url") == row["url"]
                for r in self._email_leak_rows
            ):
                self._email_leak_rows.append(row)

        self._refresh_email_leak_panel()

    def _refresh_email_leak_panel(self) -> None:
        """Асинхронное обновление таблицы Email Leak."""
        rows = list(self._email_leak_rows)

        self.email_leak_tree.delete(*self.email_leak_tree.get_children())

        def render_chunk(i: int) -> None:
            chunk = rows[i:i + 100]
            for row in chunk:
                field = row.get("field", "")
                tag = (
                    "critical" if field in {"credit_cards", "cvv", "passwords", "account_numbers"}
                    else "high" if field in {"emails", "logins", "phones", "full_names"}
                    else "info"
                )
                self.email_leak_tree.insert(
                    "",
                    "end",
                    values=(row.get("category", "—"), row.get("value", "—"), row.get("url", "—")),
                    tags=(tag,),
                )

            if i + 100 < len(rows):
                self.after(1, lambda: render_chunk(i + 100))

        render_chunk(0)

    # ============================================================
    #  AutoRecon Red Team Integration (Fix unresolved references)
    # ============================================================

    def ingest_autorecon(self, report: dict):
        """
        Принимает отчёт AutoRecon и добавляет его в Threat Intel.
        Вызывается оркестратором.
        """
        try:
            # ThreatConnector ingestion
            if hasattr(self, "threat_connector"):
                self.threat_connector.add_artifact("AUTORECON", "ThreatAnalysisTab", report)

            # GUI update
            if hasattr(self, "text"):
                self.text.delete("1.0", "end")
                self.text.insert("end", json.dumps(report, indent=2, ensure_ascii=False))

            self.last_autorecon_report = report

        except Exception as e:
            print(f"[ThreatAnalysisTab] ingest_autorecon error: {e}")

    def update_report(self, report: dict):
        """
        Универсальный метод обновления отчёта.
        Используется Dashboard, History, Combat Results.
        """
        try:
            self.last_autorecon_report = report

            if hasattr(self, "text"):
                self.text.delete("1.0", "end")
                self.text.insert("end", json.dumps(report, indent=2, ensure_ascii=False))

        except Exception as e:
            print(f"[ThreatAnalysisTab] update_report error: {e}")

    def refresh(self):
        """
        Обновляет Threat Analysis после AutoRecon.
        Вызывается HistoryTab и оркестратором.
        """
        try:
            if hasattr(self, "load_threatintel"):
                self.load_threatintel()

            elif hasattr(self, "text"):
                self.text.insert("end", "\n[🔄] ThreatAnalysisTab refreshed\n")
                self.text.see("end")

        except Exception as e:
            print(f"[ThreatAnalysisTab] refresh error: {e}")

    def get_all_threats(self) -> List[Dict[str, Any]]:
        """
        Возвращает полный список Threat Intel событий.
        Red Team версия:
        • Priority: ThreatDataLoader → ThreatConnector
        • MITRE: Collection (TA0009)
        • OPSEC-aware
        • LiveAttackMonitor events
        • Telemetry для Dashboard
        """

        events: List[Dict[str, Any]] = []

        # === 1. ThreatDataLoader (primary) ===
        try:
            loader = ThreatDataLoader(json_path=None)
            if loader.load():
                artifacts = [
                    loader.convert_artifact_for_gui(a)
                    for a in loader.artifacts
                ]
                events.extend(artifacts)

                # MITRE: Collection
                self.user_tracker.track_attack_chain(
                    tactic="TA0009",
                    technique="T1005",
                    subtechnique=None,
                    target="ThreatDataLoader",
                    status="success",
                    details={"count": len(artifacts)},
                    operator_note="ThreatDataLoader artifacts collected."
                )

        except Exception as e:
            self.logger.warning(f"[ThreatIntel] Loader error: {e}")

        # === 2. ThreatConnector (fallback) ===
        try:
            summary = THREAT_CONNECTOR.summary()
            entries = summary.get("entries", [])
            if isinstance(entries, list):
                events.extend(entries)

                # LiveAttackMonitor
                try:
                    self._event_queue.put({
                        "type": "threatintel_update",
                        "count": len(entries),
                        "timestamp": datetime.now(UTC).isoformat()

                    })
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"[ThreatIntel] Summary error: {e}")

        return events

    def send_to_threat_intel(self, module: str, data: Any) -> None:
        """
        Локальный предпросмотр данных от модулей (crawler, autorecon и т.д.).
        Red Team версия:
        • MITRE Execution (TA0002)
        • Command and Control (TA0011)
        • ThreatConnector enrichment
        • LiveAttackMonitor events
        • OPSEC-aware payload filtering
        • GUI-safe chunked render
        """

        try:
            # === Normalize payload ===
            entries = data if isinstance(data, list) else [data]
            payload = {"module": module, "entries": entries}

            # === OPSEC-aware filtering ===
            if getattr(self.ctx, "opsec_mode", "") == "high":
                entries = [e for e in entries if not getattr(e, "aggressive", False)]
                payload["entries"] = entries

            # === MITRE: Execution ===
            self.user_tracker.track_attack_chain(
                tactic="TA0002",
                technique="T1059",
                subtechnique="T1059.007",
                target=module,
                status="executed",
                details={"entries": len(entries)},
                operator_note="Local threat intel preview."
            )

            # === ThreatConnector enrichment ===
            THREAT_CONNECTOR.add_artifact("LOCAL_PREVIEW", module, payload)

            # === LiveAttackMonitor ===
            try:
                self._event_queue.put({
                    "type": "local_threatintel",
                    "module": module,
                    "count": len(entries),
                    "timestamp": datetime.now(UTC).isoformat()

                })
            except Exception:
                pass

            # === GUI-safe chunked render ===
            self.load_results_safe(payload)
            self.status_var.set(f"Получены данные от модуля: {module}")

        except Exception as e:
            self._render_empty(f"Ошибка обработки данных: {e}")
            self.status_var.set("Ошибка Threat Intel")

    # ============================================================
    # Ошибки / пустые состояния
    # ============================================================

    def _show_error(self, error: Exception) -> None:
        if not self.winfo_exists():
            return
        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", f"❌ Ошибка загрузки Threat Intel:\n{error}")
        self.status_var.set("Ошибка Threat Intel")

    def _render_empty(self, message: str) -> None:
        if not self.winfo_exists():
            return

        self.tree.delete(*self.tree.get_children())
        root = self.tree.insert("", "end", text="Пусто", open=True)
        self.tree.insert(root, "end", text="→", values=(message,))

        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", message)

        self.status_var.set(message)

    # ============================================================
    # Основные методы
    # ============================================================

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.text_widget.delete("1.0", "end")
        self.status_var.set("Очищено")
        self._last_summary = None
        self._email_leak_pii = {}
        self._email_leak_rows = []
        if hasattr(self, "email_leak_tree"):
            self.email_leak_tree.delete(*self.email_leak_tree.get_children())
        self.email_leak_summary.set("Нет данных — запустите краулинг или RealTimeWatcher")
        self._ssrf_heatmap = {}

    def _apply_summary(self, summary: Dict[str, Any]) -> None:
        if not self.winfo_exists():
            return

        # Рендер summary в текстовое окно
        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", json.dumps(summary, indent=2, ensure_ascii=False))

        # Обновляем фильтры
        modules = list(summary.get("by_module", {}).keys()) if isinstance(summary, dict) else []
        values = ["Все"] + modules if modules else []
        if "SSRF" not in values:
            values.append("SSRF")
        self.filter_box["values"] = values
        self.filter_box.set("Все" if modules else "")

        # 🔥 ВАЖНО: chunked‑render, НЕ load_results
        self.load_results_safe(summary)

        self.status_var.set("Summary обновлён")

    # ============================================================
    # Экспорт
    # ============================================================

    def export_json(self) -> None:
        summary = self._last_summary
        if not summary:
            try:
                loader = ThreatDataLoader(json_path=None)
                if loader.load():
                    summary = loader.get_summary()
                    summary["entries"] = [loader.convert_artifact_for_gui(a) for a in loader.artifacts]
                else:
                    if hasattr(THREAT_CONNECTOR, "generate_report"):
                        summary = THREAT_CONNECTOR.generate_report()
                    else:
                        summary = THREAT_CONNECTOR.summary()
            except Exception as e:
                self.status_var.set(f"Ошибка экспорта: {e}")
                return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            self.status_var.set(f"Экспортировано: {path}")
        except Exception as e:
            self.status_var.set(f"Ошибка экспорта: {e}")

    # ============================================================
    # Фильтр и поиск
    # ============================================================

    def apply_filter(self) -> None:
        module = self.filter_var.get()
        summary = self._last_summary
        if not summary or not isinstance(summary, dict):
            return

        if module == "SSRF":
            ssrf_entries: List[Dict[str, Any]] = []
            for entry in summary.get("entries", []):
                if entry.get("category") == "ssrf_candidate":
                    ssrf_entries.append(entry)

            filtered = {
                "module": "SSRF",
                "count": len(ssrf_entries),
                "entries": ssrf_entries,
            }

            # 🔥 ВАЖНО: chunked‑render
            self.load_results_safe(filtered)
            self.status_var.set("Фильтр: только SSRF")
            return

        if module == "Все" or not module:
            # 🔥 chunked‑render
            self.load_results_safe(summary)
            self.status_var.set("Фильтр: все модули")
            return

        by_module = summary.get("by_module", {})
        filtered = {
            "module": module,
            "count": by_module.get(module, 0),
            "entries": [
                e for e in summary.get("entries", [])
                if e.get("module") == module
            ],
        }

        # 🔥 chunked‑render
        self.load_results_safe(filtered)
        self.status_var.set(f"Фильтр по модулю: {module}")

    def apply_search(self) -> None:
        query = self.search_var.get().lower().strip()
        if not query:
            return

        summary = self._last_summary
        if not summary:
            return

        self.tree.delete(*self.tree.get_children())
        root = self.tree.insert("", "end", text="Результаты поиска", open=True)

        text = json.dumps(summary, ensure_ascii=False)
        if query in text.lower():
            self.tree.insert(root, "end", text="Совпадение", values=("Есть совпадения",))
        else:
            self.tree.insert(root, "end", text="Нет совпадений", values=("—",))

        self.status_var.set(f"Поиск: {query}")

    # ============================================================
    # Рендеринг дерева (включая SSRF Burp‑style)
    # ============================================================

    def load_results(self, summary_or_payload: Dict[str, Any]) -> None:
        """
        Универсальный рендерер Threat Intel (обёртка над безопасным load_results_safe).
        Старый рекурсивный рендер отключён.
        """
        if not self.winfo_exists():
            return

        # 🔥 ВАЖНО: всегда используем chunked‑рендер
        self.load_results_safe(summary_or_payload)

    def _render_ssrf_attacks(self, parent: str, entries: List[Dict[str, Any]]) -> None:
        """
        Спеціальний SSRF‑рендерer (Burp Suite‑style, Attack #N).
        Очікує entries з полями:
        - url
        - payload
        - param
        - final_host
        - internal_port_scan
        - severity / risk
        - http_status
        - response_length
        - cloud_metadata / docker_api_detected / redis_service_detected / ...
        """
        attack_index = 1
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            attack_node = self.tree.insert(
                parent,
                "end",
                text=f"Attack #{attack_index}",
                open=False,
            )

            severity = str(entry.get("risk") or entry.get("severity") or "info").lower()
            tag = "critical" if severity == "critical" else ("high" if severity == "high" else "info")

            for k, v in entry.items():
                child = self.tree.insert(attack_node, "end", text=str(k), open=False, tags=(tag,))
                self.tree.insert(child, "end", text="→", values=(self._to_str(v),), tags=(tag,))

            attack_index += 1

        self.tree.item(parent, open=True)

    # ============================================================
    # Expand / Collapse
    # ============================================================

    def expand_all(self) -> None:
        """Раскрывает все узлы дерева."""
        def walk(node: str) -> None:
            self.tree.item(node, open=True)
            for child in self.tree.get_children(node):
                walk(child)

        walk("")

    def collapse_all(self) -> None:
        """Сворачивает все узлы дерева, кроме корня."""
        def walk(node: str) -> None:
            for child in self.tree.get_children(node):
                self.tree.item(child, open=False)
                walk(child)

        walk("")

    def destroy(self) -> None:
        """
        Безопасное уничтожение ThreatAnalysisTab:
        - останавливает UIQueueBridge
        - предотвращает ошибки Tkinter при закрытии вкладки
        """
        try:
            if hasattr(self, "_bridge") and self._bridge:
                self._bridge.stop()
        except Exception:
            pass

        super().destroy()
