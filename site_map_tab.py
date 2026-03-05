# xss_security_gui/site_map_tab.py
"""
SiteMapTab ULTRA 5.0

• Живая карта сайта поверх logs/crawler_results.json
• Разделы:
    - URLs
    - JS Files
    - API Endpoints
    - Tokens
    - Emails
    - User IDs
• DOM-анализ (формы, iframe, DOM-события) через DOMParser
• Декомпозиция сайта через SiteDecomposerEngine
• Risk scoring для:
    - URL’ов (по паттернам)
    - DOM-событий
• Интеграция с Threat Intel (threat_tab.add_threat)
• Подсветка high/medium-risk узлов
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse, parse_qs
import json
import os
import time
import threading
from typing import Dict, Any, List

from xss_security_gui.dom_parser import DOMParser
from xss_security_gui.site_decomposer import SiteDecomposerEngine
from xss_security_gui.settings import crawler_results_path

class SiteMapTab(ttk.Frame):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab

        # === Дерево SiteMap ===
        self.tree = ttk.Treeview(self)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_node_selected)

        # Цветовые теги
        self.tree.tag_configure("risk_high", foreground="#b30000")
        self.tree.tag_configure("risk_medium", foreground="#b36b00")
        self.tree.tag_configure("risk_low", foreground="#006600")

        # === Панель управления ===
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", pady=5)

        ttk.Button(control_frame, text="📊 Статистика", command=self.show_stats).pack(side="left", padx=5)

        self.search_entry = ttk.Entry(control_frame)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(control_frame, text="🔍 Поиск", command=self.apply_filter).pack(side="left", padx=5)
        ttk.Button(control_frame, text="♻ Сброс", command=self.reset_filter).pack(side="left", padx=5)

        # === Декомпозиция сайта ===
        self.url_entry = tk.Entry(self)
        self.url_entry.pack(fill="x", padx=5, pady=(5, 0))
        ttk.Button(self, text="🧠 Декомпозиция сайта", command=self.run_decomposition).pack(pady=4)

        # === DOM-панель ===
        self.dom_frame = ttk.Frame(self)
        self.dom_frame.pack(fill="both", expand=True, pady=5)

        self.forms_box = tk.Text(self.dom_frame, height=8)
        self.forms_box.pack(fill="x", padx=5)

        self.iframe_box = tk.Text(self.dom_frame, height=4)
        self.iframe_box.pack(fill="x", padx=5)

        self.events_box = tk.Text(self.dom_frame, height=8)
        self.events_box.pack(fill="x", padx=5)

        # === JSON crawler (универсальный путь) ===
        self.json_path = crawler_results_path()
        self.last_size = 0
        self.data: Dict[str, Any] = {}

        self._filter_text = ""
        self.load_json()
        threading.Thread(target=self.auto_refresh_loop, daemon=True).start()

    # ============================================================
    #                      Статистика
    # ============================================================
    def show_stats(self):
        try:
            if not os.path.exists(self.json_path):
                messagebox.showwarning("Нет данных", f"Файл не найден:\n{self.json_path}")
                return

            with open(self.json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            msg = "\n".join(
                [
                    f"🔗 URLs: {len(data.get('visited', []))}",
                    f"📜 JS Files: {len(data.get('scripts', []))}",
                    f"📡 API Endpoints: {len(data.get('api_endpoints', []))}",
                    f"📧 Emails: {len(data.get('emails', []))}",
                    f"🔑 Tokens: {len(data.get('tokens', []))}",
                    f"🆔 User IDs: {len(data.get('user_ids', []))}",
                ]
            )
            messagebox.showinfo("📊 Статистика SiteMap", msg)

        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ============================================================
    #                      Декомпозиция сайта
    # ============================================================
    def run_decomposition(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Ввод", "Введите целевой URL для декомпозиции")
            return

        try:
            engine = SiteDecomposerEngine(url)
            report = engine.run()
            engine.export_json()

            if self.threat_tab:
                for inp in report.get("inputs", []):
                    self.threat_tab.add_threat(
                        {
                            "type": "FORM_INPUT",
                            "input": inp,
                            "url": url,
                            "source": "Site Decomposer",
                        }
                    )

                for ev in report.get("events", []):
                    self.threat_tab.add_threat(
                        {
                            "type": "DOM_EVENT",
                            "event": ev,
                            "url": url,
                            "risk": ev.get("risk_level", "UNKNOWN"),
                            "source": "Site Decomposer",
                        }
                    )

            msg = (
                f"🔍 Декомпозиция завершена\n\n"
                f"✅ Форм: {len(report.get('inputs', []))}\n"
                f"✅ Событий: {len(report.get('events', []))}\n"
                f"✅ Угроз: {sum(1 for e in report.get('events', []) if e.get('risk_level') in ['HIGH', 'MEDIUM'])}"
            )
            messagebox.showinfo("📊 Декомпозиция сайта", msg)

        except Exception as e:
            messagebox.showerror("Ошибка декомпозиции", str(e))

    # ============================================================
    #                      Автообновление JSON
    # ============================================================
    def auto_refresh_loop(self):
        while True:
            try:
                if os.path.exists(self.json_path):
                    size = os.path.getsize(self.json_path)
                    if size != self.last_size:
                        self.last_size = size
                        self.after(0, self.load_json)
                time.sleep(5)
            except Exception as e:
                print(f"[⚠️] Ошибка автообновления SiteMap: {e}")
                time.sleep(10)

    # ============================================================
    #                      Risk scoring
    # ============================================================
    def classify_url_risk(self, url: str) -> str:
        """
        Простейший risk scoring по URL:
        • /admin, /root, /manage → HIGH
        • /auth, /login, /signup → MEDIUM
        • ?id=, ?user=, ?uid= → MEDIUM
        • ?redirect=, ?url= → HIGH
        """
        u = url.lower()

        high_markers = ["/admin", "/root", "/manage", "redirect=", "url="]
        medium_markers = ["/auth", "/login", "/signup", "id=", "user=", "uid="]

        if any(m in u for m in high_markers):
            return "HIGH"
        if any(m in u for m in medium_markers):
            return "MEDIUM"
        return "LOW"

    def classify_dom_event_risk(self, event_name: str) -> str:
        high = {"onerror", "onload", "onclick", "onmouseover", "onmouseenter"}
        medium = {"onfocus", "onblur", "onchange", "onsubmit", "oninput"}

        e = event_name.lower()
        if e in high:
            return "HIGH"
        if e in medium:
            return "MEDIUM"
        return "LOW"

    # ============================================================
    #                      Загрузка JSON
    # ============================================================
    def load_json(self):
        self.tree.delete(*self.tree.get_children())

        if not os.path.exists(self.json_path):
            messagebox.showwarning("Нет данных", f"Файл не найден:\n{self.json_path}")
            return

        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)

            # === URLs ===
            urls = self.data.get("visited", []) or []
            urls_root = self.tree.insert(
                "", "end", text=f"🔗 URLs [{len(urls)}]", open=True
            )

            for url in urls:
                if self._filter_text and self._filter_text.lower() not in url.lower():
                    continue

                parsed = urlparse(url)
                risk = self.classify_url_risk(url)
                tag = "risk_high" if risk == "HIGH" else "risk_medium" if risk == "MEDIUM" else "risk_low"

                url_node = self.tree.insert(
                    urls_root,
                    "end",
                    text=f"{parsed.path or '/'}",
                    values=(url,),
                    tags=(tag,),
                )

                for k, v in parse_qs(parsed.query).items():
                    self.tree.insert(url_node, "end", text=f"↳ {k} = {', '.join(v)}")

            # === JS Files ===
            scripts = self.data.get("scripts", []) or []
            scripts_root = self.tree.insert(
                "", "end", text=f"📜 JS Files [{len(scripts)}]", open=False
            )
            for s in scripts:
                if self._filter_text and self._filter_text.lower() not in s.lower():
                    continue
                self.tree.insert(scripts_root, "end", text=s)

            # === API Endpoints ===
            apis = self.data.get("api_endpoints", []) or []
            api_root = self.tree.insert(
                "", "end", text=f"📡 API Endpoints [{len(apis)}]", open=False
            )
            for api in apis:
                if self._filter_text and self._filter_text.lower() not in api.lower():
                    continue
                self.tree.insert(api_root, "end", text=api)

            # === Tokens ===
            tokens = self.data.get("tokens", []) or []
            tokens_root = self.tree.insert(
                "", "end", text=f"🔑 Tokens [{len(tokens)}]", open=False
            )
            for t in tokens:
                val = t if isinstance(t, str) else str(t)
                if self._filter_text and self._filter_text.lower() not in val.lower():
                    continue
                self.tree.insert(tokens_root, "end", text=val[:80] + ("..." if len(val) > 80 else ""))

            # === Emails ===
            emails = self.data.get("emails", []) or []
            emails_root = self.tree.insert(
                "", "end", text=f"📧 Emails [{len(emails)}]", open=False
            )
            for e in emails:
                if self._filter_text and self._filter_text.lower() not in e.lower():
                    continue
                self.tree.insert(emails_root, "end", text=e)

            # === User IDs ===
            user_ids = self.data.get("user_ids", []) or []
            uids_root = self.tree.insert(
                "", "end", text=f"🆔 User IDs [{len(user_ids)}]", open=False
            )
            for uid in user_ids:
                val = str(uid)
                if self._filter_text and self._filter_text.lower() not in val.lower():
                    continue
                self.tree.insert(uids_root, "end", text=val)

        except Exception as e:
            messagebox.showerror("Ошибка загрузки", str(e))

    # ============================================================
    #                      Фильтрация
    # ============================================================
    def apply_filter(self):
        self._filter_text = self.search_entry.get().strip()
        self.load_json()

    def reset_filter(self):
        self._filter_text = ""
        self.search_entry.delete(0, tk.END)
        self.load_json()

    # ============================================================
    #                      Выбор узла дерева
    # ============================================================
    def on_node_selected(self, event):
        selected = self.tree.focus()
        item = self.tree.item(selected)
        values = item.get("values", [])
        url = values[0] if values else ""

        if not url:
            return

        html_path = os.path.join("logs", "html_snapshots", f"{self.safe_filename(url)}.html")
        if not os.path.exists(html_path):
            self.forms_box.delete(1.0, tk.END)
            self.forms_box.insert(tk.END, "❌ HTML для DOM-анализ не найден")
            self.iframe_box.delete(1.0, tk.END)
            self.events_box.delete(1.0, tk.END)
            return

        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        parser = DOMParser(html)
        dom = parser.extract_all()

        # === Формы ===
        self.forms_box.delete(1.0, tk.END)
        for form in dom.get("forms", []):
            self.forms_box.insert(
                tk.END,
                f"{form.get('method', '').upper()} → {form.get('action', '')} → {form.get('inputs', [])}\n",
            )

        # === Iframes ===
        self.iframe_box.delete(1.0, tk.END)
        self.iframe_box.insert(tk.END, "\n".join(dom.get("iframes", [])))

        # === DOM Events ===
        self.events_box.delete(1.0, tk.END)
        for ev in dom.get("dom_events", []):
            risk = self.classify_dom_event_risk(ev.get("event", ""))
            self.events_box.insert(
                tk.END,
                f"[{risk}] {ev.get('tag', '')} → {ev.get('event', '')} → {ev.get('handler', '')}\n",
            )

        # === Threat Intel интеграция ===
        if self.threat_tab:
            # Формы
            for form in dom.get("forms", []):
                self.threat_tab.add_threat(
                    {
                        "type": "FORM",
                        "method": form.get("method", ""),
                        "action": form.get("action", ""),
                        "inputs": form.get("inputs", []),
                        "url": url,
                        "source": "SiteMap DOM Parser",
                    }
                )

            # Iframes
            for iframe in dom.get("iframes", []):
                self.threat_tab.add_threat(
                    {
                        "type": "IFRAME",
                        "iframe": iframe,
                        "url": url,
                        "source": "SiteMap DOM Parser",
                    }
                )

            # DOM Events
            for ev in dom.get("dom_events", []):
                risk = self.classify_dom_event_risk(ev.get("event", ""))
                self.threat_tab.add_threat(
                    {
                        "type": "DOM_EVENT",
                        "tag": ev.get("tag", ""),
                        "event": ev.get("event", ""),
                        "handler": ev.get("handler", ""),
                        "url": url,
                        "risk": risk,
                        "source": "SiteMap DOM Parser",
                    }
                )

    # ============================================================
    #                      Безопасное имя файла
    # ============================================================
    def safe_filename(self, url: str) -> str:
        return (
            url.replace("://", "_")
            .replace("/", "_")
            .replace("?", "_")
            .replace("&", "_")
            .replace("=", "_")
        )