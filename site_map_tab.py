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
from typing import Dict, Any, Callable

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
            report = engine.run()  # <-- DecompositionReport (dataclass)
            engine.export_json()

            # ============================
            #   Threat Intel интеграция
            # ============================
            if self.threat_tab:

                # --- Inputs ---
                for inp in report.inputs:
                    self.threat_tab.add_threat({
                        "type": "FORM_INPUT",
                        "input": inp.name or inp.id or "(unknown)",
                        "url": report.url,
                        "source": "Site Decomposer",
                    })

                # --- Events ---
                for ev in report.events:
                    self.threat_tab.add_threat({
                        "type": "DOM_EVENT",
                        "event": ev.type,
                        "url": report.url,
                        "risk": ev.risk_level,
                        "source": "Site Decomposer",
                    })

            # ============================
            #   Статистика для popup
            # ============================
            total_inputs = len(report.inputs)
            total_events = len(report.events)
            high_risk = sum(1 for e in report.events if e.risk_level in ("HIGH", "MEDIUM"))

            msg = (
                f"🔍 Декомпозиция завершена\n\n"
                f"📌 Заголовок: {report.title}\n"
                f"📝 Форм: {total_inputs}\n"
                f"⚡ Событий: {total_events}\n"
                f"🚨 Угроз (HIGH/MEDIUM): {high_risk}\n"
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
                        self.after(0, lambda: self.load_json())
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

    def _add_section(
            self,
            title: str,
            items: list,
            *,
            open: bool = False,
            formatter: Callable[[Any], str] = str
    ):
        """
        Универсальный метод для добавления секции в дерево.
        formatter — функция, превращающая элемент в строку.
        """
        root = self.tree.insert("", "end", text=f"{title} [{len(items)}]", open=open)

        for item in items:
            text = formatter(item)
            if self._filter_text and self._filter_text.lower() not in text.lower():
                continue
            self.tree.insert(root, "end", text=text)

        return root

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
                raw = json.load(f)

            # --------------------------------------------------------
            # НОРМАЛИЗАЦИЯ ФОРМАТА JSON
            # --------------------------------------------------------
            if isinstance(raw, dict):
                data = raw

            elif isinstance(raw, list):
                visited, scripts, api_endpoints, emails, tokens, user_ids = [], [], [], [], [], []

                for node in raw:
                    if not isinstance(node, dict):
                        continue

                    url = node.get("url")
                    if url:
                        visited.append(url)

                    for s in node.get("scripts", []):
                        if isinstance(s, dict):
                            p = s.get("path") or s.get("src") or s.get("url")
                            if p:
                                scripts.append(p)
                        else:
                            scripts.append(str(s))

                    api_endpoints.extend(node.get("api_endpoints", []))
                    emails.extend(node.get("emails", []))
                    tokens.extend(node.get("tokens", []))
                    user_ids.extend(node.get("user_ids", []))

                def _dedupe(seq):
                    return list(dict.fromkeys(seq))

                data = {
                    "visited": _dedupe(visited),
                    "scripts": _dedupe(scripts),
                    "api_endpoints": _dedupe(api_endpoints),
                    "emails": _dedupe(emails),
                    "tokens": _dedupe(tokens),
                    "user_ids": _dedupe(user_ids),
                }

            else:
                messagebox.showerror("Ошибка JSON", f"Неожиданный формат: {type(raw).__name__}")
                return

            self.data = data

            # --------------------------------------------------------
            #                ПОСТРОЕНИЕ ДЕРЕВА
            # --------------------------------------------------------

            # === URLs ===
            urls = data.get("visited", []) or []
            urls_root = self.tree.insert("", "end", text=f"🔗 URLs [{len(urls)}]", open=True)

            for url in urls:
                if self._filter_text and self._filter_text.lower() not in url.lower():
                    continue

                parsed = urlparse(url)
                risk = self.classify_url_risk(url)
                tag = (
                    "risk_high" if risk == "HIGH"
                    else "risk_medium" if risk == "MEDIUM"
                    else "risk_low"
                )

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
            self._add_section(
                "📜 JS Files",
                data.get("scripts", []) or [],
                open=False,
                formatter=str
            )

            # === API Endpoints ===
            self._add_section(
                "📡 API Endpoints",
                data.get("api_endpoints", []) or [],
                open=False,
                formatter=str
            )

            # === Tokens ===
            self._add_section(
                "🔑 Tokens",
                data.get("tokens", []) or [],
                open=False,
                formatter=lambda t: (
                        (t if isinstance(t, str) else str(t))[:80]
                        + ("..." if len(str(t)) > 80 else "")
                )
            )

            # === Emails ===
            self._add_section(
                "📧 Emails",
                data.get("emails", []) or [],
                open=False,
                formatter=str
            )

            # === User IDs ===
            self._add_section(
                "🆔 User IDs",
                data.get("user_ids", []) or [],
                open=False,
                formatter=lambda uid: str(uid)
            )

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
    def on_node_selected(self, event=None):
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