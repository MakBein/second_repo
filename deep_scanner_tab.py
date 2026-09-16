# xss_security_gui/deep_scanner_tab.py
"""
DeepScannerTab ULTRA 6.0

• GUI для глубокого сканирования
• Управление Honeypot (запуск/остановка, мониторинг логов)
• Proxy-менеджер (проверка, загрузка, ротация)
• Авторизация (логин/пароль, селекторы)
• Интеграция с ThreatConnector
• Экспорт отчётов в PDF
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import json, os, sys
from datetime import datetime
import re

from xss_security_gui.deep_crawler import deep_crawl
from xss_security_gui.utils.threat_sender import ThreatSenderMixin
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge



class GraphView(tk.Frame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.node_count = 0
        self.label = ttk.Label(self, text="Graph View")
        self.label.pack()

    def load_dot_file(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
            self.node_count = sum(1 for line in content.splitlines() if "->" in line)
        except Exception as e:
            print(f"[⚠️] Ошибка загрузки DOT-файла: {e}")
            self.node_count = 0


class DeepScannerTab(ttk.Frame, ThreatSenderMixin):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.graph_view = GraphView(self)
        self.graph_view.pack(fill="both", expand=True)
        self.use_tor = tk.BooleanVar(value=False)
        self.last_result = {}
        self.honeypot_proc = None
        self._bridge = UIQueueBridge(self, poll_ms=80)
        self._bridge.post_bg(self.monitor_log_thread)

        self.proxy_list = []
        self.proxy_index = -1

        self.build_ui()

    # === UI ===
    def build_ui(self):
        url_frame = ttk.LabelFrame(self, text="🌐 Целевой адрес")
        url_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(url_frame, text="URL:").pack(side="left", padx=5)
        self.url_entry = ttk.Entry(url_frame, width=55)
        self.url_entry.pack(side="left", padx=5)
        self.alert_label = ttk.Label(self, text="🟢 Нет XSS-попыток", foreground="green")
        self.alert_label.pack(padx=10, pady=5, anchor="w")

        self.honeypot_log_box = tk.Text(self, bg="black", fg="white", height=25)
        self.honeypot_log_box.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Button(url_frame, text="🛰️ Сканировать", command=self.start_scan).pack(side="left", padx=5)
        ttk.Button(url_frame, text="📖 Открыть отчёт", command=self.view_report).pack(side="left", padx=5)
        ttk.Button(url_frame, text="📄 Сохранить PDF", command=self.export_pdf).pack(side="left", padx=5)
        ttk.Button(self, text="🚀 Запустить Honeypot", command=self.start_honeypot).pack(pady=5)
        ttk.Button(self, text="🛑 Остановить Honeypot", command=self.stop_honeypot).pack(pady=5)

        self.honeypot_status = ttk.Label(self, text="🔴 Honeypot не запущен", foreground="red")
        self.honeypot_status.pack(pady=5)

        settings = ttk.LabelFrame(self, text="⚙️ Настройки сканера")
        settings.pack(fill="x", padx=10, pady=5)

        ttk.Label(settings, text="⏱️ Задержка (сек):").grid(row=0, column=0)
        self.delay_entry = ttk.Entry(settings, width=5)
        self.delay_entry.insert(0, "1.0")
        self.delay_entry.grid(row=0, column=1)

        ttk.Label(settings, text="🌐 Proxy:").grid(row=0, column=2)
        self.proxy_entry = ttk.Entry(settings, width=35)
        self.proxy_entry.grid(row=0, column=3)
        ttk.Button(settings, text="🧪 Проверить прокси", command=self.check_proxy).grid(row=0, column=4, padx=5)
        ttk.Button(settings, text="📂 Загрузить список", command=self.load_proxy_list).grid(row=0, column=5)
        ttk.Button(settings, text="🔀 Сменить прокси", command=self.rotate_proxy).grid(row=0, column=6)

        ttk.Label(settings, text="🧬 User-Agent:").grid(row=1, column=0)
        self.ua_entry = ttk.Entry(settings, width=60)
        self.ua_entry.insert(0, "Mozilla/5.0")
        self.ua_entry.grid(row=1, column=1, columnspan=3)

        # Авторизация
        login_frame = ttk.LabelFrame(self, text="🔐 Авторизация")
        login_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(login_frame, text="🤖 Авто‑определить логин‑форму",
                   command=self.auto_detect_login_form).grid(row=4,
                                                             column=0,
                                                             columnspan=4,
                                                             pady=5)

        ttk.Label(login_frame, text="URL входа:").grid(row=0, column=0)
        self.login_url = ttk.Entry(login_frame, width=60)
        self.login_url.grid(row=0, column=1, columnspan=3)

        ttk.Label(login_frame, text="Логин:").grid(row=1, column=0)
        self.login_user = ttk.Entry(login_frame, width=30)
        self.login_user.grid(row=1, column=1)

        ttk.Label(login_frame, text="Пароль:").grid(row=1, column=2)
        self.login_pass = ttk.Entry(login_frame, show="*", width=30)
        self.login_pass.grid(row=1, column=3)

        ttk.Label(login_frame, text="Селектор логина:").grid(row=2, column=0)
        self.selector_user = ttk.Entry(login_frame, width=30)
        self.selector_user.insert(0, "#username")
        self.selector_user.grid(row=2, column=1)

        ttk.Label(login_frame, text="Селектор пароля:").grid(row=2, column=2)
        self.selector_pass = ttk.Entry(login_frame, width=30)
        self.selector_pass.insert(0, "#password")
        self.selector_pass.grid(row=2, column=3)

        ttk.Label(login_frame, text="Кнопка входа:").grid(row=3, column=0)
        self.selector_submit = ttk.Entry(login_frame, width=30)
        self.selector_submit.insert(0, "button[type='submit']")
        self.selector_submit.grid(row=3, column=1)

        self.result_box = tk.Text(self, bg="black", fg="lime", height=25)
        self.result_box.pack(fill="both", expand=True, padx=10, pady=5)

    # === Honeypot ===
    def start_honeypot(self):
        if self.honeypot_proc and self.honeypot_proc.poll() is None:
            messagebox.showinfo("✅ Honeypot", "Уже запущен.")
            return
        try:
            script_path = os.path.join(os.path.dirname(__file__), "honeypot_server.py")
            self.honeypot_proc = subprocess.Popen([sys.executable, script_path])
            self.honeypot_status.config(text="🟢 Honeypot запущен", foreground="green")
        except Exception as e:
            messagebox.showerror("❌ Ошибка запуска", str(e))

    def stop_honeypot(self):
        if self.honeypot_proc and self.honeypot_proc.poll() is None:
            self.honeypot_proc.terminate()
            self.honeypot_status.config(text="🔴 Honeypot остановлен", foreground="red")
            messagebox.showinfo("🛑 Honeypot", "Сервер остановлен.")
        else:
            messagebox.showinfo("ℹ️ Honeypot", "Сервер не был запущен.")

    # === Сканирование ===
    def build_proxy(self):
        p = self.proxy_entry.get().strip()
        return {"http": p, "https": p} if p else None

    def build_login_config(self):
        if not self.login_url.get().strip():
            return None
        return {
            "url": self.login_url.get().strip(),
            "username": self.login_user.get().strip(),
            "password": self.login_pass.get().strip(),
            "selectors": {
                "username": self.selector_user.get().strip(),
                "password": self.selector_pass.get().strip(),
                "submit": self.selector_submit.get().strip()
            }
        }

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http"):
            messagebox.showerror("Ошибка", "Укажи корректный URL")
            return
        try:
            config = {
                "use_proxy": self.use_tor.get(),
                "delay": float(self.delay_entry.get() or 1.0),
                "user_agent": self.ua_entry.get().strip(),
                "proxy": self.build_proxy()
            }

            login_cfg = self.build_login_config()
            if login_cfg:
                config["login"] = login_cfg

            self.result_box.insert("end", f"\n🛰️ Сканирование: {url}\n")
            self._bridge.post_bg(self._prepare_and_run_scan, url, config)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Неверные параметры:\n{e}")

    def _prepare_and_run_scan(self, url, config):
        self._autodetect_login_form(url, log_to_box=True)
        self.run_scan(url, config)

    def auto_detect_login_form(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http"):
            messagebox.showerror("Ошибка", "Укажи корректный URL для анализа.")
            return
        self._bridge.post_bg(self._autodetect_login_form, url, True)

    def _autodetect_login_form(self, url: str, log_to_box: bool = True):
        try:
            from playwright.sync_api import sync_playwright
            from xss_security_gui.auth.login_flow import detect_login_form_ai
            if log_to_box:
                self._bridge.post_ui(self.result_box.insert, "end", "\n🤖 Авто‑анализ login‑формы...\n")

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=8000)

                form_info = detect_login_form_ai(page)

                if not form_info:
                    if log_to_box:
                        self._bridge.post_ui(self.result_box.insert, "end", "ℹ️ Login‑форма не найдена.\n")
                    browser.close()
                    return

                if log_to_box:
                    self._bridge.post_ui(self.result_box.insert, "end", f"🤖 Найдена login‑форма: {form_info}\n")

                def apply_form_info():
                    self.login_url.delete(0, "end")
                    self.login_url.insert(0, url)
                    self.selector_user.delete(0, "end")
                    self.selector_user.insert(0, form_info.get("username") or "")
                    self.selector_pass.delete(0, "end")
                    self.selector_pass.insert(0, form_info.get("password") or "")
                    self.selector_submit.delete(0, "end")
                    self.selector_submit.insert(0, form_info.get("submit") or "")
                    if not self.login_user.get().strip():
                        self.login_user.insert(0, "admin")
                    if not self.login_pass.get().strip():
                        self.login_pass.insert(0, "admin123")
                self._bridge.post_ui(apply_form_info)

                browser.close()

        except Exception as e:
            if log_to_box:
                self._bridge.post_ui(self.result_box.insert, "end", f"⚠️ Ошибка авто‑детектора: {e}\n")

    def load_data(self, path):
        self.graph_view.load_dot_file(path)

    def run_scan(self, url, config):
        try:
            result = deep_crawl(url, config)
            self.last_result = result
            self._bridge.post_ui(self.result_box.delete, "1.0", "end")
            self._bridge.post_ui(self.display_result, result)

            # 🔥 Передаём в Threat Intel
            self.send_to_threat_intel("deep_scanner", result)

        except Exception as e:
            self._bridge.post_ui(self.result_box.insert, "end", f"\n❌ Ошибка: {e}\n")

    def monitor_log_thread(self):
        """Моніторинг лог-файлу honeypot в фоне з перевіркою скасування."""
        import time
        path = os.path.join("logs", "honeypot.log")
        last_size = 0
        
        def monitor_work(progress_fn, is_cancelled_fn):
            nonlocal last_size
            while not is_cancelled_fn():
                try:
                    if os.path.exists(path):
                        size = os.path.getsize(path)
                        if size > last_size:
                            with open(path, "r", encoding="utf-8") as f:
                                lines = f.readlines()
                            new_lines = lines[-5:]
                            for line in new_lines:
                                if '"xss_detected": true' in line:
                                    self._bridge.post_ui(self.alert_label.config, text="🚨 XSS-попытка!", foreground="red")
                                    self._bridge.post_ui(self.honeypot_log_box.insert, "end", f"🔴 {line}\n")
                                    self.send_to_threat_intel("honeypot_event", {"event": line})
                                else:
                                    self._bridge.post_ui(self.honeypot_log_box.insert, "end", f"⚪ {line}\n")
                            last_size = size
                    time.sleep(2)
                except Exception as e:
                    self._bridge.post_ui(self.honeypot_log_box.insert, "end", f"❌ Ошибка мониторинга: {e}\n")
                    time.sleep(5)

        # Запускаємо в фоне
        self._bridge.post_bg(monitor_work)

    def check_proxy(self):
        """Проверка прокси в фоне с неблокирующим запросом."""
        import requests
        from datetime import datetime, UTC
        from pathlib import Path

        proxy = self.proxy_entry.get().strip()
        if not proxy:
            messagebox.showwarning("Пустой прокси", "Сначала укажи адрес прокси")
            return

        def check_work():
            """Фоновая работа - проверка прокси."""
            proxies = {"http": proxy, "https": proxy}
            now = datetime.now(UTC).isoformat().replace("+00:00", "Z")

            try:
                ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=7).text
                
                entry = {
                    "time": now,
                    "proxy": proxy,
                    "ip": ip,
                    "status": "success"
                }
                
                self._bridge.post_ui(messagebox.showinfo, "✅ Прокси работает", f"Внешний IP: {ip}")
                msg = f"✅ Прокси успешно проверен: {ip}"

            except Exception as e:
                entry = {
                    "time": now,
                    "proxy": proxy,
                    "error": str(e),
                    "status": "error"
                }
                
                self._bridge.post_ui(messagebox.showerror, "❌ Прокси не работает", f"Ошибка:\n{e}")
                msg = f"❌ Ошибка проверки: {e}"

            # Логування
            try:
                Path("logs").mkdir(exist_ok=True)
                log_path = Path("logs") / "proxy_check.json"
                with open(log_path, "a", encoding="utf-8") as f:
                    json.dump(entry, f, ensure_ascii=False)
                    f.write("\n")
            except Exception as e:
                print(f"[⚠️] Ошибка записи лога прокси: {e}")

        # Запускаємо в фоне
        self._bridge.post_bg(check_work)

    def display_result(self, result):
        self.result_box.insert("end", f"🔗 URLs: {len(result['visited'])}\n")
        for u in result["visited"]:
            self.result_box.insert("end", f"  • {u}\n")

        self.result_box.insert("end", f"\n📜 JS-файлы: {len(result['scripts'])}\n")
        for js in result["scripts"]:
            self.result_box.insert("end", f"  • {js}\n")

        self.result_box.insert("end", f"\n📡 API endpoints:\n")
        for api in result["api_endpoints"]:
            self.result_box.insert("end", f"  • {api}\n")

        self.result_box.insert("end", f"\n📧 Emails:\n")
        for email in result["emails"]:
            self.result_box.insert("end", f"  • {email}\n")

        self.result_box.insert("end", f"\n🔑 Tokens:\n")
        for token in result["tokens"]:
            short = token[:60] + "..." if len(token) > 60 else token
            self.result_box.insert("end", f"  • {short}\n")

        self.result_box.insert("end", f"\n🆔 User IDs:\n")
        for uid in result["user_ids"]:
            self.result_box.insert("end", f"  • {uid}\n")

        self.result_box.insert("end", "\n✅ Скан завершён.\n")

        summary = {
            "visited": len(result.get("visited", [])),
            "scripts": len(result.get("scripts", [])),
            "api_endpoints": len(result.get("api_endpoints", [])),
            "emails": len(result.get("emails", [])),
            "tokens": len(result.get("tokens", [])),
            "user_ids": len(result.get("user_ids", [])),
        }
        self.send_to_threat_intel("deep_scanner_summary", summary)

    def load_proxy_list(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_lines = [line.strip() for line in f if line.strip()]

            valid_proxies, invalid_proxies = [], []
            pattern = re.compile(r"^(https?|socks5)://(?:[^:@\s]+:[^:@\s]+@)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d+$")

            for proxy in raw_lines:
                if pattern.match(proxy):
                    valid_proxies.append(proxy)
                else:
                    invalid_proxies.append(proxy)

            self.proxy_list = valid_proxies
            self.proxy_index = -1

            summary = f"✅ Загружено: {len(valid_proxies)}\n❌ Пропущено: {len(invalid_proxies)}"
            if invalid_proxies:
                summary += f"\n\nНекорректные строки:\n" + "\n".join(f"• {p}" for p in invalid_proxies[:5])
                if len(invalid_proxies) > 5:
                    summary += "\n…ещё строки пропущены."

            messagebox.showinfo("Результат загрузки", summary)
        except Exception as e:
            messagebox.showerror("❌ Ошибка", f"Не удалось загрузить список:\n{e}")

    def rotate_proxy(self):
        if not self.proxy_list:
            messagebox.showwarning("Список пуст", "Сначала загрузи файл с прокси.")
            return
        self.proxy_index = (self.proxy_index + 1) % len(self.proxy_list)
        new_proxy = self.proxy_list[self.proxy_index]
        self.proxy_entry.delete(0, "end")
        self.proxy_entry.insert(0, new_proxy)
        self.check_proxy()

    def destroy(self):
        try:
            self._bridge.stop()
        except Exception:
            pass
        super().destroy()

    def view_report(self):
        path = filedialog.askopenfilename(filetypes=[("JSON or TXT", "*.json *.txt")])
        if not path:
            return
        try:
            if path.endswith(".json"):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.last_result = data
                self.result_box.delete("1.0", "end")
                self.display_result(data)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.result_box.delete("1.0", "end")
                self.result_box.insert("end", f"{content}")
        except Exception as e:
            self.result_box.insert("end", f"\n❌ Ошибка при загрузке: {e}\n")

    def export_pdf(self):
        if not self.last_result:
            messagebox.showinfo("Нет данных", "Сначала запусти сканирование.")
            return

        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Report", "*.pdf")])
        if not path:
            return

        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import mm

            c = canvas.Canvas(path, pagesize=A4)
            width, height = A4
            y = height - 20 * mm

            # Заголовок
            c.setFont("Helvetica-Bold", 14)
            c.drawString(20 * mm, y, "🔍 Deep Scanner Отчёт")
            y -= 10 * mm

            # Метаданные
            c.setFont("Helvetica", 10)
            c.drawString(20 * mm, y, f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y -= 6 * mm
            c.drawString(20 * mm, y, f"Цель: {self.url_entry.get().strip()}")
            y -= 10 * mm

            def draw_section(title, items):
                nonlocal y
                c.setFont("Helvetica-Bold", 11)
                c.drawString(20 * mm, y, f"{title} ({len(items)}):")
                y -= 6 * mm
                c.setFont("Helvetica", 9)
                for item in items:
                    if y < 20 * mm:
                        c.showPage()
                        y = height - 20 * mm
                        c.setFont("Helvetica", 9)
                    c.drawString(25 * mm, y, f"• {item[:100]}")
                    y -= 5 * mm
                y -= 5 * mm

            # Разделы
            draw_section("🔗 URLs", self.last_result.get("visited", []))
            draw_section("📜 JS-файлы", self.last_result.get("scripts", []))
            draw_section("📡 API endpoints", self.last_result.get("api_endpoints", []))
            draw_section("📧 Emails", self.last_result.get("emails", []))
            draw_section("🔑 Tokens", self.last_result.get("tokens", []))
            draw_section("🆔 User IDs", self.last_result.get("user_ids", []))

            c.save()
            messagebox.showinfo("✅ PDF сохранён", f"Отчёт сохранён:\n{path}")
        except Exception as e:
            messagebox.showerror("Ошибка PDF", f"Не удалось сохранить PDF:\n{e}")

