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
from pathlib import Path
from datetime import datetime
import re

from deep_crawler import deep_crawl
from utils.threat_sender import ThreatSenderMixin


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
        threading.Thread(target=self.monitor_log_thread, daemon=True).start()

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
            threading.Thread(target=lambda: self.run_scan(url, config), daemon=True).start()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Неверные параметры:\n{e}")

    def load_data(self, path):
        self.graph_view.load_dot_file(path)

    def run_scan(self, url, config):
        try:
            result = deep_crawl(url, config)
            self.last_result = result
            self.result_box.delete("1.0", "end")
            self.display_result(result)

            # 🔥 Передаём в Threat Intel
            self.send_to_threat_intel("deep_scanner", result)

        except Exception as e:
            self.result_box.insert("end", f"\n❌ Ошибка: {e}\n")

    def monitor_log_thread(self):
        import time
        path = os.path.join("logs", "honeypot.log")
        last_size = 0
        while True:
            try:
                if os.path.exists(path):
                    size = os.path.getsize(path)
                    if size > last_size:
                        with open(path, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                        new_lines = lines[-5:]
                        for line in new_lines:
                            if '"xss_detected": true' in line:
                                self.alert_label.config(text="🚨 XSS-попытка!", foreground="red")
                                self.honeypot_log_box.insert("end", f"🔴 {line}\n")
                                self.send_to_threat_intel("honeypot_event", {"event": line})
                            else:
                                self.honeypot_log_box.insert("end", f"⚪ {line}\n")
                        last_size = size
                time.sleep(2)
            except Exception as e:
                self.honeypot_log_box.insert("end", f"❌ Ошибка мониторинга: {e}\n")
                time.sleep(5)

    def check_proxy(self):
        import requests
        proxy = self.proxy_entry.get().strip()
        if not proxy:
            messagebox.showwarning("Пустой прокси", "Сначала укажи адрес прокси")
            return

        proxies = {"http": proxy, "https": proxy}
        try:
            ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=7).text
            messagebox.showinfo("✅ Прокси работает", f"Внешний IP: {ip}")
            entry = {
                "time": datetime.utcnow().isoformat(),
                "proxy": proxy,
                "ip": ip,
                "status": "success"
            }
        except Exception as e:
            messagebox.showerror("❌ Прокси не работает", f"Ошибка:\n{e}")
            entry = {
                "time": datetime.utcnow().isoformat(),
                "proxy": proxy,
                "error": str(e),
                "status": "error"
            }

        try:
            Path("logs").mkdir(exist_ok=True)
            log_path = os.path.join("logs", "proxy_check_log.json")
            if os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = []
            data.append(entry)
            with open(log_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as log_error:
            print(f"[⚠️] Ошибка записи в лог: {log_error}")

        self.send_to_threat_intel("proxy_check", entry)

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

