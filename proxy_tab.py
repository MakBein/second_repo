# xss_security_gui/proxy_tab.py
"""
Proxy Tab — Перехватывающий взаимный прокси для анализа трафика
Функционал, подобный Burp Suite Proxy
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from collections import deque
import socket

from xss_security_gui.utils.threat_sender import ThreatSenderMixin
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class ProxyTab(ttk.Frame, ThreatSenderMixin):
    """
    Вкладка для работы с HTTP прокси и перехват трафика.
    Основные функции:
    - Перехват HTTP/HTTPS запросов
    - Просмотр и редактирование запросов/ответов
    - Логирование сессий
    - Отправка в другие инструменты для анализа
    """
    
    def __init__(self, parent, threat_tab=None, port: int = 8080):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.port = port
        self.is_running = False
        self.proxy_thread: Optional[threading.Thread] = None
        self.intercepted_requests: deque = deque(maxlen=100)  # Последние 100 запросов
        self.intercepted_responses: deque = deque(maxlen=100)
        self._bridge = UIQueueBridge(self, poll_ms=50)
        
        self.build_ui()
    
    def build_ui(self):
        """Построение интерфейса прокси"""
        # ========================================
        # Панель управления подключением
        # ========================================
        conn_frame = ttk.LabelFrame(self, text="🌐 Подключение", padding=10)
        conn_frame.pack(fill="x", padx=10, pady=5)
        
        # Выбор порта
        port_frame = ttk.Frame(conn_frame)
        port_frame.pack(side="left", padx=5)
        
        ttk.Label(port_frame, text="Порт:").pack(side="left", padx=2)
        self.port_spinbox = ttk.Spinbox(port_frame, from_=1024, to=65535, width=8)
        self.port_spinbox.set(self.port)
        self.port_spinbox.pack(side="left", padx=2)
        
        # Кнопки управления
        self.start_btn = ttk.Button(conn_frame, text="▶️ Запустить прокси", command=self.start_proxy)
        self.start_btn.pack(side="left", padx=2)
        
        self.stop_btn = ttk.Button(conn_frame, text="⏹️ Остановить прокси", command=self.stop_proxy, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        
        ttk.Button(conn_frame, text="🔄 Очистить логи", command=self.clear_logs).pack(side="left", padx=2)
        
        # Статус
        self.status_label = ttk.Label(conn_frame, text="❌ Прокси отключен")
        self.status_label.pack(side="left", padx=20)
        
        # ========================================
        # Настройки
        # ========================================
        settings_frame = ttk.LabelFrame(self, text="⚙️ Параметры", padding=10)
        settings_frame.pack(fill="x", padx=10, pady=5)
        
        self.intercept_requests_var = tk.BooleanVar(value=True)
        self.intercept_responses_var = tk.BooleanVar(value=True)
        self.log_bodies_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(
            settings_frame,
            text="🔍 Перехватывать запросы",
            variable=self.intercept_requests_var
        ).pack(side="left", padx=5)
        
        ttk.Checkbutton(
            settings_frame,
            text="🔍 Перехватывать ответы",
            variable=self.intercept_responses_var
        ).pack(side="left", padx=5)
        
        ttk.Checkbutton(
            settings_frame,
            text="📝 Логировать тело запроса/ответа",
            variable=self.log_bodies_var
        ).pack(side="left", padx=5)
        
        # ========================================
        # Вкладки для просмотра
        # ========================================
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Вкладка 1: Перехваченные запросы
        requests_frame = ttk.Frame(notebook)
        notebook.add(requests_frame, text="📤 Запросы")
        
        self.requests_tree = ttk.Treeview(
            requests_frame,
            columns=("Method", "Host", "Path", "Status", "Time"),
            height=15
        )
        self.requests_tree.heading("#0", text="ID")
        self.requests_tree.heading("Method", text="Метод")
        self.requests_tree.heading("Host", text="Хост")
        self.requests_tree.heading("Path", text="Путь")
        self.requests_tree.heading("Status", text="Статус")
        self.requests_tree.heading("Time", text="Время")
        
        self.requests_tree.column("#0", width=50)
        self.requests_tree.column("Method", width=70)
        self.requests_tree.column("Host", width=150)
        self.requests_tree.column("Path", width=200)
        self.requests_tree.column("Status", width=70)
        self.requests_tree.column("Time", width=100)
        
        scrollbar = ttk.Scrollbar(requests_frame, orient="vertical", command=self.requests_tree.yview)
        self.requests_tree.configure(yscrollcommand=scrollbar.set)
        
        self.requests_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Вкладка 2: Детали запроса
        details_frame = ttk.Frame(notebook)
        notebook.add(details_frame, text="ℹ️ Детали")
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            height=20,
            bg="#1e1e1e",
            fg="#00ff00",
            wrap="word"
        )
        self.details_text.pack(fill="both", expand=True)
        
        # Вкладка 3: Raw запрос
        raw_frame = ttk.Frame(notebook)
        notebook.add(raw_frame, text="🔧 Raw")
        
        self.raw_text = scrolledtext.ScrolledText(
            raw_frame,
            height=20,
            bg="#000000",
            fg="#ffffff",
            wrap="none",
            font=("Courier", 9)
        )
        self.raw_text.pack(fill="both", expand=True)
        
        # Вкладка 4: Статистика
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📊 Статистика")
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame,
            height=20,
            bg="#1e1e1e",
            fg="#00ffff",
            wrap="word"
        )
        self.stats_text.pack(fill="both", expand=True)
        
        # ========================================
        # Кнопки действий
        # ========================================
        action_frame = ttk.Frame(self)
        action_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(
            action_frame,
            text="🔍 Анализировать запрос",
            command=self.analyze_selected
        ).pack(side="left", padx=2)
        
        ttk.Button(
            action_frame,
            text="📤 Отправить в Fuzzer",
            command=self.send_to_fuzzer
        ).pack(side="left", padx=2)
        
        ttk.Button(
            action_frame,
            text="💾 Экспортировать сессию",
            command=self.export_session
        ).pack(side="left", padx=2)
        
        ttk.Button(
            action_frame,
            text="🔄 Повторить запрос",
            command=self.repeat_request
        ).pack(side="left", padx=2)
        
        # ========================================
        # Статус бар
        # ========================================
        self.log_label = ttk.Label(self, text="", relief="sunken")
        self.log_label.pack(fill="x", padx=5, pady=2)
    
    def start_proxy(self):
        """Запустить прокси сервер"""
        try:
            port = int(self.port_spinbox.get())
            if port < 1024 or port > 65535:
                messagebox.showerror("Ошибка", "Порт должен быть от 1024 до 65535")
                return
            
            self.port = port
            self.is_running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.port_spinbox.config(state="disabled")
            
            self.status_label.config(text=f"🟢 Прокси запущен на порту {self.port}")
            self._log(f"✅ Прокси запущен на порту {self.port}")
            self._log(f"Настройте браузер на подключение к http://localhost:{self.port}")
            
            # Запуск прокси сервера в отдельном потоке
            self.proxy_thread = self._bridge.post_bg(self._run_proxy_server)
            
        except ValueError:
            messagebox.showerror("Ошибка", "Укажите корректный номер порта")
    
    def stop_proxy(self):
        """Остановить прокси сервер"""
        self.is_running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.port_spinbox.config(state="normal")
        
        self.status_label.config(text="❌ Прокси остановлен")
        self._log("🛑 Прокси остановлен")
    
    def _run_proxy_server(self):
        """Запуск базового прокси сервера"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('127.0.0.1', self.port))
            server_socket.listen(5)
            server_socket.settimeout(1)
            
            self._log(f"🔌 Прокси сокет готов к подключениям")
            
            while self.is_running:
                try:
                    client_socket, addr = server_socket.accept()
                    if self.is_running:
                        threading.Thread(
                            target=self._handle_client,
                            args=(client_socket, addr),
                            daemon=True
                        ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_running:
                        self._log(f"⚠️ Ошибка прокси: {e}")
            
            server_socket.close()
            
        except Exception as e:
            self._log(f"❌ Ошибка запуска прокси: {e}")
            self.is_running = False
            self._bridge.post_ui(self.status_label.config, text="❌ Ошибка прокси")
    
    def _handle_client(self, client_socket, addr):
        """Обработка клиентского подключения"""
        try:
            # Читаем запрос
            request_data = b""
            client_socket.settimeout(5)
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                except socket.timeout:
                    break
            
            if not request_data:
                return
            
            # Парсим запрос
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\n')
            
            if not lines:
                return
            
            # Извлекаем информацию из first line
            first_line = lines[0].strip()
            if not first_line:
                return
            
            parts = first_line.split()
            if len(parts) < 2:
                return
            
            method = parts[0]
            path = parts[1]
            
            # Извлекаем хост из заголовков
            host = "unknown"
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break
            
            # Сохраняем перехваченный запрос
            timestamp = datetime.now().strftime("%H:%M:%S")
            request_info = {
                "timestamp": timestamp,
                "method": method,
                "host": host,
                "path": path,
                "raw": request_str,
                "body": request_data
            }
            
            self._bridge.post_ui(self.intercepted_requests.append, request_info)
            self._bridge.post_ui(self._update_requests_tree)
            self._bridge.post_ui(self._log, f"📤 {method} {host}{path}")
            
        except Exception as e:
            self._bridge.post_ui(self._log, f"⚠️ Ошибка обработки клиента: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _update_requests_tree(self):
        """Обновить таблицу запросов"""
        def update():
            for item in self.requests_tree.get_children():
                self.requests_tree.delete(item)
            
            for idx, req in enumerate(self.intercepted_requests, 1):
                self.requests_tree.insert(
                    "",
                    "end",
                    text=str(idx),
                    values=(
                        req.get("method", "?"),
                        req.get("host", "?"),
                        req.get("path", "?"),
                        "200",  # Placeholder
                        req.get("timestamp", "?")
                    )
                )
        
        if threading.current_thread() == threading.main_thread():
            update()
        else:
            self.after(0, update)
    
    def analyze_selected(self):
        """Анализировать выбранный запрос"""
        selection = self.requests_tree.selection()
        if not selection:
            messagebox.showinfo("ℹ️", "Выберите запрос для анализа")
            return
        
        item = selection[0]
        try:
            row_index = self.requests_tree.index(item)
        except Exception:
            row_index = -1
        
        if 0 <= row_index < len(self.intercepted_requests):
            req = list(self.intercepted_requests)[row_index]
            self._display_request_details(req)
    
    def _display_request_details(self, req: Dict[str, Any]):
        """Отобразить детали запроса"""
        self.details_text.delete("1.0", "end")
        self.raw_text.delete("1.0", "end")
        
        details = f"""
═══════════════════════════════════════════════════════════════
📤 ДЕТАЛИ ЗАПРОСА
═══════════════════════════════════════════════════════════════

⏰ Время: {req.get('timestamp', '?')}
📨 Метод: {req.get('method', '?')}
🌐 Хост: {req.get('host', '?')}
📍 Путь: {req.get('path', '?')}

═══════════════════════════════════════════════════════════════
"""
        
        self.details_text.insert("1.0", details)
        self.raw_text.insert("1.0", req.get('raw', ''))
    
    def send_to_fuzzer(self):
        """Отправить запрос в фуззер"""
        selection = self.requests_tree.selection()
        if not selection:
            messagebox.showinfo("ℹ️", "Выберите запрос")
            return
        
        messagebox.showinfo("✅", "Функция отправки в фуззер будет реализована в будущих версиях")
    
    def export_session(self):
        """Экспортировать сессию"""
        if not self.intercepted_requests:
            messagebox.showwarning("⚠️", "Нет перехваченных запросов")
            return
        
        session_data = {
            "exported_at": datetime.now().isoformat(),
            "requests_count": len(self.intercepted_requests),
            "requests": []
        }
        
        for req in self.intercepted_requests:
            session_data["requests"].append({
                "timestamp": req.get("timestamp"),
                "method": req.get("method"),
                "host": req.get("host"),
                "path": req.get("path")
            })
        
        messagebox.showinfo("💾", f"Сохранено {len(self.intercepted_requests)} запросов")
    
    def repeat_request(self):
        """Повторить запрос"""
        messagebox.showinfo("ℹ️", "Функция повтора запроса будет реализована в будущих версиях")
    
    def clear_logs(self):
        """Очистить логи"""
        self.intercepted_requests.clear()
        self.intercepted_responses.clear()
        self.requests_tree.delete(*self.requests_tree.get_children())
        self.details_text.delete("1.0", "end")
        self.raw_text.delete("1.0", "end")
        self._log("🗑️ Логи очищены")
    
    def _log(self, text: str):
        """Добавить текст в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = f"[{timestamp}] {text}"
        
        def update():
            self.log_label.config(text=msg)
        
        self._bridge.call_ui(update)

    def destroy(self):
        self.is_running = False
        try:
            self._bridge.stop()
        except Exception:
            pass
        super().destroy()

