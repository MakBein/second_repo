# xss_security_gui/dom_parser_tab.py
"""
DOMParser Tab — DOM анализ и парсинг форм/скриптов/событий
Интеграция модуля dom_parser в GUI
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List
import requests

try:
    from xss_security_gui.dom_parser import DOMParser, DOMParserAsync
except ImportError:
    DOMParser = None
    DOMParserAsync = None

from xss_security_gui.utils.threat_sender import ThreatSenderMixin
from xss_security_gui.utils.core_utils import normalize_url
from xss_security_gui.file_loader import save_json


class DOMParserTab(ttk.Frame, ThreatSenderMixin):
    """
    Вкладка для анализа DOM структуры веб-страниц.
    Извлекает формы, скрипты, события, медиа и другие элементы.
    """
    
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.current_html = None
        self.dom_results = {}
        self.is_parsing = False
        self.parser = DOMParser() if DOMParser else None
        
        if not self.parser:
            self._show_missing_parser_warning()
        
        self.build_ui()
    
    def _show_missing_parser_warning(self):
        """Показать предупреждение о отсутствии парсера"""
        messagebox.showwarning(
            "⚠️ DOM Parser",
            "DOMParser модуль не загружен. Проверьте зависимости."
        )
    
    def build_ui(self):
        """Построение интерфейса"""
        # ========================================
        # Панель управления
        # ========================================
        ctrl_frame = ttk.LabelFrame(self, text="🔧 Управление", padding=10)
        ctrl_frame.pack(fill="x", padx=10, pady=5)
        
        # Ввод URL или пути к HTML файлу
        url_frame = ttk.Frame(ctrl_frame)
        url_frame.pack(fill="x", pady=5)
        
        ttk.Label(url_frame, text="URL/Файл:").pack(side="left", padx=5)
        self.url_entry = ttk.Entry(url_frame, width=40)
        self.url_entry.insert(0, "https://example.com")
        self.url_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        ttk.Button(url_frame, text="📂 Загрузить HTML", command=self.load_html_file).pack(side="left", padx=2)
        
        # Кнопки действий
        btn_frame = ttk.Frame(ctrl_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="🌐 Загрузить с URL", command=self.fetch_and_parse).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="📄 Анализировать HTML", command=self.parse_html).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="🗑️ Очистить", command=self.clear_results).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="💾 Экспорт JSON", command=self.export_results).pack(side="left", padx=2)
        
        # Опции анализа
        options_frame = ttk.LabelFrame(ctrl_frame, text="⚙️ Опции анализа", padding=5)
        options_frame.pack(fill="x", pady=5)
        
        self.extract_forms_var = tk.BooleanVar(value=True)
        self.extract_scripts_var = tk.BooleanVar(value=True)
        self.extract_events_var = tk.BooleanVar(value=True)
        self.extract_media_var = tk.BooleanVar(value=True)
        self.extract_links_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="📋 Формы", variable=self.extract_forms_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="📜 Скрипты", variable=self.extract_scripts_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="⚡ События", variable=self.extract_events_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="🖼️ Медиа", variable=self.extract_media_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="🔗 Ссылки", variable=self.extract_links_var).pack(side="left", padx=5)
        
        # ========================================
        # Панель результатов
        # ========================================
        result_frame = ttk.LabelFrame(self, text="📊 Результаты анализа", padding=10)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Вкладки для разных типов результатов
        self.notebook = ttk.Notebook(result_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Вкладка 1: Общая информация
        self.summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.summary_frame, text="📋 Сводка")
        
        self.summary_text = tk.Text(self.summary_frame, height=15, bg="#1e1e1e", fg="#00ff00", wrap="word")
        scrollbar = ttk.Scrollbar(self.summary_frame, orient="vertical", command=self.summary_text.yview)
        self.summary_text.configure(yscrollcommand=scrollbar.set)
        self.summary_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Вкладка 2: Формы
        self.forms_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.forms_frame, text="📋 Формы")
        
        self.forms_text = tk.Text(self.forms_frame, height=15, bg="#1e1e1e", fg="#ffff00", wrap="word")
        scrollbar = ttk.Scrollbar(self.forms_frame, orient="vertical", command=self.forms_text.yview)
        self.forms_text.configure(yscrollcommand=scrollbar.set)
        self.forms_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Вкладка 3: Скрипты
        self.scripts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scripts_frame, text="📜 Скрипты")
        
        self.scripts_text = tk.Text(self.scripts_frame, height=15, bg="#1e1e1e", fg="#00ffff", wrap="word")
        scrollbar = ttk.Scrollbar(self.scripts_frame, orient="vertical", command=self.scripts_text.yview)
        self.scripts_text.configure(yscrollcommand=scrollbar.set)
        self.scripts_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Вкладка 4: События
        self.events_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.events_frame, text="⚡ События")
        
        self.events_text = tk.Text(self.events_frame, height=15, bg="#1e1e1e", fg="#ff00ff", wrap="word")
        scrollbar = ttk.Scrollbar(self.events_frame, orient="vertical", command=self.events_text.yview)
        self.events_text.configure(yscrollcommand=scrollbar.set)
        self.events_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Вкладка 5: Медиа
        self.media_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.media_frame, text="🖼️ Медиа")
        
        self.media_text = tk.Text(self.media_frame, height=15, bg="#1e1e1e", fg="#00ff99", wrap="word")
        scrollbar = ttk.Scrollbar(self.media_frame, orient="vertical", command=self.media_text.yview)
        self.media_text.configure(yscrollcommand=scrollbar.set)
        self.media_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # ========================================
        # Статус бар
        # ========================================
        self.status_label = ttk.Label(self, text="Готов к анализу", relief="sunken")
        self.status_label.pack(fill="x", padx=5, pady=2)
        
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill="x", padx=5, pady=1)
    
    def load_html_file(self):
        """Загрузить HTML файл"""
        path = filedialog.askopenfilename(
            title="Выбери HTML файл",
            filetypes=[("HTML files", "*.html *.htm"), ("All files", "*.*")]
        )
        if path:
            self.url_entry.delete(0, "end")
            self.url_entry.insert(0, path)
    
    def fetch_and_parse(self):
        """Загрузить страницу с URL и анализировать её"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("⚠️ Требуется URL", "Пожалуйста, введите URL")
            return
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        threading.Thread(target=self._fetch_and_parse_thread, args=(url,), daemon=True).start()
    
    def _fetch_and_parse_thread(self, url):
        """Поток для загрузки и анализа"""
        try:
            self._update_status("⏳ Загрузка страницы...", True)
            
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            self.current_html = response.text
            
            self._update_status("🔍 Анализ DOM...", True)
            self.parse_html()
            
        except requests.exceptions.Timeout:
            self._update_status("❌ Таймаут при загрузке URL", False)
            messagebox.showerror("Ошибка", "Таймаут при загрузке URL")
        except requests.exceptions.ConnectionError:
            self._update_status("❌ Ошибка подключения", False)
            messagebox.showerror("Ошибка", "Ошибка подключения к URL")
        except Exception as e:
            self._update_status(f"❌ Ошибка: {e}", False)
            messagebox.showerror("Ошибка", f"Ошибка загрузки: {e}")
    
    def parse_html(self):
        """Анализировать HTML"""
        if not self.current_html:
            # Попытаться загрузить из файла
            path = self.url_entry.get().strip()
            if os.path.isfile(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        self.current_html = f.read()
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка чтения файла: {e}")
                    return
            else:
                messagebox.showwarning("⚠️ HTML не загружен", "Сначала загрузите страницу с URL или выберите HTML файл")
                return
        
        threading.Thread(target=self._parse_thread, daemon=True).start()
    
    def _parse_thread(self):
        """Поток для анализа"""
        try:
            self._update_status("🔍 Анализ DOM структуры...", True)
            
            if not self.parser:
                self._update_status("❌ DOMParser не доступен", False)
                return
            
            # Парсим HTML
            results = self.parser.parse(self.current_html)
            self.dom_results = results
            
            # Отображаем результаты
            self._display_results(results)
            self._update_status("✅ Анализ завершён", False)
            messagebox.showinfo("✅ Анализ", "Анализ DOM завершён успешно!")
            
        except Exception as e:
            self._update_status(f"❌ Ошибка анализа: {e}", False)
            messagebox.showerror("Ошибка", f"Ошибка при анализе: {e}")
    
    def _display_results(self, results: Dict[str, Any]):
        """Отобразить результаты анализа"""
        # Очистить все вкладки
        self.summary_text.delete("1.0", "end")
        self.forms_text.delete("1.0", "end")
        self.scripts_text.delete("1.0", "end")
        self.events_text.delete("1.0", "end")
        self.media_text.delete("1.0", "end")
        
        # Сводка
        summary = f"""
═══════════════════════════════════════════════════════════════
🔍 DOM АНАЛИЗ — СВОДКА
═══════════════════════════════════════════════════════════════

📊 Статистика:
  • Всего элементов: {len(results.get('elements', []))}
  • Форм: {len(results.get('forms', []))}
  • Скриптов: {len(results.get('scripts', []))}
  • Событий: {len(results.get('events', []))}
  • Медиа: {len(results.get('media', []))}
  • Ссылок: {len(results.get('links', []))}

⚠️ Потенциальные риски:
  • Встроенные скрипты: {len([s for s in results.get('scripts', []) if 'inline' in str(s)])}
  • Элементы с обработчиками: {len(results.get('events', []))}

═══════════════════════════════════════════════════════════════
"""
        self.summary_text.insert("1.0", summary)
        
        # Формы
        if self.extract_forms_var.get():
            forms_text = "═══════════════════════════════════════════════════════════════\n"
            forms_text += "📋 ФОРМЫ\n"
            forms_text += "═══════════════════════════════════════════════════════════════\n\n"
            
            for idx, form in enumerate(results.get('forms', []), 1):
                forms_text += f"🔹 Форма #{idx}\n"
                forms_text += f"   Action: {form.get('action', '—')}\n"
                forms_text += f"   Method: {form.get('method', 'GET')}\n"
                forms_text += f"   Inputs: {', '.join([i.get('name', '?') for i in form.get('inputs', [])])}\n"
                forms_text += f"   JS обработчики: {', '.join(form.get('js_events', {}).keys()) if form.get('js_events') else '—'}\n\n"
            
            self.forms_text.insert("1.0", forms_text)
        
        # Скрипты
        if self.extract_scripts_var.get():
            scripts_text = "═══════════════════════════════════════════════════════════════\n"
            scripts_text += "📜 СКРИПТЫ\n"
            scripts_text += "═══════════════════════════════════════════════════════════════\n\n"
            
            for idx, script in enumerate(results.get('scripts', []), 1):
                src = script.get('src', '')
                content = script.get('content', '')
                inline = "[INLINE]" if content else f"[EXTERNAL]"
                scripts_text += f"🔹 Скрипт #{idx} {inline}\n"
                if src:
                    scripts_text += f"   Src: {src}\n"
                if content:
                    preview = content[:100].replace('\n', ' ')
                    scripts_text += f"   Content: {preview}...\n"
                scripts_text += "\n"
            
            self.scripts_text.insert("1.0", scripts_text)
        
        # События
        if self.extract_events_var.get():
            events_text = "═══════════════════════════════════════════════════════════════\n"
            events_text += "⚡ СОБЫТИЯ И ОБРАБОТЧИКИ\n"
            events_text += "═══════════════════════════════════════════════════════════════\n\n"
            
            for idx, event in enumerate(results.get('events', []), 1):
                events_text += f"🔹 Событие #{idx}\n"
                events_text += f"   Тип: {event.get('type', '?')}\n"
                events_text += f"   Элемент: {event.get('element', '?')}\n"
                events_text += f"   Обработчик: {event.get('handler', '—')}\n"
                events_text += f"   Риск: {'⚠️ ВЫСОКИЙ' if event.get('risk') == 'high' else 'ℹ️ СРЕДНИЙ' if event.get('risk') == 'medium' else '✓ НИЗКИЙ'}\n\n"
            
            self.events_text.insert("1.0", events_text)
        
        # Медиа
        if self.extract_media_var.get():
            media_text = "═══════════════════════════════════════════════════════════════\n"
            media_text += "🖼️  МЕДИА (изображения, видео, аудио)\n"
            media_text += "═══════════════════════════════════════════════════════════════\n\n"
            
            for idx, media in enumerate(results.get('media', []), 1):
                media_text += f"🔹 Медиа #{idx}\n"
                media_text += f"   Тип: {media.get('type', '?')}\n"
                media_text += f"   Src: {media.get('src', '—')[:80]}...\n"
                media_text += f"   Alt: {media.get('alt', '—')}\n\n"
            
            self.media_text.insert("1.0", media_text)
    
    def clear_results(self):
        """Очистить результаты"""
        self.summary_text.delete("1.0", "end")
        self.forms_text.delete("1.0", "end")
        self.scripts_text.delete("1.0", "end")
        self.events_text.delete("1.0", "end")
        self.media_text.delete("1.0", "end")
        self.dom_results = {}
        self.current_html = None
        self.status_label.config(text="Готов к анализу")
    
    def export_results(self):
        """Экспортировать результаты в JSON"""
        if not self.dom_results:
            messagebox.showwarning("⚠️ Нет результатов", "Сначала проведите анализ")
            return
        
        path = filedialog.asksaveasfilename(
            title="Сохранить результаты DOM анализа",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not path:
            return
        
        try:
            export_data = {
                "exported_at": datetime.now().isoformat(),
                "module": "dom_parser_tab",
                "analysis": self.dom_results
            }
            
            save_json(path, export_data)
            messagebox.showinfo("✅ Экспорт", f"Результаты сохранены:\n{path}")
            self._update_status(f"✅ Экспортировано в {path}", False)
            
            # Отправить в Threat Intel
            if self.threat_tab:
                self.send_to_threat_intel("dom_parser", [self.dom_results])
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при экспорте: {e}")
    
    def _update_status(self, text: str, is_loading: bool = False):
        """Обновить статус"""
        def update():
            self.status_label.config(text=text)
            if is_loading:
                self.progress.start()
            else:
                self.progress.stop()
        
        if threading.current_thread() == threading.main_thread():
            update()
        else:
            self.after(0, update)

