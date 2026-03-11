# xss_security_gui/xss_tab.py

import os
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any, Dict, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.xss_module import XSSTester


class XSSTab(ttk.Frame):
    """
    XSSTab ULTRA 6.x

    • Гнучке завантаження payload-файлу:
      - явний шлях
      - settings["xss.payload_file"]
      - дефолтний "xss_payloads.json" біля модуля
    • Потокобезпечний лог (через .after)
    • Толерантний до формату результатів TesterBase:
      - не вимагає обов'язкової наявності response_length
      - працює з будь-яким підкласом XSSTester/TesterBase
    """

    def __init__(self, parent: tk.Misc, url: str, payload_file: str | None = None) -> None:
        super().__init__(parent)

        self.url = url

        # Шлях до payload-файлу: або явно, або з settings, або дефолт
        default_payload_file = settings.get("xss.payload_file", "xss_payloads.json")
        base_dir = os.path.dirname(__file__)
        self.payload_file = payload_file or os.path.join(base_dir, default_payload_file)

        self.payloads: Dict[str, List[str]] = self._load_payloads()
        self._build_ui()

    # ---------------------------------------------------------
    # Payload loader
    # ---------------------------------------------------------
    def _load_payloads(self) -> Dict[str, List[str]]:
        """
        Завантажує payload-и з JSON-файлу.
        Очікується формат:
        {
            "category1": ["payload1", "payload2", ...],
            "category2": [...]
        }
        """
        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("Файл payload-ів повинен містити JSON-об'єкт з категоріями")

            # Нормалізація: гарантуємо, що значення — списки рядків
            normalized: Dict[str, List[str]] = {}
            for cat, items in data.items():
                if isinstance(items, list):
                    normalized[cat] = [str(x) for x in items]
                else:
                    normalized[cat] = [str(items)]
            return normalized

        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося завантажити XSS payload-и:\n{e}")
            return {}

    # ---------------------------------------------------------
    # UI builder
    # ---------------------------------------------------------
    def _build_ui(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        # URL (read-only)
        ttk.Label(top, text="Цільовий URL:").grid(row=0, column=0, sticky="w", padx=5)
        self.url_var = tk.StringVar(value=self.url)
        ttk.Entry(top, textvariable=self.url_var, width=70, state="readonly").grid(
            row=0, column=1, columnspan=3, sticky="we", padx=5
        )

        # Параметр
        ttk.Label(top, text="Параметр:").grid(row=1, column=0, sticky="w", padx=5)
        self.param_entry = ttk.Entry(top, width=20)
        self.param_entry.insert(0, "q")
        self.param_entry.grid(row=1, column=1, sticky="w", padx=5)

        # Значення
        ttk.Label(top, text="Базове значення:").grid(row=1, column=2, sticky="e", padx=5)
        self.value_entry = ttk.Entry(top, width=20)
        self.value_entry.insert(0, "")
        self.value_entry.grid(row=1, column=3, sticky="w", padx=5)

        # Категорія payload-ів
        ttk.Label(top, text="Категорія payload-ів:").grid(row=2, column=0, sticky="w", padx=5)
        self.category_var = tk.StringVar(self)
        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_var.set("Всі категорії")
        self.category_combo = ttk.Combobox(
            top,
            textvariable=self.category_var,
            values=categories,
            state="readonly",
        )
        self.category_combo.grid(row=2, column=1, sticky="w", padx=5)

        # Buttons
        btn_frame = ttk.Frame(top)
        btn_frame.grid(row=2, column=2, columnspan=2, sticky="e", padx=5)

        ttk.Button(btn_frame, text="💉 Запустити", command=self.run_tests).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="🧹 Очистити вивід", command=self.clear_output).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="📂 Вибрати payload-файл", command=self.choose_payload_file).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="🗑 Очистити лог артефактів", command=self.clear_artifact_log).pack(
            side="left", padx=3
        )

        # Output
        self.output = tk.Text(
            self,
            height=20,
            wrap="none",
            bg="black",
            fg="lime",
            insertbackground="white",
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

    # ---------------------------------------------------------
    # Потокобезпечний лог
    # ---------------------------------------------------------
    def _safe_log(self, text: str) -> None:
        self.after(0, lambda: self._append_text(text))

    def _append_text(self, text: str) -> None:
        self.output.insert("end", text)
        self.output.see("end")

    # ---------------------------------------------------------
    # Actions
    # ---------------------------------------------------------
    def run_tests(self) -> None:
        if not self.payloads:
            messagebox.showerror("Помилка", "Payload-и не завантажені")
            return

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param:
            self._safe_log("⚠️ Введіть параметр перед запуском\n")
            return

        # Вибір payload-ів
        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads.get(category, [])}

        # Якщо в обраній категорії немає payload-ів — лог, але не падаємо
        total = sum(len(v) for v in selected_payloads.values())
        if total == 0:
            self._safe_log("⚠️ У вибраній категорії немає payload-ів\n")
            return

        tester = XSSTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self.display_result,
        )
        tester.start()

        self._safe_log(f"🚀 Запущено XSS-тестування для {self.url} (param={param})\n")

    def display_result(self, result: Dict[str, Any]) -> None:
        """
        Гнучкий, безпечний вивід результатів:
        - не падає, якщо немає ключів
        - працює з будь-яким підкласом TesterBase
        """
        if not isinstance(result, dict):
            self._safe_log(f"⚠️ Некоректний формат результату: {result!r}\n")
            return

        status = result.get("status", "unknown")
        length = result.get("response_length")
        category = result.get("category", "?")
        payload = result.get("payload", "?")

        if isinstance(length, (int, float)):
            len_part = f"(len={int(length)})"
        else:
            len_part = ""

        line = f"[{category}] {payload} → {status} {len_part}\n"
        self._safe_log(line)

    def clear_output(self) -> None:
        self.output.delete("1.0", "end")

    def choose_payload_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Вибрати файл XSS payload-ів",
            filetypes=[("JSON файли", "*.json"), ("Всі файли", "*.*")],
        )
        if not path:
            return

        self.payload_file = path
        self.payloads = self._load_payloads()

        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_combo["values"] = categories
        self.category_var.set("Всі категорії")

        self._safe_log(f"✅ Payload-и завантажено з: {path}\n")

    def clear_artifact_log(self) -> None:
        artifact_path = settings.get("threat_intel.artifact_path", "threat_artifacts.json")
        try:
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump([], f)
            self._safe_log(f"✅ Лог артефактів очищено: {artifact_path}\n")
        except Exception as e:
            self._safe_log(f"❌ Помилка очищення: {e}\n")