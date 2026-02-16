# xss_security_gui/token_view_tab.py

import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import secrets
import string
from typing import List, Dict


class TokenViewTab(ttk.Frame):
    """
    TokenViewTab 5.0

    • Больше не зависит от legacy token_generator
    • Умеет:
        - читать токены и их риски из logs/token_risks.json
        - генерировать тестовые токены (ULTRA‑режим) прямо из GUI
    • Формат отображения унифицирован:
        linked_url, value, type, exp, aud, alg, risk_level, risks
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)
        self.build_ui()

    # ============================================================
    #  UI
    # ============================================================

    def build_ui(self):
        ttk.Label(self, text="🔐 Найденные токены:").pack(anchor="w", padx=10, pady=5)

        columns = ("linked_url", "value", "type", "exp", "aud", "alg", "risk_level", "risks")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")

        widths = {
            "linked_url": 250,
            "value": 350,
            "type": 100,
            "exp": 100,
            "aud": 120,
            "alg": 80,
            "risk_level": 90,
            "risks": 200,
        }

        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=widths[col], anchor="w")

        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="📂 Загрузить лог", command=self.load_log).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🧪 Сгенерировать тестовые токены", command=self.generate_and_display_tokens).pack(
            side="left", padx=5
        )

    # ============================================================
    #  Вспомогательные методы
    # ============================================================

    def clear_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    # ============================================================
    #  Загрузка токенов из лога (analyzer / engine output)
    # ============================================================

    def load_log(self, report_path: str = "logs/token_risks.json"):
        try:
            if not os.path.exists(report_path):
                raise FileNotFoundError(f"Файл не найден: {report_path}")

            with open(report_path, encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                raise ValueError("Ожидался список объектов в JSON")

            self.clear_tree()

            for item in data:
                value = item.get("value", "")
                val_short = value[:80] + "..." if len(value) > 80 else value

                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        item.get("linked_url", ""),
                        val_short,
                        item.get("type", ""),
                        item.get("exp", ""),
                        item.get("aud", ""),
                        item.get("alg", ""),
                        item.get("risk_level", ""),
                        "; ".join(item.get("risks", [])),
                    ),
                    tags=("high_risk",) if item.get("risk_level") == "high" else (),
                )

            self.tree.tag_configure("high_risk", background="#ffdddd")

        except Exception as e:
            messagebox.showerror("Ошибка загрузки", f"Не удалось загрузить лог:\n{e}")

    # ============================================================
    #  Генерация тестовых токенов (ULTRA‑режим, без внешних модулей)
    # ============================================================

    def _generate_test_tokens(self, count: int = 20) -> List[Dict]:
        """
        Генератор тестовых токенов 5.0:
        • имитирует разные типы токенов (JWT / opaque / API key)
        • добавляет простой risk‑scoring и источник
        • используется только для демонстрации в GUI
        """
        tokens: List[Dict] = []

        for _ in range(count):
            token_type = secrets.choice(["jwt", "opaque", "api_key"])
            risk_level = secrets.choice(["low", "medium", "high"])

            if token_type == "jwt":
                header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                payload = "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ"
                sig = "".join(secrets.choice(string.ascii_letters + string.digits + "-_") for _ in range(32))
                value = f"{header}.{payload}.{sig}"
                alg = "HS256"
                aud = "example.com"
                exp = "2026-12-31"
                risks = ["admin role", "long-lived", "weak secret"] if risk_level != "low" else ["generic jwt"]

            elif token_type == "api_key":
                value = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
                alg = ""
                aud = "internal-api"
                exp = ""
                risks = ["hardcoded key", "possible cloud access"] if risk_level != "low" else ["generic api key"]

            else:  # opaque
                value = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
                alg = ""
                aud = "session"
                exp = ""
                risks = ["session token", "possible hijack"] if risk_level != "low" else ["generic session token"]

            tokens.append(
                {
                    "linked_url": "",
                    "value": value,
                    "type": token_type,
                    "exp": exp,
                    "aud": aud,
                    "alg": alg,
                    "risk_level": risk_level,
                    "risks": risks,
                    "source": "GUI generator 5.0",
                }
            )

        return tokens

    def generate_and_display_tokens(self):
        try:
            self.clear_tree()

            tokens = self._generate_test_tokens(count=20)

            for token in tokens:
                val_short = token["value"][:80] + "..." if len(token["value"]) > 80 else token["value"]

                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        token.get("linked_url", ""),
                        val_short,
                        token.get("type", ""),
                        token.get("exp", ""),
                        token.get("aud", ""),
                        token.get("alg", ""),
                        token.get("risk_level", ""),
                        "; ".join(token.get("risks", [])),
                    ),
                    tags=("high_risk",) if token.get("risk_level") == "high" else (),
                )

            self.tree.tag_configure("high_risk", background="#ffdddd")
            messagebox.showinfo("Готово", f"Сгенерировано тестовых токенов: {len(tokens)}")

        except Exception as e:
            messagebox.showerror("Ошибка генерации", f"Не удалось сгенерировать токены:\n{e}")