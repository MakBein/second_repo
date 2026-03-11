# xss_security_gui/token_view_tab.py

import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import secrets
import string
from typing import List, Dict, Any


class TokenViewTab(ttk.Frame):
    """
    TokenViewTab 6.5 (ULTRA)

    • Автоматичне визначення типу токена (JWT / API key / opaque)
    • Автоматичний risk‑scoring, навіть якщо лог його не містить
    • Потокобезпечне оновлення UI
    • Швидке завантаження великих логів
    • Уніфікований формат відображення
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
    #  Helpers
    # ============================================================

    def clear_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def _safe_insert(self, values: tuple, high_risk: bool = False):
        """Потокобезпечне вставлення рядка."""
        self.after(0, lambda: self._insert(values, high_risk))

    def _insert(self, values: tuple, high_risk: bool):
        self.tree.insert(
            "",
            tk.END,
            values=values,
            tags=("high_risk",) if high_risk else (),
        )
        self.tree.tag_configure("high_risk", background="#ffdddd")

    # ============================================================
    #  Token classification
    # ============================================================

    def classify_token(self, value: str) -> Dict[str, Any]:
        """Визначає тип токена та базові ризики."""
        if "." in value and value.count(".") == 2:
            return {"type": "jwt", "alg": "?", "aud": "?", "exp": "?", "risks": ["possible JWT"]}

        if value.startswith("AKIA") and len(value) > 16:
            return {"type": "api_key", "alg": "", "aud": "cloud", "exp": "", "risks": ["possible cloud key"]}

        if len(value) > 30:
            return {"type": "opaque", "alg": "", "aud": "session", "exp": "", "risks": ["opaque token"]}

        return {"type": "unknown", "alg": "", "aud": "", "exp": "", "risks": ["unclassified"]}

    def compute_risk_level(self, risks: List[str]) -> str:
        if any("admin" in r.lower() for r in risks):
            return "high"
        if any("cloud" in r.lower() for r in risks):
            return "medium"
        if any("session" in r.lower() for r in risks):
            return "medium"
        return "low"

    # ============================================================
    #  Load tokens from log
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
                short = value[:80] + "..." if len(value) > 80 else value

                # Автокласифікація, якщо лог не містить типу
                meta = self.classify_token(value)

                token_type = item.get("type") or meta["type"]
                alg = item.get("alg") or meta["alg"]
                aud = item.get("aud") or meta["aud"]
                exp = item.get("exp") or meta["exp"]

                risks = item.get("risks") or meta["risks"]
                risk_level = item.get("risk_level") or self.compute_risk_level(risks)

                self._safe_insert(
                    (
                        item.get("linked_url", ""),
                        short,
                        token_type,
                        exp,
                        aud,
                        alg,
                        risk_level,
                        "; ".join(risks),
                    ),
                    high_risk=(risk_level == "high"),
                )

        except Exception as e:
            messagebox.showerror("Ошибка загрузки", f"Не удалось загрузить лог:\n{e}")

    # ============================================================
    #  Test token generator (ULTRA)
    # ============================================================

    def _generate_test_tokens(self, count: int = 20) -> List[Dict]:
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
                risks = ["admin role", "weak secret"] if risk_level != "low" else ["generic jwt"]

            elif token_type == "api_key":
                value = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
                alg = ""
                aud = "internal-api"
                exp = ""
                risks = ["hardcoded key"] if risk_level != "low" else ["generic api key"]

            else:
                value = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
                alg = ""
                aud = "session"
                exp = ""
                risks = ["session token"] if risk_level != "low" else ["generic session token"]

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
                    "source": "GUI generator 6.5",
                }
            )

        return tokens

    def generate_and_display_tokens(self):
        try:
            self.clear_tree()

            tokens = self._generate_test_tokens(count=20)

            for token in tokens:
                short = token["value"][:80] + "..." if len(token["value"]) > 80 else token["value"]

                self._safe_insert(
                    (
                        token.get("linked_url", ""),
                        short,
                        token.get("type", ""),
                        token.get("exp", ""),
                        token.get("aud", ""),
                        token.get("alg", ""),
                        token.get("risk_level", ""),
                        "; ".join(token.get("risks", [])),
                    ),
                    high_risk=(token.get("risk_level") == "high"),
                )

            messagebox.showinfo("Готово", f"Сгенерировано тестовых токенов: {len(tokens)}")

        except Exception as e:
            messagebox.showerror("Ошибка генерации", f"Не удалось сгенерировать токены:\n{e}")