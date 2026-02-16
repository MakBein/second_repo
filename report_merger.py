# xss_security_gui/report_merger.py
"""
Threat Report Merger ULTRA 5.0

- Асинхронное объединение логов form_fuzzer, api_parser и других модулей
- Нормализация данных для Threat Intel
- Устойчивость к ошибкам
- Callback после завершения
- Готово для интеграции с OverviewTab и ThreatAnalysisTab
"""

import os
import json
import threading
from typing import Callable, Optional, Dict, Any


class ReportMerger:
    def __init__(
        self,
        form_fuzzer_path: str = "logs/form_fuzz_hits.log",
        api_parser_path: str = "logs/api_parser_results.json",
        out_path: str = "logs/threatintel_report.json",
    ):
        self.form_fuzzer_path = form_fuzzer_path
        self.api_parser_path = api_parser_path
        self.out_path = out_path

        self.report: Dict[str, Any] = {
            "form_fuzzer": [],
            "api_parser": {},
            "meta": {
                "merged": False,
                "sources": [],
            }
        }

    # ============================================================
    #  Публичный API
    # ============================================================

    def merge(self) -> Dict[str, Any]:
        """Синхронное объединение отчётов."""
        self._load_form_fuzzer()
        self._load_api_parser()
        self._save()
        self.report["meta"]["merged"] = True
        return self.report

    def merge_async(self, callback: Optional[Callable[[Dict[str, Any], Optional[Exception]], None]] = None):
        """
        Асинхронное объединение отчётов.
        callback(report, error)
        """

        def worker():
            try:
                result = self.merge()
                if callback:
                    callback(result, None)
            except Exception as e:
                if callback:
                    callback({}, e)

        threading.Thread(target=worker, daemon=True).start()

    # ============================================================
    #  Внутренние методы
    # ============================================================

    def _load_form_fuzzer(self):
        """Чтение и нормализация form_fuzzer."""
        if not os.path.exists(self.form_fuzzer_path):
            return

        try:
            with open(self.form_fuzzer_path, encoding="utf-8") as f:
                raw = f.read().strip()

            blocks = [b.strip() for b in raw.split("\n\n") if b.strip()]

            normalized = []
            for block in blocks:
                normalized.append({
                    "raw": block,
                    "severity": self._detect_severity(block),
                    "indicators": self._extract_indicators(block),
                })

            self.report["form_fuzzer"] = normalized
            self.report["meta"]["sources"].append("form_fuzzer")

        except Exception as e:
            self.report["form_fuzzer"] = [{"error": str(e)}]

    def _load_api_parser(self):
        """Чтение и нормализация api_parser."""
        if not os.path.exists(self.api_parser_path):
            return

        try:
            with open(self.api_parser_path, encoding="utf-8") as f:
                data = json.load(f)

            normalized = {
                "endpoints": data.get("endpoints", []),
                "tokens": data.get("tokens", []),
                "emails": data.get("emails", []),
                "ips": data.get("ips", []),
                "raw": data,
            }

            self.report["api_parser"] = normalized
            self.report["meta"]["sources"].append("api_parser")

        except Exception as e:
            self.report["api_parser"] = {"error": str(e)}

    def _save(self):
        """Сохранение объединённого отчёта."""
        os.makedirs(os.path.dirname(self.out_path), exist_ok=True)
        try:
            with open(self.out_path, "w", encoding="utf-8") as f:
                json.dump(self.report, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[❌] Ошибка сохранения отчёта: {e}")

    # ============================================================
    #  Утилиты нормализации
    # ============================================================

    def _detect_severity(self, text: str) -> str:
        """Простейшая эвристика определения уровня угрозы."""
        text_low = text.lower()
        if any(x in text_low for x in ["critical", "exploit", "xss", "csrf", "sqli"]):
            return "HIGH"
        if any(x in text_low for x in ["warning", "suspicious"]):
            return "MEDIUM"
        return "LOW"

    def _extract_indicators(self, text: str):
        """Извлечение индикаторов из текста."""
        indicators = []
        for token in text.split():
            if "http" in token:
                indicators.append({"type": "url", "value": token})
            if "token" in token.lower():
                indicators.append({"type": "token", "value": token})
            if "@" in token:
                indicators.append({"type": "email", "value": token})
        return indicators


# ============================================================
#  Пример использования
# ============================================================

if __name__ == "__main__":
    merger = ReportMerger()

    def done(report, error):
        if error:
            print("Ошибка:", error)
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))

    merger.merge_async(done)