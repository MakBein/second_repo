# xss_security_gui/auto_recon/token_extractor.py
"""
Token Extractor ULTRA 6.5
-------------------------
• Извлекает токены из заголовков и HTML
• Анализирует JWT и CSRF
• Оценивает риски
• Сохраняет отчёт в JSON
• Поддерживает CLI и GUI режимы
"""
import sys
import re
import json
import logging
import threading
from pathlib import Path
from typing import List, Dict, Any

from xss_security_gui.utils.jwt_decoder import decode_jwt, assess_risks
from xss_security_gui.settings import LOG_DIR

# 📁 Универсальный путь к логам
LOG_DIR: Path = LOG_DIR / "tokens"
LOG_FILE: Path = LOG_DIR / "token_risks.json"
LOG_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
#  Извлечение токенов
# ============================================================
def extract_tokens(headers: Dict[str, str], html: str) -> List[Dict[str, str]]:
    """Извлекает токены из заголовков и HTML."""
    tokens: List[Dict[str, str]] = []
    try:
        # Заголовки
        for k, v in headers.items():
            if "token" in k.lower() or "authorization" in k.lower():
                tokens.append({"source": k, "value": v})

        # CSRF hidden field
        csrf_matches = re.findall(r'name=["\']csrf["\'].*?value=["\'](.*?)["\']', html, re.I)
        for match in csrf_matches:
            tokens.append({"source": "CSRF Hidden Field", "value": match})

        # localStorage
        storage_matches = re.findall(r'localStorage\.setItem\(["\'](\w+)["\']\s*,\s*["\'](.*?)["\']\)', html)
        for key, val in storage_matches:
            tokens.append({"source": f"localStorage:{key}", "value": val})
    except Exception as e:
        logging.error(f"[TokenExtractor] Ошибка извлечения токенов: {e}", exc_info=True)

    return tokens


# ============================================================
#  Анализ токенов
# ============================================================
def analyze_tokens(tokens: List[Dict[str, str]], expected_aud: str = "expected-aud") -> List[Dict[str, Any]]:
    """Анализирует токены, определяет тип и риски."""
    analyzed: List[Dict[str, Any]] = []
    for t in tokens:
        result: Dict[str, Any] = {
            "source": t.get("source"),
            "value": t.get("value"),
            "type": "opaque",
            "risks": [],
            "risk_level": "low",
        }

        decoded = decode_jwt(t["value"])
        if decoded:
            result["type"] = "JWT"
            result["decoded"] = decoded
            result["risks"] = assess_risks(decoded, expected_aud)

            if "📛 Алгоритм подписи: none" in result["risks"]:
                result["risk_level"] = "high"
            elif len(result["risks"]) >= 2:
                result["risk_level"] = "medium"
            else:
                result["risk_level"] = "low"

        analyzed.append(result)
    return analyzed


# ============================================================
#  Сохранение лога
# ============================================================
def save_token_log(analyzed: List[Dict[str, Any]], path: Path = LOG_FILE) -> None:
    """Сохраняет результаты анализа токенов в JSON."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(analyzed, f, indent=2, ensure_ascii=False)
        logging.info(f"[TokenExtractor] Лог сохранён: {path}")
    except Exception as e:
        logging.error(f"[TokenExtractor] Ошибка записи лога: {e}", exc_info=True)


# ============================================================
#  Общая логика
# ============================================================
def _process_tokens(headers: Dict[str, str], html: str, output_path: Path = LOG_FILE) -> List[Dict[str, Any]]:
    """Общая логика извлечения, анализа и сохранения токенов."""
    tokens = extract_tokens(headers, html)
    analyzed = analyze_tokens(tokens)
    save_token_log(analyzed, output_path)
    return analyzed


# ============================================================
#  CLI-режим
# ============================================================
def run_from_cli(headers_path: Path, html_path: Path, output_path: Path = LOG_FILE) -> None:
    """Запуск анализа токенов из CLI."""
    try:
        with headers_path.open(encoding="utf-8") as f:
            headers = json.load(f)
        with html_path.open(encoding="utf-8") as f:
            html = f.read()
    except Exception as e:
        print(f"❌ Ошибка загрузки входных данных: {e}")
        return

    analyzed = _process_tokens(headers, html, output_path)
    print(f"✅ Анализ завершён. Лог сохранён в: {output_path}")


# ============================================================
#  GUI-режим (асинхронный запуск)
# ============================================================
def analyze_from_gui(headers: Dict[str, str], html: str, output_path: Path = LOG_FILE, callback=None) -> None:
    """Запускает анализ токенов в фоне, чтобы не блокировать GUI."""
    def worker():
        analyzed = _process_tokens(headers, html, output_path)
        if callback:
            try:
                callback(analyzed)
            except Exception as e:
                logging.error(f"[TokenExtractor] Ошибка в GUI callback: {e}", exc_info=True)

    threading.Thread(target=worker, daemon=True).start()


# ============================================================
#  Автоматический выбор режима
# ============================================================
if __name__ == "__main__":


    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_DIR / "token_extractor.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )

    if len(sys.argv) >= 3:
        headers_file = Path(sys.argv[1])
        html_file = Path(sys.argv[2])
        output_file = Path(sys.argv[3]) if len(sys.argv) > 3 else LOG_FILE
        run_from_cli(headers_file, html_file, output_file)
    else:
        print("📘 Использование:")
        print("  python -m xss_security_gui.auto_recon.token_extractor headers.json response.html [output.json]")