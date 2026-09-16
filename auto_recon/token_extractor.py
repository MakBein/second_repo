# xss_security_gui/auto_recon/token_extractor.py
"""
Token Extractor ULTRA 13.0 (GOD‑ENGINE)
---------------------------------------
• Извлекает токены из заголовков и HTML/JS
• Анализирует JWT и риски
• Интегрируется в ThreatConnector / EmailLeakWorker / GUI
• Даёт unified ULTRA‑MODE schema + entropy + severity
"""

import sys
import re
import json
import logging
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from xss_security_gui.utils.jwt_decoder import decode_jwt, assess_risks
from xss_security_gui.settings import LOG_DIR
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR, ThreatConnector
from xss_security_gui.threat_data_loader import ThreatRisk

LOG_DIR: Path = LOG_DIR / "tokens"
LOG_FILE: Path = LOG_DIR / "token_risks.json"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)

# ============================================================
#  Расширенные паттерны извлечения токенов
# ============================================================
_HEADER_TOKEN_KEYS = (
    "token", "authorization", "x-csrf-token", "x-xsrf-token",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "set-cookie",
)

_HTML_TOKEN_PATTERNS = [
    ("CSRF Hidden Field", r'name=["\']csrf[_\-]?(?:token)?["\'].*?value=["\']([^"\']+)["\']', re.I),
    ("CSRF Meta", r'<meta[^>]+name=["\']csrf[_\-]?token["\'][^>]+content=["\']([^"\']+)["\']', 0),
    ("Anti-CSRF _token", r'name=["\']_token["\'].*?value=["\']([^"\']+)["\']', re.I),
    ("JWT in JS", r'["\']?(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)["\']?', 0),
    ("API Key in JS", r'(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I),
    ("Bearer in JS", r'["\']Bearer\s+([A-Za-z0-9._~+/=-]+)["\']', 0),
    ("OAuth Token", r'access_token["\']?\s*[=:]\s*["\']([^"\']+)["\']', re.I),
    ("AWS Key", r'(AKIA[0-9A-Z]{16})', 0),
    ("Slack Token", r'(xox[bpors]-[0-9a-zA-Z]{10,48})', 0),
    ("GitHub Token", r'(gh[pousr]_[0-9a-zA-Z]{36})', 0),
    ("localStorage", r'localStorage\.setItem\(["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']\)', 0),
    ("sessionStorage", r'sessionStorage\.setItem\(["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']\)', 0),
    ("Stripe Key", r'(sk_live_[0-9a-zA-Z]{24})', 0),
    ("SendGrid Key", r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})', 0),
    ("Google API Key", r'(AIza[0-9A-Za-z\-_]{35})', 0),
    ("Private Key", r'(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)', 0),
]


def extract_tokens(headers: Dict[str, str], html: str) -> List[Dict[str, str]]:
    """Расширенное извлечение токенов из заголовков и HTML/JS."""
    tokens: List[Dict[str, str]] = []
    try:
        for k, v in headers.items():
            if any(tk in k.lower() for tk in _HEADER_TOKEN_KEYS):
                tokens.append({"source": f"Header:{k}", "value": v})

        for name, pattern, flags in _HTML_TOKEN_PATTERNS:
            for match in re.finditer(pattern, html, flags):
                groups = match.groups()
                if len(groups) == 2:
                    tokens.append({"source": f"{name}:{groups[0]}", "value": groups[1]})
                elif len(groups) == 1:
                    tokens.append({"source": name, "value": groups[0]})
                else:
                    tokens.append({"source": name, "value": match.group()})
    except Exception as e:
        logger.error(f"[TokenExtractor] Ошибка извлечения токенов: {e}", exc_info=True)

    return tokens


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


def save_token_log(analyzed: List[Dict[str, Any]], path: Path = LOG_FILE) -> None:
    """Сохраняет результаты анализа токенов в JSON."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(analyzed, f, indent=2, ensure_ascii=False)
        logger.info(f"[TokenExtractor] Лог сохранён: {path}")
    except Exception as e:
        logger.error(f"[TokenExtractor] Ошибка записи лога: {e}", exc_info=True)


def _process_tokens(headers: Dict[str, str], html: str, output_path: Path = LOG_FILE) -> List[Dict[str, Any]]:
    """Общая логика извлечения, анализа и сохранения токенов."""
    tokens = extract_tokens(headers, html)
    analyzed = analyze_tokens(tokens)
    save_token_log(analyzed, output_path)
    return analyzed


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


def analyze_from_gui(headers: Dict[str, str], html: str, output_path: Path = LOG_FILE, callback=None) -> None:
    """Запускает анализ токенов в фоне, чтобы не блокировать GUI."""
    def worker():
        analyzed = _process_tokens(headers, html, output_path)
        if callback:
            try:
                callback(analyzed)
            except Exception as e:
                logger.error(f"[TokenExtractor] Ошибка в GUI callback: {e}", exc_info=True)

    threading.Thread(target=worker, daemon=True).start()


# ============================================================
#  TokenExtractorEngine 13.0 ULTRA‑MODE (GOD‑ENGINE)
# ============================================================
class TokenExtractorEngine:
    """
    TokenExtractorEngine 13.0 ULTRA‑MODE:

    - Оборачивает token_extractor в ULTRA‑MODE schema
    - Интегрируется в ThreatConnector / EmailLeakWorker / GUI
    - Даёт:
        * unified result schema
        * severity normalization через ThreatRisk
        * entropy
        * event‑stream (on_event)
    """

    def __init__(
        self,
        connector: Optional[ThreatConnector] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        debug_telemetry: bool = False,
    ) -> None:
        self.connector: ThreatConnector = connector or THREAT_CONNECTOR
        self.on_event = on_event
        self.debug_telemetry = debug_telemetry
        self.heatmap: Dict[str, int] = {}
        self.last_ml_prediction: Optional[Any] = None

    def _log_debug(self, msg: str) -> None:
        if self.debug_telemetry:
            logger.info(f"[TokenExtractorEngine] {msg}")

    def _ingest(self, analyzed: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Приводит анализ токенов к ULTRA‑MODE unified schema и отправляет в ThreatConnector.
        """
        items: List[Dict[str, Any]] = []

        for t in analyzed:
            risk_raw = t.get("risk_level", "low")
            severity = ThreatRisk.normalize(risk_raw)

            item = {
                "source": t.get("source"),
                "value": t.get("value"),
                "type": t.get("type", "opaque"),
                "decoded": t.get("decoded"),
                "risks": t.get("risks", []),
                "severity": severity,
            }
            items.append(item)

        # Entropy по JSON
        entropy_val = 0.0
        try:
            import math
            blob = json.dumps(items, ensure_ascii=False)
            freq: Dict[str, int] = {}
            for c in blob:
                freq[c] = freq.get(c, 0) + 1
            total = len(blob) or 1
            entropy_val = round(
                -sum((f / total) * math.log2(f / total) for f in freq.values()),
                3,
            )
        except Exception:
            entropy_val = 0.0

        module_name = "Token Extractor"
        family = "Tokens & Secrets"
        base_risk = "medium"
        tags = ["tokens", "jwt", "api_keys", "secrets"]

        self.heatmap.setdefault(module_name, 0)
        self.heatmap[module_name] += len(items)

        unified = {
            "module": module_name,
            "family": family,
            "risk": base_risk,
            "tags": tags,
            "status": "ok",
            "count": len(items),
            "items": items,
            "entropy": entropy_val,
        }

        # ThreatConnector ingestion
        try:
            self.connector.ingest_artifact(
                {
                    "module": module_name,
                    "family": family,
                    "result": unified,
                }
            )
        except Exception:
            logger.exception("[TokenExtractorEngine] ThreatConnector ingest error")

        # Event‑stream
        cb = self.on_event
        if callable(cb):
            try:
                cb("token_extractor_ultra", unified)
            except Exception:
                logger.exception("[TokenExtractorEngine] on_event callback error")

        self._log_debug(
            f"{module_name}: items={unified['count']} risk={unified['risk']} entropy={unified['entropy']}"
        )
        return unified

    def run(
        self,
        headers: Dict[str, str],
        html: str,
        output_path: Path = LOG_FILE,
    ) -> Dict[str, Any]:
        """
        Синхронный запуск TokenExtractor в ULTRA‑MODE (для EmailLeakWorker / ThreatConnector).
        """
        analyzed = _process_tokens(headers, html, output_path)
        return self._ingest(analyzed)

    def run_async(
        self,
        headers: Dict[str, str],
        html: str,
        output_path: Path = LOG_FILE,
    ) -> None:
        """
        Асинхронный запуск TokenExtractor в ULTRA‑MODE (для GUI / ThreatAnalysisTab).
        """
        def worker():
            try:
                analyzed = _process_tokens(headers, html, output_path)
                self._ingest(analyzed)
            except Exception:
                logger.exception("[TokenExtractorEngine] async worker error")

        threading.Thread(target=worker, daemon=True, name="TokenExtractorEngineULTRA").start()

    def build_summary(self) -> Dict[str, Any]:
        """
        ULTRA‑MODE summary по токенам (heatmap + last_ml_prediction).
        """
        summary = {
            "heatmap": dict(self.heatmap),
            "ml_prediction": self.last_ml_prediction or "unavailable",
        }
        return summary


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
