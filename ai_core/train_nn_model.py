"""
AI Core 26.0 — train_nn_model.py (ENTERPRISE EDITION)

- Читає всі файли у xss_security_gui/logs/, незалежно від розширення
- Не падає на пошкоджених/бінарних файлах
- Витягує JS/XSS-поведінку з тексту
- Дедуплікує фрагменти
- Додає synthetic XSS samples (балансування класів)
- Будує фічі, тренує модель (XGBoost)
- Рахує метрики (precision/recall/F1)
- Пише:
    - ai_training.log        — детальний лог тренування
    - training_report.json   — метрики + статистика
- Має функцію train_from_logs(), яку можна викликати з GUI
"""

from pathlib import Path
from typing import List, Tuple, Dict, Set, Any, Optional, Callable
import re
import json
import logging
import joblib
import time
import threading
import queue
from logging.handlers import RotatingFileHandler

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from xss_security_gui.js_inspector import extract_js_insights
from xss_security_gui.ai_core.features import build_js_features
from xss_security_gui.settings import LOG_DIR, AI_MODEL_PATH
from xss_security_gui.ai_core.synthetic_xss import generate_synthetic_xss

from xgboost import XGBClassifier


LOGS_DIR = Path(LOG_DIR)

TRAINING_REPORT_PATH = AI_MODEL_PATH.parent / "training_report.json"
TRAINING_LOG_PATH = AI_MODEL_PATH.parent / "ai_training.log"

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024   # 50 MB


# ============================================================
#  COLOR FORMATTER (для консолі)
# ============================================================
class ColorFormatter(logging.Formatter):
    COLORS = {
        "INFO": "\033[92m",      # зелений
        "WARNING": "\033[93m",   # жовтий
        "ERROR": "\033[91m",     # червоний
        "CRITICAL": "\033[95m",  # пурпурний
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        base = super().format(record)
        return f"{color}{base}{self.RESET}"


# ============================================================
#  JSON FORMATTER (для файлу)
# ============================================================
class JsonFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        from datetime import datetime
        dt = datetime.fromtimestamp(record.created)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.isoformat()

    def format(self, record):
        log = {
            "time": self.formatTime(record, "%Y-%m-%d %H:%M:%S.%f"),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "name": record.name,
        }
        return json.dumps(log, ensure_ascii=False)



# ============================================================
#  LOGGER SETUP (ENTERPRISE EDITION)
# ============================================================
def setup_logger() -> logging.Logger:
    """Створює enterprise‑логер з ротацією, JSON‑логами та кольорами."""
    logger = logging.getLogger("ai_training")

    # Захист від дублювання хендлерів
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    TRAINING_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    # -----------------------------
    # Формат для консолі (кольоровий)
    # -----------------------------
    console_fmt = ColorFormatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(console_fmt)
    logger.addHandler(sh)

    # -----------------------------
    # Формат для файлу (JSON + ротація)
    # -----------------------------
    fh = RotatingFileHandler(
        TRAINING_LOG_PATH,
        maxBytes=5 * 1024 * 1024,   # 5 MB
        backupCount=5,
        encoding="utf-8"
    )
    fh.setLevel(logging.INFO)
    fh.setFormatter(JsonFormatter())
    logger.addHandler(fh)

    return logger


# ============================================================
#  JS EXTRACTION
# ============================================================
def extract_js_from_text(text: str) -> List[str]:
    """Витягує підозрілі JS-фрагменти з тексту."""
    js_blocks: List[str] = []

    # <script>...</script>
    js_blocks += re.findall(
        r"<script[^>]*>(.*?)</script>",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    # eval(...)
    js_blocks += re.findall(r"eval\((.*?)\)", text, flags=re.DOTALL)

    # inline event handlers
    if any(k in text for k in ("onerror=", "onload=", "onclick=", "onmouseover=")):
        js_blocks.append(text)

    # alert()
    if "alert(" in text:
        js_blocks.append(text)

    # javascript: URLs
    if "javascript:" in text.lower():
        js_blocks.append(text)

    # data:text payloads
    if "data:text" in text.lower():
        js_blocks.append(text)

    # suspicious keywords
    suspicious_keywords = [
        "window.name",
        "srcdoc=",
        "http-equiv=\"refresh\"",
        "@import",
        "fromCharCode",
        "atob(",
        "document.cookie",
    ]
    if any(k in text for k in suspicious_keywords):
        js_blocks.append(text)

    cleaned = [block.strip() for block in js_blocks if block and block.strip()]
    return cleaned


def auto_label(js: str) -> int:
    """Автоматичне маркування JS як XSS (1) або безпечний (0)."""
    s = js.lower()
    bad_markers = [
        "alert(",
        "onerror=",
        "onload=",
        "onclick=",
        "javascript:",
        "data:text",
        "document.cookie",
        "fromcharcode",
        "atob(",
        "eval(",
        "settimeout(",
        "setinterval(",
    ]
    return 1 if any(m in s for m in bad_markers) else 0


# ============================================================
#  LOAD DATASET
# ============================================================
def load_dataset_from_logs(logger: logging.Logger) -> Tuple[List[Tuple[str, int]], Dict[str, int]]:
    """Читає всі файли з LOGS_DIR, витягує JS, повертає (js, label)."""
    samples: List[Tuple[str, int]] = []
    stats = {
        "files_total": 0,
        "files_skipped_size": 0,
        "files_failed_read": 0,
        "files_processed": 0,
    }

    if not LOGS_DIR.exists():
        logger.warning(f"Папка логів {LOGS_DIR} не існує.")
        return samples, stats

    for file in LOGS_DIR.iterdir():
        if not file.is_file():
            continue

        stats["files_total"] += 1

        # Розмір
        try:
            size = file.stat().st_size
        except OSError:
            stats["files_failed_read"] += 1
            logger.warning(f"Неможливо отримати розмір файлу: {file.name}")
            continue

        if size > MAX_FILE_SIZE_BYTES:
            stats["files_skipped_size"] += 1
            logger.info(f"Пропуск великого файлу (> {MAX_FILE_SIZE_BYTES}): {file.name}")
            continue

        # Читання
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            stats["files_failed_read"] += 1
            logger.warning(f"Неможливо прочитати {file.name}: {e}")
            continue

        stats["files_processed"] += 1

        # Витяг JS
        js_blocks = extract_js_from_text(text)

        for js in js_blocks:
            label = auto_label(js)
            samples.append((js, label))

    return samples, stats


# ============================================================
#  DEDUPLICATION
# ============================================================
def deduplicate_samples(samples: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Усування дублікатів JS-фрагментів."""
    seen: Set[str] = set()
    unique: List[Tuple[str, int]] = []

    for js, label in samples:
        key = js.strip()
        if key in seen:
            continue
        seen.add(key)
        unique.append((js, label))

    return unique


# ============================================================
#  FEATURE BUILDING + SYNTHETIC XSS
# ============================================================
def build_dataset(samples: List[Tuple[str, int]]):
    """Будує фічі + додає synthetic XSS."""
    X, y = [], []

    # Synthetic XSS (балансування класів)
    synthetic = generate_synthetic_xss(20000)
    for js in synthetic:
        samples.append((js, 1))

    # Побудова фіч
    for raw_js, label in samples:
        js_insights = extract_js_insights(raw_js)
        feats = build_js_features(js_insights, raw_js)

        x = [
            feats.get("num_dom_sinks", 0),
            feats.get("num_dangerous_calls", 0),
            feats.get("num_dynamic_execution", 0),
            feats.get("num_prototype_pollution", 0),
            feats.get("num_csp_bypass", 0),
            feats.get("num_api_endpoints", 0),
            feats.get("behavior_density", 0.0),
            feats.get("sink_score", 0.0),
            feats.get("danger_score", 0.0),
            feats.get("execution_score", 0.0),
            feats.get("sig_hex_obfuscation", 0),
            feats.get("sig_infinite_loop", 0),
            feats.get("sig_eval_chain", 0),
            feats.get("sig_cookie_access", 0),
            feats.get("sig_anti_debug", 0),
            feats.get("sig_fromCharCode", 0),
            feats.get("sig_base64", 0),
            feats.get("js_length", 0),
            feats.get("js_lines", 0),
            feats.get("js_avg_line_len", 0.0),
            feats.get("entropy", 0.0),
            feats.get("complexity", 0.0),
        ]

        X.append(x)
        y.append(label)

    return X, y


# ============================================================
#  SAVE REPORT
# ============================================================
def save_training_report(report: Dict[str, Any], logger: logging.Logger) -> None:
    """Зберігає training_report.json."""
    TRAINING_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        TRAINING_REPORT_PATH.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        logger.info(f"training_report.json збережено у: {TRAINING_REPORT_PATH}")
    except Exception as e:
        logger.error(f"Не вдалося зберегти training_report.json: {e}")


# ============================================================
#  TRAINING PIPELINE
# ============================================================
def train_from_logs() -> Dict[str, Any]:
    logger = setup_logger()
    logger.info("=== Запуск тренування AI з логів ===")
    logger.info(f"LOGS_DIR = {LOGS_DIR}")
    logger.info(f"AI_MODEL_PATH = {AI_MODEL_PATH}")

    # -----------------------------
    # 1. Завантаження логів
    # -----------------------------
    samples, stats = load_dataset_from_logs(logger)

    logger.info("Статистика по файлах:")
    logger.info(f"  • Всього файлів:          {stats['files_total']}")
    logger.info(f"  • Оброблено:              {stats['files_processed']}")
    logger.info(f"  • Пропущено (розмір):     {stats['files_skipped_size']}")
    logger.info(f"  • Помилки читання:        {stats['files_failed_read']}")

    if not samples:
        msg = "Немає JS-коду в логах. Немає даних для тренування."
        logger.warning(msg)
        report = {
            "status": "no_data",
            "message": msg,
            "files_stats": stats,
        }
        save_training_report(report, logger)
        return report

    logger.info(f"Знайдено сирих JS-фрагментів: {len(samples)}")

    # -----------------------------
    # 2. Дедуплікація
    # -----------------------------
    samples = deduplicate_samples(samples)
    logger.info(f"Після дедуплікації: {len(samples)} унікальних JS-фрагментів.")

    # -----------------------------
    # 3. Побудова фіч
    # -----------------------------
    logger.info("Побудова фіч...")
    X, y = build_dataset(samples)

    class_set = set(y)
    if len(class_set) < 2:
        logger.warning("В датасеті тільки один клас. Модель буде слабкою.")

    # -----------------------------
    # 4. Train/Test split
    # -----------------------------
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.25,
            random_state=42,
            stratify=y if len(class_set) > 1 else None
        )
    except ValueError:
        logger.warning("Недостатньо даних для окремого тестового набору.")
        X_train, X_test, y_train, y_test = X, [], y, []

    # -----------------------------
    # 5. Тренування моделі
    # -----------------------------
    logger.info("Тренування XGBoostClassifier...")

    model = XGBClassifier(
        n_estimators=600,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=4,
        scale_pos_weight=20,  # балансування класів
    )

    model.fit(X_train, y_train)

    # -----------------------------
    # 6. Метрики
    # -----------------------------
    metrics: Dict[str, Any] = {}

    if X_test:
        logger.info("Оцінка якості на тесті...")
        y_pred = model.predict(X_test)
        cls_report = classification_report(
            y_test, y_pred,
            digits=4,
            output_dict=True
        )

        logger.info("Класифікаційний звіт:")
        logger.info(json.dumps(cls_report, ensure_ascii=False, indent=2))

        metrics["classification_report"] = cls_report
    else:
        logger.warning("Тестовий набір відсутній — метрики не обчислені.")
        metrics["classification_report"] = None

    # -----------------------------
    # 7. Збереження моделі
    # -----------------------------
    AI_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, AI_MODEL_PATH)
    logger.info(f"Модель збережена у: {AI_MODEL_PATH}")

    # -----------------------------
    # 8. Формування фінального звіту
    # -----------------------------
    report: Dict[str, Any] = {
        "status": "ok",
        "message": "Модель успішно натренована.",
        "files_stats": stats,
        "num_samples_raw": len(samples),
        "num_classes": len(class_set),
        "metrics": metrics,
        "model_path": str(AI_MODEL_PATH),
        "training_log_path": str(TRAINING_LOG_PATH),
    }

    save_training_report(report, logger)
    logger.info("=== Тренування завершено ===")

    return report


# ============================================================
#  CLI ENTRYPOINT
# ============================================================
def main():
    train_from_logs()


if __name__ == "__main__":
    main()


class AITrainingRunner:
    """
    Tk-friendly async runner:
    - training у фоні
    - callbacks у GUI-потоці через queue + root.after(...)
    """

    def __init__(self, root, poll_ms: int = 120):
        self._root = root
        self._poll_ms = max(30, int(poll_ms))
        self._q: "queue.Queue[Tuple[str, Optional[Dict[str, Any]], Optional[Exception], Optional[Callable], Optional[Callable]]]" = queue.Queue()
        self._active = True
        self._root.after(self._poll_ms, self._poll)

    def stop(self) -> None:
        self._active = False

    def train_async(self, *, on_done=None, on_error=None) -> str:
        task_id = f"TRAIN-{int(time.time() * 1000)}"

        def _job():
            try:
                report = train_from_logs()
                self._q.put((task_id, report, None, on_done, on_error))
            except Exception as e:
                self._q.put((task_id, None, e, on_done, on_error))

        threading.Thread(target=_job, daemon=True, name=f"AITraining-{task_id}").start()
        return task_id

    def _poll(self) -> None:
        try:
            while True:
                task_id, report, err, on_done, on_error = self._q.get_nowait()
                if err is None:
                    if callable(on_done):
                        try:
                            on_done(task_id, report)
                        except Exception:
                            pass
                else:
                    if callable(on_error):
                        try:
                            on_error(task_id, err)
                        except Exception:
                            pass
        except queue.Empty:
            pass
        finally:
            if self._active:
                self._root.after(self._poll_ms, self._poll)





