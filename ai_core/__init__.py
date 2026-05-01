"""
AI Core 26.0 — __init__.py (SAFE MODE, ENTERPRISE)

Єдиний вхідний модуль для AI-аналізу:

- JS Risk Engine
- Python Project Risk Engine
- Витяг фіч та аналіз JS
- ML/NN-модель (класифікація XSS-поведінки)
- Synthetic XSS генератор (для тренування)
- Тренування моделі з логів (train_from_logs)
- SAFE MODE: AI ніколи не валить GUI, навіть якщо модель відсутня
"""

import threading

from xss_security_gui.settings import (
    AI_MODEL_PATH,
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
)

from .risk_engine import analyze_security_risk
from .nn_model import load_trained_model
from .project_analyzer import scan_project, ProjectAnalyzerRunner
from .py_risk_engine import analyze_py_risk
from .worker import AIWorker

# Тренування та synthetic XSS
from .train_nn_model import train_from_logs, AITrainingRunner
from .synthetic_xss import generate_synthetic_xss


# ============================================================
#  Завантаження NN-моделі (SAFE MODE)
# ============================================================

_MODEL_LOADED = False
_MODEL_ERROR = None
_MODEL_LOADING = False


def _load_model_background() -> None:
    global _MODEL_LOADED, _MODEL_ERROR, _MODEL_LOADING
    try:
        load_trained_model(AI_MODEL_PATH)
        print(f"[AI Core] NN model loaded: {AI_MODEL_PATH}")
        _MODEL_LOADED = True
        _MODEL_ERROR = None
    except Exception as e:
        _MODEL_ERROR = e
        print(f"[AI Core] NN model not loaded: {e}")
        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            print("[AI Core] SAFE MODE active — fallback NN scoring enabled")
        else:
            print("[AI Core] WARNING: SAFE MODE disabled, але модель не завантажена.")
    finally:
        _MODEL_LOADING = False


def warmup_model_async() -> None:
    """
    Неблокуюче прогрівання моделі.
    Виклик безпечний для GUI-потоку (mainloop не блокується).
    """
    global _MODEL_LOADING
    if _MODEL_LOADING or _MODEL_LOADED:
        return
    _MODEL_LOADING = True
    threading.Thread(target=_load_model_background, daemon=True, name="AICoreModelWarmup").start()


# Важливо: не блокуємо GUI на імпорті ai_core
warmup_model_async()


# ============================================================
#  Публічний API
# ============================================================

__all__ = [
    # JS / Web
    "analyze_security_risk",   # Аналіз JS / XSS-поведінки

    # Python / Project
    "scan_project",            # Аналіз Python-проєкту
    "analyze_py_risk",         # Аналіз ризиків у Python-коді

    # AI Training / Synthetic
    "train_from_logs",         # Тренування моделі з логів
    "generate_synthetic_xss",  # Генерація synthetic XSS-патернів
    "AITrainingRunner",        # Async runner для train_from_logs
    "ProjectAnalyzerRunner",   # Async runner для project scan
    "AIWorker",                # Async JS risk worker (queue + after)

    # Службова інформація
    "_MODEL_LOADED",
    "_MODEL_ERROR",
    "_MODEL_LOADING",
    "warmup_model_async",
]

