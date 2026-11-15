# xss_security_gui/ai_adapter.py
"""
AI Adapter — connects GUI to AI Core with real model training support.

Modules:
- AIAssistant: high-level interface with analyze() and learn()
- train_ai_async(): trigger training from logs in background thread
- get_training_status(): check model status
"""
from __future__ import annotations

import importlib
import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Callable

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True, parents=True)

# Global state
_training_in_progress = False
_training_report = None


class AIAssistant:
    def __init__(self) -> None:
        self.core = None
        self.train_fn = None
        
        # Try to import ai_core (real implementation with XGBoost)
        tried = []
        for mod in ("xss_security_gui.ai_core", "ai_core"):
            try:
                self.core = importlib.import_module(mod)
                # Try to instantiate AICore if exposed
                if hasattr(self.core, "AICore"):
                    try:
                        self.core = getattr(self.core, "AICore")()
                    except Exception:
                        # Keep module as-is if instantiation fails
                        pass
                break
            except Exception as e:
                tried.append((mod, str(e)))
                self.core = None

        # Import training function if available
        try:
            from xss_security_gui.ai_core.train_nn_model import train_from_logs
            self.train_fn = train_from_logs
        except Exception:
            self.train_fn = None

    def analyze(self, threat: Any) -> Dict[str, Any]:
        """Return analysis dict with at least 'summary' key."""
        if self.core:
            try:
                if hasattr(self.core, "analyze"):
                    return self.core.analyze(threat)
                elif hasattr(self.core, "predict"):
                    return {"summary": str(self.core.predict(threat))}
            except Exception:
                pass

        # Fallback heuristic analyzer
        try:
            summary = "ok"
            tags = []
            txt = json.dumps(threat, ensure_ascii=False)
            if "password" in txt.lower() or "smtp_password" in txt.lower():
                tags.append("credentials")
                summary = "credentials_found"
            if "credit_card" in txt.lower() or "card" in txt.lower():
                tags.append("payment")
                if summary == "ok":
                    summary = "payment_data"
            if "email" in txt.lower():
                tags.append("email")
            return {"summary": summary, "tags": tags, "confidence": 0.5}
        except Exception:
            return {"summary": "error", "confidence": 0.0}

    def learn(self, threat: Any) -> None:
        """Learn from a threat: if ai_core exposes `train`, call it."""
        if self.core and hasattr(self.core, "train"):
            try:
                self.core.train(threat)
                return
            except Exception:
                pass

        # Fallback: append to local training file
        try:
            training_file = LOG_DIR / "ai_training.json"
            data = []
            if training_file.exists():
                with open(training_file, "r", encoding="utf-8") as f:
                    data = json.load(f) or []
            data.append({"timestamp": __import__("datetime").datetime.now().isoformat(), "entry": threat})
            with open(training_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


# Singleton instance
_ai_assistant = None


def get_ai_assistant() -> AIAssistant:
    """Get or create singleton AIAssistant."""
    global _ai_assistant
    if _ai_assistant is None:
        _ai_assistant = AIAssistant()
    return _ai_assistant


def train_ai_async(on_done: Optional[Callable] = None, on_error: Optional[Callable] = None) -> bool:
    """
    Trigger AI training in background thread.
    Returns True if training started, False if already in progress or no trainer available.
    """
    global _training_in_progress, _training_report

    if _training_in_progress:
        return False

    assistant = get_ai_assistant()
    if not assistant.train_fn:
        return False

    _training_in_progress = True

    def _worker():
        global _training_in_progress, _training_report
        try:
            report = assistant.train_fn()
            _training_report = report
            if callable(on_done):
                try:
                    on_done(report)
                except Exception:
                    pass
        except Exception as e:
            _training_report = {"error": str(e)}
            if callable(on_error):
                try:
                    on_error(e)
                except Exception:
                    pass
        finally:
            _training_in_progress = False

    thread = threading.Thread(target=_worker, daemon=True, name="AITraining")
    thread.start()
    return True


def get_training_status() -> Dict[str, Any]:
    """Get current training status and report."""
    global _training_in_progress, _training_report
    return {
        "in_progress": _training_in_progress,
        "report": _training_report,
    }


