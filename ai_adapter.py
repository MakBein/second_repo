# xss_security_gui/ai_adapter.py
"""
AI Adapter — thin wrapper to connect your local `ai_core` module (if present)
and provide a stable interface for threat analysis and online learning.

It tries to import `xss_security_gui.ai_core` or `ai_core` and will gracefully
fall back to a lightweight built-in analyzer if the module is not found.

Public API:
- AIAssistant.analyze(threat) -> Dict[str, Any]
- AIAssistant.learn(threat) -> None
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True, parents=True)

class AIAssistant:
    def __init__(self) -> None:
        self.core = None
        # Try to import package inside xss_security_gui first
        tried = []
        for mod in ("xss_security_gui.ai_core", "ai_core"):
            try:
                self.core = importlib.import_module(mod)
                break
            except Exception as e:
                tried.append((mod, str(e)))
                self.core = None
        # If core exposes an initializer, try to instantiate
        if self.core and hasattr(self.core, "AICore"):
            try:
                self.core = getattr(self.core, "AICore")()
            except Exception:
                # keep module as-is
                pass

    def analyze(self, threat: Any) -> Dict[str, Any]:
        """Return analysis dict with at least 'summary' key.

        If user-provided ai_core module exists and provides `analyze(threat)`
        this adapter will call it. Otherwise it will run a simple heuristic
        analyzer.
        """
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
        """Learn from a threat: if ai_core exposes `train`, call it, otherwise
        append to a local training file for offline ingestion.
        """
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

