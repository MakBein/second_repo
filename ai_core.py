# xss_security_gui/ai_core.py
"""
Example local AI core for demonstration and development.

This module implements a small AICore with `analyze` and `train` methods
and can be replaced by your own more advanced AI implementation.

Place your real AI model here (same module path) and `AIAssistant` will
pick it up automatically.
"""
from __future__ import annotations

import re
import json
from typing import Any, Dict

class AICore:
    def __init__(self):
        # Optionally, load a lightweight ruleset or model from file
        self.rules = {
            "credentials": [r"password", r"passwd", r"smtp_password"],
            "credit_card": [r"\b4[0-9]{12}(?:[0-9]{3})?\b", r"\b5[1-5][0-9]{14}\b"],
        }
        self.training = []

    def analyze(self, threat: Any) -> Dict[str, Any]:
        txt = json.dumps(threat, ensure_ascii=False).lower()
        tags = []
        if any(re.search(p, txt) for p in self.rules.get("credentials", [])):
            tags.append("credentials")
        if any(re.search(p, txt) for p in self.rules.get("credit_card", [])):
            tags.append("payment")
        if "email" in txt:
            tags.append("email")

        summary = "ok"
        if "credentials" in tags:
            summary = "credentials_found"
        elif "payment" in tags:
            summary = "payment_data"

        return {"summary": summary, "tags": tags, "confidence": 0.7}

    def train(self, threat: Any) -> None:
        # Very simple: append to in-memory training list
        self.training.append(threat)

    # Backwards compatibility
    def learn(self, threat: Any) -> None:
        return self.train(threat)

