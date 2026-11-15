# xss_security_gui/ai_core.py
"""
AI Core Integration Module — connects to train_nn_model.py for real ML-based threat analysis.

Provides:
- AICore class with analyze(threat) and train/learn(threat) methods
- train_from_logs() for triggering XGBoost model retraining
- Model inference with fallback to heuristics if model not available
"""
from __future__ import annotations

import re
import json
import logging
from pathlib import Path
from typing import Any, Dict
import joblib

# Try to import the training pipeline
try:
    from xss_security_gui.ai_core.train_nn_model import train_from_logs, AITrainingRunner
    TRAIN_FROM_LOGS_AVAILABLE = True
except Exception:
    TRAIN_FROM_LOGS_AVAILABLE = False

# Settings
try:
    from xss_security_gui.settings import AI_MODEL_PATH
except Exception:
    AI_MODEL_PATH = Path(__file__).parent / "logs" / "xss_model.joblib"

logger = logging.getLogger("ai_core")


class AICore:
    """
    Real AI Core with XGBoost model inference + heuristics fallback.
    Auto-loads trained model if available; otherwise uses simple rules.
    """

    def __init__(self):
        self.model = None
        self.rules = {
            "credentials": [r"password", r"passwd", r"smtp_password"],
            "credit_card": [r"\b4[0-9]{12}(?:[0-9]{3})?\b", r"\b5[1-5][0-9]{14}\b"],
        }
        self.training = []
        self._load_model()

    def _load_model(self) -> None:
        """Load trained XGBoost model if available."""
        if not AI_MODEL_PATH.exists():
            logger.info(f"Model not found at {AI_MODEL_PATH}, will use heuristics")
            return

        try:
            self.model = joblib.load(AI_MODEL_PATH)
            logger.info(f"✅ Model loaded from {AI_MODEL_PATH}")
        except Exception as e:
            logger.warning(f"Failed to load model: {e}, using heuristics")
            self.model = None

    def analyze(self, threat: Any) -> Dict[str, Any]:
        """
        Analyze threat using ML model (if available) or heuristics.
        Returns dict with: summary, tags, confidence, model_used
        """
        txt = json.dumps(threat, ensure_ascii=False).lower()
        tags = []

        # Heuristic tagging
        if any(re.search(p, txt) for p in self.rules.get("credentials", [])):
            tags.append("credentials")
        if any(re.search(p, txt) for p in self.rules.get("credit_card", [])):
            tags.append("payment")
        if "email" in txt:
            tags.append("email")

        summary = "ok"
        model_used = "heuristics"

        # Try ML model if available
        if self.model:
            try:
                # Extract JS features for model input
                from xss_security_gui.js_inspector import extract_js_insights
                from xss_security_gui.ai_core.features import build_js_features

                raw_js = txt[:500]  # Use first 500 chars as JS
                js_insights = extract_js_insights(raw_js)
                feats = build_js_features(js_insights, raw_js)

                # Build feature vector (must match training order)
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

                pred = self.model.predict([x])[0]
                proba = self.model.predict_proba([x])[0]
                confidence = float(max(proba))

                if pred == 1:  # XSS detected
                    summary = "xss_detected"
                    tags.append("xss")
                    model_used = "ml_model"
                else:
                    summary = "safe"
                    model_used = "ml_model"

                return {
                    "summary": summary,
                    "tags": tags,
                    "confidence": confidence,
                    "model_used": model_used,
                    "prediction": int(pred),
                }

            except Exception as e:
                logger.debug(f"ML prediction failed: {e}, fallback to heuristics")

        # Fallback heuristics
        if "credentials" in tags:
            summary = "credentials_found"
        elif "payment" in tags:
            summary = "payment_data"

        return {
            "summary": summary,
            "tags": tags,
            "confidence": 0.5,
            "model_used": model_used,
        }

    def train(self, threat: Any) -> None:
        """Append threat to training buffer (will be picked up by train_from_logs)."""
        self.training.append(threat)

    def learn(self, threat: Any) -> None:
        """Alias for train()."""
        self.train(threat)

