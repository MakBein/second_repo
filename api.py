# xss_security_gui/api.py
"""
Minimal HTTP API for Threat Intel

Endpoints (Flask if available):
- GET /health -> {status: ok}
- GET /threats -> current summary from THREAT_CONNECTOR
- POST /export -> JSON body {format: "csv"|"json"|"xml"|"pdf"} returns path
- POST /send -> send threats to external connector
- POST /train -> send provided threats to AI assistant for learning

This module tries to import Flask; if not available it provides a very small
fallback WSGI app that responds to /health only.
"""
from __future__ import annotations

import json
from typing import Any, Dict

try:
    from flask import Flask, jsonify, request
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

from xss_security_gui.threat_export import (
    export_threats_csv,
    export_threats_json,
    export_threats_xml,
    export_threats_pdf,
)
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.ai_adapter import AIAssistant

app = None
ai = AIAssistant()

if FLASK_AVAILABLE:
    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health() -> Any:
        return jsonify({"status": "ok"})

    @app.route("/threats", methods=["GET"])
    def get_threats() -> Any:
        try:
            if hasattr(THREAT_CONNECTOR, "generate_report"):
                summary = THREAT_CONNECTOR.generate_report()
            else:
                summary = THREAT_CONNECTOR.summary()
            return jsonify(summary)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/export", methods=["POST"])
    def export_route() -> Any:
        body = request.get_json(silent=True) or {}
        fmt = (body.get("format") or "json").lower()
        try:
            threats = body.get("threats")
            if not threats:
                # fetch from connector
                if hasattr(THREAT_CONNECTOR, "generate_report"):
                    summary = THREAT_CONNECTOR.generate_report()
                else:
                    summary = THREAT_CONNECTOR.summary()
                threats = summary.get("entries") or []

            if fmt == "csv":
                path = export_threats_csv(threats)
            elif fmt == "xml":
                path = export_threats_xml(threats)
            elif fmt == "pdf":
                path = export_threats_pdf(threats)
            else:
                path = export_threats_json(threats)
            return jsonify({"path": path})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/send", methods=["POST"])
    def send_route() -> Any:
        body = request.get_json(silent=True) or {}
        threats = body.get("threats")
        try:
            if not threats:
                if hasattr(THREAT_CONNECTOR, "generate_report"):
                    summary = THREAT_CONNECTOR.generate_report()
                else:
                    summary = THREAT_CONNECTOR.summary()
                threats = summary.get("entries") or []

            if hasattr(THREAT_CONNECTOR, "send"):
                THREAT_CONNECTOR.send(threats)
            elif hasattr(THREAT_CONNECTOR, "push"):
                THREAT_CONNECTOR.push(threats)
            else:
                return jsonify({"error": "THREAT_CONNECTOR has no send/push method"}), 500

            return jsonify({"status": "sent"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/train", methods=["POST"])
    def train_route() -> Any:
        body = request.get_json(silent=True) or {}
        threats = body.get("threats") or []
        try:
            for t in threats:
                ai.learn(t)
            return jsonify({"status": "ok", "trained": len(threats)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/predict", methods=["POST"])
    def predict_route() -> Any:
        body = request.get_json(silent=True) or {}
        raw_js = body.get("raw_js") or body.get("sample") or ""
        if not raw_js:
            return jsonify({"error": "raw_js required"}), 400
        try:
            from xss_security_gui.js_inspector import extract_js_insights
            from xss_security_gui.ai_core.risk_engine import analyze_security_risk

            js_insights = extract_js_insights(raw_js)
            res = analyze_security_risk(js_insights, raw_js)
            return jsonify(res)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

else:
    # Fallback minimal WSGI app
    def simple_app(environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == "/health":
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b"{\"status\": \"ok\"}"]
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not Found"]

    app = simple_app


if __name__ == "__main__":
    if FLASK_AVAILABLE:
        app.run(host="127.0.0.1", port=5005)
    else:
        print("Flask not available. This module provides a minimal WSGI app only.")

