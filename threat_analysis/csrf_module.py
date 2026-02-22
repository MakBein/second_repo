# xss_security_gui/threat_analysis/csrf_module.py
import requests
from datetime import datetime
from xss_security_gui.threat_analysis.tester_base import TesterBase


class CSRFTester(TesterBase):
    def __init__(self, base_url, param, base_value, payloads, output_callback=None):
        super().__init__("CSRF", base_url, param, base_value, payloads, output_callback)

    def _test_single(self, category, payload, full_value):
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "category": category,
            "param": self.param,
            "payload": payload,
        }

        try:
            headers = {
                "Referer": "https://gazprombank.ru",
                "Origin": "https://gazprombank.ru"
            }

            r = requests.get(
                self.base_url,
                params={self.param: full_value},
                headers=headers,
                timeout=7,
                allow_redirects=True
            )

            text = r.text.lower()
            hdr = {k.lower(): v.lower() for k, v in r.headers.items()}

            # === Індикатори CSRF-вразливості ===
            missing_samesite = "set-cookie" in hdr and "samesite" not in hdr.get("set-cookie", "")
            missing_csrf_header = "x-csrf-token" not in hdr
            missing_origin_check = r.status_code == 200 and "origin" not in hdr

            # === Підозрілі ключові слова ===
            body_indicators = ["success", "done", "updated", "changed", "saved"]

            body_hit = any(x in text for x in body_indicators)

            # === Формування статусу ===
            if missing_samesite or missing_csrf_header or body_hit:
                status = "possible CSRF"
            else:
                status = "no signal"

            result.update({
                "status": status,
                "http_status": r.status_code,
                "response_length": len(r.text),
                "headers": dict(r.headers),
                "final_url": r.url,
                "redirects": [h.url for h in r.history],
            })

            return result

        except Exception as e:
            result.update({
                "status": "error",
                "error": str(e),
                "response_length": 0
            })
            return result