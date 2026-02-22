# xss_security_gui/utils/threat_sender.py
import json
from typing import Any, Dict, List, Union

class ThreatSenderMixin:
    def send_to_threat_intel(self, module_name: str, data: Union[Dict[str, Any], List[Any], Any]) -> None:
        if not hasattr(self, "threat_tab") or self.threat_tab is None:
            if hasattr(self, "log"):
                self.log.debug("Threat Intel skipped: no tab")
            return

        payload = {"module": module_name, "entries": []}

        try:
            if isinstance(data, dict):
                for k, v in data.items():
                    payload["entries"].append({"key": str(k), "value": json.dumps(v, ensure_ascii=False)})

            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            payload["entries"].append({"key": str(k), "value": json.dumps(v, ensure_ascii=False)})
                    else:
                        payload["entries"].append({"key": "info", "value": str(item)})

            else:
                payload["entries"].append({"key": "info", "value": str(data)})

            self.threat_tab.load_results(payload)

        except Exception as e:
            if hasattr(self, "log"):
                self.log.error(f"Threat Intel send error: {type(e).__name__}: {e}", exc_info=True)