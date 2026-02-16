# xss_security_gui/utils/threat_sender.py
class ThreatSenderMixin:
    def send_to_threat_intel(self, module_name, data):
        if not hasattr(self, "threat_tab") or self.threat_tab is None:
            return

        payload = {"module": module_name, "entries": []}

        if isinstance(data, dict):
            for k, v in data.items():
                payload["entries"].append({"key": str(k), "value": str(v)})

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for k, v in item.items():
                        payload["entries"].append({"key": str(k), "value": str(v)})
                elif isinstance(item, (list, tuple)):
                    payload["entries"].append({"key": str(item[0]), "value": str(item[1:])})
                else:
                    payload["entries"].append({"key": "info", "value": str(item)})

        else:
            payload["entries"].append({"key": "info", "value": str(data)})

        self.threat_tab.load_results(payload)