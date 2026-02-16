class DOMEventMapper:
    def run(self, page_data):
        dom = page_data.get("dom", "")
        scripts = page_data.get("scripts", [])
        events = []

        for script in scripts:
            code = script.get("content", "")
            for event_type in ["click", "input", "submit", "mouseover"]:
                if event_type in code:
                    events.append({
                        "type": event_type,
                        "code": code[:100],
                        "risk": "HIGH" if "eval(" in code else "LOW"
                    })
        return {"events": events}