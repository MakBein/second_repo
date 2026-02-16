# xss_security_gui/threat_analysis/engine.py

from .csp_module import CSPAnalyzer
from .dom_events_module import DOMEventMapper
from .cookie_tracer import CookieTracer

class ThreatEngine:
    def __init__(self):
        self.modules = {
            "csp": CSPAnalyzer(),
            "dom": DOMEventMapper(),
            "cookie": CookieTracer()
        }

    def run_all(self, page_data):
        results = {}
        for name, module in self.modules.items():
            try:
                results[name] = module.run(page_data)
            except Exception as e:
                results[name] = {"error": str(e)}
        return results