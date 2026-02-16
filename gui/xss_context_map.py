# xss_security_gui/gui/xss_context_map.py

from typing import List, Dict, Any
from xss_security_gui.auto_recon.scanner import load_reflected_responses


class XSSContextMapTab:
    """
    Логическая вкладка "XSS Context Map":
    - группировка по категориям
    - список URL
    - быстрый переход к сниппетам
    """

    def __init__(self, gui_callback=None):
        self.gui_callback = gui_callback

    def load_data(self) -> List[Dict[str, Any]]:
        return load_reflected_responses()

    def build_context_map(self) -> Dict[str, List[Dict[str, Any]]]:
        data = self.load_data()
        ctx_map: Dict[str, List[Dict[str, Any]]] = {}
        for r in data:
            cat = r.get("category", "unknown")
            ctx_map.setdefault(cat, []).append(r)
        return ctx_map

    def render(self):
        ctx_map = self.build_context_map()
        payload = {
            "xss_context_map": ctx_map,
            "total": sum(len(v) for v in ctx_map.values())
        }
        if self.gui_callback:
            self.gui_callback(payload)
        return payload