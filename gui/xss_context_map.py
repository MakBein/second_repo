# xss_security_gui/gui/xss_context_map.py

from typing import List, Dict, Any, Optional
from collections import defaultdict
from xss_security_gui.auto_recon.scanner import load_reflected_responses


class XSSContextMapTab:
    """
    Логическая вкладка "XSS Context Map":
    • группировка по категориям
    • список URL
    • быстрый переход к сниппетам
    """

    def __init__(self, gui_callback: Optional[callable] = None):
        self.gui_callback = gui_callback

    # ---------------------------------------------------------
    # Вспомогательный метод для безопасного вызова callback
    # ---------------------------------------------------------
    def _emit(self, key: str, payload: Any) -> None:
        if self.gui_callback:
            try:
                self.gui_callback({key: payload})
            except Exception as e:
                print(f"[XSSContextMapTab] Ошибка gui_callback: {e}")

    # ---------------------------------------------------------
    # Загрузка данных
    # ---------------------------------------------------------
    def load_data(self) -> List[Dict[str, Any]]:
        """Загружает артефакты XSS из NDJSON."""
        try:
            return load_reflected_responses()
        except Exception as e:
            print(f"[XSSContextMapTab] Ошибка загрузки данных: {e}")
            return []

    # ---------------------------------------------------------
    # Построение карты контекста
    # ---------------------------------------------------------
    def build_context_map(self) -> Dict[str, List[Dict[str, Any]]]:
        """Группирует артефакты по категориям."""
        data = self.load_data()
        ctx_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for r in data:
            category = r.get("category", "unknown")
            ctx_map[category].append(r)

        return dict(ctx_map)

    # ---------------------------------------------------------
    # Рендеринг payload для GUI
    # ---------------------------------------------------------
    def render(self) -> Dict[str, Any]:
        """
        Формирует payload для GUI:
        • карта контекста
        • общее количество артефактов
        """
        ctx_map = self.build_context_map()
        payload = {
            "xss_context_map": ctx_map,
            "total": sum(len(v) for v in ctx_map.values()),
        }

        self._emit("xss_context_map", payload)
        return payload