# xss_security_gui/unified_threat_loader.py
"""
Unified Threat Loader — enterprise-уровень агрегации угроз.

Источники:
1. analyzer1.json (исторические артефакты)
2. real_breaches.json (реалистичные сценарии атак)
3. threat_history.json (история AI/GUI событий)

Функции:
- безопасная загрузка всех источников
- нормализация формата угроз
- AI-анализ (если доступен)
- экспорт в формат ThreatAnalysisTab
- сохранение объединённого анализа
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from xss_security_gui.threat_data_loader import ThreatDataLoader, ThreatCategory, ThreatRisk

logger = logging.getLogger(__name__)


class UnifiedThreatLoader:
    """Загружает и объединяет угрозы из различных источников"""

    def __init__(self, base_dir: Optional[Path | str] = None):
        if base_dir is None:
            base_dir = Path(__file__).resolve().parent
        else:
            base_dir = Path(base_dir)

        self.base_dir: Path = base_dir
        self.logs_dir: Path = base_dir / "logs"

        self.threats: List[Dict[str, Any]] = []

        self.statistics: Dict[str, Any] = {
            "from_analyzer": 0,
            "from_real_breaches": 0,
            "from_history": 0,
            "total": 0,
            "by_category": {},
            "by_risk": {},
            "by_source": {},
        }

    # ============================================================
    #  LOW-LEVEL JSON LOADER
    # ============================================================

    def _load_json(self, filename: str) -> Optional[Any]:
        path = self.logs_dir / filename
        if not path.exists():
            logger.info("UnifiedThreatLoader: файл %s не найден", path)
            return None

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info("UnifiedThreatLoader: загружен %s (%s)", filename, path)
            return data
        except Exception as e:
            logger.exception("UnifiedThreatLoader: ошибка загрузки %s: %s", filename, e)
            return None

    # ============================================================
    #  SOURCE LOADERS
    # ============================================================

    def load_all_sources(self) -> bool:
        """Загружает угрозы из всех доступных источников"""
        self._load_analyzer()
        self._load_real_breaches()
        self._load_history()

        self.statistics["total"] = len(self.threats)
        logger.info("UnifiedThreatLoader: всего угроз после объединения: %d", len(self.threats))
        return len(self.threats) > 0

    def _load_analyzer(self) -> bool:
        data = self._load_json("analyzer1.json")
        if not data:
            return False

        artifacts = data.get("artifacts", []) or []
        artifacts = [a for a in artifacts if isinstance(a, dict)]
        self.threats.extend(artifacts)
        self.statistics["from_analyzer"] = len(artifacts)
        logger.info("UnifiedThreatLoader: из analyzer1.json загружено %d артефактов", len(artifacts))
        return True

    def _load_real_breaches(self) -> bool:
        data = self._load_json("real_breaches.json")
        if not data:
            return False

        scenarios = data.get("scenarios", []) or []
        scenarios = [s for s in scenarios if isinstance(s, dict)]
        self.threats.extend(scenarios)
        self.statistics["from_real_breaches"] = len(scenarios)
        logger.info("UnifiedThreatLoader: из real_breaches.json загружено %d сценариев", len(scenarios))
        return True

    def _load_history(self) -> bool:
        data = self._load_json("threat_history.json")
        if not data:
            return False

        if isinstance(data, list):
            entries = [
                h.get("entry") for h in data
                if isinstance(h, dict) and isinstance(h.get("entry"), dict)
            ]
            self.threats.extend(entries)
            self.statistics["from_history"] = len(entries)
            logger.info("UnifiedThreatLoader: из threat_history.json загружено %d записей", len(entries))
            return True

        return False

    # ============================================================
    #  AI ANALYSIS
    # ============================================================

    def analyze_with_ai(self) -> None:
        """Анализирует угрозы через AI, если доступен адаптер"""
        try:
            from xss_security_gui.ai_adapter import get_ai_assistant
            ai = get_ai_assistant()
        except Exception as e:
            logger.warning("UnifiedThreatLoader: AI недоступен: %s", e)
            return

        analyzed: List[Dict[str, Any]] = []

        for threat in self.threats:
            try:
                result = ai.analyze(threat)
                ai.learn(threat)
                analyzed.append({
                    **threat,
                    "ai_analysis": result,
                    "analyzed_at": datetime.now().isoformat(),
                })
            except Exception as e:
                logger.exception("UnifiedThreatLoader: ошибка AI для угрозы: %s", e)
                analyzed.append(threat)

        self.threats = analyzed
        logger.info("UnifiedThreatLoader: AI проанализировал %d угроз", len(analyzed))

    # ============================================================
    #  STATISTICS
    # ============================================================

    def get_statistics(self) -> Dict[str, Any]:
        by_category: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        by_source: Dict[str, int] = {}

        for threat in self.threats:
            result = threat.get("result", {}) or {}

            category = result.get("category", "unknown")
            by_category[category] = by_category.get(category, 0) + 1

            risk = ThreatRisk.normalize(result.get("risk"))
            by_risk[risk] = by_risk.get(risk, 0) + 1

            source = threat.get("module", "unknown")
            by_source[source] = by_source.get(source, 0) + 1

        self.statistics["by_category"] = by_category
        self.statistics["by_risk"] = by_risk
        self.statistics["by_source"] = by_source

        return self.statistics

    # ============================================================
    #  NORMALIZATION FOR GUI
    # ============================================================

    def export_to_gui_format(self) -> List[Dict[str, Any]]:
        """
        Нормализует угрозы в формат ThreatAnalysisTab через ThreatDataLoader.convert_artifact_for_gui
        """
        loader = ThreatDataLoader(base_dir=self.base_dir)
        gui_threats: List[Dict[str, Any]] = []

        for threat in self.threats:
            try:
                if "result" in threat:
                    gui = loader.convert_artifact_for_gui(threat)
                else:
                    gui = threat

                if gui:
                    gui_threats.append(gui)
            except Exception as e:
                logger.exception("UnifiedThreatLoader: ошибка конвертации угрозы в GUI формат: %s", e)

        logger.info("UnifiedThreatLoader: в GUI формат конвертировано %d угроз", len(gui_threats))
        return gui_threats

    # ============================================================
    #  SAVE COMBINED ANALYSIS
    # ============================================================

    def save_combined_analysis(self, output_file: Optional[str | Path] = None) -> str:
        if output_file is None:
            output_file = self.logs_dir / "combined_threat_analysis.json"
        else:
            output_file = Path(output_file)

        output_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "threats": self.threats,
        }

        with output_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info("UnifiedThreatLoader: combined analysis saved to %s", output_file)
        return str(output_file)


# ============================================================
#  LOAD INTO GUI
# ============================================================

def load_all_threats_to_gui(threat_tab) -> int:
    """
    Загружает ВСЕ угрозы из всех источников в ThreatAnalysisTab.
    """
    loader = UnifiedThreatLoader()

    logger.info("UnifiedThreatLoader: старт загрузки всех источников...")
    if not loader.load_all_sources():
        logger.warning("UnifiedThreatLoader: угрозы не найдены ни в одном источнике")
        return 0

    logger.info("UnifiedThreatLoader: всего сырых угроз: %d", len(loader.threats))

    logger.info("UnifiedThreatLoader: запуск AI анализа...")
    loader.analyze_with_ai()

    logger.info("UnifiedThreatLoader: конвертация в GUI формат...")
    gui_threats = loader.export_to_gui_format()

    count = 0
    errors = 0

    for threat in gui_threats:
        try:
            threat_tab.add_threat(threat)
            count += 1
        except Exception as e:
            errors += 1
            logger.exception("UnifiedThreatLoader: ошибка добавления угрозы в GUI: %s", e)

    loader.save_combined_analysis()

    logger.info(
        "UnifiedThreatLoader: загружено в Threat Tab %d угроз, ошибок: %d",
        count,
        errors,
    )
    return count



