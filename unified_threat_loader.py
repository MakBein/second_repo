# xss_security_gui/unified_threat_loader.py
"""
Unified Threat Loader - загружает данные из multiple источников:
1. analyzer1.json (исторические данные)
2. real_breaches.json (реалистичные сценарии с техниками обхода)
3. threat_history.json (AI-собранные угрозы)

Анализирует и классифицирует угрозы с помощью AI.
Сохраняет результаты для тренирования.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime


class UnifiedThreatLoader:
    """Загружает и объединяет угрозы из различных источников"""
    
    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = Path(__file__).parent
        self.base_dir = base_dir
        self.logs_dir = base_dir / "logs"
        self.threats: List[Dict[str, Any]] = []
        self.statistics = {
            "from_analyzer": 0,
            "from_real_breaches": 0,
            "from_history": 0,
            "total": 0,
            "by_category": {},
            "by_risk": {},
        }

    def load_all_sources(self) -> bool:
        """Загружает угрозы из всех доступных источников"""
        success = True
        
        # Load analyzer1.json
        if self._load_analyzer():
            pass
        
        # Load real_breaches.json
        if self._load_real_breaches():
            pass
        
        # Load threat_history.json
        if self._load_history():
            pass
        
        self.statistics["total"] = len(self.threats)
        return len(self.threats) > 0

    def _load_analyzer(self) -> bool:
        """Загружает analyzer1.json"""
        path = self.logs_dir / "analyzer1.json"
        if not path.exists():
            return False
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            artifacts = data.get("artifacts", [])
            self.threats.extend(artifacts)
            self.statistics["from_analyzer"] = len(artifacts)
            return True
        except Exception as e:
            print(f"[⚠️] Error loading analyzer1.json: {e}")
            return False

    def _load_real_breaches(self) -> bool:
        """Загружает real_breaches.json с реалистичными сценариями"""
        path = self.logs_dir / "real_breaches.json"
        if not path.exists():
            return False
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            scenarios = data.get("scenarios", [])
            self.threats.extend(scenarios)
            self.statistics["from_real_breaches"] = len(scenarios)
            return True
        except Exception as e:
            print(f"[⚠️] Error loading real_breaches.json: {e}")
            return False

    def _load_history(self) -> bool:
        """Загружает threat_history.json"""
        path = self.logs_dir / "threat_history.json"
        if not path.exists():
            return False
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                history = json.load(f)
            
            if isinstance(history, list):
                # Format: [{"timestamp": ..., "entry": {...}}, ...]
                threats_from_history = [h.get("entry") for h in history if "entry" in h]
                self.threats.extend(threats_from_history)
                self.statistics["from_history"] = len(threats_from_history)
            return len(threats_from_history) > 0
        except Exception as e:
            print(f"[⚠️] Error loading threat_history.json: {e}")
            return False

    def analyze_with_ai(self):
        """Анализирует все загруженные угрозы с помощью AI助手"""
        try:
            from xss_security_gui.ai_adapter import get_ai_assistant
            ai = get_ai_assistant()
            
            analyzed_threats = []
            for threat in self.threats:
                result = ai.analyze(threat)
                threat_with_analysis = {
                    **threat,
                    "ai_analysis": result,
                    "analyzed_at": datetime.now().isoformat(),
                }
                analyzed_threats.append(threat_with_analysis)
                
                # Learn for future training
                ai.learn(threat)
            
            self.threats = analyzed_threats
            print(f"[✅] Analyzed {len(analyzed_threats)} threats with AI")
        except Exception as e:
            print(f"[⚠️] AI analysis error: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Возвращает статистику загруженных угроз"""
        stats = {
            **self.statistics,
            "by_category": {},
            "by_risk": {},
            "by_source": {},
        }
        
        for threat in self.threats:
            # By category
            category = threat.get("result", {}).get("category", "unknown")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            # By risk
            risk = threat.get("result", {}).get("risk", "unknown")
            stats["by_risk"][risk] = stats["by_risk"].get(risk, 0) + 1
            
            # By source
            source = threat.get("module", "unknown")
            stats["by_source"][source] = stats["by_source"].get(source, 0) + 1
        
        self.statistics = {**self.statistics, **stats}
        return self.statistics

    def export_to_gui_format(self) -> List[Dict[str, Any]]:
        """Преобразует все загруженные угрозы в формат для GUI"""
        from xss_security_gui.threat_data_loader import ThreatDataLoader
        
        loader = ThreatDataLoader()
        gui_threats = []
        
        for threat in self.threats:
            try:
                if "result" in threat:
                    # Format from analyzer1.json or real_breaches.json
                    gui_threat = loader.convert_artifact_for_gui(threat)
                else:
                    # Already in GUI format or from history
                    gui_threat = threat
                
                gui_threats.append(gui_threat)
            except Exception as e:
                print(f"[⚠️] Error converting threat to GUI format: {e}")
        
        return gui_threats

    def save_combined_analysis(self, output_file: str = None) -> str:
        """Сохраняет объединённый анализ всех угроз"""
        if output_file is None:
            output_file = self.logs_dir / "combined_threat_analysis.json"
        else:
            output_file = Path(output_file)
        
        output_file.parent.mkdir(exist_ok=True, parents=True)
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "threats": self.threats,
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"[✅] Combined analysis saved to: {output_file}")
        return str(output_file)


def load_all_threats_to_gui(threat_tab) -> int:
    """
    Загружает ВСЕ угрозы из всех источников в GUI
    
    :param threat_tab: ThreatAnalysisTab instance
    :return: количество загруженных угроз
    """
    loader = UnifiedThreatLoader()
    
    print("[*] Loading threats from all sources...")
    if not loader.load_all_sources():
        print("[⚠️] No threats found in any source")
        return 0
    
    print(f"[✅] Loaded {len(loader.threats)} threats total")
    
    # Analyze with AI
    print("[*] Analyzing threats with AI...")
    loader.analyze_with_ai()
    
    # Get statistics
    stats = loader.get_statistics()
    print(f"\n[📊] Statistics:")
    for category, count in stats["by_category"].items():
        print(f"  {category}: {count}")
    
    # Convert to GUI format and load
    print("[*] Loading into GUI...")
    gui_threats = loader.export_to_gui_format()
    
    count = 0
    for threat in gui_threats:
        try:
            if hasattr(threat_tab, 'add_threat'):
                threat_tab.add_threat(threat)
                count += 1
        except Exception as e:
            print(f"[⚠️] Error adding threat to GUI: {e}")
    
    # Save combined analysis
    loader.save_combined_analysis()
    
    print(f"[✅] Loaded {count} threats into Threat Tab")
    return count


if __name__ == "__main__":
    # Example usage
    loader = UnifiedThreatLoader()
    
    print("Loading all threat sources...")
    if loader.load_all_sources():
        stats = loader.get_statistics()
        print(f"\n[📊] Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Save analysis
        loader.save_combined_analysis()
    else:
        print("[⚠️] No threats loaded")

