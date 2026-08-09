# xss_security_gui/threat_data_loader.py
"""
Загрузчик данных Threat Intel из analyzer1.json
Интегрируется с GUI при запуске

Загружает:
- Email Leaks
- Credit Card Leaks
- Password Dumps
- Account States
- Locations
- Phone Numbers
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional


class ThreatDataLoader:
    """Загружает и фильтрует данные Threat Intel"""
    
    def __init__(self, json_path: Optional[str] = None):
        """
        :param json_path: путь к analyzer1.json (если None, ищет в logs/)
        """
        if json_path is None:
            base_dir = Path(__file__).parent
            json_path = base_dir / "logs" / "analyzer1.json"
        else:
            json_path = Path(json_path)
        
        self.json_path = Path(json_path)
        self.data: Dict[str, Any] = {}
        self.artifacts: List[Dict[str, Any]] = []
    
    def load(self) -> bool:
        """Загружает данные из JSON файла"""
        if not self.json_path.exists():
            print(f"[⚠️] Файл не найден: {self.json_path}")
            return False
        
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            
            self.artifacts = self.data.get("artifacts", [])
            print(f"[✅] Загружено {len(self.artifacts)} артефактов")
            return True
        
        except Exception as e:
            print(f"[❌] Ошибка загрузки JSON: {e}")
            return False
    
    def get_email_leaks(self) -> List[Dict[str, Any]]:
        """Возвращает только EMAIL LEAK артефакты"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("category") == "email_leak"
        ]
    
    def get_credit_card_leaks(self) -> List[Dict[str, Any]]:
        """Возвращает только CREDIT CARD LEAK артефакты"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("category") == "credit_card_leak"
        ]
    
    def get_password_dumps(self) -> List[Dict[str, Any]]:
        """Возвращает только PASSWORD DUMP артефакты"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("category") == "password_dump"
        ]
    
    def get_user_data_leaks(self) -> List[Dict[str, Any]]:
        """Возвращает только USER DATA LEAK артефакты"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("category") == "user_data_leak"
        ]
    
    def get_account_states(self) -> List[Dict[str, Any]]:
        """Возвращает ACCOUNT STATE артефакты"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("category") == "account_state_leak"
        ]
    
    def get_phone_leaks(self) -> List[Dict[str, Any]]:
        """Возвращает PHONE NUMBER LEAK артефакты"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("category") == "phone_leak"
        ]
    
    def get_location_leaks(self) -> List[Dict[str, Any]]:
        """Возвращает LOCATION LEAK артефакты"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("category") == "location_leak"
        ]
    
    def get_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Возвращает артефакты по уровню серьезности"""
        return [
            a for a in self.artifacts
            if a.get("result", {}).get("severity") == severity
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Возвращает сводку данных"""
        return {
            "total": self.data.get("total", 0),
            "by_module": self.data.get("by_module", {}),
            "by_severity": self.data.get("by_severity", {}),
            "by_category": self.data.get("by_category", {}),
            "by_source": self.data.get("by_source", {}),
            "artifact_count": len(self.artifacts),
        }
    
    def convert_artifact_for_gui(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Преобразует артефакт из analyzer1.json в формат для threat_tab.add_threat()
        """
        result = artifact.get("result", {})
        
        # Базовая структура
        gui_artifact = {
            "type": result.get("type", "event"),
            "module": artifact.get("module", "unknown"),
            "url": artifact.get("target", ""),
            "risk": result.get("risk", "unknown"),
            "category": result.get("category", "unknown"),
            "source": result.get("source", "analyzer"),
            "timestamp": artifact.get("timestamp", ""),
        }
        
        # Специальная обработка для email_leak
        if result.get("category") == "email_leak":
            email_leak = result.get("email_leak", {})
            gui_artifact["email_leak"] = {
                "emails": email_leak.get("emails", []),
                "smtp_users": email_leak.get("smtp_users", []),
                "smtp_passwords": email_leak.get("smtp_passwords", []),
            }
            gui_artifact["url"] = result.get("url", "")
            gui_artifact["payload"] = result.get("payload", "")
            gui_artifact["status"] = result.get("status", "")
        
        # Credit card leaks
        elif result.get("category") == "credit_card_leak":
            gui_artifact["credit_cards"] = result.get("credit_cards", [])
            gui_artifact["user_data"] = result.get("user_data", {})
        
        # Password dumps
        elif result.get("category") == "password_dump":
            gui_artifact["passwords"] = result.get("passwords", [])
            gui_artifact["user_passwords"] = result.get("user_passwords", [])
        
        # User data leaks
        elif result.get("category") == "user_data_leak":
            gui_artifact["leaked_users"] = result.get("leaked_users", [])
            gui_artifact["count"] = result.get("count", 0)
        
        # Account states
        elif result.get("category") == "account_state_leak":
            gui_artifact["accounts"] = result.get("accounts", [])
        
        # Phone leaks
        elif result.get("category") == "phone_leak":
            gui_artifact["phone_numbers"] = result.get("phone_numbers", [])
            gui_artifact["phone_with_names"] = result.get("phone_with_names", [])
        
        # Location leaks
        elif result.get("category") == "location_leak":
            gui_artifact["addresses"] = result.get("addresses", [])
            gui_artifact["cities"] = result.get("cities", [])
            gui_artifact["user_locations"] = result.get("user_locations", [])
        
        return gui_artifact


def load_threat_data_to_gui(threat_tab) -> int:
    """
    Загружает все данные из analyzer1.json в Threat Tab GUI
    
    :param threat_tab: экземпляр ThreatAnalysisTab
    :return: количество загруженных артефактов
    """
    loader = ThreatDataLoader()
    
    if not loader.load():
        return 0
    
    count = 0
    for artifact in loader.artifacts:
        try:
            gui_artifact = loader.convert_artifact_for_gui(artifact)
            threat_tab.add_threat(gui_artifact)
            count += 1
        except Exception as e:
            print(f"[⚠️] Ошибка обработки артефакта: {e}")
    
    return count


if __name__ == "__main__":
    # Пример использования
    loader = ThreatDataLoader()
    
    if loader.load():
        print("\n[📊] SUMMARY:")
        summary = loader.get_summary()
        for key, value in summary.items():
            print(f"  {key}: {value}")
        
        print("\n[📧] EMAIL LEAKS:")
        for leak in loader.get_email_leaks():
            print(f"  - {leak.get('module')}: {len(leak['result']['email_leak']['emails'])} emails")
        
        print("\n[💳] CREDIT CARD LEAKS:")
        for leak in loader.get_credit_card_leaks():
            print(f"  - {leak.get('module')}: {len(leak['result']['credit_cards'])} cards")
        
        print("\n[🔐] PASSWORD DUMPS:")
        for dump in loader.get_password_dumps():
            print(f"  - {dump.get('module')}: {len(dump['result']['passwords'])} passwords")

