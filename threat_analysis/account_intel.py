# xss_security_gui/threat_analysis/account_intel.py
"""
Account Intelligence 11.0 — Unified Pipeline
============================================

Єдиний бойовий пайплайн:
- AccountExtractor 11.0 → витягує акаунти з одного артефакта
- AccountAggregator 10.0 → агрегує акаунти з усіх артефактів
- ThreatConnector‑friendly output:
    • category=account_intel
    • risk
    • accounts[]
"""

from __future__ import annotations
from typing import Dict, Any, List

from xss_security_gui.threat_analysis.account_extractor import AccountExtractor
from xss_security_gui.threat_analysis.account_aggregator import AccountAggregator


class AccountIntelPipeline:
    """
    Account Intelligence 11.0 — ThreatConnector‑friendly пайплайн.
    """

    def __init__(self, artifacts: List[Dict[str, Any]]):
        self.artifacts = artifacts
        self._extracted_accounts: List[Dict[str, Any]] = []
        self._aggregated_accounts: List[Dict[str, Any]] = []

    def run(self) -> List[Dict[str, Any]]:
        """
        Повний цикл:
        1) прогнати AccountExtractor 11.0 по кожному артефакту
        2) зібрати всі акаунти
        3) прогнати AccountAggregator 10.0
        4) повернути агрегований список акаунтів
        """
        extracted_per_artifact: List[Dict[str, Any]] = []

        for art in self.artifacts:
            try:
                extractor = AccountExtractor(art)
                accounts = extractor.extract()
                self._extracted_accounts.extend(accounts)

                extracted_per_artifact.append({
                    "module": art.get("module"),
                    "target": art.get("target"),
                    "_hash": art.get("_hash"),
                    "result": {
                        "extracted_accounts": accounts,
                        "url": art.get("result", {}).get("url") or art.get("target"),
                    },
                })
            except Exception:
                continue

        aggregator = AccountAggregator(extracted_per_artifact)
        self._aggregated_accounts = aggregator.aggregate()
        return self._aggregated_accounts

    def build_threat_artifact(self) -> Dict[str, Any]:
        """
        ThreatConnector‑friendly артефакт category=account_intel.
        """
        accounts = self._aggregated_accounts or self.run()
        risk = self._overall_risk(accounts)

        return {
            "type": "AccountIntel",
            "category": "account_intel",
            "risk": risk,
            "accounts": accounts,
            "summary": {
                "total": len(accounts),
                "high_risk": sum(1 for a in accounts if a.get("risk", 0) >= 100),
                "with_cards": sum(1 for a in accounts if a.get("credit_card")),
                "with_passwords": sum(1 for a in accounts if a.get("password")),
            },
        }

    def _overall_risk(self, accounts: List[Dict[str, Any]]) -> str:
        if not accounts:
            return "low"

        max_score = max(a.get("risk", 0) for a in accounts)
        if max_score >= 150:
            return "critical"
        if max_score >= 100:
            return "high"
        if max_score >= 50:
            return "medium"
        return "low"
