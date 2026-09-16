# xss_security_gui/threat_analysis/account_aggregator.py
"""
AccountAggregator 10.0 — Combat Edition
=======================================

Особенности:
- Полная интеграция с PII Intelligence 10.0 Extended
- Поддержка всех типов утечек:
    • leaked_users
    • user_passwords
    • email_leak
    • extracted_accounts
    • accounts / credentials / pii / db_leak / login_dump / password_dump
- Нормализация всех полей (email, username, phone, card)
- Расширенный risk‑engine 3.0
- Deduplication Engine 2.0
- ThreatConnector‑friendly output
- SecurityDashboardPanel‑friendly events
"""

from __future__ import annotations
from typing import Dict, Any, List, Tuple


class AccountAggregator:
    """
    Threat Intel 10.0+ — Account Intelligence Engine
    """

    def __init__(self, artifacts: List[Dict[str, Any]]):
        self.artifacts = artifacts
        self.accounts: List[Dict[str, Any]] = []
        self._seen: set[Tuple] = set()

    # ============================================================
    # MAIN ENTRY
    # ============================================================
    def aggregate(self) -> List[Dict[str, Any]]:
        for a in self.artifacts:
            try:
                result = a.get("result") or {}
                module = a.get("module")
                url = result.get("url") or a.get("target")
                h = a.get("_hash")

                self._from_user_passwords(result, module, url, h)
                self._from_leaked_users(result, module, url, h)
                self._from_email_leak(result, module, url, h)
                self._from_extracted_accounts(result, module, url, h)
                self._from_generic_structures(result, module, url, h)
                self._from_pii_intelligence(result, module, url, h)

            except Exception:
                continue

        return self.accounts

    # ============================================================
    # SOURCES
    # ============================================================
    def _from_user_passwords(self, result, module, url, h):
        for u in result.get("user_passwords", []):
            self._add({
                "username": u.get("username"),
                "email": None,
                "password": u.get("password"),
                "hash_type": u.get("hash_type"),
                "phone": None,
                "address": None,
                "credit_card": None,
                "cvv": None,
                "expiry": None,
                "account_status": None,
                "source": module,
                "artifact_hash": h,
                "url": url,
            })

    def _from_leaked_users(self, result, module, url, h):
        for u in result.get("leaked_users", []):
            self._add({
                "username": u.get("email"),
                "email": u.get("email"),
                "password": u.get("password"),
                "phone": u.get("phone"),
                "address": u.get("address"),
                "credit_card": u.get("credit_card"),
                "cvv": None,
                "expiry": None,
                "account_status": u.get("account_status"),
                "hash_type": None,
                "source": module,
                "artifact_hash": h,
                "url": url,
            })

    def _from_email_leak(self, result, module, url, h):
        leak = result.get("email_leak") or {}
        emails = leak.get("emails", [])
        passwords = leak.get("passwords", [])
        phones = leak.get("phones", [])
        addresses = leak.get("addresses", [])
        credit_cards = leak.get("credit_cards", [])
        cvv = leak.get("cvv", [])
        expiry = leak.get("card_expiry", [])

        for i, email in enumerate(emails):
            self._add({
                "username": email,
                "email": email,
                "password": passwords[i] if i < len(passwords) else None,
                "phone": phones[i] if i < len(phones) else None,
                "address": addresses[i] if i < len(addresses) else None,
                "credit_card": credit_cards[i] if i < len(credit_cards) else None,
                "cvv": cvv[i] if i < len(cvv) else None,
                "expiry": expiry[i] if i < len(expiry) else None,
                "account_status": None,
                "hash_type": None,
                "source": module,
                "artifact_hash": h,
                "url": url,
            })

    def _from_extracted_accounts(self, result, module, url, h):
        for u in result.get("extracted_accounts", []):
            self._add({
                "username": u.get("username"),
                "email": u.get("email"),
                "password": u.get("password"),
                "phone": u.get("phone"),
                "address": u.get("address"),
                "credit_card": u.get("credit_card"),
                "cvv": u.get("cvv"),
                "expiry": u.get("expiry"),
                "account_status": u.get("account_status"),
                "hash_type": u.get("hash_type"),
                "source": u.get("source") or module,
                "artifact_hash": h,
                "url": u.get("url") or url,
            })

    def _from_generic_structures(self, result, module, url, h):
        keys = ["accounts", "credentials", "pii", "db_leak", "login_dump", "password_dump"]
        for key in keys:
            for u in result.get(key, []):
                self._add({
                    "username": u.get("username") or u.get("login") or u.get("email"),
                    "email": u.get("email"),
                    "password": u.get("password") or u.get("pass"),
                    "phone": u.get("phone"),
                    "address": u.get("address"),
                    "credit_card": u.get("credit_card") or u.get("card"),
                    "cvv": u.get("cvv"),
                    "expiry": u.get("expiry"),
                    "account_status": u.get("status") or u.get("account_status"),
                    "hash_type": u.get("hash_type"),
                    "source": module,
                    "artifact_hash": h,
                    "url": url,
                })

    # ============================================================
    # PII Intelligence 10.0 Extended
    # ============================================================
    def _from_pii_intelligence(self, result, module, url, h):
        pii = result.get("pii") or {}
        if not isinstance(pii, dict):
            return

        emails = pii.get("emails", [])
        passwords = pii.get("passwords", [])
        phones = pii.get("phones", [])
        addresses = pii.get("addresses", [])
        cards = pii.get("credit_cards", [])
        logins = pii.get("logins", [])

        for i, email in enumerate(emails):
            self._add({
                "username": email,
                "email": email,
                "password": passwords[i] if i < len(passwords) else None,
                "phone": phones[i] if i < len(phones) else None,
                "address": addresses[i] if i < len(addresses) else None,
                "credit_card": cards[i] if i < len(cards) else None,
                "cvv": None,
                "expiry": None,
                "account_status": None,
                "hash_type": None,
                "source": module,
                "artifact_hash": h,
                "url": url,
            })

        for login in logins:
            self._add({
                "username": login,
                "email": None,
                "password": None,
                "phone": None,
                "address": None,
                "credit_card": None,
                "cvv": None,
                "expiry": None,
                "account_status": None,
                "hash_type": None,
                "source": module,
                "artifact_hash": h,
                "url": url,
            })

    # ============================================================
    # NORMALIZATION + DEDUP + RISK ENGINE
    # ============================================================
    def _add(self, acc):
        email = acc.get("email")
        if email:
            acc["email"] = str(email).strip().lower()

        username = acc.get("username")
        if username:
            acc["username"] = str(username).strip()

        phone = acc.get("phone")
        if phone:
            acc["phone"] = str(phone).replace(" ", "").replace("-", "")

        card = acc.get("credit_card")
        if card:
            card = str(card).replace(" ", "").replace("-", "")
            if not (13 <= len(card) <= 19):
                card = None
            acc["credit_card"] = card

        key = (
            acc.get("username"),
            acc.get("email"),
            acc.get("password"),
            acc.get("phone"),
            acc.get("credit_card"),
            acc.get("url"),
            acc.get("source"),
        )

        if key in self._seen:
            return

        self._seen.add(key)
        acc["risk"] = self._risk_score(acc)
        self.accounts.append(acc)

    def _risk_score(self, acc):
        score = 0
        if acc.get("password"): score += 50
        if acc.get("email"): score += 25
        if acc.get("phone"): score += 15
        if acc.get("credit_card"): score += 70
        if acc.get("cvv"): score += 40
        if acc.get("expiry"): score += 10

        src = (acc.get("source") or "").lower()
        if "leak" in src: score += 25
        if "sqli" in src: score += 20
        if "lfi" in src: score += 15
        if "endpointscanner" in src: score += 5

        fields = ["username", "email", "password", "phone", "credit_card"]
        completeness = sum(1 for f in fields if acc.get(f))
        score += completeness * 5

        return score



