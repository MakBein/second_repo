# xss_security_gui/threat_analysis/account_extractor.py
import re
import json
from typing import Dict, Any, List, Optional, Tuple

# ============================
# Бойова бібліотека regex'ів
# ============================

EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?:[A-Za-z]{2,63})\b"
)

PHONE_RE = re.compile(
    r"\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{2,4}[\s\-]?\d{2,4}\b"
)

CARD_RE = re.compile(
    r"\b(?:"
    r"4[0-9]{12}(?:[0-9]{3})?"              # Visa
    r"|5[1-5][0-9]{14}"                    # MasterCard
    r"|3[47][0-9]{13}"                     # American Express
    r"|6(?:011|5[0-9]{2})[0-9]{12}"        # Discover
    r"|62[0-9]{14,17}"                     # UnionPay
    r")\b"
)

CVV_RE = re.compile(r"\b\d{3,4}\b")

CARD_EXPIRY_RE = re.compile(
    r"\b(?:0[1-9]|1[0-2])\/(?:\d{2}|\d{4})\b"
)

IBAN_RE = re.compile(
    r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b"
)

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\b"
)

PASSWORD_RE = re.compile(
    r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?([^'\"\s]{4,})['\"]?",
    re.IGNORECASE
)

USERNAME_RE = re.compile(
    r"\b[a-zA-Z0-9._-]{3,32}\b"
)

IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

IPV6_RE = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"
)

MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
)

ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9\s\.,'-]{5,80}\b"
)


class AccountExtractor:
    """
    AccountExtractor 11.0 — бойовий екстрактор акаунтів:
    - HTML (full_response)
    - cookies (Set-Cookie + Playwright cookies)
    - JS (window.*, JSON у <script>)
    - API JSON (result["api_response"])
    - форми (result["params"])
    - розширена PII/Account Intelligence бібліотека
    """

    def __init__(self, artifact: Dict[str, Any]):
        self.artifact = artifact
        self.result: Dict[str, Any] = artifact.get("result", {}) or {}
        self.module: Optional[str] = artifact.get("module")
        self.url: Optional[str] = self.result.get("url") or artifact.get("target")
        self.accounts: List[Dict[str, Any]] = []
        self._seen: set[Tuple] = set()

    def extract(self) -> List[Dict[str, Any]]:
        self._from_params()
        self._from_response_headers()
        self._from_playwright_cookies()
        self._from_full_response()
        self._from_api_json()
        return self.accounts

    # ---------- 1. Параметри форми ----------
    def _from_params(self) -> None:
        params = self.result.get("params") or {}
        if not isinstance(params, dict):
            return

        username = params.get("email") or params.get("login") or params.get("username")
        password = params.get("password") or params.get("pass")
        phone = params.get("phone") or params.get("tel")
        card = params.get("card") or params.get("credit_card")

        if any([username, password, phone, card]):
            self._add_account({
                "username": username,
                "email": username if username and "@" in str(username) else None,
                "password": password,
                "phone": phone,
                "address": None,
                "credit_card": card,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

    # ---------- 2. Cookies (Set-Cookie) ----------
    def _from_response_headers(self) -> None:
        headers = self.result.get("response_headers") or {}
        if not isinstance(headers, dict):
            return

        set_cookie = headers.get("Set-Cookie")
        if not set_cookie or not isinstance(set_cookie, str):
            return

        cookies = set_cookie.split(",")
        for c in cookies:
            c = c.strip()
            lower = c.lower()
            if any(k in lower for k in ("email=", "user=", "login=", "uid=")):
                parts = c.split(";")[0].split("=", 1)
                if len(parts) == 2:
                    _, val = parts
                    val = val.strip()
                    self._add_account({
                        "username": val,
                        "email": val if "@" in val else None,
                        "password": None,
                        "phone": None,
                        "address": None,
                        "credit_card": None,
                        "account_status": None,
                        "source": self.module,
                        "url": self.url,
                    })

    # ---------- 2.1. Playwright cookies ----------
    def _from_playwright_cookies(self) -> None:
        cookies = self.result.get("cookies") or []
        if not isinstance(cookies, list):
            return

        for c in cookies:
            if not isinstance(c, dict):
                continue
            name = str(c.get("name", "")).lower()
            value = str(c.get("value", "")).strip()
            if not value:
                continue

            if any(k in name for k in ("email", "user", "login", "uid")):
                self._add_account({
                    "username": value,
                    "email": value if "@" in value else None,
                    "password": None,
                    "phone": None,
                    "address": None,
                    "credit_card": None,
                    "account_status": None,
                    "source": self.module,
                    "url": self.url,
                })

    # ---------- 3. HTML / JS / PII ----------
    def _from_full_response(self) -> None:
        html = self.result.get("full_response")
        if not html or not isinstance(html, str):
            return

        # Email
        for email in set(EMAIL_RE.findall(html)):
            self._add_account({
                "username": email,
                "email": email,
                "password": None,
                "phone": None,
                "address": None,
                "credit_card": None,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # Phone
        for phone in set(PHONE_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "phone": phone,
                "address": None,
                "credit_card": None,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # Credit cards
        for card in set(CARD_RE.findall(html)):
            cleaned = card.replace(" ", "").replace("-", "")
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "phone": None,
                "address": None,
                "credit_card": cleaned,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # CVV
        for cvv in set(CVV_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "phone": None,
                "address": None,
                "credit_card": None,
                "cvv": cvv,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # Card expiry
        for expiry in set(CARD_EXPIRY_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "phone": None,
                "address": None,
                "credit_card": None,
                "expiry": expiry,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # IBAN
        for iban in set(IBAN_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "phone": None,
                "address": None,
                "credit_card": None,
                "iban": iban,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # JWT
        for jwt in set(JWT_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "jwt": jwt,
                "phone": None,
                "address": None,
                "credit_card": None,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # UUID
        for uuid in set(UUID_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "uuid": uuid,
                "phone": None,
                "address": None,
                "credit_card": None,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # IPv4 / IPv6
        for ip in set(IPV4_RE.findall(html)) | set(IPV6_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "ip": ip,
                "phone": None,
                "address": None,
                "credit_card": None,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # MAC
        for mac in set(MAC_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "mac": mac,
                "phone": None,
                "address": None,
                "credit_card": None,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # Address
        for addr in set(ADDRESS_RE.findall(html)):
            self._add_account({
                "username": None,
                "email": None,
                "password": None,
                "address": addr,
                "phone": None,
                "credit_card": None,
                "account_status": None,
                "source": self.module,
                "url": self.url,
            })

        # JSON у <script>
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
            script_body = m.group(1)
            if not script_body:
                continue

            if any(k in script_body for k in ("window.user", "window.profile", "window.account")):
                try:
                    json_match = re.search(r"=\s*({.*?})", script_body, re.DOTALL)
                    if json_match:
                        obj = json.loads(json_match.group(1))
                        if isinstance(obj, dict):
                            self._from_json_object(obj)
                except Exception:
                    continue

    # ---------- 4. API JSON ----------
    def _from_api_json(self) -> None:
        api = self.result.get("api_response")
        if not api:
            return

        if isinstance(api, dict):
            self._from_json_object(api)
        elif isinstance(api, list):
            for item in api:
                if isinstance(item, dict):
                    self._from_json_object(item)

    # ---------- 5. Generic JSON object ----------
    def _from_json_object(self, obj: Dict[str, Any]) -> None:
        email = obj.get("email")
        username = obj.get("username") or obj.get("login") or email
        phone = obj.get("phone") or obj.get("tel")
        address = obj.get("address") or obj.get("location")
        card = obj.get("credit_card") or obj.get("card")
        status = obj.get("status") or obj.get("account_status")

        if any([email, username, phone, card]):
            self._add_account({
                "username": username,
                "email": email,
                "password": obj.get("password") or obj.get("pass"),
                "phone": phone,
                "address": address,
                "credit_card": card,
                "account_status": status,
                "source": self.module,
                "url": self.url,
            })

    # ---------- 6. Додавання акаунта + уникнення дублікатів + risk ----------
    def _add_account(self, acc: Dict[str, Any]) -> None:
        # Нормалізація
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
            self.url,
            self.module,
        )

        if key in self._seen:
            return

        self._seen.add(key)

        acc["risk"] = self._risk_score(acc)
        self.accounts.append(acc)

    # ---------- 7. Risk Score ----------
    def _risk_score(self, acc: Dict[str, Any]) -> int:
        score = 0

        if acc.get("password"): score += 40
        if acc.get("email"): score += 20
        if acc.get("phone"): score += 10
        if acc.get("credit_card"): score += 50
        if acc.get("account_status"): score += 5
        if acc.get("cvv"): score += 40
        if acc.get("expiry"): score += 10
        if acc.get("iban"): score += 60
        if acc.get("jwt"): score += 30
        if acc.get("uuid"): score += 15

        src = (self.module or "").lower()
        if "leak" in src: score += 20
        if "sqli" in src: score += 15

        fields = ["username", "email", "password", "phone", "credit_card"]
        completeness = sum(1 for f in fields if acc.get(f))
        score += completeness * 3

        return score

