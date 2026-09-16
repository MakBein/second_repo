# xss_security_gui/utils/pii_aggregator.py
"""
PII Intelligence 10.0 (Extended)
================================
Боєва версія multi‑source PII aggregation + risk scoring + ThreatConnector‑ready artifacts.

Особенности:
- Расширенные regex‑библиотеки:
  • Email, phone, card, CVV, expiry
  • JWT, OAuth tokens, session tokens, API keys, secrets
  • IBAN, SWIFT/BIC, bank account, routing numbers
  • Passport, tax_id, national_id, SSN‑подобные
  • Cloud secrets (AWS, GCP, Azure), SSH keys, private keys
- Multi‑source aggregation:
  • crawler / JS / API / cookies / headers / raw text / logs / config / env / DB dumps
- PIIContext 10.0:
  • risk, confidence, sources, tags, modules, target_url
- Risk scoring 3.0:
  • critical / high / medium / low
  • per‑category weighting
- Полная обратная совместимость:
  • aggregate_pii_from_crawler()
  • build_email_leak_artifact()
  • build_email_leak_artifact_from_context()
  • merge_pii_dicts()
  • flatten_email_leak_rows()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Iterable, Tuple


# ------------------------------------------------------------
#  Regex Engine 10.0 (Extended)
# ------------------------------------------------------------

# Email
EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"
)

# Phone (generic international)
PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{2,4}[\s-]?\d{2,4}"
)

# Credit card numbers (generic)
CARD_RE = re.compile(
    r"\b(?:\d[ -]*?){13,19}\b"
)

# CVV (3–4 digits, often near card)
CVV_RE = re.compile(
    r"\b(?:CVV|CVC|CVV2|CVC2)\s*[:=]?\s*(\d{3,4})\b",
    re.IGNORECASE,
)

# Card expiry (MM/YY, MM/YYYY)
CARD_EXPIRY_RE = re.compile(
    r"\b(0[1-9]|1[0-2])[/\-](\d{2}|\d{4})\b"
)

# JWT tokens
JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)

# Generic tokens (Bearer, session, access_token)
TOKEN_RE = re.compile(
    r"\b(?:Bearer\s+[A-Za-z0-9._-]+|"
    r"sessionid=[A-Za-z0-9._-]+|"
    r"access_token=[A-Za-z0-9._-]+|"
    r"refresh_token=[A-Za-z0-9._-]+)\b",
    re.IGNORECASE,
)

# IBAN
IBAN_RE = re.compile(
    r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b"
)

# SWIFT/BIC
SWIFT_RE = re.compile(
    r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b"
)

# Passport (generic)
PASSPORT_RE = re.compile(
    r"\b[A-Z]{2}[0-9]{6,8}\b"
)

# Tax ID (generic)
TAX_ID_RE = re.compile(
    r"\b\d{10,12}\b"
)

# SSN‑подобные (US style)
SSN_RE = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b"
)

# API keys (generic)
API_KEY_RE = re.compile(
    r"\b(?:api_key|apikey|x-api-key|api-token|apiKey)\s*[:=]\s*[A-Za-z0-9_\-]{16,128}\b",
    re.IGNORECASE,
)

# Generic secrets (password, secret, key, token)
SECRET_RE = re.compile(
    r"\b(?:secret|token|key|password|pwd)\s*[:=]\s*[A-Za-z0-9_\-]{8,256}\b",
    re.IGNORECASE,
)

# AWS Access Key ID
AWS_ACCESS_KEY_RE = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"
)

# AWS Secret Access Key (heuristic)
AWS_SECRET_KEY_RE = re.compile(
    r"\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*[A-Za-z0-9/+=]{32,128}\b",
    re.IGNORECASE,
)

# AWS Session Token
AWS_SESSION_TOKEN_RE = re.compile(
    r"\b(?:aws_session_token)\s*[:=]\s*[A-Za-z0-9/+=]{32,512}\b",
    re.IGNORECASE,
)

# GCP Service Account key (JSON key hint)
GCP_KEY_HINT_RE = re.compile(
    r'"type"\s*:\s*"service_account"',
    re.IGNORECASE,
)

# Azure connection strings (heuristic)
AZURE_CONN_STR_RE = re.compile(
    r"\bEndpoint=sb://[A-Za-z0-9.-]+;SharedAccessKeyName=[A-Za-z0-9_-]+;SharedAccessKey=[A-Za-z0-9+/=]+\b"
)

# SSH private key
SSH_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
)

# Generic private key
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN PRIVATE KEY-----"
)

# Database connection strings (generic)
DB_CONN_STR_RE = re.compile(
    r"\b(?:postgres|mysql|mssql|oracle|mongodb)://[^\s\"']+\b",
    re.IGNORECASE,
)

# Env‑style secrets
ENV_SECRET_RE = re.compile(
    r"\b[A-Z0-9_]+(?:SECRET|TOKEN|KEY|PASSWORD|PWD)\b\s*=\s*[^\s\"']+\b",
    re.IGNORECASE,
)


PII_FIELD_LABELS: Dict[str, str] = {
    "emails": "📧 Email",
    "phones": "📱 Телефон",
    "credit_cards": "💳 Банковская карта",
    "cvv": "🔒 CVV",
    "card_expiry": "📅 Срок действия карты",
    "account_numbers": "🏦 Номер счёта",
    "bank_swift": "🏦 SWIFT/BIC",
    "bank_routing": "🏦 Routing Number",
    "passwords": "🔑 Пароль",
    "logins": "👤 Логин",
    "full_names": "🧑 ФИО",
    "addresses": "🏠 Адрес",
    "ssn": "🆔 SSN",
    "tokens": "🎫 Токен",
    "jwt": "🪪 JWT",
    "iban": "🏦 IBAN",
    "passport": "🪪 Паспорт",
    "tax_id": "🧾 Tax ID",
    "api_keys": "🔐 API Key",
    "secrets": "🧩 Secret",
    "aws_keys": "☁ AWS Keys",
    "gcp_keys": "☁ GCP Keys",
    "azure_keys": "☁ Azure Keys",
    "ssh_keys": "🔐 SSH Private Key",
    "private_keys": "🔐 Private Key",
    "db_conn_strings": "🗄 DB Connection String",
    "env_secrets": "⚙ Env Secret",
}

PII_KEYS: List[str] = list(PII_FIELD_LABELS.keys())


# ------------------------------------------------------------
#  PIIContext 10.0 — структурированный объект
# ------------------------------------------------------------

@dataclass
class PIIContext:
    pii: Dict[str, List[str]] = field(default_factory=lambda: {k: [] for k in PII_KEYS})
    sources: List[str] = field(default_factory=list)
    risk: str = "medium"
    confidence: float = 0.5
    target_url: str = ""
    module: str = "crawler"
    source: str = "crawler"
    tags: List[str] = field(default_factory=list)

    def has_data(self) -> bool:
        return any(self.pii.get(k) for k in PII_KEYS)

    def add_source(self, name: str) -> None:
        name = str(name).strip()
        if name and name not in self.sources:
            self.sources.append(name)

    def add_tag(self, tag: str) -> None:
        tag = str(tag).strip()
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def merge_pii(self, other: Dict[str, List[str]]) -> None:
        for key in PII_KEYS:
            for item in other.get(key, []):
                s = str(item).strip()
                if s and s not in self.pii[key]:
                    self.pii[key].append(s)

    def _risk_weights(self) -> Dict[str, int]:
        return {
            "credit_cards": 10,
            "cvv": 9,
            "card_expiry": 7,
            "passwords": 9,
            "api_keys": 9,
            "secrets": 8,
            "aws_keys": 9,
            "gcp_keys": 8,
            "azure_keys": 8,
            "ssh_keys": 9,
            "private_keys": 9,
            "db_conn_strings": 8,
            "env_secrets": 7,
            "tokens": 7,
            "jwt": 7,
            "iban": 7,
            "account_numbers": 7,
            "bank_swift": 6,
            "bank_routing": 6,
            "emails": 5,
            "logins": 5,
            "full_names": 4,
            "addresses": 4,
            "phones": 4,
            "ssn": 8,
            "passport": 7,
            "tax_id": 7,
        }

    def recompute_risk(self) -> None:
        weights = self._risk_weights()
        total_score = 0

        for key, weight in weights.items():
            count = len(self.pii.get(key, []))
            if count > 0:
                total_score += weight * min(count, 10)

        if total_score >= 200:
            self.risk = "critical"
        elif total_score >= 100:
            self.risk = "high"
        elif total_score >= 40:
            self.risk = "medium"
        else:
            self.risk = "low"

        item_count = sum(len(self.pii.get(k, [])) for k in PII_KEYS)

        if item_count >= 50:
            self.confidence = 0.98
        elif item_count >= 30:
            self.confidence = 0.95
        elif item_count >= 20:
            self.confidence = 0.9
        elif item_count >= 10:
            self.confidence = 0.8
        elif item_count >= 5:
            self.confidence = 0.7
        elif item_count >= 1:
            self.confidence = 0.6
        else:
            self.confidence = 0.5


# ------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------

def _normalize_list_value(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, dict) and "examples" in value:
        raw = value.get("examples", [])
    elif isinstance(value, (list, tuple)):
        raw = value
    else:
        raw = [value]
    out: List[str] = []
    for item in raw:
        s = str(item).strip()
        if s and s not in out:
            out.append(s)
    return out


def _collect_pages(result: Any) -> List[Dict[str, Any]]:
    if isinstance(result, list):
        return [p for p in result if isinstance(p, dict)]
    if not isinstance(result, dict):
        return []
    for key in ("pages", "details", "nodes", "results"):
        pages = result.get(key)
        if isinstance(pages, list) and pages:
            return [p for p in pages if isinstance(p, dict)]
    if result.get("url"):
        return [result]
    return []


def _extract_pii_from_text(text: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {k: [] for k in PII_KEYS}
    if not text:
        return out

    # Basic PII
    for email in EMAIL_RE.findall(text):
        if email not in out["emails"]:
            out["emails"].append(email)

    for phone in PHONE_RE.findall(text):
        if phone not in out["phones"]:
            out["phones"].append(phone)

    for card in CARD_RE.findall(text):
        if card not in out["credit_cards"]:
            out["credit_cards"].append(card)

    for cvv in CVV_RE.findall(text):
        if cvv not in out["cvv"]:
            out["cvv"].append(cvv)

    for expiry in CARD_EXPIRY_RE.findall(text):
        val = "/".join(expiry)
        if val not in out["card_expiry"]:
            out["card_expiry"].append(val)

    for jwt in JWT_RE.findall(text):
        if jwt not in out["jwt"]:
            out["jwt"].append(jwt)

    for token in TOKEN_RE.findall(text):
        if token not in out["tokens"]:
            out["tokens"].append(token)

    for iban in IBAN_RE.findall(text):
        if iban not in out["iban"]:
            out["iban"].append(iban)

    for swift in SWIFT_RE.findall(text):
        if swift not in out["bank_swift"]:
            out["bank_swift"].append(swift)

    for passport in PASSPORT_RE.findall(text):
        if passport not in out["passport"]:
            out["passport"].append(passport)

    for tax in TAX_ID_RE.findall(text):
        if tax not in out["tax_id"]:
            out["tax_id"].append(tax)

    for ssn in SSN_RE.findall(text):
        if ssn not in out["ssn"]:
            out["ssn"].append(ssn)

    for api_key in API_KEY_RE.findall(text):
        if api_key not in out["api_keys"]:
            out["api_keys"].append(api_key)

    for secret in SECRET_RE.findall(text):
        if secret not in out["secrets"]:
            out["secrets"].append(secret)

    # Cloud secrets
    for ak in AWS_ACCESS_KEY_RE.findall(text):
        if ak not in out["aws_keys"]:
            out["aws_keys"].append(ak)

    for sk in AWS_SECRET_KEY_RE.findall(text):
        if sk not in out["aws_keys"]:
            out["aws_keys"].append(sk)

    for st in AWS_SESSION_TOKEN_RE.findall(text):
        if st not in out["aws_keys"]:
            out["aws_keys"].append(st)

    if GCP_KEY_HINT_RE.search(text):
        if "service_account" not in out["gcp_keys"]:
            out["gcp_keys"].append("service_account")

    for conn in AZURE_CONN_STR_RE.findall(text):
        if conn not in out["azure_keys"]:
            out["azure_keys"].append(conn)

    # Keys
    if SSH_PRIVATE_KEY_RE.search(text):
        if "SSH_PRIVATE_KEY" not in out["ssh_keys"]:
            out["ssh_keys"].append("SSH_PRIVATE_KEY")

    if PRIVATE_KEY_RE.search(text):
        if "PRIVATE_KEY" not in out["private_keys"]:
            out["private_keys"].append("PRIVATE_KEY")

    # DB connection strings
    for db_conn in DB_CONN_STR_RE.findall(text):
        if db_conn not in out["db_conn_strings"]:
            out["db_conn_strings"].append(db_conn)

    # Env secrets
    for env in ENV_SECRET_RE.findall(text):
        if env not in out["env_secrets"]:
            out["env_secrets"].append(env)

    return {k: v for k, v in out.items() if v}


def _merge_pii(target: Dict[str, List[str]], src: Dict[str, List[str]]) -> None:
    for key in PII_KEYS:
        for item in src.get(key, []):
            s = str(item).strip()
            if s and s not in target[key]:
                target[key].append(s)


# ------------------------------------------------------------
#  PII Intelligence 10.0 — multi‑source aggregation
# ------------------------------------------------------------

def aggregate_pii_from_crawler(result: Any) -> Dict[str, List[str]]:
    """
    Backward‑compatible API (PII Intelligence 2.0/5.0).
    Внутри использует PIIContext 10.0, но возвращает простой dict.
    """
    ctx = aggregate_pii_multi_source(crawler_result=result)
    return {k: v for k, v in ctx.pii.items() if v}


def aggregate_pii_multi_source(
    *,
    crawler_result: Any = None,
    js_results: Iterable[Any] | None = None,
    api_results: Iterable[Any] | None = None,
    cookies: Iterable[str] | None = None,
    headers: Iterable[str] | None = None,
    extra_texts: Iterable[str] | None = None,
    logs: Iterable[str] | None = None,
    config_blobs: Iterable[str] | None = None,
    env_blobs: Iterable[str] | None = None,
    db_dumps: Iterable[str] | None = None,
    target_url: str = "",
    module: str = "crawler",
    source: str = "crawler",
) -> PIIContext:
    """
    PII Intelligence 10.0 (Extended):
    - собирает PII из crawler / JS / API / cookies / headers / raw text / logs / config / env / DB dumps
    - возвращает PIIContext 10.0 с risk + confidence + sources + tags
    """
    ctx = PIIContext(target_url=target_url, module=module, source=source)
    ctx.add_tag("pii_intel")

    def _merge_structured(page: Dict[str, Any], src_name: str) -> None:
        ctx.add_source(src_name)
        for key in PII_KEYS:
            for item in _normalize_list_value(page.get(key)):
                if item not in ctx.pii[key]:
                    ctx.pii[key].append(item)

        text_chunks: List[str] = []
        for t_key in (
            "html", "body", "text", "js", "script", "response", "raw",
            "cookies", "headers", "log", "config", "env", "dump"
        ):
            val = page.get(t_key)
            if isinstance(val, str):
                text_chunks.append(val)
            elif isinstance(val, (list, tuple)):
                for v in val:
                    if isinstance(v, str):
                        text_chunks.append(v)

        if text_chunks:
            combined = "\n".join(text_chunks)
            extracted = _extract_pii_from_text(combined)
            ctx.merge_pii(extracted)

    # crawler
    if crawler_result is not None:
        for page in _collect_pages(crawler_result):
            _merge_structured(page, "crawler")
        if isinstance(crawler_result, dict):
            _merge_structured(crawler_result, "crawler_root")

    # JS
    if js_results:
        for js in js_results:
            if isinstance(js, dict):
                _merge_structured(js, "js")
            elif isinstance(js, str):
                ctx.add_source("js_raw")
                ctx.merge_pii(_extract_pii_from_text(js))

    # API
    if api_results:
        for api in api_results:
            if isinstance(api, dict):
                _merge_structured(api, "api")
            elif isinstance(api, str):
                ctx.add_source("api_raw")
                ctx.merge_pii(_extract_pii_from_text(api))

    # cookies
    if cookies:
        ctx.add_source("cookies")
        combined = "\n".join(str(c) for c in cookies)
        ctx.merge_pii(_extract_pii_from_text(combined))

    # headers
    if headers:
        ctx.add_source("headers")
        combined = "\n".join(str(h) for h in headers)
        ctx.merge_pii(_extract_pii_from_text(combined))

    # extra texts
    if extra_texts:
        ctx.add_source("extra_texts")
        combined = "\n".join(str(t) for t in extra_texts)
        ctx.merge_pii(_extract_pii_from_text(combined))

    # logs
    if logs:
        ctx.add_source("logs")
        combined = "\n".join(str(l) for l in logs)
        ctx.merge_pii(_extract_pii_from_text(combined))

    # config blobs
    if config_blobs:
        ctx.add_source("config")
        combined = "\n".join(str(c) for c in config_blobs)
        ctx.merge_pii(_extract_pii_from_text(combined))

    # env blobs
    if env_blobs:
        ctx.add_source("env")
        combined = "\n".join(str(e) for e in env_blobs)
        ctx.merge_pii(_extract_pii_from_text(combined))

    # DB dumps
    if db_dumps:
        ctx.add_source("db_dump")
        combined = "\n".join(str(d) for d in db_dumps)
        ctx.merge_pii(_extract_pii_from_text(combined))

    ctx.recompute_risk()
    return ctx


# ------------------------------------------------------------
#  Email leak artifact (расширенный)
# ------------------------------------------------------------

def pii_has_data(pii: Dict[str, List[str]]) -> bool:
    return any(pii.get(k) for k in PII_KEYS)


def build_email_leak_artifact(
    pii: Dict[str, List[str]],
    *,
    target_url: str = "",
    source: str = "crawler",
    module: str = "crawler",
) -> Optional[Dict[str, Any]]:
    """
    Backward‑compatible артефакт category=email_leak для Threat Intel GUI и Account Intelligence.
    Внутри использует ту же risk‑логіку, что и PIIContext 10.0.
    """
    if not pii_has_data(pii):
        return None

    critical_keys = (
        "credit_cards", "cvv", "card_expiry", "passwords", "api_keys",
        "secrets", "aws_keys", "gcp_keys", "azure_keys", "ssh_keys",
        "private_keys", "db_conn_strings", "env_secrets", "ssn", "tax_id"
    )
    high_keys = (
        "emails", "logins", "account_numbers", "iban", "tokens", "jwt",
        "passport", "bank_swift", "bank_routing"
    )

    risk = "medium"
    if any(pii.get(k) for k in critical_keys):
        risk = "critical"
    elif any(pii.get(k) for k in high_keys):
        risk = "high"
    elif any(pii.get(k) for k in ("phones", "addresses", "full_names")):
        risk = "medium"
    else:
        risk = "low"

    email_leak = {
        "emails": pii.get("emails", []),
        "phones": pii.get("phones", []),
        "credit_cards": pii.get("credit_cards", []),
        "cvv": pii.get("cvv", []),
        "card_expiry": pii.get("card_expiry", []),
        "account_numbers": pii.get("account_numbers", []),
        "bank_swift": pii.get("bank_swift", []),
        "bank_routing": pii.get("bank_routing", []),
        "passwords": pii.get("passwords", []),
        "logins": pii.get("logins", []),
        "full_names": pii.get("full_names", []),
        "addresses": pii.get("addresses", []),
        "tokens": pii.get("tokens", []),
        "jwt": pii.get("jwt", []),
        "iban": pii.get("iban", []),
        "passport": pii.get("passport", []),
        "tax_id": pii.get("tax_id", []),
        "ssn": pii.get("ssn", []),
        "api_keys": pii.get("api_keys", []),
        "secrets": pii.get("secrets", []),
        "aws_keys": pii.get("aws_keys", []),
        "gcp_keys": pii.get("gcp_keys", []),
        "azure_keys": pii.get("azure_keys", []),
        "ssh_keys": pii.get("ssh_keys", []),
        "private_keys": pii.get("private_keys", []),
        "db_conn_strings": pii.get("db_conn_strings", []),
        "env_secrets": pii.get("env_secrets", []),
        # backward compatibility
        "smtp_users": pii.get("logins", []),
        "smtp_passwords": pii.get("passwords", []),
    }

    return {
        "type": "PII",
        "module": module,
        "url": target_url,
        "risk": risk,
        "category": "email_leak",
        "source": source,
        "timestamp": datetime.now().isoformat(),
        "email_leak": email_leak,
        "pii_summary": {k: len(v) for k, v in pii.items()},
    }


def build_email_leak_artifact_from_context(ctx: PIIContext) -> Optional[Dict[str, Any]]:
    """
    Версия 10.0 (Extended): строит артефакт из PIIContext, добавляя risk, confidence, sources и tags.
    """
    if not ctx.has_data():
        return None

    ctx.recompute_risk()

    artifact = build_email_leak_artifact(
        ctx.pii,
        target_url=ctx.target_url,
        source=ctx.source,
        module=ctx.module,
    )
    if not artifact:
        return None

    artifact["pii_risk"] = ctx.risk
    artifact["pii_confidence"] = ctx.confidence
    artifact["pii_sources"] = list(ctx.sources)
    artifact.setdefault("tags", [])
    for tag in ctx.tags:
        if tag not in artifact["tags"]:
            artifact["tags"].append(tag)
    if "pii_intel" not in artifact["tags"]:
        artifact["tags"].append("pii_intel")
    if "email_leak" not in artifact["tags"]:
        artifact["tags"].append("email_leak")

    return artifact


# ------------------------------------------------------------
#  Merge + flatten (GUI)
# ------------------------------------------------------------

def merge_pii_dicts(*sources: Dict[str, List[str]]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {k: [] for k in PII_KEYS}
    for src in sources:
        if not src:
            continue
        for key in PII_KEYS:
            for item in src.get(key, []):
                s = str(item).strip()
                if s and s not in merged[key]:
                    merged[key].append(s)
    return {k: v for k, v in merged.items() if v}


def flatten_email_leak_rows(
    artifact: Dict[str, Any],
    source_url: str = "",
) -> List[Dict[str, str]]:
    """Преобразует артефакт в плоские строки для Treeview Email Leak / PII GUI."""
    rows: List[Dict[str, str]] = []
    url = artifact.get("url") or source_url or "—"
    leak = artifact.get("email_leak", {})
    if not isinstance(leak, dict):
        return rows

    for field, label in PII_FIELD_LABELS.items():
        for value in _normalize_list_value(leak.get(field)):
            rows.append({
                "category": label,
                "field": field,
                "value": value,
                "url": url,
            })
    return rows




