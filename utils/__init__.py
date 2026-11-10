# xss_security_gui/utils/__init__.py
"""
XSS Security GUI — Utils 10.0 (Combat Edition)
==============================================

Експорт всіх бойових утиліт для модулів 9.0–10.0:

• network 10.0              — TokenBucket, retry-сессии, UA Engine
• core_utils                — URL-хелперы, логирование, анализ данных
• jwt_decoder 9.0           — безопасный декодер JWT + risk-анализ
• disable_ssl_warnings 9.0  — отключение SSL/TLS предупреждений
• ui_queue_bridge 9.0       — безопасный мост между потоками и Tkinter
• safe_call 10.0            — безопасный вызов callback'ов
• thread_worker 10.0        — асинхронное ядро + Dashboard integration
• pii_aggregator 10.0       — PII Intelligence Extended
• threat_sender 9.0         — ThreatConnector-friendly sender
"""

# ------------------------------------------------------------
# Network utilities (10.0)
# ------------------------------------------------------------
from .network import (
    TokenBucket,
    create_retry_session,
    rotating_user_agents,
    default_accepts,
)

# ------------------------------------------------------------
# Core utilities
# ------------------------------------------------------------
from .core_utils import (
    normalize_url,
    hash_url,
    url_fingerprint,
    is_valid_url,
    safe_crawl_site,
    log_xss_flood,
    log_error,
    contains_sensitive,
    flatten_dict,
    safe_get,
)

# ------------------------------------------------------------
# JWT utilities (9.0)
# ------------------------------------------------------------
from .jwt_decoder import (
    decode_jwt,
    assess_risks,
    base64url_decode,
)

# ------------------------------------------------------------
# SSL warnings (9.0)
# ------------------------------------------------------------
from .disable_ssl_warnings import (
    disable_ssl_warnings,
    ssl_warnings_disabled,
)

# ------------------------------------------------------------
# UI Queue Bridge (9.0)
# ------------------------------------------------------------
from .ui_queue_bridge import UIQueueBridge

# ------------------------------------------------------------
# SafeCall 10.0
# ------------------------------------------------------------
from .safe_call import safe_invoke

# ------------------------------------------------------------
# ThreadWorker 10.0 (Dashboard Integration)
# ------------------------------------------------------------
from .thread_worker import (
    ThreadWorker,
    init_global_worker,
    get_global_worker,
    run_in_thread,
)

# ------------------------------------------------------------
# PII Intelligence 10.0 (Extended)
# ------------------------------------------------------------
from .pii_aggregator import (
    PIIContext,
    aggregate_pii_multi_source,
    aggregate_pii_from_crawler,
    build_email_leak_artifact,
    build_email_leak_artifact_from_context,
    merge_pii_dicts,
    flatten_email_leak_rows,
)

# ------------------------------------------------------------
# Threat Sender 9.0
# ------------------------------------------------------------
from .threat_sender import (
    ThreatSenderMixin,
    normalize_threat_artifact,
)


__all__ = [
    # network
    "TokenBucket",
    "create_retry_session",
    "rotating_user_agents",
    "default_accepts",

    # core utils
    "normalize_url",
    "hash_url",
    "url_fingerprint",
    "is_valid_url",
    "safe_crawl_site",
    "log_xss_flood",
    "log_error",
    "contains_sensitive",
    "flatten_dict",
    "safe_get",

    # jwt
    "decode_jwt",
    "assess_risks",
    "base64url_decode",

    # ssl
    "disable_ssl_warnings",
    "ssl_warnings_disabled",

    # ui
    "UIQueueBridge",

    # safe call
    "safe_invoke",

    # thread worker
    "ThreadWorker",
    "init_global_worker",
    "get_global_worker",
    "run_in_thread",

    # pii intelligence
    "PIIContext",
    "aggregate_pii_multi_source",
    "aggregate_pii_from_crawler",
    "build_email_leak_artifact",
    "build_email_leak_artifact_from_context",
    "merge_pii_dicts",
    "flatten_email_leak_rows",

    # threat sender
    "ThreatSenderMixin",
    "normalize_threat_artifact",
]



