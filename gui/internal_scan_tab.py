"""Internal-target web audit UI with allowlist-gated active checks."""

from __future__ import annotations

from xss_security_gui.tabs.xss_flooder_tab import XSSFlooderTab


class InternalScanTab(XSSFlooderTab):
    """Audit a selected internal HTTP(S) service using the shared safe scanner."""

    TITLE = "Internal Scan"
    TARGET_LABEL = "Внутренний HTTP(S) URL:"
    HELP_TEXT = (
        "Сбор страниц не отправляет формы. Активные GET/POST проверки доступны "
        "только при ALLOW_REAL_RUN и совпадении хоста с ALLOWED_TARGETS."
    )
