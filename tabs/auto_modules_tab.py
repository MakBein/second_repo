"""Auto Modules audit interface with allowlist-gated active checks."""

from __future__ import annotations

from typing import Any

from xss_security_gui.tabs.xss_flooder_tab import XSSFlooderTab


class AutoModulesTab(XSSFlooderTab):
    """Run bounded page discovery and approved form reflection checks.

    Legacy threat-tab injection remains accepted by the constructor. The audit
    itself uses the shared bounded crawler and never runs exploit payloads.
    """

    TITLE = "Auto Modules"
    TARGET_LABEL = "URL для аудита:"
    HELP_TEXT = (
        "Сбор страниц выполняется для указанной HTTP(S)-цели; отправка форм "
        "и активные пробы доступны только разрешенной цели."
    )

    def __init__(self, parent, threat_tab=None, **kwargs: Any) -> None:
        self.threat_tab = threat_tab
        super().__init__(parent, **kwargs)
