"""Account-focused Threat Intel view with sensitive values masked."""

from __future__ import annotations

from typing import Any

from xss_security_gui.threat_analysis.accounts_tab import AccountsTab


class AccountIntelligenceTab(AccountsTab):
    """Present persisted account and identity artifacts without probing accounts."""

    def __init__(self, parent, threat_connector, **kwargs: Any) -> None:
        super().__init__(parent, threat_connector, **kwargs)
