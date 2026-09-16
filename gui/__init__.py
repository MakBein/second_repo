# xss_security_gui/gui/__init__.py
"""
XSS Security GUI — GUI package
==============================

Turns ``xss_security_gui.gui`` into a real (non-namespace) package and exposes
the public tab/panel classes through lazy attribute access (PEP 562).

Lazy loading matters here: most of these modules import Tkinter and heavy
project internals at import time. Importing them all eagerly would slow every
``import xss_security_gui.gui`` and make a single broken module poison the whole
package. Instead each symbol is imported only when first accessed, e.g.::

    from xss_security_gui.gui import AttackGUI          # imported on demand
    from xss_security_gui.gui.attack_gui import AttackGUI   # still works too
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

# public name -> submodule that defines it
_EXPORTS = {
    "AttackGUI": "attack_gui",
    "AutoReconDashboard": "autorecon_dashboard",
    "AutoReconDashboardTab": "autorecon_dashboard_tab",
    "DefenseEvasionLab": "defense_evasion_lab",
    "EnvironmentTab": "environment_tab",
    "InternalScanTab": "internal_scan_tab",
    "LiveAttackMonitor": "live_attack_monitor",
    "MutatorTasksPanel": "mutator_tasks_panel",
    "RealTimeMonitoringTab": "real_time_monitoring_tab",
    "SecurityDashboardPanel": "security_dashboard_panel",
    "ServerSideAttacksDashboard": "server_side_attacks_dashboard",
    "XSSContextMapTab": "xss_context_map",
    "XSSContextMapView": "xss_context_map",
    "XSSLogViewer": "xss_log_viewer",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str):  # PEP 562 — module-level lazy attribute access
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(f"{__name__}.{module_name}")
    value = getattr(module, name)
    globals()[name] = value  # cache so subsequent lookups skip import_module
    return value


def __dir__():
    return sorted(set(globals()) | set(_EXPORTS))


if TYPE_CHECKING:  # help IDEs / type-checkers resolve the lazy names
    from .attack_gui import AttackGUI
    from .autorecon_dashboard import AutoReconDashboard
    from .autorecon_dashboard_tab import AutoReconDashboardTab
    from .defense_evasion_lab import DefenseEvasionLab
    from .environment_tab import EnvironmentTab
    from .internal_scan_tab import InternalScanTab
    from threat_analysis.live_attack_monitor import LiveAttackMonitor
    from .mutator_tasks_panel import MutatorTasksPanel
    from .real_time_monitoring_tab import RealTimeMonitoringTab
    from .security_dashboard_panel import SecurityDashboardPanel
    from .server_side_attacks_dashboard import ServerSideAttacksDashboard
    from .xss_context_map import XSSContextMapTab, XSSContextMapView
    from .xss_log_viewer import XSSLogViewer
