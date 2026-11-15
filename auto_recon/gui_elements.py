# xss_security_gui/auto_recon/gui_elements.py
from tkinter import Frame, Button, Label
from typing import Callable
from xss_security_gui.auto_recon.user_tracker import get_user_context


def build_auto_recon_panel(
    parent,
    on_scan: Callable[[], None],
    on_generate: Callable[[], None],
    on_attack: Callable[[], None],
    on_rotate_session: Callable[[], None],
    on_show_surface: Callable[[], None],
    on_show_history: Callable[[], None],
    on_save_report: Callable[[], None],
) -> Frame:
    """
    AutoRecon Red Team Dashboard — боевой GUI уровня Burp Suite / Cobalt Strike.
    """

    ctx = get_user_context()
    panel = Frame(parent, padx=12, pady=12)

    # === HEADER ===
    Label(
        panel,
        text="🛡 AutoRecon — Red Team Recon Dashboard",
        font=("Consolas", 15, "bold")
    ).pack(pady=(0, 12))

    # === OPERATOR CONTEXT ===
    Label(panel, text="Operator Context", font=("Consolas", 11, "bold")).pack(anchor="w")
    Label(panel, text=f"👤 Operator: {ctx.user.operator}", font=("Consolas", 10)).pack(anchor="w")
    Label(panel, text=f"🎯 Target: {ctx.current_target or '—'}", font=("Consolas", 10)).pack(anchor="w")
    Label(panel, text=f"📌 Phase: {ctx.current_phase}", font=("Consolas", 10)).pack(anchor="w")
    Label(panel, text=f"🔐 OPSEC Mode: {ctx.opsec_mode}", font=("Consolas", 10)).pack(anchor="w")
    Label(panel, text=f"⚠ Threat Level: {ctx.threat_level}", font=("Consolas", 10, "bold")).pack(anchor="w", pady=(0, 10))

    # === RECON ACTIONS ===
    Label(panel, text="Recon Actions", font=("Consolas", 11, "bold")).pack(anchor="w", pady=(10, 4))

    Button(panel, text="🔍 Endpoint Recon", command=on_scan, width=34).pack(pady=3)
    Button(panel, text="🧬 Generate Payloads", command=on_generate, width=34).pack(pady=3)
    Button(panel, text="💥 Execute Attack", command=on_attack, width=34).pack(pady=3)

    # === INTEL & REPORTS ===
    Label(panel, text="Intel & Reports", font=("Consolas", 11, "bold")).pack(anchor="w", pady=(12, 4))

    Button(panel, text="📡 View Attack Surface", command=on_show_surface, width=34).pack(pady=2)
    Button(panel, text="📜 View Event History", command=on_show_history, width=34).pack(pady=2)
    Button(panel, text="📝 Save Session Report", command=on_save_report, width=34).pack(pady=2)

    # === SESSION & OPSEC ===
    Label(panel, text="Session & OPSEC", font=("Consolas", 11, "bold")).pack(anchor="w", pady=(12, 4))

    Button(panel, text="🔄 Rotate Session (OPSEC)", command=on_rotate_session, width=34).pack(pady=3)

    return panel

