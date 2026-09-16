#xss_security_gui/auto_recon/__init__.py
"""
AutoRecon Enterprise V7 — комплексная система автоматизированной разведки веб-приложений.

Основные компоненты:
• core_logger — структурированное логирование всех операций
• user_tracker — отслеживание пользователей и их операций
• metrics — сбор метрик и статистики
• reporting — генерация comprehensive отчётов (HTML/JSON/CSV)
• orchestrator — главный оркестратор всех компонентов
• scanner — сканирование эндпоинтов и XSS/SQLi/CSRF/SSRF
• analyzer — анализ уязвимостей
• planner — планирование и выполнение атак

Использование:

    from xss_security_gui.auto_recon import run_full_autorecon
    report = run_full_autorecon("https://target.com")

    # С callback для прогресса
    report = run_full_autorecon(
        ["https://target1.com", "https://target2.com"],
        callback=lambda msg: print(msg["status"])
    )

Документация: https://docs.autorecon.local/v7
"""

# =========================================================
# Core Logger (ENTERPRISE)
# =========================================================
from .core_logger import (
    EnterpriseLogger,
    LogLevel,
    get_logger,
)

# =========================================================
# User Tracker (ENTERPRISE)
# =========================================================
from .user_tracker import (
    UserContext,
    UserTracker,
    get_user_tracker,
    get_user_context,
)

# =========================================================
# Metrics (ENTERPRISE)
# =========================================================
from .metrics import (
    OperationMetrics,
    MetricsCollector,
    MetricType,
    get_metrics_collector,
)

# =========================================================
# Reporting (ENTERPRISE)
# =========================================================
from .reporting import (
    ReportGenerator,
    get_report_generator,
)

# =========================================================
# Orchestrator (ENTERPRISE)
# =========================================================
from .orchestrator import (
    AutoReconOrchestrator,
    run_full_autorecon as run_full_autorecon_enterprise,
    run_aggressive_scan,
)

# =========================================================
# Token extractor
# =========================================================
from .token_extractor import (
    extract_tokens,
    analyze_tokens,
    save_token_log,
)

# =========================================================
# Analyzer
# =========================================================
from .analyzer import (
    analyze_page,
    analyze_structure,
    AutoReconAnalyzerV2,
)

# =========================================================
# Scanner
# =========================================================
from .scanner import (
    scan_url,
    scan_multiple,
    EndpointScanner,
    save_reflected_response,
)

# =========================================================
# Payload generator
# =========================================================
from .payloads import (
    generate_xss_payloads,
    generate_fuzz_payloads,
    PayloadGenerator,
)

# =========================================================
# Planner
# =========================================================
from .planner import (
    build_attack_plan,
    save_attack_plan,
    AttackPlanner,
    AttackPlannerV2,
)

# =========================================================
# Recon pipeline
# =========================================================
from .recon_pipeline import (
    run_recon_pipeline,
    load_recon_config,
    run_full_recon,
    run_advanced_recon,
)

# =========================================================
# Full AutoRecon runner
# =========================================================
from .run_full_autorecon import (
    run_full_autorecon,
)

# =========================================================
# GUI Elements
# =========================================================
from .gui_elements import (
    build_auto_recon_panel,
)

# =========================================================
# Public API
# =========================================================
__all__ = [
    # Enterprise Components
    "EnterpriseLogger",
    "LogLevel",
    "get_logger",
    "UserContext",
    "UserTracker",
    "get_user_tracker",
    "get_user_context",
    "OperationMetrics",
    "MetricsCollector",
    "MetricType",
    "get_metrics_collector",
    "ReportGenerator",
    "get_report_generator",
    "AutoReconOrchestrator",
    "run_full_autorecon_enterprise",
    "run_aggressive_scan",

    # Token extractor
    "extract_tokens",
    "analyze_tokens",
    "save_token_log",

    # Analyzer
    "analyze_page",
    "analyze_structure",
    "AutoReconAnalyzerV2",

    # Scanner
    "scan_url",
    "scan_multiple",
    "EndpointScanner",
    "save_reflected_response",

    # Payloads
    "generate_xss_payloads",
    "generate_fuzz_payloads",
    "PayloadGenerator",

    # Planner
    "build_attack_plan",
    "save_attack_plan",
    "AttackPlanner",
    "AttackPlannerV2",

    # Recon pipeline
    "run_recon_pipeline",
    "load_recon_config",
    "run_full_recon",
    "run_advanced_recon",

    # Full AutoRecon
    "run_full_autorecon",

    # GUI Elements
    "build_auto_recon_panel",
]