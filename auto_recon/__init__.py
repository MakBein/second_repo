#xss_security_gui/auto_recon/__init__.py
"""
AutoRecon Framework
-------------------

Высокоуровневый фасад для всех модулей автоматического анализа:

• Извлечение токенов
• Анализ страниц
• Планирование атак
• Генерация полезных нагрузок
• Автоматический рекогносинг
• Полный AutoRecon-процесс
• GUI-элементы для визуализации

Этот файл предоставляет единый API для всего пакета auto_recon.
"""

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
)

# =========================================================
# Scanner
# =========================================================
from .scanner import (
    scan_url,
    scan_multiple,
)

# =========================================================
# Payload generator
# =========================================================
from .payloads import (
    generate_xss_payloads,
    generate_fuzz_payloads,
)

# =========================================================
# Planner
# =========================================================
from .planner import (
    build_attack_plan,
    save_attack_plan,
)

# =========================================================
# Recon pipeline
# =========================================================
from .recon_pipeline import (
    run_recon_pipeline,
    load_recon_config,
)

# =========================================================
# Full AutoRecon runner
# =========================================================
from .run_full_autorecon import (
    run_full_autorecon,
)

# =========================================================
# Public API
# =========================================================
__all__ = [
    # Token extractor
    "extract_tokens",
    "analyze_tokens",
    "save_token_log",

    # Analyzer
    "analyze_page",
    "analyze_structure",

    # Scanner
    "scan_url",
    "scan_multiple",

    # Payloads
    "generate_xss_payloads",
    "generate_fuzz_payloads",

    # Planner
    "build_attack_plan",
    "save_attack_plan",

    # Recon pipeline
    "run_recon_pipeline",
    "load_recon_config",

    # Full AutoRecon
    "run_full_autorecon",
]