# xss_security_gui/utils/disable_ssl_warnings.py
"""
Disable SSL Warnings Utility
----------------------------
Отключает предупреждения SSL/TLS для безопасного тестирования,
чтобы не засорять вывод лишними сообщениями.
"""

import urllib3
import warnings


def disable_ssl_warnings():
    """
    Отключает предупреждения SSL/TLS:
    • urllib3 InsecureRequestWarning
    • глобально через warnings
    """
    try:
        # Отключаем предупреждения напрямую в urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    try:
        # Отключаем предупреждения глобально через warnings
        warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass