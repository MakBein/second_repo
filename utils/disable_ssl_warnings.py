# xss_security_gui/utils/disable_ssl_warnings.py
# ============================================================
# Disable SSL Warnings Utility 9.0 — full coverage, safe, idempotent
# ============================================================

import warnings
import urllib3
from urllib3.exceptions import InsecureRequestWarning


def disable_ssl_warnings() -> None:
    """
    Полностью отключает SSL/TLS предупреждения.
    Безопасно вызывается многократно.
    Покрывает urllib3, requests, OpenSSL и глобальные warnings.
    """

    # 1. urllib3
    try:
        urllib3.disable_warnings(InsecureRequestWarning)
    except Exception:
        pass

    # 2. requests → urllib3
    try:
        import requests
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
    except Exception:
        pass

    # 3. OpenSSL / pyopenssl (редко, но встречается)
    try:
        warnings.filterwarnings("ignore", message=".*SSL.*")
        warnings.filterwarnings("ignore", message=".*certificate.*")
        warnings.filterwarnings("ignore", message=".*insecure.*")
    except Exception:
        pass

    # 4. aiohttp SSL warnings
    try:
        warnings.filterwarnings("ignore", message=".*SSLContext.*")
        warnings.filterwarnings("ignore", message=".*sslproto.*")
    except Exception:
        pass

    # 5. Глобальный фильтр для InsecureRequestWarning
    try:
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    except Exception:
        pass


def ssl_warnings_disabled() -> bool:
    """
    Проверяет, отключены ли SSL/TLS предупреждения.
    Проверяет все уровни фильтров.
    """

    try:
        for f in warnings.filters:
            if f[0] == "ignore":
                # urllib3
                if f[2] is InsecureRequestWarning:
                    return True

                # OpenSSL / pyopenssl / aiohttp
                if isinstance(f[2], type) and "SSL" in f[2].__name__:
                    return True

        return False

    except Exception:
        return False

