# xss_security_gui/idor_tester.py

import hashlib
import math
import requests
import time
import threading

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional, Callable

from xss_security_gui.auto_recon.scope import (
    is_target_authorized,
    normalize_http_url,
    scoped_request,
)
from xss_security_gui.settings import settings

_DEFAULT_MAX_RESPONSE_BYTES = 2_000_000
_MAX_REQUESTS_PER_TEST = 200


# ---------------------------------------------------------
# URL builder
# ---------------------------------------------------------
def build_url_with_param(url: str, param: str, value: str) -> str:
    """
    Формує новий URL з підміненою змінною параметра.
    Завжди повертає коректний URL.
    """
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)

    query[param] = [value]
    new_query = urlencode(query, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


# ---------------------------------------------------------
# Hash helper
# ---------------------------------------------------------
def hash_response(text: str) -> str:
    """Повертає MD5-хеш відповіді."""
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


# ---------------------------------------------------------
# Request sender
# ---------------------------------------------------------
def send_request(
    url: str,
    method: str,
    param: str,
    value: str,
    headers: Dict[str, str],
    timeout: int,
    session: Optional[requests.Session] = None,
    root_url: Optional[str] = None,
    cancel_event: Optional[threading.Event] = None,
) -> Optional[requests.Response]:
    """
    Відправляє GET або POST запит.
    GET — параметр уже в URL (fuzz_id_parameter його збирає).
    POST — параметр у form-data.
    Підтримує session, root_url і cancel_event.
    """
    method = method.upper()

    # скасування перед запитом
    if cancel_event and cancel_event.is_set():
        return None

    root_url = root_url or url

    # session за замовчуванням
    if session is None:
        session = requests.Session()

    if method not in {"GET", "POST"}:
        raise ValueError(f"Unsupported method: {method}")
    return scoped_request(
        session,
        method,
        url,
        root_url=root_url or url,
        headers=dict(headers),
        data={param: value} if method == "POST" else None,
        timeout=timeout,
        stream=True,
    )


# ---------------------------------------------------------
# Main IDOR fuzzing engine
# ---------------------------------------------------------
def fuzz_id_parameter(
    url: str,
    param: str = "id",
    start: int = 1,
    stop: int = 10,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    delay: Optional[float] = None,
    timeout: Optional[int] = None,
    auth_token: Optional[str] = None,
    cancel_event: Optional[threading.Event] = None,
    on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Основний IDOR‑фаззер.
    Повертає список результатів у форматі:
    {
        "url": str,
        "status": int | "ERR",
        "length": int,
        "hash": str | None,
        "differs": bool,
        "error": Optional[str]
    }
    """

    # -----------------------------
    # Валідація
    # -----------------------------
    if (
        not isinstance(url, str)
        or not url.strip()
        or not isinstance(param, str)
        or not param.strip()
    ):
        raise ValueError("URL і параметр повинні бути вказані")

    if not isinstance(start, int) or isinstance(start, bool):
        raise ValueError("Start повинен бути цілим числом")
    if not isinstance(stop, int) or isinstance(stop, bool):
        raise ValueError("Stop повинен бути цілим числом")
    if start < 0:
        raise ValueError("Start не може бути від’ємним")
    if start > stop:
        raise ValueError("Start не може бути більшим за Stop")
    if stop - start + 1 > _MAX_REQUESTS_PER_TEST:
        raise ValueError(
            f"Один тест може виконати не більше {_MAX_REQUESTS_PER_TEST} запитів"
        )
    if not isinstance(method, str):
        raise ValueError("Метод повинен бути GET або POST")
    method = method.upper()
    if method not in {"GET", "POST"}:
        raise ValueError("Метод повинен бути GET або POST")

    url = normalize_http_url(url)
    param = param.strip()
    if not is_target_authorized(url):
        raise ValueError("Ціль не входить до дозволеного списку для реального тестування")

    # -----------------------------
    # Settings defaults
    # -----------------------------
    delay = delay if delay is not None else getattr(settings, "IDOR_DELAY", 0.5)
    timeout = timeout if timeout is not None else getattr(settings, "REQUEST_TIMEOUT", 10)
    if not isinstance(delay, (int, float)) or not math.isfinite(delay) or delay < 0:
        raise ValueError("Delay повинен бути скінченним невід’ємним числом")
    if (
        not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout повинен бути скінченним додатним числом")
    try:
        max_rps = float(settings.get("crawl.max_rps", 2.0))
    except (TypeError, ValueError):
        max_rps = 2.0
    if not math.isfinite(max_rps):
        max_rps = 2.0
    max_rps = min(5.0, max(0.1, max_rps))
    if delay < 1.0 / max_rps:
        raise ValueError(f"Delay не може бути меншим за {1.0 / max_rps:.2f} секунди")
    if auth_token is not None and not isinstance(auth_token, str):
        raise ValueError("Auth token повинен бути текстовим значенням")

    try:
        max_response_bytes = int(
            settings.get("http.max_response_bytes", _DEFAULT_MAX_RESPONSE_BYTES)
        )
    except (TypeError, ValueError):
        max_response_bytes = _DEFAULT_MAX_RESPONSE_BYTES
    max_response_bytes = max(1, min(max_response_bytes, 20_000_000))

    # -----------------------------
    # Headers
    # -----------------------------
    request_headers = dict(headers) if headers is not None else {
        "User-Agent": getattr(settings, "DEFAULT_USER_AGENT", "IDOR-Scanner")
    }
    if auth_token and not any(
        name.lower() == "authorization" for name in request_headers
    ):
        request_headers["Authorization"] = "Bearer " + auth_token

    results: List[Dict[str, Any]] = []
    base_hash: Optional[str] = None
    base_length: Optional[int] = None
    base_status: Optional[int] = None
    base_comparison_reliable = False

    with requests.Session() as session:
        for value in range(start, stop + 1):
            if cancel_event and cancel_event.is_set():
                break

            if method == "GET":
                request_url = build_url_with_param(url, param, str(value))
            else:
                request_url = url

            response: Optional[requests.Response] = None
            try:
                response = send_request(
                    request_url,
                    method,
                    param,
                    str(value),
                    request_headers,
                    timeout,
                    session=session,
                    root_url=url,
                    cancel_event=cancel_event,
                )
                if response is None:
                    # скасовано
                    break
                body = bytearray()
                truncated = False
                cancelled = False
                for chunk in response.iter_content(chunk_size=8192):
                    if cancel_event and cancel_event.is_set():
                        cancelled = True
                        break
                    if not chunk:
                        continue
                    remaining = max_response_bytes - len(body)
                    if remaining <= 0:
                        truncated = True
                        break
                    body.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                if cancelled:
                    break

                text = bytes(body).decode(
                    response.encoding or "utf-8", errors="replace"
                ).strip()
                resp_hash = hash_response(text)
                resp_len = len(body)
                if base_hash is None:
                    base_hash = resp_hash
                    base_length = resp_len
                    base_status = response.status_code
                    base_comparison_reliable = not truncated

                comparison_reliable = base_comparison_reliable and not truncated
                differs = (
                    resp_hash != base_hash
                    or resp_len != base_length
                    or response.status_code != base_status
                )

                result = {
                    "url": response.url,
                    "value": value,
                    "status": response.status_code,
                    "length": resp_len,
                    "hash": resp_hash,
                    "differs": differs,
                    "truncated": truncated,
                    "comparison_reliable": comparison_reliable,
                }
                results.append(result)
                if on_result is not None:
                    on_result(result)
            except requests.RequestException as exc:
                result = {
                    "url": request_url,
                    "value": value,
                    "status": "ERR",
                    "length": 0,
                    "hash": None,
                    "differs": False,
                    "error": str(exc),
                }
                results.append(result)
                if on_result is not None:
                    on_result(result)
            finally:
                if response is not None:
                    response.close()

            if value < stop and delay:
                if cancel_event:
                    if cancel_event.wait(delay):
                        break
                else:
                    time.sleep(delay)

    return results


# ---------------------------------------------------------
# Test run
# ---------------------------------------------------------
if __name__ == "__main__":
    test_url = "https://gazprombank.ru/profile?user_id=1"
    param = "user_id"
    COMMON_IDOR_PARAMS = [

        # 1. Класичні IDOR
        "id", "user_id", "uid", "account_id", "profile_id", "customer_id",
        "client_id", "member_id", "session_id", "login_id", "person_id",

        # 2. Авторизація / доступ
        "auth_id", "access_id", "role_id", "group_id", "team_id",
        "department_id", "permission_id", "policy_id", "security_id",

        # 3. Файли / документи
        "file_id", "document_id", "doc_id", "attachment_id", "image_id",
        "photo_id", "pdf_id", "record_id", "report_id", "contract_id",

        # 4. Операції / транзакції
        "transaction_id", "payment_id", "invoice_id", "order_id",
        "operation_id", "action_id", "event_id", "log_id", "history_id",

        # 5. Товари / замовлення
        "product_id", "item_id", "cart_id", "order_item_id", "shipment_id",
        "delivery_id", "package_id", "warehouse_id", "stock_id",

        # 6. API‑ендпоінти
        "resource_id", "entity_id", "object_id", "ref_id", "reference_id",
        "key", "pk", "primary_key", "external_id", "internal_id",

        # 7. Соцмережі / комунікації
        "post_id", "comment_id", "message_id", "chat_id", "thread_id",
        "conversation_id", "friend_id", "follow_id", "like_id",

        # 8. Медичні системи
        "patient_id", "medical_id", "appointment_id", "visit_id",
        "doctor_id", "clinic_id", "case_id",

        # 9. Страхові системи
        "claim_id", "policy_id", "coverage_id", "risk_id", "agent_id",

        # 10. Логістика / доставка
        "tracking_id", "parcel_id", "shipment_id", "route_id",
        "driver_id", "vehicle_id",

        # 11. Телеком
        "subscriber_id", "msisdn", "sim_id", "contract_id", "plan_id",

        # 12. Держсервіси
        "application_id", "request_id", "ticket_id", "service_id",

        # 13. Маскування IDOR (найпідступніші)
        "uuid", "guid", "public_id", "external_id", "internal_id",
        "hash", "code", "reference", "ref", "number", "no",
        "index", "idx", "row", "position",

        # 14. Мобільні додатки
        "device_id", "installation_id", "session_token", "push_id",

        # 15. Банківські системи
        "account_number", "iban", "card_id", "agreement_id",
        "profile_id", "client_id", "customer_id",
    ]
    HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


    def status_sort_key(result: Dict[str, Any]) -> tuple[int, Any]:
        status = result.get("status")
        try:
            return 0, int(status)
        except (TypeError, ValueError):
            return 1, str(status)


    for p in COMMON_IDOR_PARAMS:

        print(f"\n\n==============================")
        print(f"🔍 Тестування параметра: {p}")
        print(f"==============================\n")

        for method in HTTP_METHODS:

            print(f"\n=== {method} param={p} ===")

            res = fuzz_id_parameter(
                test_url,
                param=p,
                start=1,
                stop=5,
                method=method,
                headers={"User-Agent": "Igor"},
                delay=0.2,
                timeout=5,
            )

            for r in sorted(res, key=status_sort_key):
                mark = "✅" if r["differs"] else "⚠️"
                print(f"{mark} {r['url']} | status={r['status']} | len={r['length']} | hash={r['hash']}")
                if "error" in r:
                    print(f"   ❌ Error: {r['error']}")
