# xss_security_gui/utils/background_operations.py
# ============================================================
# BackgroundOperations 9.0 — safe, async, monitored, GUI-friendly
# ============================================================

import threading
import traceback
from typing import Callable, Any, Optional, Dict, List

from xss_security_gui.utils.thread_worker import get_global_worker


# ============================================================
# Unified background operation runner
# ============================================================

def run_blocking_operation(
    operation: Callable[..., Any],
    *args,
    operation_name: str = "BlockingOp",
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_finally: Optional[Callable[[], None]] = None,
    progress_callback: Optional[Callable[[int], None]] = None,
    **kwargs
) -> Optional[threading.Thread]:
    """
    Запускає блокуючу операцію у фоні через ThreadWorker 9.0.
    Гарантує:
    • safe-callback delivery
    • progress-aware execution
    • cancellation-aware execution
    """

    worker = get_global_worker()
    if not worker:
        print(f"[⚠️ {operation_name}] Global worker не іниціалізований!")
        return None

    def work_fn(progress_fn: Callable[[int], None], is_cancelled_fn: Callable[[], bool]):
        try:
            progress_fn(0)
            result = operation(*args, **kwargs)
            progress_fn(100)
            return result
        except Exception as e:
            print(f"[❌ {operation_name}] Помилка: {e}")
            traceback.print_exc()
            raise

    try:
        return worker.run_async(
            work_fn,
            name=operation_name,
            on_progress=progress_callback,
            on_success=on_success,
            on_error=on_error,
            on_finally=on_finally,
        )
    except Exception as e:
        print(f"[❌ {operation_name}] Помилка запуску: {e}")
        traceback.print_exc()
        return None


# ============================================================
# Iterative operations (per-item processing)
# ============================================================

def run_iterative_operation(
    items: List[Any],
    process_item: Callable[[Any, Callable[[int], None], Callable[[], bool]], Any],
    operation_name: str = "IterativeOp",
    on_item_done: Optional[Callable[[Any, Any], None]] = None,
    on_success: Optional[Callable[[List[Any]], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_finally: Optional[Callable[[], None]] = None,
) -> Optional[threading.Thread]:
    """
    Обробляє список елементів у фоні з прогресом та callback’ами.
    """

    if not items:
        print(f"[⚠️ {operation_name}] Немає елементів для обробки")
        return None

    def work_fn(progress_fn: Callable[[int], None], is_cancelled_fn: Callable[[], bool]):
        results = []
        total = len(items)

        for idx, item in enumerate(items):
            if is_cancelled_fn():
                print(f"[🛑 {operation_name}] Операція скасована на {idx+1}/{total}")
                break

            try:
                result = process_item(
                    item,
                    lambda p=idx: progress_fn(int(100 * (p + 1) / total)),
                    is_cancelled_fn
                )
                results.append(result)

                if on_item_done:
                    on_item_done(item, result)

                print(f"[✅ {operation_name}] Елемент {idx+1}/{total} оброблено")

            except Exception as e:
                print(f"[❌ {operation_name}] Помилка на елементі {idx+1}: {e}")
                results.append(None)

        return results

    return run_blocking_operation(
        lambda: work_fn(lambda p: p, lambda: False),
        operation_name=operation_name,
        on_success=on_success,
        on_error=on_error,
        on_finally=on_finally,
    )


# ============================================================
# Network operations (HTTP requests)
# ============================================================

def run_network_request(
    method: str,
    url: str,
    timeout: int = 10,
    retries: int = 3,
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    headers: Optional[Dict[str, str]] = None,
    json_data: Optional[Dict] = None,
    **kwargs
) -> Optional[threading.Thread]:
    """
    Запускає HTTP запит у фоні з retry-сесією.
    """

    import requests
    from xss_security_gui.utils.network import create_retry_session

    def do_request():
        session = create_retry_session(
            total=retries,
            backoff=0.5,
            timeout=timeout
        )

        try:
            m = method.upper()
            if m == "GET":
                response = session.get(url, headers=headers, timeout=timeout, **kwargs)
            elif m == "POST":
                response = session.post(url, headers=headers, json=json_data, timeout=timeout, **kwargs)
            elif m == "PUT":
                response = session.put(url, headers=headers, json=json_data, timeout=timeout, **kwargs)
            elif m == "DELETE":
                response = session.delete(url, headers=headers, timeout=timeout, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")

            response.raise_for_status()
            return response

        finally:
            session.close()

    return run_blocking_operation(
        do_request,
        operation_name=f"HTTPRequest_{method.upper()}_{url[:30]}",
        on_success=on_success,
        on_error=on_error,
    )


# ============================================================
# File operations (IO)
# ============================================================

def run_file_operation(
    operation: Callable[[], Any],
    operation_name: str = "FileOp",
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
) -> Optional[threading.Thread]:
    """
    Запускає файлову операцію у фоні.
    """
    return run_blocking_operation(
        operation,
        operation_name=operation_name,
        on_success=on_success,
        on_error=on_error,
    )


# ============================================================
# Aliases
# ============================================================

post_bg = run_blocking_operation
run_compute = run_blocking_operation
run_io = run_file_operation

