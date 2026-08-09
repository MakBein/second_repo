# xss_security_gui/utils/thread_worker.py
"""
Универсальный ThreadWorker для запуска долгих операций в отдельных потоках.
Гарантирует, что GUI поток остается свободным.

Использование:
    worker = ThreadWorker(gui_root, name="MyWorker")
    worker.run_async(
        work_fn=lambda: some_blocking_operation(),
        on_success=lambda result: on_success_handler(result),
        on_error=lambda exc: on_error_handler(exc),
        on_finally=lambda: cleanup()
    )
"""

import threading
import queue
import traceback
from typing import Any, Callable, Optional


class ThreadWorker:
    """
    Безопасный рабочий класс для выполнения операций вне GUI потока.

    Гарантирует:
    - GUI поток никогда не блокируется
    - Все обновления GUI идут через self.after()
    - Исключения обрабатываются корректно
    - Корректное завершение при закрытии GUI
    """

    def __init__(self, gui_root, name: str = "Worker", poll_ms: int = 50):
        """
        :param gui_root: tkinter.Tk или ttk.Frame (главное окно)
        :param name: имя рабочего потока для логирования
        :param poll_ms: интервал опроса очереди результатов (в миллисекундах)
        """
        self.gui_root = gui_root
        self.name = name
        self.poll_ms = poll_ms
        self._result_queue = queue.Queue()
        self._poll_id = None

    def run_async(
        self,
        work_fn: Callable[[], Any],
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_finally: Optional[Callable[[], None]] = None,
    ) -> threading.Thread:
        """
        Запускает долгую операцию в отдельном потоке.

        :param work_fn: функция, которая выполняет долгую работу
        :param on_success: коллбэк успеха (получит результат work_fn)
        :param on_error: коллбэк ошибки (получит Exception)
        :param on_finally: коллбэк завершения (выполнится в любом случае)
        :return: объект threading.Thread
        """
        def worker_thread():
            try:
                result = work_fn()
                self._result_queue.put(("success", result))
            except Exception as exc:
                self._result_queue.put(("error", exc))
            finally:
                self._result_queue.put(("finally", None))

        thread = threading.Thread(target=worker_thread, name=self.name, daemon=True)
        thread.start()

        # Запустить опрос очереди в GUI потоке
        self._start_polling(on_success, on_error, on_finally)

        return thread

    def _start_polling(
        self,
        on_success: Optional[Callable[[Any], None]],
        on_error: Optional[Callable[[Exception], None]],
        on_finally: Optional[Callable[[], None]],
    ):
        """Опрашивает результаты из очереди в GUI потоке."""
        def poll():
            try:
                if not self.gui_root.winfo_exists():
                    return

                # Вытащить все доступные результаты
                result_received = False
                finally_received = False

                while not self._result_queue.empty():
                    msg_type, msg_data = self._result_queue.get_nowait()

                    if msg_type == "success" and on_success:
                        try:
                            on_success(msg_data)
                        except Exception as e:
                            print(f"[{self.name}] Error in on_success: {e}")
                            traceback.print_exc()
                        result_received = True

                    elif msg_type == "error" and on_error:
                        try:
                            on_error(msg_data)
                        except Exception as e:
                            print(f"[{self.name}] Error in on_error: {e}")
                            traceback.print_exc()
                        result_received = True

                    elif msg_type == "finally":
                        if on_finally:
                            try:
                                on_finally()
                            except Exception as e:
                                print(f"[{self.name}] Error in on_finally: {e}")
                                traceback.print_exc()
                        finally_received = True

                # Если получен "finally", перестать опрашивать
                if finally_received:
                    self._poll_id = None
                    return

                # Продолжить опрос
                self._poll_id = self.gui_root.after(self.poll_ms, poll)

            except Exception as e:
                print(f"[{self.name}] Error in polling: {e}")
                traceback.print_exc()

        # Запустить первый опрос
        poll()

    def stop(self):
        """Остановить опрос результатов."""
        if self._poll_id:
            self.gui_root.after_cancel(self._poll_id)
            self._poll_id = None


# Удобный глобальный ThreadWorker для использования во всем приложении
_global_worker_instance: Optional[ThreadWorker] = None


def init_global_worker(gui_root, name: str = "GlobalWorker"):
    """Инициализирует глобальный ThreadWorker."""
    global _global_worker_instance
    _global_worker_instance = ThreadWorker(gui_root, name=name)
    return _global_worker_instance


def get_global_worker() -> Optional[ThreadWorker]:
    """Получить глобальный ThreadWorker."""
    return _global_worker_instance


def run_in_thread(
    work_fn: Callable[[], Any],
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_finally: Optional[Callable[[], None]] = None,
) -> Optional[threading.Thread]:
    """
    Запустить работу в отдельном потоке, используя глобальный ThreadWorker.

    :return: объект threading.Thread или None, если ThreadWorker не инициализирован
    """
    worker = get_global_worker()
    if worker:
        return worker.run_async(work_fn, on_success, on_error, on_finally)
    else:
        print("[⚠️] Global ThreadWorker not initialized. Call init_global_worker() first.")
        return None

