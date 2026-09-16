"""
ThreatEngine 12.0 — Enterprise Combat Edition
==============================================
Оркестратор для модулів аналізу загроз:
✅ Параллельное выполнение всех модулей (NO BLOCKING)
✅ Intelligent caching of results
✅ Priority-based execution
✅ Full thread pool integration
✅ ThreatConnector-ready
✅ BURP Suite Enterprise level
"""

from __future__ import annotations

import traceback
import time
import uuid
import logging
from typing import Any, Dict, Optional, Callable, List
from concurrent.futures import as_completed

from xss_security_gui.core import (
    get_thread_pool,
    submit_task,
    TaskPriority,
    get_cache,
)
from xss_security_gui.threat_analysis.csp_module import CSPAnalyzer
from xss_security_gui.threat_analysis.dom_events_module import DOMEventMapper
from xss_security_gui.threat_analysis.cookie_tracer import CookieTracer

_logger = logging.getLogger(__name__)


class ThreatEngineExecutionContext:
    """Контекст выполнения анализа"""
    
    def __init__(self):
        self.execution_id = str(uuid.uuid4())
        self.start_time = time.time()
        self.results: Dict[str, Any] = {}
        self.errors: Dict[str, str] = {}
        self.module_durations: Dict[str, float] = {}
        self.callbacks: Dict[str, List[Callable]] = {}

    def add_result(self, module_name: str, result: Any) -> None:
        """Добавить результат модуля"""
        self.results[module_name] = result
        self.module_durations[module_name] = time.time() - self.start_time

    def add_error(self, module_name: str, error: str) -> None:
        """Добавить ошибку модуля"""
        self.errors[module_name] = error

    def get_summary(self) -> Dict[str, Any]:
        """Получить summary выполнения"""
        return {
            "execution_id": self.execution_id,
            "total_duration": time.time() - self.start_time,
            "modules_completed": len(self.results),
            "modules_failed": len(self.errors),
            "module_durations": self.module_durations,
            "errors": self.errors,
        }


class ThreatEngine:
    """
    Enterprise-grade threat analysis orchestrator
    
    Features:
    - Parallel module execution
    - Intelligent caching
    - Priority-based task scheduling
    - Full monitoring & health checks
    - ThreatConnector integration
    """

    def __init__(self, threat_connector: Optional[Any] = None, enable_cache: bool = True):
        self.modules: Dict[str, Any] = {
            "csp": CSPAnalyzer(),
            "dom_events": DOMEventMapper(),
            "cookie": CookieTracer(),
        }
        self.threat_connector = threat_connector
        self.enable_cache = enable_cache
        self.thread_pool = get_thread_pool()
        self.cache = get_cache() if enable_cache else None
        self.active_executions: Dict[str, ThreatEngineExecutionContext] = {}
        _logger.info("ThreatEngine 12.0 initialized with parallel execution support")

    # ============================================================
    # Регистрация модулей
    # ============================================================
    def register_module(self, name: str, module: Any, priority: int = 1) -> None:
        """
        Зарегистрировать новый модуль анализа
        
        :param name: Имя модуля
        :param module: Модуль (должен иметь run() или run_async())
        :param priority: Приоритет (0=max, 3=min)
        """
        self.modules[name] = {"instance": module, "priority": priority}
        _logger.info(f"Registered module: {name} (priority={priority})")

    # ============================================================
    # Параллельное выполнение модулей
    # ============================================================
    def run_all_parallel(
        self,
        page_data: dict,
        execution_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
    ) -> str:
        """
        Запустить все модули параллельно (для GUI)
        
        :param page_data: Данные страницы
        :param execution_callback: Callback при завершении
        :param progress_callback: Callback для прогресса
        :return: execution_id для отслеживания
        """
        execution_id = str(uuid.uuid4())
        context = ThreatEngineExecutionContext()
        self.active_executions[execution_id] = context

        # Проверить кэш
        cache_key = f"threat_analysis:{self._hash_page_data(page_data)}"
        if self.enable_cache and self.cache:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                _logger.info(f"Execution {execution_id}: Cache HIT")
                if execution_callback:
                    execution_callback(cached_result)
                return execution_id

        _logger.info(f"Starting parallel threat analysis (execution_id={execution_id})")

        # Задачи для thread pool
        task_ids = []
        for module_name, module_info in self.modules.items():
            module = module_info["instance"] if isinstance(module_info, dict) else module_info
            priority = module_info.get("priority", 1) if isinstance(module_info, dict) else 1

            task_id = f"threat_module_{module_name}_{execution_id}"

            def module_task(m=module, mn=module_name, pd=page_data):
                try:
                    if hasattr(m, "run_async"):
                        container = {"done": False, "result": None}

                        def callback(res):
                            container["done"] = True
                            container["result"] = res

                        m.run_async(pd, callback)

                        # Safe-wait: не блокирует GUI
                        for _ in range(300):
                            if container["done"]:
                                break
                            time.sleep(0.01)

                        return container["result"]
                    else:
                        return m.run(pd) if hasattr(m, "run") else None
                except Exception as e:
                    _logger.error(f"Module {mn} failed: {e}")
                    return None

            submit_task(
                task_id,
                module_task,
                priority=TaskPriority(priority),
                callback=lambda res, mn=module_name: self._on_module_complete(
                    execution_id, mn, res, progress_callback
                ),
                error_callback=lambda e, mn=module_name: self._on_module_error(
                    execution_id, mn, e
                ),
                timeout=120,
            )
            task_ids.append((module_name, task_id))

        # Запустить monitor для завершения
        self._start_execution_monitor(execution_id, context, execution_callback, len(task_ids))

        return execution_id

    def _on_module_complete(
        self,
        execution_id: str,
        module_name: str,
        result: Any,
        progress_callback: Optional[Callable],
    ) -> None:
        """Обработать завершение модуля"""
        context = self.active_executions.get(execution_id)
        if context:
            context.add_result(module_name, result)

            # ThreatConnector integration
            if self.threat_connector and result:
                try:
                    self.threat_connector.add_artifact({
                        "module": module_name,
                        "data": result,
                        "execution_id": execution_id,
                    })
                except Exception as e:
                    _logger.warning(f"ThreatConnector integration failed: {e}")

            if progress_callback:
                try:
                    progress_callback({
                        "module": module_name,
                        "status": "completed",
                        "progress": len(context.results) / len(self.modules),
                    })
                except Exception as e:
                    _logger.warning(f"Progress callback failed: {e}")

    def _on_module_error(
        self,
        execution_id: str,
        module_name: str,
        error: Exception,
    ) -> None:
        """Обработать ошибку модуля"""
        context = self.active_executions.get(execution_id)
        if context:
            context.add_error(module_name, str(error))
            _logger.error(f"Module {module_name} error: {error}")

    def _start_execution_monitor(
        self,
        execution_id: str,
        context: ThreatEngineExecutionContext,
        execution_callback: Optional[Callable],
        expected_modules: int,
    ) -> None:
        """Мониторить выполнение до завершения"""
        monitor_task_id = f"monitor_{execution_id}"

        def monitor_fn():
            # Ждать, пока все модули завершат работу
            timeout = 300  # 5 минут
            start = time.time()

            while time.time() - start < timeout:
                total_done = len(context.results) + len(context.errors)
                if total_done >= expected_modules:
                    break
                time.sleep(0.5)

            # Получить final results
            final_results = {
                "modules": context.results,
                "errors": context.errors,
                "summary": context.get_summary(),
            }

            # Кэшировать результаты
            if self.enable_cache and self.cache:
                cache_key = f"threat_analysis:{self._hash_page_data({})}"
                self.cache.set(cache_key, final_results, ttl=600)

            # Callback
            if execution_callback:
                try:
                    execution_callback(final_results)
                except Exception as e:
                    _logger.error(f"Execution callback failed: {e}")

            # Cleanup
            if execution_id in self.active_executions:
                del self.active_executions[execution_id]

        submit_task(
            monitor_task_id,
            monitor_fn,
            timeout=310,
        )

    # ============================================================
    # Синхронный запуск (legacy compatibility)
    # ============================================================
    def run_all(self, page_data: dict) -> Dict[str, Any]:
        """
        Синхронно запустить все модули (с таймаутом)
        
        :param page_data: Данные страницы
        :return: Результаты всех модулей
        """
        results: Dict[str, Any] = {}

        for name, module_info in self.modules.items():
            module = module_info["instance"] if isinstance(module_info, dict) else module_info
            try:
                if hasattr(module, "run_async"):
                    container = {"done": False, "result": None}

                    def callback(res):
                        container["done"] = True
                        container["result"] = res

                    module.run_async(page_data, callback)

                    # Safe-wait
                    for _ in range(300):
                        if container["done"]:
                            break
                        time.sleep(0.01)

                    results[name] = {
                        "status": "success",
                        "data": container["result"],
                    }
                else:
                    results[name] = {
                        "status": "success",
                        "data": module.run(page_data) if hasattr(module, "run") else None,
                    }

            except Exception as e:
                _logger.error(f"Module {name} sync execution failed: {e}")
                results[name] = {
                    "status": "error",
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }

        return results

    # ============================================================
    # Утилиты
    # ============================================================
    @staticmethod
    def _hash_page_data(data: dict) -> str:
        """Создать хэш для кэширования"""
        import hashlib
        import json
        content = json.dumps(data, sort_keys=True, default=str)
        return hashlib.md5(content.encode()).hexdigest()

    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Получить статус выполнения"""
        context = self.active_executions.get(execution_id)
        if context:
            return {
                "execution_id": execution_id,
                "completed_modules": len(context.results),
                "failed_modules": len(context.errors),
                "summary": context.get_summary(),
            }
        return None

    def health_check(self) -> Dict[str, Any]:
        """Health check"""
        return {
            "status": "healthy",
            "modules": len(self.modules),
            "active_executions": len(self.active_executions),
            "thread_pool_health": self.thread_pool.health_check() if self.thread_pool else None,
            "cache_health": self.cache.stats() if self.cache else None,
        }

    def shutdown(self):
        """Graceful shutdown"""
        _logger.info("Shutting down ThreatEngine")
        self.active_executions.clear()
        if self.thread_pool:
            self.thread_pool.shutdown()
