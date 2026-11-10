# xss_security_gui/core/enterprise_integrator.py
"""
EnterpriseIntegrator 12.0 — One-Click Integration for main.py
============================================================
Интегрирует все enterprise компоненты в существующий GUI без фризов и падений

Usage:
    from xss_security_gui.core.enterprise_integrator import EnterpriseIntegrator
    
    integrator = EnterpriseIntegrator()
    integrator.initialize()
"""

from __future__ import annotations

import logging
from typing import Optional, Dict, Any, Callable

from xss_security_gui.core import (
    get_thread_pool,
    get_cache,
    get_http_cache,
    ReportGenerator,
    WAFDetector,
    ThreadPoolManager,
    CacheEngine,
)
from xss_security_gui.threat_analysis.engine_v12 import ThreatEngine

_logger = logging.getLogger(__name__)


class EnterpriseIntegrator:
    """
    One-stop integration for all enterprise features
    """

    _instance: Optional[EnterpriseIntegrator] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return

        self.thread_pool: Optional[ThreadPoolManager] = None
        self.cache: Optional[CacheEngine] = None
        self.http_cache = None
        self.report_generator: Optional[ReportGenerator] = None
        self.waf_detector: Optional[WAFDetector] = None
        self.threat_engine: Optional[ThreatEngine] = None
        self.callbacks: Dict[str, Callable] = {}
        self._initialized = False

        _logger.info("EnterpriseIntegrator created")

    def initialize(self, threat_connector: Optional[Any] = None) -> None:
        """
        Инициализировать все компоненты
        
        :param threat_connector: Optional threat connector для интеграции
        """
        if self._initialized:
            _logger.info("EnterpriseIntegrator already initialized")
            return

        _logger.info("Initializing Enterprise components...")

        try:
            # Initialize thread pool
            self.thread_pool = get_thread_pool()
            _logger.info("✓ ThreadPoolManager initialized")

            # Initialize caching
            self.cache = get_cache()
            self.http_cache = get_http_cache()
            _logger.info("✓ CacheEngine initialized")

            # Initialize report generator
            self.report_generator = ReportGenerator("XSS Security Assessment")
            _logger.info("✓ ReportGenerator initialized")

            # Initialize WAF detector
            self.waf_detector = WAFDetector()
            _logger.info("✓ WAFDetector initialized")

            # Initialize threat engine
            self.threat_engine = ThreatEngine(
                threat_connector=threat_connector,
                enable_cache=True,
            )
            _logger.info("✓ ThreatEngine initialized")

            self._initialized = True
            _logger.info("✅ All Enterprise components initialized successfully!")

        except Exception as e:
            _logger.error(f"Failed to initialize enterprise components: {e}")
            raise

    def submit_analysis_task(
        self,
        task_name: str,
        task_func,
        args: tuple = (),
        kwargs: dict = None,
        priority: str = "NORMAL",
        on_complete: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        timeout: int = 60,
    ) -> str:
        """
        Отправить задачу анализа в thread pool (без блокирования GUI)
        
        :param task_name: Имя задачи
        :param task_func: Функция для выполнения
        :param args: Аргументы
        :param kwargs: Keyword аргументы
        :param priority: "CRITICAL", "HIGH", "NORMAL", "LOW"
        :param on_complete: Callback при завершении
        :param on_error: Callback при ошибке
        :param timeout: Timeout в секундах
        :return: Task ID для отслеживания
        """
        if not self._initialized:
            raise RuntimeError("EnterpriseIntegrator not initialized")

        if kwargs is None:
            kwargs = {}

        from xss_security_gui.core import TaskPriority

        priority_map = {
            "CRITICAL": TaskPriority.CRITICAL,
            "HIGH": TaskPriority.HIGH,
            "NORMAL": TaskPriority.NORMAL,
            "LOW": TaskPriority.LOW,
        }

        task_priority = priority_map.get(priority, TaskPriority.NORMAL)

        task_id = self.thread_pool.submit(
            task_name,
            task_func,
            args,
            kwargs,
            priority=task_priority,
            callback=on_complete,
            error_callback=on_error,
            timeout=timeout,
        )

        _logger.debug(f"Task submitted: {task_id} (priority={priority})")
        return task_id

    def run_threat_analysis_async(
        self,
        page_data: dict,
        on_complete: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
    ) -> str:
        """
        Запустить анализ угроз асинхронно (не блокирует GUI)
        
        :param page_data: Данные страницы
        :param on_complete: Callback при завершении
        :param on_progress: Callback для прогресса
        :return: execution_id
        """
        if not self._initialized or not self.threat_engine:
            raise RuntimeError("ThreatEngine not initialized")

        execution_id = self.threat_engine.run_all_parallel(
            page_data,
            execution_callback=on_complete,
            progress_callback=on_progress,
        )

        _logger.info(f"Threat analysis started: {execution_id}")
        return execution_id

    def get_analysis_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Получить статус анализа"""
        if not self.threat_engine:
            return None
        return self.threat_engine.get_execution_status(execution_id)

    def cache_get(self, key: str) -> Optional[Any]:
        """Получить значение из кэша"""
        if not self.cache:
            return None
        return self.cache.get(key)

    def cache_set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Сохранить значение в кэш"""
        if not self.cache:
            return False
        return self.cache.set(key, value, ttl)

    def cache_invalidate(self, pattern: Optional[str] = None) -> int:
        """Инвалидировать кэш"""
        if not self.cache:
            return 0
        return self.cache.invalidate(pattern)

    def generate_report(
        self,
        vulnerabilities: list,
        project_name: str = "Security Assessment",
        export_format: str = "html",
        filepath: Optional[str] = None,
    ) -> str:
        """
        Генерировать отчёт
        
        :param vulnerabilities: Список уязвимостей
        :param project_name: Имя проекта
        :param export_format: "html", "json", "pdf"
        :param filepath: Путь для сохранения (опционально)
        :return: Содержимое отчёта или путь к файлу
        """
        if not self.report_generator:
            raise RuntimeError("ReportGenerator not initialized")

        self.report_generator.project_name = project_name
        self.report_generator.vulnerabilities = vulnerabilities

        if export_format == "html":
            content = self.report_generator.generate_html()
            if filepath:
                self.report_generator.save_html(filepath)
        elif export_format == "json":
            content = self.report_generator.generate_json()
            if filepath:
                self.report_generator.save_json(filepath)
        elif export_format == "pdf":
            content = self.report_generator.generate_pdf()
            if filepath:
                self.report_generator.save_pdf(filepath)
        else:
            raise ValueError(f"Unknown format: {export_format}")

        return filepath or content

    def detect_waf(
        self,
        url: str,
        response_text: str,
        response_headers: Dict[str, str],
        status_code: int,
    ):
        """
        Определить WAF
        
        :return: WAFType или None
        """
        if not self.waf_detector:
            raise RuntimeError("WAFDetector not initialized")

        return self.waf_detector.detect_waf(url, response_text, response_headers, status_code)

    def get_waf_evasion_payloads(
        self,
        original_payload: str,
        detected_waf=None,
        max_variants: int = 10,
    ) -> list:
        """Получить payload для обхода WAF"""
        if not self.waf_detector:
            raise RuntimeError("WAFDetector not initialized")

        return self.waf_detector.get_evasion_payloads(original_payload, detected_waf, max_variants)

    def health_check(self) -> Dict[str, Any]:
        """Получить health check всех компонентов"""
        return {
            "initialized": self._initialized,
            "thread_pool": self.thread_pool.health_check() if self.thread_pool else None,
            "cache": self.cache.stats() if self.cache else None,
            "threat_engine": self.threat_engine.health_check() if self.threat_engine else None,
        }

    def shutdown(self) -> None:
        """Graceful shutdown"""
        _logger.info("Shutting down EnterpriseIntegrator...")
        if self.threat_engine:
            self.threat_engine.shutdown()
        if self.thread_pool:
            self.thread_pool.shutdown()
        self._initialized = False
        _logger.info("✓ EnterpriseIntegrator shut down")


# Global singleton
def get_integrator() -> EnterpriseIntegrator:
    """Получить глобальный экземпляр EnterpriseIntegrator"""
    return EnterpriseIntegrator()


def initialize_enterprise() -> EnterpriseIntegrator:
    """Инициализировать и вернуть integrator"""
    integrator = get_integrator()
    integrator.initialize()
    return integrator
