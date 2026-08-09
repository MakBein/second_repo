# xss_security_gui/auto_recon/reporting_v2.py
"""
Reporting — генерация comprehensive отчётов внутри AutoRecon Enterprise V7.

Функции:
• HTML/JSON отчёты с профессиональным дизайном
• Сводки по уязвимостям с priority scoring
• Рекомендации по исправлению и best practices
• CSV экспорт метрик
• Сравнение сканирований
• Thread-safe операции
"""

import json
import csv
import datetime
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
import threading

from xss_security_gui.settings import LOG_DIR


class ReportGenerator:
    """Enterprise-grade генератор comprehensive отчётов."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or LOG_DIR / "auto_recon" / "reports"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

    def generate_scan_report(
        self,
        scan_results: List[Dict[str, Any]],
        scan_name: str = "AutoRecon Scan",
        targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Генерирует отчёт о сканировании."""
        report = {
            "metadata": {
                "report_type": "scan_report",
                "generated_at": datetime.datetime.utcnow().isoformat(),
                "scan_name": scan_name,
                "targets": targets or [],
                "total_items_scanned": len(scan_results),
            },
            "statistics": self._analyze_results(scan_results),
            "vulnerabilities": self._group_vulnerabilities(scan_results),
            "details": scan_results[:100],  # Cap to prevent bloat
            "recommendations": self._generate_recommendations(scan_results),
        }

        return report

    def generate_vulnerability_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target: str,
    ) -> Dict[str, Any]:
        """Генерирует отчёт об уязвимостях."""
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for vuln in vulnerabilities:
            severity_counts[vuln.get("severity", "unknown")] += 1
            type_counts[vuln.get("type", "unknown")] += 1

        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: self._severity_to_number(v.get("severity", "low")),
            reverse=True
        )

        report = {
            "metadata": {
                "report_type": "vulnerability_report",
                "generated_at": datetime.datetime.utcnow().isoformat(),
                "target": target,
                "total_vulnerabilities": len(vulnerabilities),
                "critical_count": severity_counts.get("critical", 0),
                "high_count": severity_counts.get("high", 0),
                "medium_count": severity_counts.get("medium", 0),
                "low_count": severity_counts.get("low", 0),
            },
            "severity_distribution": dict(severity_counts),
            "type_distribution": dict(type_counts),
            "vulnerabilities_sorted": sorted_vulns[:50],  # Cap to 50
            "executive_summary": self._create_executive_summary(vulnerabilities),
            "remediation_steps": self._create_remediation_steps(vulnerabilities),
        }

        return report

    def generate_detailed_analysis(
        self,
        endpoints: List[Dict[str, Any]],
        analysis_results: Dict[str, List[Dict[str, Any]]],
        user_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Генерирует детальный анализ."""
        report = {
            "metadata": {
                "report_type": "detailed_analysis",
                "generated_at": datetime.datetime.utcnow().isoformat(),
                "total_endpoints": len(endpoints),
                "user": user_context or {},
            },
            "endpoints_analyzed": len(endpoints),
            "analysis_modules": {
                "xss": len(analysis_results.get("xss", [])),
                "sqli": len(analysis_results.get("sqli", [])),
                "csrf": len(analysis_results.get("csrf", [])),
                "ssrf": len(analysis_results.get("ssrf", [])),
                "dom_xss": len(analysis_results.get("dom_xss", [])),
                "csp": len(analysis_results.get("csp", [])),
            },
            "findings": analysis_results,
            "risk_assessment": self._calculate_risk_score(analysis_results),
        }

        return report

    @staticmethod
    def _severity_to_number(severity: str) -> int:
        """Конвертирует severity в число для сортировки."""
        mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return mapping.get(severity.lower(), 0)

    def _analyze_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализирует результаты сканирования."""
        vulnerable_items = [
            r for r in results
            if r.get("vulnerable", False) or r.get("context", "") != "❌ Not reflected"
        ]
        error_items = [r for r in results if "error" in r]

        return {
            "total_scanned": len(results),
            "vulnerable_found": len(vulnerable_items),
            "errors": len(error_items),
            "success_rate_percent": (
                ((len(results) - len(error_items)) / len(results) * 100) if results else 0
            ),
            "vulnerability_rate_percent": (
                (len(vulnerable_items) / len(results) * 100) if results else 0
            ),
        }

    def _group_vulnerabilities(
        self,
        results: List[Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Группирует уязвимости по типам."""
        grouped = defaultdict(list)

        for r in results:
            context = r.get("context", "unknown")
            if context != "❌ Not reflected":
                grouped[context].append(r)

        return dict(grouped)

    def _generate_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """Генерирует рекомендации на основе результатов."""
        recommendations = []

        vulnerable_count = sum(1 for r in results if r.get("vulnerable"))
        if vulnerable_count > 5:
            recommendations.append(
                "🔴 КРИТИЧНО: Множественные уязвимости обнаружены. "
                "Немедленно проведите код-ревью и имплементируйте WAF."
            )

        xss_count = sum(1 for r in results if "XSS" in str(r.get("type", "")))
        if xss_count > 0:
            recommendations.append(
                "🟡 ВАЖНО: XSS уязвимости обнаружены. "
                "Экранируйте user-input и используйте Content Security Policy."
            )

        sqli_context = sum(1 for r in results if "SQL" in str(r.get("context", "")))
        if sqli_context > 0:
            recommendations.append(
                "🟡 ВАЖНО: Потенциальные SQLi уязвимости обнаружены. "
                "Используйте prepared statements и параметризованные запросы."
            )

        if not vulnerable_count:
            recommendations.append(
                "✅ ХОРОШО: Нет критических уязвимостей обнаружено "
                "при использованном наборе тестов."
            )

        return recommendations

    def _create_executive_summary(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Создаёт executive summary."""
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        medium = sum(1 for v in vulnerabilities if v.get("severity") == "medium")

        risk_level = "КРИТИЧЕСКИЙ" if critical > 0 else "ВЫСОКИЙ" if high > 0 else "СРЕДНИЙ" if medium > 0 else "НИЗКИЙ"

        summary = f"""
EXECUTIVE SUMMARY

Дата сканирования: {datetime.datetime.utcnow().strftime('%d.%m.%Y %H:%M:%S UTC')}
Всего уязвимостей: {len(vulnerabilities)}
  • Критические: {critical}
  • Высокие: {high}
  • Средние: {medium}

Общий уровень риска: {risk_level}

На основе проведённого сканирования рекомендуется:
1. Немедленно исправить все критические уязвимости
2. Планомерно проработать высокие уязвимости
3. Имплементировать средства защиты (WAF, CSP, HSTS)
4. Проводить регулярное переоценку безопасности
        """

        return summary.strip()

    def _create_remediation_steps(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Создаёт шаги по исправлению уязвимостей."""
        remediation = defaultdict(list)

        # Базовые рекомендации для каждого типа
        base_steps = {
            "XSS": [
                "1. Используйте функции экранирования (escape) для всех user-input",
                "2. Имплементируйте Content Security Policy (CSP) заголовки",
                "3. Используйте HTTPOnly флаг для cookies",
                "4. Регулярно обновляйте front-end dependencies",
                "5. Добавьте SAST/DAST в CI/CD pipeline",
            ],
            "SQL": [
                "1. Замените raw SQL на prepared statements",
                "2. Используйте параметризованные запросы",
                "3. Используйте ORM вместо сырых SQL запросов",
                "4. Дайте минимальные привилегии для DB аккаунтов",
                "5. Валидируйте и санитизируйте все входные данные",
            ],
            "CSRF": [
                "1. Добавьте CSRF token в формы",
                "2. Используйте SameSite атрибут для cookies",
                "3. Проверяйте Origin и Referer заголовки",
                "4. Требуйте double-submit cookies",
                "5. Используйте CORS правильно",
            ],
            "SSRF": [
                "1. Белый лист URL'ов вместо чёрного",
                "2. Блокируйте доступ к внутренним IP адресам",
                "3. Отключите automatic redirects",
                "4. Используйте Network segmentation",
                "5. Логируйте все исходящие соединения",
            ],
        }

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")

            # Определяем категорию
            for base_type, steps in base_steps.items():
                if base_type in vuln_type:
                    if vuln_type not in remediation:
                        remediation[vuln_type].extend(steps)
                    break

        return dict(remediation)

    def _calculate_risk_score(self, analysis_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Расчитывает общий риск-скор."""
        total_issues = sum(len(v) for v in analysis_results.values())

        critical_weight = len(analysis_results.get("xss", [])) * 2
        high_weight = len(analysis_results.get("sqli", [])) * 1.5

        risk_score = min(10.0, (total_issues * 0.5 + critical_weight + high_weight) / 10)

        if risk_score >= 8:
            risk_level = "🔴 CRITICAL"
        elif risk_score >= 6:
            risk_level = "🟠 HIGH"
        elif risk_score >= 4:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"

        return {
            "overall_score": round(risk_score, 2),
            "risk_level": risk_level,
            "total_issues": total_issues,
        }

    def save_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> Path:
        """Сохраняет отчёт в JSON."""
        if filename is None:
            report_type = report.get("metadata", {}).get("report_type", "unknown")
            filename = f"{report_type}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

        path = self.log_dir / filename

        with self._lock:
            try:
                with path.open("w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                self.logger.info(f"Report saved: {path}")
            except Exception as e:
                self.logger.error(f"Report save error: {e}", exc_info=True)

        return path

    def generate_html_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> Path:
        """Генерирует профессиональный HTML отчёт."""
        if filename is None:
            filename = f"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"

        html_content = self._build_html(report)
        path = self.log_dir / filename

        with self._lock:
            try:
                with path.open("w", encoding="utf-8") as f:
                    f.write(html_content)
                self.logger.info(f"HTML report saved: {path}")
            except Exception as e:
                self.logger.error(f"HTML report save error: {e}", exc_info=True)

        return path

    def _build_html(self, report: Dict[str, Any]) -> str:
        """Строит профессиональный HTML из отчёта."""
        metadata = report.get("metadata", {})
        stats = report.get("statistics", {})
        vulns = report.get("vulnerabilities", {})
        recommendations = report.get("recommendations", [])

        vuln_html = self._build_vulnerability_html(vulns)
        rec_html = self._build_recommendations_html(recommendations)

        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoRecon Report - {metadata.get('scan_name', 'Scan')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        }}
        header {{
            border-bottom: 4px solid #667eea;
            margin-bottom: 30px;
            padding-bottom: 20px;
        }}
        h1 {{ font-size: 2.2em; margin-bottom: 10px; color: #222; }}
        h1 small {{ display: block; font-size: 0.5em; color: #999; margin-top: 5px; }}
        h2 {{ font-size: 1.6em; margin-top: 35px; margin-bottom: 15px; color: #333; border-left: 4px solid #667eea; padding-left: 15px; }}
        h3 {{ font-size: 1.2em; margin-top: 20px; color: #555; }}
        
        .metadata {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
        }}
        .metadata p {{ margin: 8px 0; }}
        .metadata strong {{ color: #333; }}
        
        .stats-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat {{
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ font-size: 0.9em; opacity: 0.9; margin-top: 8px; }}
        
        .vulnerability {{
            padding: 15px;
            margin: 12px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }}
        .vulnerability.critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        .vulnerability.high {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        .vulnerability.medium {{
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }}
        .vulnerability.low {{
            background: #d4edda;
            border-left-color: #28a745;
        }}
        .vuln-title {{ font-weight: bold; font-size: 1.1em; margin-bottom: 8px; }}
        .vuln-url {{ color: #666; font-size: 0.9em; }}
        .vuln-payload {{ 
            font-family: 'Courier New', monospace; 
            background: rgba(0,0,0,0.05); 
            padding: 8px 12px; 
            border-radius: 3px;
            font-size: 0.85em;
            margin-top: 8px;
            overflow-x: auto;
        }}
        
        .recommendation {{
            padding: 15px;
            margin: 12px 0;
            border-radius: 5px;
            border-left: 4px solid #28a745;
            background: #d4edda;
        }}
        .recommendation.warning {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        .recommendation.critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 30px;
            color: #999;
            font-style: italic;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 AutoRecon Security Assessment Report</h1>
            <small>Enterprise-level vulnerability assessment</small>
        </header>
        
        <div class="metadata">
            <p><strong>Тип отчёта:</strong> {metadata.get('report_type', 'N/A')}</p>
            <p><strong>Дата и время:</strong> {metadata.get('generated_at', 'N/A')}</p>
            <p><strong>Целевые системы:</strong> {', '.join(metadata.get('targets', ['N/A']))}</p>
        </div>

        <h2>📊 Статистика сканирования</h2>
        <div class="stats-container">
            <div class="stat">
                <div class="stat-value">{stats.get('total_scanned', 0)}</div>
                <div class="stat-label">Элементов отсканировано</div>
            </div>
            <div class="stat">
                <div class="stat-value">{stats.get('vulnerable_found', 0)}</div>
                <div class="stat-label">Уязвимостей найдено</div>
            </div>
            <div class="stat">
                <div class="stat-value">{stats.get('success_rate_percent', 0):.1f}%</div>
                <div class="stat-label">Успешность проверок</div>
            </div>
            <div class="stat">
                <div class="stat-value">{stats.get('errors', 0)}</div>
                <div class="stat-label">Ошибок при тестировании</div>
            </div>
        </div>

        <h2>🔓 Найденные уязвимости</h2>
        {vuln_html}

        <h2>💡 Рекомендации по исправлению</h2>
        {rec_html}
        
        <footer>
            <p>Отчёт сгенерирован AutoRecon Enterprise V7</p>
            <p style="margin-top: 10px; font-size: 0.85em;">
                Дата: {datetime.datetime.utcnow().strftime('%d.%m.%Y %H:%M:%S')} UTC
            </p>
        </footer>
    </div>
</body>
</html>"""
        return html

    def _build_vulnerability_html(self, vulns: Dict[str, List[Dict]]) -> str:
        """Строит HTML для уязвимостей."""
        if not vulns:
            return '<div class="empty-state">✅ Уязвимостей не найдено</div>'

        html = ""
        total_idx = 0
        for category, items in vulns.items():
            for idx, item in enumerate(items[:10], 1):
                total_idx += 1
                severity = item.get('severity', 'unknown').lower()
                vuln_type = item.get('type', 'Unknown')
                url = item.get('url', 'N/A')
                payload = item.get('payload', 'N/A')[:100]

                html += f"""<div class='vulnerability {severity}'>
                    <div class='vuln-title'>#{total_idx} {vuln_type}</div>
                    <div class='vuln-url'>🔗 {url}</div>
                    <div class='vuln-payload'>📋 {payload}</div>
                </div>"""

        return html

    def _build_recommendations_html(self, recommendations: List[str]) -> str:
        """Строит HTML для рекомендаций."""
        if not recommendations:
            return '<div class="empty-state">ℹ️ Нет рекомендаций</div>'

        html = ""
        for rec in recommendations:
            if "🔴" in rec:
                rec_class = "recommendation critical"
            elif "🟡" in rec:
                rec_class = "recommendation warning"
            else:
                rec_class = "recommendation"

            html += f"<div class='{rec_class}'>{rec}</div>"

        return html

    def export_to_csv(self, vulnerabilities: List[Dict[str, Any]], filename: Optional[str] = None) -> Path:
        """Экспортирует уязвимости в CSV."""
        if filename is None:
            filename = f"vulnerabilities_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

        path = self.log_dir / filename

        with self._lock:
            try:
                with path.open("w", newline="", encoding="utf-8") as f:
                    if vulnerabilities:
                        fieldnames = vulnerabilities[0].keys()
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(vulnerabilities[:500])  # Cap to 500 rows
                self.logger.info(f"CSV export saved: {path}")
            except Exception as e:
                self.logger.error(f"CSV export error: {e}", exc_info=True)

        return path


def get_report_generator(log_dir: Optional[Path] = None) -> ReportGenerator:
    """Возвращает экземпляр ReportGenerator."""
    return ReportGenerator(log_dir)


__all__ = [
    "ReportGenerator",
    "get_report_generator",
]

