# xss_security_gui/auto_recon/reporting.py
"""
Reporting — генерация comprehensive отчётов внутри AutoRecon Enterprise.
Функции:
• HTML/JSON/PDF отчёты
• Сводки по уязвимостям
• Рекомендации по исправлению
• Сравнение сканирований
"""

import json
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
import base64

from xss_security_gui.settings import LOG_DIR


class ReportGenerator:
    """Генератор comprehensive отчётов."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or LOG_DIR / "auto_recon" / "reports"
        self.log_dir.mkdir(parents=True, exist_ok=True)

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
            "details": scan_results,
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
            "vulnerabilities": vulnerabilities,
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

    def _analyze_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализирует результаты сканирования."""
        vulnerable_items = [r for r in results if r.get("vulnerable", False) or r.get("context", "") != "❌ Not reflected"]
        error_items = [r for r in results if "error" in r]

        return {
            "total_scanned": len(results),
            "vulnerable_found": len(vulnerable_items),
            "errors": len(error_items),
            "success_rate_percent": ((len(results) - len(error_items)) / len(results) * 100) if results else 0,
            "vulnerability_rate_percent": (len(vulnerable_items) / len(results) * 100) if results else 0,
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
                "🔴 Множественные уязвимости обнаружены. Рекомендуется провести код-ревью и "
                "имплементировать WAF (Web Application Firewall)."
            )

        xss_count = sum(1 for r in results if "XSS" in str(r.get("type", "")))
        if xss_count > 0:
            recommendations.append(
                "🟡 XSS уязвимости обнаружены. Убедитесь, что все user-input должным образом "
                "экранирован и используются Content Security Policy заголовки."
            )

        sqli_context = sum(1 for r in results if "SQL" in str(r.get("context", "")))
        if sqli_context > 0:
            recommendations.append(
                "🟡 Потенциальные SQLi уязвимости обнаружены. Используйте prepared statements "
                "и параметризованные запросы."
            )

        if not vulnerable_count:
            recommendations.append("✅ Нет критических уязвимостей обнаружено при использованном наборе тестов.")

        return recommendations

    def _create_executive_summary(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Создаёт executive summary."""
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "high")

        summary = f"""
        EXECUTIVE SUMMARY
        
        Дата сканирования: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}
        Всего уязвимостей: {len(vulnerabilities)}
        Критические: {critical}
        Высокие: {high}
        
        На основе проведённого сканирования обнаружены следующие типы уязвимостей:
        {', '.join(set(v.get('type', 'unknown') for v in vulnerabilities[:5]))}
        
        Рекомендуется немедленно приступить к исправлению найденных уязвимостей.
        """

        return summary.strip()

    def _create_remediation_steps(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Создаёт шаги по исправлению уязвимостей."""
        remediation = defaultdict(list)

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")

            if "XSS" in vuln_type:
                remediation[vuln_type].extend([
                    "Используйте функции экранирования (escape) для всех user-input",
                    "Имплементируйте Content Security Policy (CSP) заголовки",
                    "Используйте HTTPOnly флаг для cookies",
                    "Регулярно обновляйте зависимости",
                ])

            elif "SQL" in vuln_type:
                remediation[vuln_type].extend([
                    "Используйте prepared statements и параметризованные запросы",
                    "Менее привилегированные аккаунты БД для приложения",
                    "Валидируйте и санитизируйте все входные данные",
                    "Используйте ORMs вместо сырых SQL запросов",
                ])

            elif "CSRF" in vuln_type:
                remediation[vuln_type].extend([
                    "Добавьте CSRF token в формы",
                    "Используйте SameSite атрибут для cookies",
                    "Проверяйте Origin и Referer заголовки",
                ])

        return dict(remediation)

    def _calculate_risk_score(self, analysis_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Расчитывает общий риск-скор."""
        total_issues = sum(len(v) for v in analysis_results.values())

        critical_weight = len(analysis_results.get("xss", [])) * 2
        high_weight = len(analysis_results.get("sqli", [])) * 1.5

        risk_score = min(10.0, (total_issues * 0.5 + critical_weight + high_weight) / 10)

        risk_level = "🔴 CRITICAL" if risk_score >= 8 else "🟡 HIGH" if risk_score >= 6 else "🟠 MEDIUM" if risk_score >= 4 else "🟢 LOW"

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

        with path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return path

    def generate_html_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> Path:\n        \"\"\"Генерирует HTML отчёт.\"\"\"\n        if filename is None:\n            filename = f\"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html\"\n\n        html_content = self._build_html(report)\n        path = self.log_dir / filename\n\n        with path.open(\"w\", encoding=\"utf-8\") as f:\n            f.write(html_content)\n\n        return path\n\n    def _build_html(self, report: Dict[str, Any]) -> str:\n        \"\"\"Строит HTML из отчёта.\"\"\"\n        metadata = report.get(\"metadata\", {})\n        stats = report.get(\"statistics\", {})\n        vulns = report.get(\"vulnerabilities\", {})\n        recommendations = report.get(\"recommendations\", [])\n\n        html = f\"\"\"\n<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n    <meta charset=\"UTF-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n    <title>AutoRecon Report - {metadata.get('scan_name', 'Scan')}</title>\n    <style>\n        body {{\n            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;\n            margin: 0;\n            padding: 20px;\n            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n        }}\n        .container {{\n            max-width: 1200px;\n            margin: 0 auto;\n            background: white;\n            padding: 30px;\n            border-radius: 10px;\n            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);\n        }}\n        h1 {{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}\n        h2 {{ color: #555; margin-top: 30px; }}\n        .metadata {{\n            background: #f5f5f5;\n            padding: 15px;\n            border-radius: 5px;\n            margin: 20px 0;\n        }}\n        .stat {{\n            display: inline-block;\n            margin: 10px 20px 10px 0;\n            padding: 10px 15px;\n            background: #667eea;\n            color: white;\n            border-radius: 5px;\n        }}\n        .vulnerability {{\n            background: #fff3cd;\n            border-left: 4px solid #ffc107;\n            padding: 15px;\n            margin: 10px 0;\n            border-radius: 5px;\n        }}\n        .critical {{\n            background: #f8d7da;\n            border-left-color: #dc3545;\n        }}\n        .high {{\n            background: #fff3cd;\n            border-left-color: #ffc107;\n        }}\n        .recommendation {{\n            background: #d1ecf1;\n            border-left: 4px solid #17a2b8;\n            padding: 15px;\n            margin: 10px 0;\n            border-radius: 5px;\n        }}\n        table {{\n            width: 100%;\n            border-collapse: collapse;\n            margin: 15px 0;\n        }}\n        th {{\n            background: #667eea;\n            color: white;\n            padding: 12px;\n            text-align: left;\n        }}\n        td {{\n            padding: 10px;\n            border-bottom: 1px solid #ddd;\n        }}\n        tr:hover {{ background: #f5f5f5; }}\n    </style>\n</head>\n<body>\n    <div class=\"container\">\n        <h1>🔒 AutoRecon Security Report</h1>\n        \n        <div class=\"metadata\">\n            <p><strong>Отчёт:</strong> {metadata.get('report_type', 'Scan')}</p>\n            <p><strong>Время:</strong> {metadata.get('generated_at', 'N/A')}</p>\n            <p><strong>Цель:</strong> {', '.join(metadata.get('targets', ['N/A']))}</p>\n        </div>\n\n        <h2>📊 Статистика</h2>\n        <div>\n            <div class=\"stat\">Всего отсканировано: {stats.get('total_scanned', 0)}</div>\n            <div class=\"stat\">Найдено уязвимостей: {stats.get('vulnerable_found', 0)}</div>\n            <div class=\"stat\">Ошибок: {stats.get('errors', 0)}</div>\n            <div class=\"stat\">Успешность: {stats.get('success_rate_percent', 0):.1f}%</div>\n        </div>\n\n        <h2>🔓 Найденные уязвимости</h2>\n        {self._build_vulnerability_html(vulns)}\n\n        <h2>💡 Рекомендации</h2>\n        {self._build_recommendations_html(recommendations)}\n    </div>\n</body>\n</html>\n        \"\"\"\n        return html\n\n    def _build_vulnerability_html(self, vulns: Dict[str, List[Dict]]) -> str:\n        \"\"\"Строит HTML для уязвимостей.\"\"\"\n        if not vulns:\n            return \"<p>Уязвимостей не найдено</p>\"\n\n        html = \"\"\n        for category, items in vulns.items():\n            html += f\"<h3>{category} ({len(items)})</h3>\"\n            for item in items[:5]:  # Show top 5\n                severity = item.get('severity', 'unknown')\n                html += f\"<div class='vulnerability {severity}'>\"\n                html += f\"<strong>{item.get('type', 'Unknown')}</strong> - {item.get('url', 'N/A')}\"\n                html += f\"<br><small>Payload: {item.get('payload', 'N/A')[:50]}</small>\"\n                html += \"</div>\"\n\n        return html\n\n    def _build_recommendations_html(self, recommendations: List[str]) -> str:\n        \"\"\"Строит HTML для рекомендаций.\"\"\"\n        html = \"\"\n        for rec in recommendations:\n            html += f\"<div class='recommendation'>{rec}</div>\"\n        return html\n\n\ndef get_report_generator(log_dir: Optional[Path] = None) -> ReportGenerator:\n    \"\"\"Возвращает экземпляр ReportGenerator.\"\"\"\n    return ReportGenerator(log_dir)\n\n\n__all__ = [\n    \"ReportGenerator\",\n    \"get_report_generator\",\n]\n
