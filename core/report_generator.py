# xss_security_gui/core/report_generator.py
"""
ReportGenerator 12.0 — Burp Suite Enterprise Level Reports
===========================================================
✅ HTML/PDF/JSON export
✅ Executive summaries
✅ Detailed vulnerability reports
✅ Risk rating & CVSS scores
✅ Timeline & charts
✅ Professional formatting
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from html import escape

_logger = logging.getLogger(__name__)


class VulnerabilityReport:
    """Представление уязвимости в отчёте"""
    
    SEVERITIES = {
        "CRITICAL": {"value": 9, "color": "#d32f2f", "bg": "#ffebee"},
        "HIGH": {"value": 7, "color": "#f57c00", "bg": "#ffe0b2"},
        "MEDIUM": {"value": 5, "color": "#fbc02d", "bg": "#fff9c4"},
        "LOW": {"value": 3, "color": "#388e3c", "bg": "#e8f5e9"},
        "INFO": {"value": 1, "color": "#1976d2", "bg": "#e3f2fd"},
    }

    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        proof: str,
        remediation: str,
        category: str,
        target_url: str,
        timestamp: Optional[str] = None,
        cvss_score: Optional[float] = None,
    ):
        self.title = title
        self.severity = severity
        self.description = description
        self.proof = proof
        self.remediation = remediation
        self.category = category
        self.target_url = target_url
        self.timestamp = timestamp or datetime.now().isoformat()
        self.cvss_score = cvss_score or self._estimate_cvss_score(severity)
        self.id = self._generate_id()

    def _generate_id(self) -> str:
        """Генерировать уникальный ID"""
        import hashlib
        content = f"{self.title}:{self.target_url}:{self.timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:8]

    def _estimate_cvss_score(self, severity: str) -> float:
        """Оценить CVSS score по severity"""
        return float(self.SEVERITIES.get(severity, {}).get("value", 1))

    def to_dict(self) -> Dict[str, Any]:
        """Сериализовать в dict"""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "proof": self.proof,
            "remediation": self.remediation,
            "category": self.category,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
        }


class ReportGenerator:
    """
    Professional security report generator
    """

    def __init__(self, project_name: str = "Security Assessment"):
        self.project_name = project_name
        self.vulnerabilities: List[VulnerabilityReport] = []
        self.scans: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "created_at": datetime.now().isoformat(),
            "generator": "XSS-Security-GUI/12.0",
            "version": "1.0",
        }

    # ============================================================
    # Добавление данных в отчёт
    # ============================================================
    def add_vulnerability(self, vuln: VulnerabilityReport) -> None:
        """Добавить уязвимость в отчёт"""
        self.vulnerabilities.append(vuln)
        _logger.debug(f"Added vulnerability: {vuln.title}")

    def add_vulnerabilities(self, vulns: List[VulnerabilityReport]) -> None:
        """Добавить несколько уязвимостей"""
        self.vulnerabilities.extend(vulns)

    def add_scan(self, scan_data: Dict[str, Any]) -> None:
        """Добавить результаты сканирования"""
        self.scans.append(scan_data)

    # ============================================================
    # Генерация отчётов
    # ============================================================
    def generate_json(self) -> str:
        """Генерировать JSON отчёт"""
        report_data = {
            "metadata": self.metadata,
            "project": self.project_name,
            "summary": self._generate_summary(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scans": self.scans,
        }
        return json.dumps(report_data, indent=2)

    def generate_html(self) -> str:
        """Генерировать HTML отчёт (Burp Suite style)"""
        summary = self._generate_summary()
        html_parts = [
            self._html_header(),
            self._html_executive_summary(summary),
            self._html_vulnerability_table(),
            self._html_vulnerability_details(),
            self._html_charts(summary),
            self._html_footer(),
        ]
        return "\n".join(html_parts)

    def generate_pdf(self) -> bytes:
        """Генерировать PDF (требует reportlab)"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, PageBreak
            from reportlab.lib import colors

            # Создать PDF
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5 * inch)
            elements = []

            # Title
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#d32f2f"),
            )
            elements.append(Paragraph(f"Security Assessment Report", title_style))
            elements.append(Spacer(1, 0.3 * inch))

            # Executive Summary
            summary = self._generate_summary()
            elements.append(Paragraph(f"Project: {self.project_name}", styles["Heading2"]))
            elements.append(Paragraph(f"Total Issues: {summary['total']}", styles["Normal"]))
            elements.append(Spacer(1, 0.2 * inch))

            # Vulnerability table
            for vuln in self.vulnerabilities[:10]:  # First 10 for PDF
                elements.append(Paragraph(vuln.title, styles["Heading3"]))
                elements.append(Paragraph(f"Severity: {vuln.severity}", styles["Normal"]))
                elements.append(Paragraph(f"Description: {vuln.description}", styles["Normal"]))
                elements.append(Spacer(1, 0.1 * inch))

            doc.build(elements)
            return buffer.getvalue()

        except ImportError:
            _logger.warning("reportlab not installed, generating JSON instead")
            return self.generate_json().encode()

    # ============================================================
    # Вспомогательные методы для HTML
    # ============================================================
    def _html_header(self) -> str:
        """HTML заголовок"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Security Assessment Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 40px;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }}
                .header {{
                    border-bottom: 3px solid #d32f2f;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    color: #d32f2f;
                    margin: 0;
                    font-size: 32px;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    color: #666;
                }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }}
                .summary-card {{
                    background: #f9f9f9;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    border-left: 4px solid #d32f2f;
                }}
                .summary-card h3 {{
                    margin: 0;
                    color: #333;
                    font-size: 24px;
                }}
                .summary-card p {{
                    margin: 10px 0 0 0;
                    color: #999;
                    font-size: 12px;
                }}
                .vulnerability {{
                    margin: 30px 0;
                    border-left: 4px solid;
                    padding: 20px;
                    background: #fafafa;
                    border-radius: 4px;
                }}
                .vulnerability.CRITICAL {{
                    border-color: #d32f2f;
                    background: #ffebee;
                }}
                .vulnerability.HIGH {{
                    border-color: #f57c00;
                    background: #ffe0b2;
                }}
                .vulnerability.MEDIUM {{
                    border-color: #fbc02d;
                    background: #fff9c4;
                }}
                .vulnerability.LOW {{
                    border-color: #388e3c;
                    background: #e8f5e9;
                }}
                .vuln-title {{
                    font-size: 18px;
                    font-weight: bold;
                    margin: 0 0 10px 0;
                }}
                .vuln-meta {{
                    display: flex;
                    gap: 20px;
                    margin: 10px 0;
                    flex-wrap: wrap;
                }}
                .vuln-badge {{
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }}
                .severity-badge {{
                    background: #d32f2f;
                    color: white;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background: #f5f5f5;
                    font-weight: bold;
                }}
                tr:hover {{
                    background: #f9f9f9;
                }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    color: #999;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
        <div class="container">
        """

    def _html_footer(self) -> str:
        """HTML подвал"""
        return f"""
            <div class="footer">
                <p>Report generated by XSS-Security-GUI/12.0</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
        </body>
        </html>
        """

    def _html_executive_summary(self, summary: Dict[str, Any]) -> str:
        """HTML executive summary"""
        return f"""
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Project: {escape(self.project_name)}</p>
            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>{summary['critical']}</h3>
                <p>Critical Issues</p>
            </div>
            <div class="summary-card">
                <h3>{summary['high']}</h3>
                <p>High Issues</p>
            </div>
            <div class="summary-card">
                <h3>{summary['medium']}</h3>
                <p>Medium Issues</p>
            </div>
            <div class="summary-card">
                <h3>{summary['total']}</h3>
                <p>Total Issues</p>
            </div>
        </div>
        """

    def _html_vulnerability_table(self) -> str:
        """HTML таблица уязвимостей"""
        rows = [
            "<tr><th>Title</th><th>Severity</th><th>Category</th><th>CVSS Score</th></tr>"
        ]
        for vuln in self.vulnerabilities:
            rows.append(
                f"""<tr>
                    <td>{escape(vuln.title)}</td>
                    <td><span class="vuln-badge severity-badge">{vuln.severity}</span></td>
                    <td>{escape(vuln.category)}</td>
                    <td>{vuln.cvss_score:.1f}</td>
                </tr>"""
            )
        return f"<h2>Vulnerability Overview</h2><table>{''.join(rows)}</table>"

    def _html_vulnerability_details(self) -> str:
        """HTML детали уязвимостей"""
        details = ["<h2>Vulnerability Details</h2>"]
        for vuln in self.vulnerabilities:
            details.append(f"""
            <div class="vulnerability {vuln.severity}">
                <div class="vuln-title">{escape(vuln.title)}</div>
                <div class="vuln-meta">
                    <span class="vuln-badge severity-badge">{vuln.severity}</span>
                    <span>CVSS: {vuln.cvss_score:.1f}</span>
                    <span>Category: {escape(vuln.category)}</span>
                </div>
                <p><strong>Description:</strong></p>
                <p>{escape(vuln.description)}</p>
                <p><strong>Proof of Concept:</strong></p>
                <pre>{escape(vuln.proof)}</pre>
                <p><strong>Remediation:</strong></p>
                <p>{escape(vuln.remediation)}</p>
            </div>
            """)
        return "\n".join(details)

    def _html_charts(self, summary: Dict[str, Any]) -> str:
        """HTML charts"""
        return f"""
        <h2>Risk Distribution</h2>
        <div style="text-align: center; margin: 30px 0;">
            <p>Critical: {summary['critical']} | High: {summary['high']} | Medium: {summary['medium']} | Low: {summary['low']}</p>
        </div>
        """

    # ============================================================
    # Утилиты
    # ============================================================
    def _generate_summary(self) -> Dict[str, int]:
        """Генерировать summary"""
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            key = vuln.severity.lower()
            if key in severities:
                severities[key] += 1

        return {
            "critical": severities["critical"],
            "high": severities["high"],
            "medium": severities["medium"],
            "low": severities["low"],
            "info": severities["info"],
            "total": len(self.vulnerabilities),
        }

    def save_html(self, filepath: str) -> None:
        """Сохранить HTML отчёт"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate_html())
        _logger.info(f"HTML report saved: {filepath}")

    def save_json(self, filepath: str) -> None:
        """Сохранить JSON отчёт"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate_json())
        _logger.info(f"JSON report saved: {filepath}")

    def save_pdf(self, filepath: str) -> None:
        """Сохранить PDF отчёт"""
        with open(filepath, "wb") as f:
            f.write(self.generate_pdf())
        _logger.info(f"PDF report saved: {filepath}")
