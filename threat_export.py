# xss_security_gui/threat_export.py
"""
Threat Export Module 1.0 — Экспорт угроз в различные форматы

Форматы:
- CSV (для Excel, Google Sheets)
- XML (для интеграции с внешними системами)
- PDF (для отчетов)
- JSON (для API)
"""

from __future__ import annotations

import json
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom

# Импортируем опционально для PDF
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


class ThreatExporter:
    """Экспортер угроз в различные форматы"""
    
    def __init__(self):
        self.export_dir = Path(__file__).parent / "exports"
        self.export_dir.mkdir(exist_ok=True, parents=True)
    
    def export_to_csv(self, threats: List[Dict[str, Any]], filename: str = "threats_export.csv") -> str:
        """
        Экспортирует угрозы в CSV
        """
        filepath = self.export_dir / filename
        
        if not threats:
            print("[⚠️] No threats to export")
            return str(filepath)
        
        try:
            # Получаем все ключи из всех угроз
            all_keys = set()
            for threat in threats:
                all_keys.update(self._flatten_dict(threat).keys())
            
            fieldnames = sorted(list(all_keys))
            
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for threat in threats:
                    flat_threat = self._flatten_dict(threat)
                    # Заполняем недостающие ключи
                    for key in fieldnames:
                        if key not in flat_threat:
                            flat_threat[key] = ""
                    writer.writerow(flat_threat)
            
            print(f"[✅] Threats exported to CSV: {filepath}")
            return str(filepath)
            
        except Exception as e:
            print(f"[❌] CSV export error: {e}")
            return str(filepath)
    
    def export_to_xml(self, threats: List[Dict[str, Any]], filename: str = "threats_export.xml") -> str:
        """
        Экспортирует угрозы в XML
        """
        filepath = self.export_dir / filename
        
        try:
            root = Element("threats")
            root.set("timestamp", datetime.now().isoformat())
            root.set("count", str(len(threats)))
            
            for threat in threats:
                threat_elem = SubElement(root, "threat")
                self._dict_to_xml(threat, threat_elem)
            
            # Pretty print
            xml_str = minidom.parseString(tostring(root)).toprettyxml(indent="  ")
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(xml_str)
            
            print(f"[✅] Threats exported to XML: {filepath}")
            return str(filepath)
            
        except Exception as e:
            print(f"[❌] XML export error: {e}")
            return str(filepath)
    
    def export_to_json(self, threats: List[Dict[str, Any]], filename: str = "threats_export.json") -> str:
        """
        Экспортирует угрозы в JSON
        """
        filepath = self.export_dir / filename
        
        try:
            export_data = {
                "timestamp": datetime.now().isoformat(),
                "total": len(threats),
                "threats": threats
            }
            
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"[✅] Threats exported to JSON: {filepath}")
            return str(filepath)
            
        except Exception as e:
            print(f"[❌] JSON export error: {e}")
            return str(filepath)
    
    def export_to_pdf(self, threats: List[Dict[str, Any]], filename: str = "threats_export.pdf") -> str:
        """
        Экспортирует угрозы в PDF
        """
        filepath = self.export_dir / filename
        
        if not PDF_AVAILABLE:
            print("[⚠️] ReportLab not installed, trying alternative method...")
            return self._export_to_pdf_simple(threats, filename)
        
        try:
            doc = SimpleDocTemplate(str(filepath), pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # Заголовок
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#DC3545"),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            story.append(Paragraph("🚨 Threat Intelligence Report", title_style))
            story.append(Spacer(1, 0.5*inch))
            
            # Метаинформация
            meta_style = styles["Normal"]
            story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
            story.append(Paragraph(f"<b>Total Threats:</b> {len(threats)}", meta_style))
            
            # Группируем по категориям
            by_category = {}
            for threat in threats:
                category = threat.get("result", {}).get("category", "unknown")
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(threat)
            
            story.append(Paragraph(f"<b>Categories:</b> {', '.join(by_category.keys())}", meta_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Таблица угроз
            table_data = [["Category", "Risk", "Module", "Count"]]
            
            for category, category_threats in by_category.items():
                avg_risk = self._get_avg_risk(category_threats)
                modules = set(t.get("module", "unknown") for t in category_threats)
                table_data.append([
                    category,
                    avg_risk,
                    ", ".join(sorted(modules)),
                    str(len(category_threats))
                ])
            
            table = Table(table_data, colWidths=[2*inch, 1.5*inch, 2*inch, 1*inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DC3545")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), TA_CENTER),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(table)
            story.append(PageBreak())
            
            # Детали по каждой категории
            for category, category_threats in by_category.items():
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph(f"<b>{category.upper()}</b>", styles["Heading2"]))
                story.append(Spacer(1, 0.1*inch))
                
                for threat in category_threats[:5]:  # Максимум 5 деталей на категорию
                    threat_text = json.dumps(threat, indent=2, ensure_ascii=False, default=str)
                    story.append(Paragraph(threat_text[:200] + "...", styles["Normal"]))
                    story.append(Spacer(1, 0.1*inch))
            
            doc.build(story)
            print(f"[✅] Threats exported to PDF: {filepath}")
            return str(filepath)
            
        except Exception as e:
            print(f"[⚠️] PDF export error (using simple format): {e}")
            return self._export_to_pdf_simple(threats, filename)
    
    def _export_to_pdf_simple(self, threats: List[Dict[str, Any]], filename: str) -> str:
        """
        Простой экспорт в PDF-текст (используется если ReportLab недоступен)
        """
        filepath = self.export_dir / filename.replace(".pdf", "_simple.txt")
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("🚨 THREAT INTELLIGENCE REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Threats: {len(threats)}\n\n")
                
                # По категориям
                by_category = {}
                for threat in threats:
                    category = threat.get("result", {}).get("category", "unknown")
                    if category not in by_category:
                        by_category[category] = []
                    by_category[category].append(threat)
                
                f.write("SUMMARY BY CATEGORY\n")
                f.write("-" * 80 + "\n")
                for category, category_threats in by_category.items():
                    f.write(f"{category}: {len(category_threats)} threats\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("DETAILED THREATS\n")
                f.write("=" * 80 + "\n\n")
                
                for i, threat in enumerate(threats, 1):
                    f.write(f"THREAT #{i}\n")
                    f.write("-" * 80 + "\n")
                    f.write(json.dumps(threat, indent=2, ensure_ascii=False, default=str))
                    f.write("\n\n")
            
            print(f"[✅] Threats exported to text: {filepath}")
            return str(filepath)
            
        except Exception as e:
            print(f"[❌] Simple export error: {e}")
            return str(filepath)
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = "", sep: str = "_") -> Dict[str, Any]:
        """Флетит вложенный словарь для CSV экспорта"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, str(v)))
        return dict(items)
    
    def _dict_to_xml(self, data: Dict[str, Any], parent: Element) -> None:
        """Конвертирует словарь в XML элементы"""
        for key, value in data.items():
            if isinstance(value, dict):
                SubElement(parent, key)
                self._dict_to_xml(value, parent[-1])
            elif isinstance(value, list):
                list_elem = SubElement(parent, key)
                for item in value:
                    if isinstance(item, dict):
                        SubElement(list_elem, "item")
                        self._dict_to_xml(item, list_elem[-1])
                    else:
                        item_elem = SubElement(list_elem, "item")
                        item_elem.text = str(item)
            else:
                elem = SubElement(parent, key)
                elem.text = str(value)
    
    def _get_avg_risk(self, threats: List[Dict[str, Any]]) -> str:
        """Получает усредненный риск по списку угроз"""
        risk_levels = []
        risk_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        
        for threat in threats:
            risk = threat.get("result", {}).get("risk", "unknown").lower()
            risk_levels.append(risk_map.get(risk, 1))
        
        if not risk_levels:
            return "unknown"
        
        avg = sum(risk_levels) / len(risk_levels)
        reverse_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        
        for threshold, level in sorted(reverse_map.items(), reverse=True):
            if avg >= threshold:
                return level
        
        return "low"


# Глобальный экспортер
_EXPORTER = ThreatExporter()


def export_threats_csv(threats: List[Dict[str, Any]], filename: str = "threats_export.csv") -> str:
    """Экспортирует угрозы в CSV"""
    return _EXPORTER.export_to_csv(threats, filename)


def export_threats_xml(threats: List[Dict[str, Any]], filename: str = "threats_export.xml") -> str:
    """Экспортирует угрозы в XML"""
    return _EXPORTER.export_to_xml(threats, filename)


def export_threats_json(threats: List[Dict[str, Any]], filename: str = "threats_export.json") -> str:
    """Экспортирует угрозы в JSON"""
    return _EXPORTER.export_to_json(threats, filename)


def export_threats_pdf(threats: List[Dict[str, Any]], filename: str = "threats_export.pdf") -> str:
    """Экспортирует угрозы в PDF"""
    return _EXPORTER.export_to_pdf(threats, filename)

