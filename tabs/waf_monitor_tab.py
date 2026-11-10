# xss_security_gui/tabs/waf_monitor_tab.py
"""
WAF Monitor Tab — Real-time WAF Detection & Analytics
Відображення інформації про обнаружені WAF та статистики обходів
"""

import json
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
                             QPushButton, QTableWidget, QTableWidgetItem, QComboBox,
                             QGroupBox, QGridLayout)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon
from datetime import datetime

from core.waf_monitor import get_waf_monitor, get_waf_analytics


class WAFMonitorTab(QWidget):
    """TAB для моніторингу WAF"""
    
    def __init__(self):
        super().__init__()
        self.waf_monitor = get_waf_monitor()
        self.waf_analytics = get_waf_analytics()
        self.init_ui()
        
        # Auto-refresh timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(2000)  # Обновляем каждые 2 секунды
    
    def init_ui(self):
        """Инициализировать UI"""
        layout = QVBoxLayout()
        
        # ============================================================
        # РАЗДЕЛ 1: Статистика обнаруженных WAF
        # ============================================================
        stats_group = QGroupBox("📊 Статистика WAF")
        stats_layout = QGridLayout()
        
        # Общая информация
        self.total_detections_label = QLabel("Всего обнаружений: 0")
        self.total_detections_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.total_detections_label.setStyleSheet("color: #2196F3;")
        
        self.unique_wafes_label = QLabel("Уникальных WAF: 0")
        self.unique_wafes_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.unique_wafes_label.setStyleSheet("color: #4CAF50;")
        
        self.avg_confidence_label = QLabel("Средняя уверенность: 0%")
        self.avg_confidence_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.avg_confidence_label.setStyleSheet("color: #FF9800;")
        
        stats_layout.addWidget(self.total_detections_label, 0, 0)
        stats_layout.addWidget(self.unique_wafes_label, 0, 1)
        stats_layout.addWidget(self.avg_confidence_label, 0, 2)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # ============================================================
        # РАЗДЕЛ 2: ТОП обнаруженных WAF
        # ============================================================
        top_wafes_group = QGroupBox("🎯 ТОП Обнаруженные WAF")
        top_layout = QVBoxLayout()
        
        self.top_wafes_table = QTableWidget()
        self.top_wafes_table.setColumnCount(2)
        self.top_wafes_table.setHorizontalHeaderLabels(["WAF Тип", "Кол-во обнаружений"])
        self.top_wafes_table.setRowCount(5)
        self.top_wafes_table.setMaximumHeight(150)
        
        top_layout.addWidget(self.top_wafes_table)
        top_wafes_group.setLayout(top_layout)
        layout.addWidget(top_wafes_group)
        
        # ============================================================
        # РАЗДЕЛ 3: Эффективность обходов
        # ============================================================
        evasion_group = QGroupBox("🚀 Эффективность Эvasion")
        evasion_layout = QVBoxLayout()
        
        self.evasion_table = QTableWidget()
        self.evasion_table.setColumnCount(4)
        self.evasion_table.setHorizontalHeaderLabels([
            "WAF Тип", "Всего попыток", "Успешных", "Success Rate %"
        ])
        self.evasion_table.setMaximumHeight(180)
        
        evasion_layout.addWidget(self.evasion_table)
        evasion_group.setLayout(evasion_layout)
        layout.addWidget(evasion_group)
        
        # ============================================================
        # РАЗДЕЛ 4: Оценка риска
        # ============================================================
        risk_group = QGroupBox("⚠️ Оценка Риска")
        risk_layout = QGridLayout()
        
        self.risk_score_label = QLabel("Risk Score: 0/100")
        self.risk_score_label.setFont(QFont("Arial", 14, QFont.Bold))
        self.risk_score_label.setStyleSheet("color: #2196F3;")
        
        self.risk_level_label = QLabel("Risk Level: LOW")
        self.risk_level_label.setFont(QFont("Arial", 14, QFont.Bold))
        self.risk_level_label.setStyleSheet("color: #4CAF50;")
        
        self.bypass_rate_label = QLabel("Bypass Success: 0%")
        self.bypass_rate_label.setFont(QFont("Arial", 14, QFont.Bold))
        self.bypass_rate_label.setStyleSheet("color: #FF9800;")
        
        risk_layout.addWidget(self.risk_score_label, 0, 0)
        risk_layout.addWidget(self.risk_level_label, 0, 1)
        risk_layout.addWidget(self.bypass_rate_label, 0, 2)
        
        risk_group.setLayout(risk_layout)
        layout.addWidget(risk_group)
        
        # ============================================================
        # РАЗДЕЛ 5: Детали последних обнаружений
        # ============================================================
        details_group = QGroupBox("📝 Последние обнаружения WAF")
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(200)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 5px;
                font-family: Monospace;
                font-size: 9pt;
            }
        """)
        
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        # ============================================================
        # Кнопки управления
        # ============================================================
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Обновить")
        refresh_btn.clicked.connect(self.refresh_data)
        
        export_btn = QPushButton("📊 Экспортировать отчёт")
        export_btn.clicked.connect(self.export_report)
        
        clear_btn = QPushButton("🗑️ Очистить данные")
        clear_btn.clicked.connect(self.clear_data)
        
        button_layout.addWidget(refresh_btn)
        button_layout.addWidget(export_btn)
        button_layout.addWidget(clear_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def refresh_data(self):
        """Обновить все данные"""
        self.update_statistics()
        self.update_top_wafes()
        self.update_evasion_stats()
        self.update_risk_assessment()
        self.update_details()
    
    def update_statistics(self):
        """Обновить основную статистику"""
        stats = self.waf_monitor.get_waf_statistics()
        
        self.total_detections_label.setText(f"Всего обнаружений: {stats['total_detections']}")
        self.unique_wafes_label.setText(f"Уникальных WAF: {stats['unique_wafes']}")
        self.avg_confidence_label.setText(f"Средняя уверенность: {stats['average_confidence'] * 100:.1f}%")
    
    def update_top_wafes(self):
        """Обновить таблицу ТОП WAF"""
        top_wafes = self.waf_monitor.get_top_wafes(5)
        
        self.top_wafes_table.setRowCount(len(top_wafes))
        
        for row, (waf_type, count) in enumerate(top_wafes):
            waf_item = QTableWidgetItem(waf_type)
            count_item = QTableWidgetItem(str(count))
            
            waf_item.setForeground(QColor("#2196F3"))
            count_item.setForeground(QColor("#FF9800"))
            
            self.top_wafes_table.setItem(row, 0, waf_item)
            self.top_wafes_table.setItem(row, 1, count_item)
    
    def update_evasion_stats(self):
        """Обновить статистику эvasion"""
        evasion_stats = self.waf_monitor.evasion_stats
        
        rows = len(evasion_stats)
        self.evasion_table.setRowCount(rows)
        
        for row, (waf_type, stats) in enumerate(evasion_stats.items()):
            waf_item = QTableWidgetItem(waf_type)
            total_item = QTableWidgetItem(str(stats['total_attempts']))
            success_item = QTableWidgetItem(str(stats['successful_evasions']))
            rate_item = QTableWidgetItem(f"{stats['success_rate']:.1f}%")
            
            #색상кодирование по успешности
            if stats['success_rate'] > 50:
                rate_item.setForeground(QColor("#4CAF50"))  # Green
            elif stats['success_rate'] > 20:
                rate_item.setForeground(QColor("#FF9800"))  # Orange
            else:
                rate_item.setForeground(QColor("#F44336"))  # Red
            
            self.evasion_table.setItem(row, 0, waf_item)
            self.evasion_table.setItem(row, 1, total_item)
            self.evasion_table.setItem(row, 2, success_item)
            self.evasion_table.setItem(row, 3, rate_item)
    
    def update_risk_assessment(self):
        """Обновить оценку риска"""
        risk = self.waf_analytics.get_risk_assessment()
        
        risk_score = risk['risk_score']
        risk_level = risk['risk_level']
        bypass_rate = risk['bypass_success_rate']
        
        self.risk_score_label.setText(f"Risk Score: {risk_score}/100")
        self.risk_level_label.setText(f"Risk Level: {risk_level}")
        self.bypass_rate_label.setText(f"Bypass Success: {bypass_rate:.1f}%")
        
        # Цвет по риску
        if risk_level == "CRITICAL":
            self.risk_level_label.setStyleSheet("color: #F44336;")  # Red
        elif risk_level == "HIGH":
            self.risk_level_label.setStyleSheet("color: #FF9800;")  # Orange
        elif risk_level == "MEDIUM":
            self.risk_level_label.setStyleSheet("color: #FFC107;")  # Yellow
        else:
            self.risk_level_label.setStyleSheet("color: #4CAF50;")  # Green
    
    def update_details(self):
        """Обновить детали последних обнаружений"""
        detections = self.waf_monitor.waf_detections[-10:]  # Последние 10
        
        details_text = "Последние обнаружения WAF:\n"
        details_text += "=" * 80 + "\n\n"
        
        for detection in reversed(detections):
            details_text += f"[{detection['timestamp']}] {detection['waf_type']}\n"
            details_text += f"  URL: {detection['url']}\n"
            details_text += f"  Confidence: {detection['confidence'] * 100:.1f}%\n"
            details_text += f"  Fingerprints: {detection['fingerprints_matched']}\n"
            details_text += "-" * 80 + "\n"
        
        self.details_text.setText(details_text)
    
    def export_report(self):
        """Экспортировать отчёт"""
        from pathlib import Path
        report_path = Path("exports") / f"waf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.parent.mkdir(exist_ok=True)
        
        try:
            self.waf_monitor.export_report(report_path)
            
            # Показать сообщение об успехе
            self.details_text.setText(
                f"✅ Отчёт успешно экспортирован:\n{report_path}\n\n"
                f"Статистика:\n{json.dumps(self.waf_monitor.get_waf_statistics(), indent=2, ensure_ascii=False)}"
            )
        except Exception as e:
            self.details_text.setText(f"❌ Ошибка экспорта: {e}")
    
    def clear_data(self):
        """Очистить данные"""
        self.waf_monitor.waf_detections.clear()
        self.waf_monitor.evasion_stats.clear()
        self.waf_monitor.waf_timeline.clear()
        
        self.details_text.setText("✅ Данные очищены")
        self.refresh_data()
