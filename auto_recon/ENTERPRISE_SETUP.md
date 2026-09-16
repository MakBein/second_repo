# xss_security_gui/auto_recon/ENTERPRISE_SETUP.md
# AutoRecon Enterprise V7 — Setup & Configuration Guide

## 📋 Содержание

1. [Общая архитектура](#архитектура)
2. [Установка и инициализация](#установка)
3. [Использование основных компонентов](#использование)
4. [Примеры](#примеры)
5. [Миграция с v6](#миграция)
6. [Troubleshooting](#troubleshooting)

---

## Архитектура

AutoRecon Enterprise V7 построен на следующих компонентах:

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator (главный)                   │
│  • Управляет всеми компонентами                             │
│  • Координирует сканирование → анализ → атаки               │
│  • Интегрирует логирование и метрики                        │
└──────────────────┬──────────────────────────────────────────┘
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
    ┌────────┐ ┌────────┐ ┌─────────┐
    │Scanner │ │Analyzer│ │Planner  │
    └───┬────┘ └───┬────┘ └────┬────┘
        │          │            │
        └──────────┼────────────┘
                   │
        ┌──────────┼──────────────────┐
        ▼          ▼                  ▼
    ┌────────┐ ┌──────────────┐ ┌──────────┐
    │ Logger │ │UserTracker   │ │Metrics   │
    │ (JSON) │ │(Sessions)    │ │(Stats)   │
    └────────┘ └──────────────┘ └──────────┘
                   │
                   ▼
            ┌─────────────────┐
            │ReportGenerator  │
            │(HTML/JSON/CSV)  │
            └─────────────────┘
```

## Установка

### 1. Проверка зависимостей

```bash
pip install -r requirements.txt
```

Необходимые пакеты:
- `requests` >= 2.28.0
- `beautifulsoup4` >= 4.11
- `pyjwt` >= 2.6
- `validators` >= 0.20

### 2. Инициализация директорий

```bash
mkdir -p logs/auto_recon/users
mkdir -p logs/auto_recon/metrics
mkdir -p logs/auto_recon/reports
mkdir -p logs/auto_recon/xss
```

### 3. Проверка конфигурации

```python
from xss_security_gui.auto_recon import get_user_context, get_logger

ctx = get_user_context()
print(f"User: {ctx.user_id}")
print(f"Session: {ctx.session_id}")
print(f"IP: {ctx.ip_address}")

logger = get_logger("Test")
logger.info("✅ AutoRecon initialized successfully")
```

---

## Использование

### Простое сканирование

```python
from xss_security_gui.auto_recon import run_full_autorecon

# Один URL
report = run_full_autorecon("https://example.com")

# Несколько URL
report = run_full_autorecon([
    "https://example1.com",
    "https://example2.com"
])

# Вывод результатов
print(f"Уязвимостей найдено: {report['vulnerability_report']['metadata']['total_vulnerabilities']}")
print(f"Риск-скор: {report['detailed_analysis']['risk_assessment']['overall_score']}")
```

### Агрессивное сканирование

```python
from xss_security_gui.auto_recon import run_aggressive_scan

report = run_aggressive_scan("https://target.com")
# Использует: 10 workers, 100 payloads, aggressive=True
```

### С callback для прогресса

```python
def progress_handler(msg):
    stage = msg.get("stage")
    status = msg.get("status")
    details = msg.get("details", {})
    
    if stage == "SCANNING":
        print(f"🔍 Сканирование: {status}")
    elif stage == "ANALYZING":
        print(f"📊 Анализ: {status}")
    elif stage == "ATTACKING":
        print(f"⚔️ Атаки: {status}")
    elif stage == "REPORTING":
        print(f"📝 Отчёт: {status}")

report = run_full_autorecon(
    "https://example.com",
    config={
        "aggressive": False,
        "max_workers": 5,
        "export_html": True,
        "export_json": True,
    },
    callback=progress_handler
)
```

### Использование логгера

```python
from xss_security_gui.auto_recon import get_logger

logger = get_logger("MyModule")

# Базовое логирование
logger.info("Операция начата", tags={"operation": "scan"})
logger.warning("Возможно медленно", target="https://slow.com")
logger.error("Ошибка подключения", exception_type="TimeoutError")

# Логирование успеха
logger.success("✅ Сканирование завершено", items=150)

# Аудит
logger.audit(
    "Пользователь запустил сканирование",
    user_id="admin",
    action="scan_start",
    target="https://example.com"
)

# Загрузка после сканирования
recent_events = logger.get_events(limit=20)
logger.save_events_snapshot()
```

### Отслеживание пользователя

```python
from xss_security_gui.auto_recon import (
    get_user_tracker, 
    get_user_context
)

# Контекст текущего пользователя
ctx = get_user_context()
print(f"User: {ctx.user_id}")
print(f"Hostname: {ctx.hostname}")
print(f"Session: {ctx.session_id}")
print(f"IP: {ctx.ip_address}")

# Tracker для операций
tracker = get_user_tracker()

# Отслеживание операции
tracker.track_operation(
    "custom_scan",
    details={"targets": ["https://example.com"]},
    target="https://example.com",
    status="started"
)

# Отслеживание уязвимости
tracker.track_vulnerability_found(
    vuln_type="XSS",
    url="https://example.com/search",
    severity="high",
    payload="<img src=x onerror=alert(1)>",
    details={"context": "🔤 Reflected HTML"}
)

# Скачивание сессионного отчёта
session_report_path = tracker.save_session_report()
```

### Сбор метрик

```python
from xss_security_gui.auto_recon import get_metrics_collector

metrics = get_metrics_collector()

# Начать отслеживание операции
op_id = metrics.start_operation(
    "test_endpoints",
    tags={"target": "https://example.com"}
)

# ... выполнить работу ...

# Завершить операцию
result = metrics.finish_operation(
    op_id,
    success=True,
    items_processed=50
)

# Просмотреть результат
print(f"Duration: {result['duration_seconds']}s")
print(f"Throughput: {result['throughput_items_per_sec']} items/sec")
print(f"Success rate: {result['success_rate_percent']}%")

# Получить итоговую сводку
summary = metrics.get_summary()
print(f"Total operations: {summary['total_operations']}")
print(f"Success rate: {summary['success_rate_percent']}%")

# Сохранить и экспортировать
metrics.save_summary()
metrics.export_metrics_csv()
```

### Генерация отчётов

```python
from xss_security_gui.auto_recon import get_report_generator

reporter = get_report_generator()

# Отчёт по сканированию
scan_report = reporter.generate_scan_report(
    scan_results=results,
    scan_name="Target Scan",
    targets=["https://example.com"]
)

# Отчёт об уязвимостях
vuln_report = reporter.generate_vulnerability_report(
    vulnerabilities=vulnerabilities,
    target="https://example.com"
)

# Детальный анализ
analysis = reporter.generate_detailed_analysis(
    endpoints=endpoints,
    analysis_results=analysis_results,
    user_context={"user_id": "admin"}
)

# Сохранение отчётов
json_path = reporter.save_report(scan_report, "scan_report.json")
html_path = reporter.generate_html_report(scan_report, "scan_report.html")

print(f"JSON: {json_path}")
print(f"HTML: {html_path}")
```

---

## Примеры

### Example 1: Полное сканирование с progress tracking

```python
from xss_security_gui.auto_recon import run_full_autorecon

def on_progress(msg):
    print(f"[{msg['stage']}] {msg['status']}")

targets = ["https://dvwa.local", "https://metavillain.local"]

report = run_full_autorecon(
    targets,
    config={
        "aggressive": True,
        "max_workers": 10,
        "max_payloads": 100,
        "export_html": True,
        "export_json": True,
    },
    callback=on_progress
)

# Анализ результатов
print(f"\n📊 Results Summary:")
summary = report['threat_summary']
for key, value in summary.items():
    print(f"  {key}: {value}")
```

### Example 2: Мониторинг сессии пользователя

```python
from xss_security_gui.auto_recon import (
    get_user_tracker,
    get_logger
)

logger = get_logger("SessionMonitor")
tracker = get_user_tracker()

# Отслеживание всех операций пользователя
logger.audit(
    "Session started",
    user_id=tracker.context.user_id,
    action="session_start",
)

# ... выполнение операций ...

# Сохранение итогового отчёта сsessии
report_path = tracker.save_session_report()
logger.info(f"Session report saved: {report_path}")

# Загрузка истории пользователя
history = tracker.load_user_history(limit=100)
print(f"User performed {len(history)} operations")
```

### Example 3: Интеграция с GUI

```python
import tkinter as tk
from threading import Thread
from xss_security_gui.auto_recon import run_aggressive_scan

def run_scan_in_background():
    def progress_callback(msg):
        # Обновление GUI из другого потока
        root.after(0, lambda: update_gui(msg))

    def update_gui(msg):
        stage = msg.get("stage")
        status = msg.get("status")
        log.insert(tk.END, f"[{stage}] {status}\n")
        log.see(tk.END)

    report = run_aggressive_scan(
        "https://target.com",
        callback=progress_callback
    )

    # После завершения
    root.after(0, lambda: scan_complete(report))

def scan_complete(report):
    vuln_count = report['vulnerability_report']['metadata']['total_vulnerabilities']
    risk_score = report['detailed_analysis']['risk_assessment']['overall_score']
    
    log.insert(tk.END, f"\n✅ Scan complete!\n")
    log.insert(tk.END, f"Vulnerabilities: {vuln_count}\n")
    log.insert(tk.END, f"Risk Score: {risk_score}\n")

root = tk.Tk()
root.title("AutoRecon Scanner")

log = tk.Text(root, height=20, width=60)
log.pack()

scan_btn = tk.Button(
    root,
    text="Start Scan",
    command=lambda: Thread(target=run_scan_in_background, daemon=True).start()
)
scan_btn.pack()

root.mainloop()
```

---

## Миграция с v6

### Изменения в API

| v6 | v7 |
|----|-----|
| `run_full_autorecon()` | `run_full_autorecon_enterprise()` |
| - | `run_aggressive_scan()` |
| - | Enterprise logging |
| - | User tracking |
| - | Metrics collection |
| - | Advanced reporting |

### Код миграции

```python
# v6
from xss_security_gui.auto_recon import run_full_autorecon as v6_run

# v7
from xss_security_gui.auto_recon import run_full_autorecon_enterprise

# Использование одинаково с улучшениями
report = run_full_autorecon_enterprise("https://example.com")
```

---

## Troubleshooting

### Проблема: Медленное сканирование

**Решение:**
```python
report = run_full_autorecon(
    target,
    config={
        "max_workers": 20,  # Увеличить workers
        "timeout": 5,       # Уменьшить timeout
        "max_payloads": 30, # Уменьшить payloads
    }
)
```

### Проблема: Out of Memory

**Решение:**
```python
# Использовать пакетное сканирование
targets = ["https://example1.com", "https://example2.com"]
for target in targets:
    report = run_full_autorecon(target)
    # Обработать результат и очистить память
    del report
```

### Проблема: SSL/TLS ошибки

**Решение:**
```python
import requests
import urllib3

# Отключить предупреждения (для тестирования)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Использование без проверки SSL
requests.packages.urllib3.disable_warnings()
```

---

## Поддержка

- 📖 Документация: https://docs.autorecon.local
- 🐛 Issues: issues@autorecon.local
- 💬 Community: community@autorecon.local

