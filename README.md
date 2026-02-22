
# 🕵️‍♂️ XSS Security GUI

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-informational)
![Status](https://img.shields.io/badge/status-in%20development-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

## 📌 Описание

**XSS Security GUI** — это очень мощный инструмент: GUI‑обёртка над XSStrike + собственный краулер + DOM‑анализатор + 
авто-атаки с графическим интерфейсом для анализа потенциальных XSS-уязвимостей,
мониторинга ловушек (honeypots), управления полезными нагрузками и экспорта результатов. 
Подходит для специалистов по безопасности, исследователей и тестировщиков.

---

## 🚀 Возможности

- 💣 Генерация и обфускация XSS-пейлоадов
- 📥 Импорт разведданных из логов api_attack.log, crawler_results.json
- 📊 Обнаружение API, токенов, user IDs, параметров
- 🔍 Deep Crawl / Deep Scanner — краулинг и поиск форм
- 🔓 IDOR и 📂 LFI тестирование
- 🛰️ Honeypot ловушка и мониторинг событий
- 📁 Живые логи и генерация отчетов (TXT / PDF)
- 🛠️ GUI JSON-редактор настроек и базы атак

🧱 Структура проекта xss_security_gui

xss_security_gui/
├── assets/                          # Статические ресурсы (иконки, изображения)
│
├── auto_recon/                      # Автоматизированное сканирование
│   ├── assets/
│   ├── configs/
│   │   ├── targets.txt              # Список целей для сканирования
│   │   └── presets.json             # Пресеты атак
│   ├── logs/
│   │   └── init.log                 # Лог запуска авто-сканера
│   ├── resources/
│   ├── analyzer.py                  # Анализ ответов (XSS, CSRF, SQLi)
│   ├── scanner.py                   # Сканирование форм, API, XHR
│   ├── payloads.py                  # Генератор XSS/JSON пейлоадов
│   ├── planner.py                   # Планировщик атак
│   ├── recon_pipeline.py            # Конвейер сбора токенов и целей
│   ├── gui_elements.py              # GUI-компоненты (панели, кнопки)
│   ├── xss_flooder.py               # Массовая отправка XSS-пейлоадов
│   ├── test_recon.py                # 🧪 Unit-тесты авто-сканера
│   └── __init__.py
│
├── configs/
│   ├── default_config.json          # Основные настройки по умолчанию
│   └── targets.txt                  # Список целей для анализа
│
├── docs/                            # Документация
│   ├── 00_overview.md               # 📊 Общее описание и архитектура
│   ├── 01_setup.md                  # ⚙️ Установка и запуск
│   ├── 02_modules.md                # 🔍 Описание модулей
│   ├── 03_usage.md                  # 🛠️ Использование GUI
│   ├── 04_examples.md               # 💣 Примеры атак
│   ├── 05_json_format.md            # 📁 Форматы JSON-логов
│   ├── 06_honeypot.md               # 🎣 Honeypot-ловушка
│   ├── 07_logs.md                   # 📥 Работа с логами
│   ├── 08_report.md                 # 📄 Генерация отчётов
│   ├── 09_api_parser.md             # 📡 Парсинг API-логов
│   └── 10_dev_notes.md              # 🧠 Заметки разработчиков
│
├── exports/                         # Экспортированные отчёты (игнорируются в .gitignore)
│   ├── json/
│   └── reports/
│
├── gui/                             # Графический интерфейс
│   ├── attack_gui.py                # Основное GUI для атак
│   ├── autorecon_dashboard.py       # Панель авто-сканера
│   ├── autorecon_dashboard_tab.py   # Вкладка авто-сканера
│   ├── mutator_tasks_panel.py       # Панель мутаций пейлоадов
│   ├── xss_context_map.py           # Карта контекста XSS
│   └── xss_log_viewer.py            # Просмотр логов XSS
│
├── logs/                            # Логи и результаты атак (игнорируются в .gitignore)
│   ├── api_attack.log               # Лог API-атак
│   ├── api_attack_history.json      # История API-атак
│   ├── crawler_results.json         # Результаты краулера
│   ├── crawler_errors.log           # Ошибки краулера
│   ├── crawler_links.log            # Ссылки, найденные краулером
│   ├── deep_analysis_export.txt     # Расширенный анализ
│   ├── dom_attack.log               # Лог DOM-атак
│   ├── attack_plan.json             # План атак
│   ├── attack_logs.md               # Markdown-лог атак
│   ├── idor_report.md               # Отчёт IDOR
│   ├── idor_test_results.json       # Результаты IDOR-тестов
│   ├── csrf_report.log              # Лог CSRF-тестов
│   ├── sqli_report.log              # Лог SQLi-тестов
│   ├── honeypot.log                 # Лог honeypot-событий
│   └── ...
│
├── payloads/                        # Библиотека пейлоадов
│   ├── payload_db.json              # База XSS-пейлоадов
│   ├── sqli.json                    # База SQLi-пейлоадов
│   └── xss.txt                      # Текстовые XSS-пейлоады
│
├── resources/                       # Дополнительные ресурсы
│   ├── rules.json                   # Правила анализа
│   └── xss_payload_db.json          # База XSS-пейлоадов
│
├── tests/                           # Тесты
│   └── test_gui/
│       ├── test_deep_scanner_tab.py # Тест GUI-вкладки Deep Scanner
│       ├── test_exploit_tab.py      # Тест GUI-вкладки Exploit
│       └── test_form_fuzzer_tab.py  # Тест GUI-вкладки Form Fuzzer
│
├── threat_analysis/                 # Модули анализа угроз
│   ├── engine.py                    # Центральный запуск анализов
│   ├── cookie_tracer.py             # Трассировка утечек cookie
│   ├── csp_module.py                # Анализ CSP-политик
│   ├── csrf_analyzer.py             # Анализ CSRF-токенов
│   ├── csrf_module.py               # Модуль CSRF
│   ├── dom_events_module.py         # Анализ DOM-событий
│   ├── dom_xss_detector.py          # Обнаружение DOM-XSS
│   ├── sqli_module.py               # Анализ SQL Injection
│   ├── ssrf_module.py               # Анализ SSRF
│   ├── xss_module.py                # Анализ XSS
│   └── threat_connector.py          # Связка модулей угроз
│
├── utils/                           # Утилиты
│   ├── core_utils.py                # Основные утилиты
│   ├── disable_ssl_warnings.py      # Отключение SSL-предупреждений
│   ├── jwt_decoder.py               # Декодер JWT
│   ├── network.py                   # Сетевые утилиты
│   └── threat_sender.py             # Отправка данных угроз
│
├── __init__.py
├── main.py                # 🎛️ Точка входа и инициализация GUI
├── requirements.txt       # 📦 Зависимости Python
├── README.md              # 📘 Описание проекта
├── .env                   # 🧠 Application Profile (auto-detected if not set)
├── api_parser.py          # 📥 Парсинг логов из `api_attack.log`
├── attack_launcher.py
├── attack_report_tab.py
├── autoanalyzer_tab.py 
├── analyzer.py            # 🕷️ Основной анализатор XSS + CSRF + SQLi
├── batch_report_tab.py    # 📄 Генерация отчётов
├── batch_scan.py
├── config.json
├── config.py
├── crawler.py             # 🛰️ Поиск форм, JS и ссылок
├── crawler_plus.py
├── dom_parser.py
├── deep_crawler.py
├── deep_scanner_tab.py    # 📡 Глубокое сканирование сайта
├── deep_analysis_tab.py   # 🧬 Расширенный краулер и анализ
├── debug_project.py
├── exploit_tab.py         # 💥 GUI-вкладка атак Exploit + генератор обходов
├── env_check.py           # Модуль Environment Check
├── export_tools.py        # 📄 Экспорт логов в TXT / PDF
├── full_analysis_tab.py
├── form_fuzzer.py
├── form_fuzzer_tab.py     # 🧪 Тестирование форм
├── gui_state.json         # 🧠 Сохранённое состояние интерфейса
├── honeypot_server.py     # 🎣 Сервер ловушки Honeypot
├── honeypot_monitor.py    # 🔍 Монитор Honeypot событий
├── idor_tester.py         # 🔓 Тестер IDOR
├── idor_tab.py            # 🔓 GUI: IDOR анализ
├── js_inspector.py
├── json_result_table.py
├── lfi_tab.py             # 📂 GUI: LFI анализ
├── lfi_tester.py
├── live_log_tab.py        # 📶 Потоковые события
├── mutator.py             # 🧪 Генератор обфускации и мутаций
├── overview_tab.py        # 📊 Обзор разведданных
├── param_fuzzer.py        # 💥 Фуззинг параметров URL
├── payloads.py            # 🧬 База кастомных XSS-пейлоадов
├── payload_generator.py   # 🎯 Генератор XSS/API/IDOR + variants()
├── settings.py            # ⚙️ Основные переменные конфигурации
├── settings.json          # 📁 GUI-настройки в формате JSON
├── settings_editor.py     # 🛠️ JSON-редактор GUI
├── settings_gui.py        # ⚙️ GUI-вкладка настроек
├── site_map_tab.py        # 🗺️ Визуализация карты сайта
├── sandbox_detector.py
├── site_decomposer.py
├── svg_viewer.py
├── threat_tab.py 
├── token_generator.py     # 🎯 Генератор ловушек и автоотправка
├── token_view_tab.py
├── trap_engine.py
├── visualizer.py          # Визуализация результатов
├── xss_attacker.py
├── xss_detector.py
├── csrf_tab.py                # 🔐 GUI-вкладка CSRF анализа, инструментом для быстрой диагностики проекта.
├── sqli_tab.py                # 💉 GUI-вкладка SQLi анализа
├── network_checker.py         # NetworkChecker ULTRA 6.1. Встроенные сетевые проверки для XSS Security Suite
├── debug_project.py           # 🔐 GUI-вкладка инструмент для быстрой диагностики проекта.

📘 Документация :

В папке docs/ находяться примеры отчётов, схемы атак, и инструкции по созданию кастомных пейлоадов 🧠📁📘


⚙️ Установка и запуск

```bash
git clone https://github.com/MakBein/second_repo.git
cd xss_security_gui

python -m venv .venv
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate      # Windows

pip install -r requirements.txt
python main.py

Пример запуска only GUI:
python -m xss_security_gui.main

Пример запуска краулера CLI&GUI:
python -m xss_security_gui.main crawl https://gazprombank.ru

Пример запуска краулера в режиме only CLI:
python -m xss_security_gui.cli crawl https://gazprombank.ru
python -m xss_security_gui.main_cli js file.js
python -m xss_security_gui.main_cli recon https://gazprombank.ru




📂 4. Выходные артефакты
| Файл | Назначение | 
| logs/crawler_results.json | Полный JSON с данными по всем страницам | 
| logs/crawl_graph.dot | Исходник карты сайта | 
| logs/crawl_graph.svg | Визуализация дерева сайта | 
| logs/form_fuzz_hits.log | Успешные XSS-инъекции в формы | 
| logs/crawler_structure.log | Деревовидный текстовый отчёт | 
| logs/api_attack.log | Сырой лог атак |
| logs/sqli_report.log | Лог SQLi атак |
| logs/csrf_report.log | Лог CSRF токенов |
| logs/honeypot.log | События honeypot‑ловушки |

🤝 Вклад

Pull requests приветствуются! Предлагай свои идеи, фикс ошибки или добавляй новые фичи.
