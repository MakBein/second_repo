
# 🕵️‍♂️ XSS Security GUI

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-informational)
![Status](https://img.shields.io/badge/status-in%20development-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

[//]: # (📌 Описание)

[//]: # (XSS Security GUI 6.5 &#40;Sidebar Edition&#41; — это комплексная платформа для анализа веб‑безопасности, объединяющая:)

[//]: # ()
[//]: # (расширенный XSS‑анализатор &#40;на базе XSStrike + собственные модули&#41;)

[//]: # ()
[//]: # (Deep Crawl 5.0 &#40;полноценный краулер с DOM‑анализом&#41;)

[//]: # ()
[//]: # (AutoRecon 6.0 &#40;автоматический сбор токенов, API, параметров и точек атаки&#41;)

[//]: # ()
[//]: # (AI‑ядро &#40;synthetic XSS, feature extraction, risk engine, NN‑модель&#41;)

[//]: # ()
[//]: # (GUI‑панель атак &#40;PyQt&#41;)

[//]: # ()
[//]: # (Honeypot‑ловушку с live‑мониторингом)

[//]: # ()
[//]: # (SQLi / CSRF / SSRF / IDOR / LFI тестирование)

[//]: # ()
[//]: # (визуализацию, отчёты, экспорт и Threat Intel интеграцию)

[//]: # ()
[//]: # (Это не просто GUI‑обёртка — это полноценный security‑suite, объединяющий разведку, анализ, фуззинг, 

[//]: # (машинное обучение и автоматизацию атак в одном приложении.&#41;)

[//]: # ()
[//]: # (Инструмент подходит для:)

[//]: # ()
[//]: # (специалистов по безопасности)

[//]: # ()
[//]: # (пентестеров)

[//]: # ()
[//]: # (исследователей)

[//]: # ()
[//]: # (разработчиков, проверяющих свои приложения)

[//]: # ()
[//]: # (bug bounty охотников)

[//]: # ()
[//]: # (студентов и энтузиастов)

[//]: # ()
[//]: # (⭐ Что делает XSS Security GUI уникальным?)

[//]: # (🔥 1. Sidebar‑архитектура &#40;Burp Suite style&#41;)

[//]: # (Полностью переработанный интерфейс:)

[//]: # ()
[//]: # (группы вкладок)

[//]: # ()
[//]: # (мгновенная навигация)

[//]: # ()
[//]: # (независимые панели)

[//]: # ()
[//]: # (отсутствие Notebook‑ограничений)

[//]: # ()
[//]: # (чистый, современный UX)

[//]: # ()
[//]: # (🧬 2. Deep Crawl 5.0)

[//]: # (Собственный краулер:)

[//]: # ()
[//]: # (анализ DOM)

[//]: # ()
[//]: # (поиск форм)

[//]: # ()
[//]: # (поиск XHR / fetch)

[//]: # ()
[//]: # (извлечение токенов)

[//]: # ()
[//]: # (карта сайта)

[//]: # ()
[//]: # (экспорт результатов)

[//]: # ()
[//]: # (интеграция с Threat Intel)

[//]: # ()
[//]: # (🧠 3. AI‑ядро &#40;ai_core/&#41;)

[//]: # (Включает:)

[//]: # ()
[//]: # (synthetic XSS generator)

[//]: # ()
[//]: # (feature extractor)

[//]: # ()
[//]: # (risk engine)

[//]: # ()
[//]: # (NN‑модель &#40;joblib&#41;)

[//]: # ()
[//]: # (training pipeline)

[//]: # ()
[//]: # (AI Verdict Tab)

[//]: # ()
[//]: # (AI Training Tab)

[//]: # ()
[//]: # (🛰️ 4. AutoRecon 6.0)

[//]: # (Автоматический сбор разведданных:)

[//]: # ()
[//]: # (токены)

[//]: # ()
[//]: # (параметры)

[//]: # ()
[//]: # (API endpoints)

[//]: # ()
[//]: # (cookies)

[//]: # ()
[//]: # (потенциальные точки атаки)

[//]: # ()
[//]: # (генерация attack plan)

[//]: # ()
[//]: # (AutoRecon Dashboard)

[//]: # ()
[//]: # (💣 5. Модули атак)

[//]: # (Включают:)

[//]: # ()
[//]: # (XSS)

[//]: # ()
[//]: # (SQLi)

[//]: # ()
[//]: # (CSRF)

[//]: # ()
[//]: # (SSRF)

[//]: # ()
[//]: # (IDOR)

[//]: # ()
[//]: # (LFI)

[//]: # ()
[//]: # (Exploit Generator)

[//]: # ()
[//]: # (Form Fuzzer)

[//]: # ()
[//]: # (Param Fuzzer)

[//]: # ()
[//]: # (🎣 6. Honeypot‑ловушка)

[//]: # (Встроенный Flask‑сервер:)

[//]: # ()
[//]: # (принимает атаки)

[//]: # ()
[//]: # (логирует события)

[//]: # ()
[//]: # (отображает в реальном времени)

[//]: # ()
[//]: # (интегрируется с Threat Intel)

[//]: # ()
[//]: # (📁 7. Логи и отчёты)

[//]: # (Поддерживает:)

[//]: # ()
[//]: # (TXT)

[//]: # ()
[//]: # (PDF)

[//]: # ()
[//]: # (JSON)

[//]: # ()
[//]: # (Markdown)

[//]: # ()
[//]: # (Graphviz визуализацию)

[//]: # ()
[//]: # (🎛️ 8. Attack GUI &#40;PyQt&#41;)

[//]: # (Отдельное окно для:)

[//]: # ()
[//]: # (запуска атак)

[//]: # ()
[//]: # (управления payload‑ами)

[//]: # ()
[//]: # (анализа ответов)

[//]: # ()
[//]: # (визуализации контекста)

[//]: # ()
[//]: # (⭐ Краткое резюме)

[//]: # (XSS Security GUI 6.5 — это:)

[//]: # ()
[//]: # (✔ мощный инструмент для анализа веб‑уязвимостей)

[//]: # (✔ современный GUI в стиле Burp Suite)

[//]: # (✔ глубокая автоматизация &#40;краулер, авторазведка, фуззинг&#41;)

[//]: # (✔ интеграция с AI‑ядром)

[//]: # (✔ honeypot‑ловушка)

[//]: # (✔ экспорт отчётов)

[//]: # (✔ удобная работа с логами)

[//]: # (✔ расширяемая архитектура)

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
│
├── ai_core/                     # AI‑ядро
│   ├── __init__.py
│   ├── features.py              # Построение фич
│   ├── py_features.py
│   ├── synthetic_xss.py         # Генератор синтетических XSS
│   ├── risk_engine.py           # Оценка рисков
│   ├── py_risk_engine.py
│   ├── llm_client.py            # LLM‑клиен (опционно)
│   ├── ml_model.py              # Обвертка ML‑модели
│   ├── nn_model.py              # Загрузка NN‑модели
│   ├── project_analyzer.py
│   ├── worker.py                # Асинхронний AI‑воркер
│   └── model_store/
│       ├── nn_model_trained.joblib
│       ├── training_report.json
│       └── README.md
│
├── tabs/                        # Вкладки Sidebar GUI
│   ├── ai_training_tab.py
│   ├── ai_verdict_tab.py
│   └── __init__.py
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

🖥️ Запуск
GUI (Sidebar Edition):
python -m xss_security_gui.main tk

Пример запуска краулера Deep Crawl CLI&GUI:
python -m xss_security_gui.main crawl https://target.com

Attack GUI (PyQt):
python -m xss_security_gui.main gui https://target.com


Пример запуска краулера в режиме only CLI:
python -m xss_security_gui.cli crawl <url>
python -m xss_security_gui.main_cli js file.js
python -m xss_security_gui.main_cli recon <url>


📄 Експорт отчетов:
exports/reports/report.txt
exports/reports/report.pdf

🧪 Тести:
pytest tests/

🗺️ Roadmap (v7.0)
[ ] Collapsible Sidebar Groups

[ ] Burp Suite Dark Theme

[ ] AI‑Driven Payload Mutator

[ ] AutoRecon v7 (LLM‑powered)

[ ] Full WebSocket Scanner

[ ] Plugin System

[ ] Cloud Sync



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
