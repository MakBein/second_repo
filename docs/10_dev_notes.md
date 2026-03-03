# xss_security_gui/deep_crawler.py >>> analyze_csp :
# Что означает csp_risk_level
# | "none" | CSP отсутствует — сайт уязвим к XSS
# | "weak" | unsafe-inlineunsafe-eval | CSP есть, но содержит unsafe-inline или unsafe-eval — частичная защита
# | "moderate"| CSP есть, но без nonce/strict-dynamic — базовая защита
# | "strong" |  CSP использует nonce или strict-dynamic — хорошая защита от XSS

Алгоритм роботи з новими змінами
Коли ти ще раз відредагуєш файл, дії будуть такі:
# Перейди у корінь проекту
cd C:\Users\sanch\PycharmProjects\itproger

# Перевір статус, щоб побачити змінені файли
git status

# Онови інформацію про віддалений репозиторій:
git fetch origin

# Перевір локальні коміти:
git log --oneline --decorate --graph --all

# Додай конкретний файл у staging
git add xss_security_gui/analyzer.py

# Якщо хочеш додати всі зміни у проекті:
# git add .

# Зроби коміт із повідомленням
git commit -m "Refactor analyzer.py: додано нові модулі та виправлено помилки"

# Відправ коміт у віддалений репозиторій (гілка main)
git push origin main

Після цього зміни з’являться у твоєму GitHub‑репозиторії.

# Отже, твій коміт уже на GitHub у гілці main.
# Перевірити можна командою:
git log origin/main --oneline

###############################################################
# cd C:\Users\sanch\PycharmProjects\itproger\xss_security_gui
# показует все файлы проекта dir -Recurse
##############################################################
Следующий шаг
Теперь можешь запустить краулер:

python -m xss_security_gui.main crawl https://gazprombank.ru

Отлично, Aleksandr — я собрал для тебя боевые версии конфигураций:
settings.prod.json (боевой режим) 
settings.ci.json (режим CI/CD), 
полностью совместимые с твоим валидатором и архитектурой ULTRA‑6.5.
Эти профили можно просто положить в configs/ и переключать через:
APP_PROFILE=prod
APP_PROFILE=ci

или через .env.
################################################################
#Потому что теперь "pages" — это список, а не словарь "raw"
#PAYLOAD_CATEGORIES: List[str] список
#PAYLOAD_CATEGORIES = {"Reflected": [...], } словарь
###############################################################

XSStrike работает корректно, но URL у тебя экранирован
Ты отправляешь:
?q=lt;scriptgt;alert(1)lt;/scriptgt;


Это HTML‑escaped, а не реальный XSS‑пейлоад.
Правильный должен быть:
?q=<script>alert(1)</script>


XSStrike видит экранированные lt; и gt; → значит сайт уже фильтрует ввод, и отражения нет.

############################################################################################

AttributeError: 'str' object has no attribute 'copy'

###########################################################################################
Что это значит для твоего проекта
• 	Сейчас у тебя всё на  и обычных функциях.
Это полностью совместимо с твоим AttackEngine и GUI.
• 	Асинхронная версия ( + ) даёт прирост скорости за счёт параллельных запросов, но требует:
• 	запускать через 
• 	переписать все вызовы модулей на 
• 	адаптировать AttackEngine и GUI под асинхронность
Если ты этого не хочешь — лучше собрать финальный  в синхронном стиле.
###########################################################################################

# auto-py-to-exe - команда запуска компилятора питона в терминале




# xss_security_gui/dom_parser.py
🧩 Схема применения методов DOMParser

crawl_site() → DOMParser → ThreatEngine / Threat Intel → вывод в GUI

GUI (XSSAnalyzerApp)
   └── Кнопки (build_ui)
         ├── 🕸️ Краулер → run_crawler() → crawl_site() → DOMParser.extract_all()
         │                                      │
         │                                      └── ThreatEngine + Threat Intel
         ├── 📎 Атаковать DOM-векторы → использует результаты DOMParser
         ├── 🧪 Фуззинг → run_fuzzing()
         ├── 🔁 Мутатор → run_mutator()
         ├── 📤 Автоатака → run_auto_attack()
         └── Экспорт / Логи

🔐 Методы для XSS и безопасности
- extract_forms() → формы, поля, события → потенциальные точки инъекции.
- extract_iframes() → sandbox и src → обход изоляции, clickjacking.
- extract_dom_events() → onerror, onload, onclick → прямые XSS‑триггеры.
- extract_scripts() → inline/внешние JS → поиск опасных функций.
- extract_inline_js() → чистый JS‑код → анализ eval, document.write.
- extract_inline_styles() → CSS‑выражения → CSS‑XSS (expression(), url(javascript:)).
- extract_media() → img, video, audio → XSS через onerror.
- extract_data_attributes() → data-* → скрытые данные, часто источник DOM‑XSS.
- extract_svg() → inline‑SVG → XSS через <script> внутри SVG.
- extract_csp_meta() → CSP‑политики → оценка защиты от XSS.

📈 Методы для SEO и контента
- extract_meta_tags() → name, property, content → SEO, OpenGraph, Twitter Cards.
- extract_links() → все <a> → структура ссылок, перелинковка.
- extract_base_tag() → <base href> → влияет на SEO и относительные ссылки.
- extract_styles() → CSS → проверка inline‑стилей и внешних стилей.
- extract_noscript() → контент для поисковиков без JS.
- extract_comments() → скрытые заметки разработчиков, иногда ключи/данные.

🛡 Методы для Threat Intel
- extract_forms() → точки атаки → Threat Intel артефакты.
- extract_iframes() → внешние ресурсы → индикаторы угроз.
- extract_scripts() / extract_inline_js() → JS‑функции → сигнатуры эксплойтов.
- extract_data_attributes() → скрытые токены → утечки.
- extract_aria_attributes() → доступность → иногда маскировка вредоносных элементов.
- extract_svg() → подозрительные SVG → индикаторы.
- extract_media() → внешние ресурсы → трекинг/эксфильтрация.
- extract_csp_meta() → политика безопасности → оценка зрелости защиты.

🧱 Методы для структурного аудита
- extract_tables() → данные в таблицах → структурный анализ.
- extract_comments() → скрытые подсказки → архитектурный аудит.
- extract_aria_attributes() → доступность → UX и compliance.
- extract_base_tag() → структура ссылок → архитектура сайта.

📊 Визуальная схема (таблица)
|  |  | 
|  |  | 
|  |  | 
|  |  | 
|  |  | 



Таким образом, твой DOMParser стал универсальным инструментом:
- для XSS‑анализа он охватывает все потенциальные точки инъекции,
- для SEO — все ключевые теги,
- для Threat Intel — все артефакты,
- для структурного аудита — архитектурные элементы.

#================================================================

Хорошо, давай соберём пошаговый рабочий сценарий использования твоего обновлённого GUI с DOMParser. Это будет последовательность действий, которую ты можешь реально выполнить в проекте.

🧩 Пример рабочего сценария
1. Запуск приложения
- Запускаешь main.py → открывается окно XSS Security GUI.
- В поле 🎯 URL / Payload вводишь адрес сайта, например:
https://testphp.vulnweb.com/

2. Краулинг сайта
- Нажимаешь кнопку 🕸️ Краулер.
- Краулер проходит страницу, сохраняет артефакты в JSON и выводит:
- найденные формы
- ссылки
- скрипты
- В этот момент DOMParser.extract_all() уже работает внутри краулера и собирает структуру.

3. Полный DOM‑анализ
- После краулера жмёшь кнопку 📜 Анализ DOM.
- В output_box появится полный отчёт:
{
  "forms": [...],
  "iframes": [...],
  "meta_tags": [...],
  "dom_events": [...],
  "scripts": [...],
  "links": [...],
  "styles": [...],
  "comments": [...],
  "noscript": [...],
  "csp_meta": [...],
  "base_tag": {...},
  "data_attributes": [...],
  "aria_attributes": [...],
  "svg": [...],
  "tables": [...],
  "media": [...],
  "inline_styles": [...]
}


4. Проверка XSS‑векторов
- Жмёшь кнопку ⚠️ Проверка XSS‑векторов.
- В окне выводятся:
- все onerror, onload, onclick события
- inline‑JS куски
- inline‑CSS стили
- Это даёт быстрый список потенциальных точек атаки.

5. Анализ ссылок
- Жмёшь кнопку 🔗 Анализ ссылок.
- Видишь список всех <a href> и их текстов.
- Если есть <base href>, он тоже выводится.

6. Анализ стилей
- Жмёшь кнопку 🎨 Анализ стилей.
- Получаешь список inline‑CSS и подключённых стилей.

7. Анализ медиа
- Жмёшь кнопку 🖼️ Анализ медиа.
- Видишь все изображения, видео, аудио с их атрибутами.
- Можно сразу заметить подозрительные img src без alt или с onerror.

8. Атрибуты Data/ARIA
- Жмёшь кнопку 🧩 Атрибуты Data/ARIA.
- Получаешь список всех data-* и aria-* атрибутов.
- Это помогает найти скрытые данные или элементы доступности.

9. Скрытый контент
- Жмёшь кнопку 📝 Комментарии/NoScript.
- Видишь все HTML‑комментарии и содержимое <noscript>.
- Иногда там бывают подсказки разработчиков или скрытые данные.

10. Таблицы и SVG
- Жмёшь кнопку 📊 Таблицы и SVG.
- Получаешь список таблиц с их строками и inline‑SVG.
- SVG часто используется для XSS, поэтому это важный анализ.

🎯 Итог
В этом сценарии ты:
- Запустил краулер.
- Получил полный DOM‑анализ.
- Прогнал отдельные проверки: XSS‑векторы, ссылки, стили, медиа, атрибуты, скрытый контент, таблицы/SVG.
Таким образом, каждая функция DOMParser используется на 100% через отдельные кнопки в GUI.


┌────────────────────────────┐
│        XSSSecurityGUI      │
│  (main.py, кнопки GUI)     │
└────────────┬───────────────┘
             │
             ▼
┌────────────────────────────┐
│       AttackEngine         │
│  - run_auto_attack()       │
│  - run_modular_auto_attack() ◄────────────┐
│  - _record_result()         │             │
│  - export_results()         │             │
│  - send_summary_to_threat_intel()         │
└────────────┬──────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────┐
│         Модули атак (attack_launcher.py)   │
│  - attack_api_endpoints()                  │
│  - brute_force_tokens()                    │
│  - attack_parameters()                     │
│  - attack_user_ids()                       │
│  - attack_xss_targets()                    │
│  - build_headers_list()                    │
│  - suggest_payloads()                      │
│  - mask_secret()                           │
└────────────────────────────────────────────┘

🧭 Как использовать
1. 📦 Запуск автоатаки из GUI
В нижней панели GUI нажми:
- 🧨 Автоатака — запускает AttackEngine.run_auto_attack()
- 📤 Сводка в Threat Intel — отправляет get_summary() через send_summary_to_threat_intel()
2. 🧠 Что делает run_auto_attack()
- Если передан launcher, он используется (например, launch_auto_attack)
- Если нет — вызывается run_modular_auto_attack(), который:
- Использует все модули из attack_launcher.py
- Собирает результаты через _record_result()
- Отправляет их в Threat Intel
3. 🧪 Что делает каждый модуль
|  |  |  | 
| attack_api_endpoints |  | List[dict] | 
| brute_force_tokens |  | List[dict] | 
| attack_parameters |  | List[dict] | 
| attack_user_ids |  | List[dict] | 
| attack_xss_targets |  | List[dict] | 


4. 🧰 Вспомогательные функции
|  |  | 
| build_headers_list() |  | 
| suggest_payloads() |  | 
| mask_secret() |  | 
| send_request() |  | 



📤 Экспорт и отчётность
- Все результаты сохраняются через export_results() в logs/attack_results.json
- Сводка (get_summary()) содержит:
- Кол-во атак
- Кол-во high/error
- Группировку по типам
- Временную метку

🛡️ Threat Intel
- Каждый результат отправляется через _send_intel()
- Сводка отправляется вручную или автоматически через send_summary_to_threat_intel()

✅ Цель
Добавить в GUI:
- Прогресс-бар с отображением выполнения модулей атак
- Лог по каждому этапу
- Асинхронный запуск, чтобы GUI не зависал

GUI (PyQt / Tkinter / etc.)
│
├── Кнопка "🧨 Автоатака"
│     └─ запускает run_auto_attack_threaded()
│
├── Прогресс-бар (QProgressBar / ttk.Progressbar)
│     └─ обновляется после каждого модуля
│
└── Лог-виджет (QTextEdit / Listbox)
      └─ получает сообщения из log_func

🧪 Результат
- GUI остаётся отзывчивым
- Прогресс-бар показывает выполнение каждого модуля
- Лог отображает статус, ошибки, успехи
- Всё работает в фоне, без блокировок


#############################################################

1. Архитектура ThreatConnector 5.0
- ThreatBackendBase — абстрактный базовый класс.
- NdjsonBackend — твой текущий формат (append‑only).
- SQLiteBackend — хранение артефактов в SQLite.
- ElasticSearchBackend — отправка артефактов в Elasticsearch индекс.
- ThreatConnector — фасад, который работает через выбранный backend.
- THREAT_CONNECTOR — глобальный экземпляр, как и раньше.

3. Как это использовать в _run_attack_background
Импорт остаётся таким:
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


А дальше ты работаешь с ним так же, как раньше:
THREAT_CONNECTOR.emit(
    module="API Endpoints",
    target=self.domain,
    result={
        "severity": "info",
        "category": "api_endpoints",
        "source": "AutoAttackEngine",
        "items": page_api_endpoints,
    },
)



4. Переключение backend'а
Через переменные окружения:
- NDJSON (по умолчанию):
THREAT_BACKEND=ndjson


- SQLite:
THREAT_BACKEND=sqlite


- Elasticsearch:
THREAT_BACKEND=elastic
THREAT_ES_URL=http://localhost:9200
THREAT_ES_INDEX=threat_intel
THREAT_ES_USER=elastic
THREAT_ES_PASS=changeme

Вот схема потоков для всего пакета ULTRA 6.0/6.1 — чтобы было видно, как взаимодействуют модули 
honeypot_server, honeypot_monitor и deep_analysis_tab:

########################################🧵 Общая схема потоков ULTRA######################################


┌───────────────────────────────┐
│        Главный поток GUI      │
│  Tkinter mainloop             │
│  └─ DeepAnalysisTab (Frame)   │
│     └─ обработка событий      │
│        (таблицы, кнопки, UI)  │
└───────────────────────────────┘
              │
              │ запускает фоновые задачи
              ▼
┌───────────────────────────────┐
│   Фоновые потоки GUI-вкладки  │
│                               │
│  • run_deep_crawl()           │
│    └─ deep_crawl_site(url)    │
│    └─ запись JSON             │
│                               │
│  • launch_attack_plan()       │
│    └─ выполнение атак         │
│    └─ проверка токенов        │
│                               │
└───────────────────────────────┘
              │
              ▼
┌───────────────────────────────┐
│   Honeypot Server (Flask)     │
│   отдельный поток/процесс     │
│   └─ принимает HTTP-запросы   │
│   └─ пишет honeypot.log       │
└───────────────────────────────┘
              │
              ▼
┌───────────────────────────────┐
│ Honeypot Monitor (threading)  │
│   отдельный поток             │
│   └─ следит за honeypot.log   │
│   └─ извлекает payloads       │
│   └─ пишет JSONL событий      │
│   └─ запускает Mutator        │
│   └─ Instant-Attack Engine    │
└───────────────────────────────┘
              │
              ▼
┌───────────────────────────────┐
│ ThreatConnector               │
│   централизованная шина       │
│   └─ принимает события        │
│   └─ передаёт в Threat Intel  │
└───────────────────────────────┘

################################### Параметры физического сервера ##################

Вот пример плана сборки физического сервера среднего уровня специально под твой проект XSS Security GUI — чтобы он тянул многопоточный краулинг, анализ XSS/CSRF/SQLi и хранение логов без ограничений:

🖥️ Конфигурация сервера (Pro‑уровень)
| Компонент | Модель/вариант                         | Обоснование                        | 
| CPU       | AMD Ryzen 9 7950X (16 ядер, 32 потока) |Многопоточный краулинг и анализатор |
|           | или Intel Xeon Silver 4310 (12 ядер)   |требуют параллельных вычислений     |
|           |                                        |                                    |
| RAM       | 64 ГБ DDR5 (или DDR4 ECC для Xeon)     |Для работы GUI, краулера, БД и honey| 
| SSD       | 2ТБ NVMe(Samsung 990Pro/WD BlackSN850X)| Высокая скорость записи/чтения для | 
|(основной) |                                        | логов и базы пейлоадов             |
|HDD(архив) | 4 ТБ SATA (Seagate IronWolf / WD Red) | Для хранения старых логов, отчётов и резервных копий | 
| Сеть      | 1GbE встроенный адаптер + опция 10GbE (Intel X550) | Для honeypot‑сервера и быстрой передачи логов | 
| Корпус    | Серверный корпус 4U или ATX с хорошим  | Поддержка длительной работы 24/7 | 
| Блок      |  охлаждением                           |                                  |
|питания    | 750–850W Platinum (Seasonic / Corsair) | Надёжность и энергоэффективность | 
|Охлаждение | Noctua NH‑U14S или жидкостная система   | Стабильность при нагрузке | 
| UPS       | APC Smart‑UPS 1500VA                    | Защита от перебоев питания | 



💰 Стоимость (ориентировочно)
- CPU: ~$600–700
- RAM 64 ГБ: ~$250–300
- SSD 2 ТБ NVMe: ~$200–250
- HDD 4 ТБ: ~$100–120
- Материнская плата (серверная/рабочая станция): ~$250–350
- Корпус + охлаждение: ~$200–300
- Блок питания: ~$150–200
- UPS: ~$300–400
👉 Итого: ~$2,200–2,500 за полный сервер «под ключ».

📊 Эксплуатация
- Электричество: ~250–350 Вт при нагрузке → ~$25–40/мес.
- Интернет: выделенный канал с фиксированным IP (~$10–20/мес).
- Обслуживание: регулярная чистка, обновления ОС и мониторинг.

🔍 Вывод
Такой сервер обеспечит:
- стабильную работу GUI и краулера,
- хранение больших логов и отчётов,
- возможность запускать honeypot‑сервисы и многопоточные атаки,
- запас мощности на будущее расширение.

Я могу расписать схему развёртывания твоего проекта на этом сервере 
(какая ОС, как настроить виртуальные окружения, базы и логи), чтобы у тебя 
был готовый план установки. Хочешь, чтобы я собрал такую схему?

⚙️ ОС и базовая настройка
• 	ОС: Ubuntu Server 22.04 LTS (стабильная, поддержка Python и GUI‑библиотек).
• 	Пакеты: , , , ,  (для контейнеризации отдельных модулей).
• 	Безопасность:
• 	Настроить  (firewall) — открыть только SSH (22), веб‑порт (80/443), honeypot‑порт.
• 	Включить автоматические обновления ().
• 	Настроить Fail2Ban для защиты от брутфорса.

🧱 Развёртывание проекта
1. 	Создание окружения

2. 	Запуск GUI и сервисов
• 	Основной GUI: 
• 	Краулер: 
• 	Honeypot: 
3. 	Логи и отчёты
• 	Все логи сохраняются в .
• 	Настроить ротацию логов через .
• 	Отчёты (PDF/TXT) хранить на отдельном HDD (архив).

📂 Хранение данных
• 	SSD (2 ТБ NVMe): активные логи, база пейлоадов, временные файлы.
• 	HDD (4 ТБ): архивные отчёты, старые логи, резервные копии.
• 	Настроить автоматическое копирование логов с SSD → HDD раз в неделю (cron + rsync).

🛰️ Сетевые сервисы
• 	Honeypot‑сервер слушает отдельный порт (например, 8080).
• 	Настроить мониторинг через  для нагрузки CPU/RAM и активности honeypot.
• 	Включить IDS/IPS (например, Suricata) для анализа сетевого трафика.

🔍 Мониторинг и администрирование
• 	Grafana Dashboard: визуализация атак, токенов, событий honeypot.
• 	Prometheus: сбор метрик (CPU, RAM, сеть).
• 	Alertmanager: уведомления на e‑mail/Telegram при критических событиях.

💰 Эксплуатационные расходы
• 	Электричество: ~30–40$/мес при круглосуточной работе.
• 	Интернет: выделенный канал с фиксированным IP (~15–20$/мес).
• 	Обслуживание (UPS, охлаждение): ~100$/год.

📊 Вывод
Такой сервер позволит:
• 	Запускать краулер и анализаторы параллельно без лагов.
• 	Хранить большие массивы логов и отчётов.
• 	Работать как полноценная лаборатория для тестирования XSS/CSRF/SQLi.
• 	Поддерживать honeypot‑сервисы и мониторинг в реальном времени.
=======================================================================================================================

Крутая идея — давай сделаем это по‑взрослому: отдельный ML‑модуль + интеграция в краулер.

1. Зачем ML‑классификация страниц
Что это даст:
- login / auth:
- приоритизация XSS/CSRF/credential‑stuffing
- отдельные payload’ы для форм логина
- admin:
- повышенный приоритет, агрессивный фуззинг
- отдельные алерты в Threat Intel
- api:
- усиленный анализ JSON, токенов, ключей
- автогенерация API‑карты для дальнейшего тестирования
- upload:
- отдельные проверки на RCE / LFI / SVG‑XSS / polyglot payload’ы
То есть краулер перестаёт быть “слепым” и начинает понимать тип страницы и подстраивать стратегию атаки.

2. Архитектура ML‑модуля
Структура:
xss_security_gui/
  ml/
    __init__.py
    model/
      __init__.py
      page_classifier.py      # inference + lazy load
      train_page_classifier.py# оффлайн обучение
      label_schema.json       # список классов

3. Формат обучающей выборки
Файл, например: xss_security_gui/ml/model/page_dataset.jsonl
Каждая строка:
{"text": "Login - MyApp\n<form>...</form>", "label": "login"}
{"text": "Admin dashboard /admin\nUsers list", "label": "admin"}
{"text": "GET /api/users\nSwagger docs", "label": "api"}
{"text": "Upload your file\n<input type='file'>", "label": "upload"}
{"text": "Just a blog page", "label": "other"}


Как собирать:
- взять уже сохранённые HTML из краулера (или логов)
- вытащить:
- title, h1, form‑тексты, button‑тексты, URL
- руками разметить 200–1000 примеров (микс login/admin/api/upload/other)
- сохранить в page_dataset.jsonl.

4. Скрипт обучения DistilBERT (train_page_classifier.py)
# xss_security_gui/ml/model/train_page_classifier.py
import json
from pathlib import Path
from typing import List, Dict

from datasets import Dataset
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "page_dataset.jsonl"
MODEL_OUT = BASE_DIR / "distilbert_page_classifier"
LABEL_SCHEMA_PATH = BASE_DIR / "label_schema.json"

LABELS = ["login", "admin", "api", "upload", "other"]
LABEL2ID = {l: i for i, l in enumerate(LABELS)}
ID2LABEL = {i: l for l, i in LABEL2ID.items()}


def load_dataset(path: Path) -> Dataset:
    rows: List[Dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            text = obj.get("text", "").strip()
            label = obj.get("label", "other")
            if not text:
                continue
            if label not in LABEL2ID:
                label = "other"
            rows.append({"text": text, "label": LABEL2ID[label]})
    return Dataset.from_list(rows)


def main():
    ds = load_dataset(DATA_PATH)
    ds = ds.train_test_split(test_size=0.1)

    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

    def tokenize(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            padding="max_length",
            max_length=256,
        )

    ds_enc = ds.map(tokenize, batched=True)
    ds_enc = ds_enc.remove_columns(["text"])
    ds_enc.set_format("torch")

    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=len(LABELS),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    args = TrainingArguments(
        output_dir=str(MODEL_OUT),
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        logging_steps=50,
        learning_rate=5e-5,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds_enc["train"],
        eval_dataset=ds_enc["test"],
        tokenizer=tokenizer,
    )

    trainer.train()
    model.save_pretrained(MODEL_OUT)
    tokenizer.save_pretrained(MODEL_OUT)

    with LABEL_SCHEMA_PATH.open("w", encoding="utf-8") as f:
        json.dump({"labels": LABELS}, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()


Этот скрипт запускается один раз оффлайн, модель сохраняется в xss_security_gui/ml/model/distilbert_page_classifier/.

5. Inference‑модуль (page_classifier.py)
# xss_security_gui/ml/model/page_classifier.py
from __future__ import annotations
import json
from pathlib import Path
from functools import lru_cache
from typing import Literal, Dict, Any

import torch
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "distilbert_page_classifier"
LABEL_SCHEMA_PATH = BASE_DIR / "label_schema.json"

PageLabel = Literal["login", "admin", "api", "upload", "other"]


@lru_cache(maxsize=1)
def _load_label_schema() -> Dict[int, str]:
    try:
        with LABEL_SCHEMA_PATH.open(encoding="utf-8") as f:
            obj = json.load(f)
        labels = obj.get("labels") or ["login", "admin", "api", "upload", "other"]
    except Exception:
        labels = ["login", "admin", "api", "upload", "other"]
    return {i: l for i, l in enumerate(labels)}


@lru_cache(maxsize=1)
def _load_model():
    id2label = _load_label_schema()
    label2id = {v: k for k, v in id2label.items()}

    tokenizer = DistilBertTokenizerFast.from_pretrained(str(MODEL_DIR))
    model = DistilBertForSequenceClassification.from_pretrained(
        str(MODEL_DIR),
        num_labels=len(id2label),
        id2label=id2label,
        label2id=label2id,
    )
    model.eval()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    return tokenizer, model, device, id2label


def classify_page(text: str) -> Dict[str, Any]:
    """
    Классификация страницы:
    returns: {"label": "login", "score": 0.93}
    """
    if not text or not text.strip():
        return {"label": "other", "score": 0.0}

    tokenizer, model, device, id2label = _load_model()

    inputs = tokenizer(
        text,
        truncation=True,
        padding="max_length",
        max_length=256,
        return_tensors="pt",
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]
        score, idx = torch.max(probs, dim=-1)
        label = id2label[int(idx)]
        return {"label": label, "score": float(score)}



6. Интеграция в crawler.py
6.1. Импорт
Вверху crawler.py:
from xss_security_gui.ml.model.page_classifier import classify_page


6.2. Сбор текста для классификации
Внутри crawl_site, после парсинга HTML (после soup = BeautifulSoup(...) и извлечения форм/кнопок/текстовых элементов) добавим:
        # ... после того, как собрали forms/buttons/selects/textareas/meta ...

        # Собираем текст для ML‑классификации
        try:
            title = (soup.title.string or "").strip() if soup.title else ""
        except Exception:
            title = ""

        headings = []
        for tag in soup.find_all(["h1", "h2", "h3"]):
            try:
                txt = (tag.get_text(" ", strip=True) or "").strip()
                if txt:
                    headings.append(txt)
            except Exception:
                continue

        form_texts = []
        for form in soup.find_all("form"):
            try:
                txt = form.get_text(" ", strip=True)
                if txt:
                    form_texts.append(txt[:300])
            except Exception:
                continue

        button_texts = []
        for btn in soup.find_all("button"):
            try:
                txt = btn.get_text(" ", strip=True)
                if txt:
                    button_texts.append(txt)
            except Exception:
                continue

        url_snippet = safe_url  # уже нормализованный URL

        ml_text_parts = [
            f"URL: {url_snippet}",
            f"TITLE: {title}",
            "HEADINGS: " + " | ".join(headings[:10]),
            "FORMS: " + " | ".join(form_texts[:5]),
            "BUTTONS: " + " | ".join(button_texts[:10]),
        ]
        ml_input_text = "\n".join(ml_text_parts)[:2000]

        try:
            ml_result = classify_page(ml_input_text)
            node["page_class"] = ml_result.get("label", "other")
            node["page_class_score"] = ml_result.get("score", 0.0)
        except Exception as e:
            node["page_class"] = "other"
            node["page_class_score"] = 0.0
            logger.debug("ML classification failed for %s: %s", safe_url, e)


Обрати внимание: здесь я использую safe_url и logger из уже существующего кода.

6.3. Проброс в Threat Intel
В report_threatintel добавим поле:
        page_class = node.get("page_class", "other")
        page_class_score = node.get("page_class_score", 0.0)

        safe_report = {
            "module": "crawler",
            "url": url,
            "page_class": page_class,
            "page_class_score": page_class_score,
            "forms_count": len(forms),
            "scripts": script_paths,
            "headers": safe_headers,
            "api_endpoints": api_endpoints[:200],
            "links_count": len(links),
            "meta": meta,
            "events": events[:100],
            "error": error,
        }

7. Использование класса страницы в логике
Дальше ты можешь уже в других модулях (FormFuzzer, Attack Engine) делать, например:
- если node["page_class"] == "login" → включать спец‑payload’ы
- если admin → повышать приоритет
- если api → добавлять в отдельный список для API‑фаззинга
- если upload → запускать upload‑фаззер.

Если хочешь, следующим шагом можем:
- придумать правила для каждого класса (что именно делать с login/admin/api/upload),
- добавить в GUI отдельную колонку “Тип страницы (ML)” и фильтры по нему.

############################################################################################################
Следующие шаги
- Проверь репозиторий на GitHub — открой MakBein/second_repo (github.com in Bing) и убедись, что структура совпадает.
- Настрой .gitignore — чтобы логи, кеши и временные артефакты не попадали в будущие коммиты.
- Продолжай работать через коммиты и пуши:
git add .
git commit -m "Update: fixed scanner pipeline"
git push

Теперь у тебя чистая история и проект в GitHub. Я могу собрать для тебя финальный .gitignore, 
идеально под твой проект (с учётом venv, __pycache__, logs, exports, .env, временных файлов и баз данных), 
чтобы все будущие коммиты были аккуратными.
##################################################################################################################

• 	Добавлен метод , который читает  и подставляет cookies в .
• 	В контексте автоатак теперь используется  с реальными cookies.
• 	Логирование показывает, сколько cookies загружено.

Теперь твой движок будет запускать автоатаки в авторизованной сессии. Это позволит корректно тестировать 
CSRF‑пейлоады из  и другие атаки, которые требуют входа в систему.