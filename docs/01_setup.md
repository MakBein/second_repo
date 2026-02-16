🧰 Установка вручную

```bash

git clone https://github.com/your-repo/xss-security-gui.git
cd xss-security-gui
pip install -r requirements.txt
python main.py
```

🐳 Запуск через Docker

```bash
docker-compose up --build


- Контейнеры: gui, honeypot, xsstrike
- Порты: 5000 (honeypot), 8000 (GUI)
🧪 Проверка установки
- GUI должен открыться с вкладками: Exploit, Honeypot, Crawler, Logs
- Honeypot логирует события в logs/honeypot_events.json
- XSStrike интегрируется через вкладку Exploit
```
