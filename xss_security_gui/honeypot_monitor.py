import os
import re
import time

HONEYPOT_LOG = "/var/log/honeypot.log"

def monitor_log_thread(gui):
    last_size = 0
    while True:
        try:
            size = os.path.getsize(HONEYPOT_LOG)
            if size > last_size:
                with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
                    f.seek(last_size)
                    new = f.read()
                    payloads = extract_payloads(new)
                    for payload in payloads:
                        gui.output_box.insert("end", f"\n🧲 Обнаружен XSS:\n{payload}\n")
                        gui.input_entry.delete(0, "end")
                        gui.input_entry.insert(0, payload)
                        gui.scan()
                last_size = size
            time.sleep(4)
        except Exception as e:
            gui.output_box.insert("end", f"\n⚠️ Ошибка Honeypot: {e}")
            time.sleep(10)

def extract_payloads(log):
    pattern = r"(?:<script.*?>.*?</script>|<img\s+[^>]*?onerror\s*=|javascript:alert|on\w+=)"
    return list(set(re.findall(pattern, log, re.IGNORECASE)))
