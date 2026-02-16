import re
import csv

def export_honeypot_csv(log_path="/var/log/honeypot.log", output="honeypot_report.csv"):
    pattern = re.compile(r"\[(.*?)\]\s+ATTACK from (\d+\.\d+\.\d+\.\d+):\s+\"(.+?)\"")
    rows = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                rows.append({"Time": m[1], "IP": m[2], "Payload": m[3]})
    with open(output, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Time", "IP", "Payload"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"✅ Экспортировано {len(rows)} событий в {output}")
