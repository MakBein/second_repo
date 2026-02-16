# xss_security_gui/export_tools.py

import re, os, json, csv
from tkinter import filedialog, messagebox

def atomic_json_write(path: str, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def save_text_atomic(content: str, default_name="response.txt"):
    try:
        path = filedialog.asksaveasfilename(
            title="Сохранить полный ответ",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text", "*.txt"), ("HTML", "*.html"), ("All", "*.*")]
        )
        if not path:
            return
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
        messagebox.showinfo("Сохранено", f"Ответ сохранён: {path}")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

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
