# xss_security_gui/ssrf_tab.py
import json
import os
import tkinter as tk
from datetime import datetime, timezone
from tkinter import ttk, messagebox, filedialog
from typing import Any, Dict, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.ssrf_module import SSRFTester
from xss_security_gui.utils.threat_sender import normalize_threat_artifact, emit_threat_event


class SSRFTab(ttk.Frame):
    """
    SSRFTab ULTRA 7.0 Pro
    ---------------------
    • Гнучке завантаження payload-файлу (settings / аргумент / дефолт)
    • Потокобезпечний лог (через .after)
    • Кольорові теги (HIGH / INFO / ERROR)
    • Контроль потоків (active_tests, max_workers)
    • Розширені SSRF payload-и:
        - file:// (локальні файли, .env, /etc/passwd)
        - AWS/GCP/Azure metadata
        - Docker / Kubernetes / internal services
    • ThreatConnector 7.0 (normalize_threat_artifact + emit_threat_event)
    • Уніфікований формат результатів для cross‑module heatmap + timeline
    """

    def __init__(self, parent, url: str | None = None, payload_file=None):
        super().__init__(parent)

        # 🔥 Захист від падіння, якщо URL не передали
        self.url = url or "http://127.0.0.1"

        self.payload_file = payload_file
        self.loop_running = False
        self.active_tests = 0
        self.max_workers = 5

        default_file = (
            settings.get("ssrf.payload_file")
            if isinstance(settings, dict)
            else getattr(settings, "SSRF_PAYLOAD_FILE", "ssrf_payloads.json")
        )

        self.payload_file: str = payload_file or default_file
        self.payloads: Dict[str, List[str]] = self._load_payloads()

        # === UIQueueBridge для фоновых операций ===
        from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
        self._bridge = UIQueueBridge(self, poll_ms=50)

        self._build_ui()

    # ---------------------------------------------------------
    # Payload loader + enrichment
    # ---------------------------------------------------------
    def _load_payloads(self) -> Dict[str, List[str]]:
        base: Dict[str, List[str]] = {}

        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("Файл payload-ів повинен містити JSON-об'єкт з категоріями")

            for k, v in data.items():
                if isinstance(v, list):
                    base[k] = v
                else:
                    base[k] = [str(v)]
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося завантажити SSRF payload-и:\n{e}")
            base = {}

        # Додаємо Pro-набір
        pro = self._build_pro_payloads()
        for cat, lst in pro.items():
            base.setdefault(cat, [])
            for p in lst:
                if p not in base[cat]:
                    base[cat].append(p)

        return base

    def _build_pro_payloads(self) -> Dict[str, List[str]]:
        """Додає Pro-набір SSRF payload-ів (file://, metadata, internal)."""
        return {
            "file_env": [
                "file:///var/www/html/.env",
                "file:///var/www/app/.env",
                "file:///var/www/.env",
                "file:///home/www-data/.env",
                "file:///.env",
            ],
            "file_passwd": [
                "file:///etc/passwd",
                "file:///etc/shadow",
            ],
            "aws_metadata": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ],
            "gcp_metadata": [
                "http://metadata.google.internal/computeMetadata/v1/",
            ],
            "azure_metadata": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ],
            "docker_internal": [
                "http://docker.for.win.localhost/",
                "http://host.docker.internal/",
            ],
            "kubernetes_internal": [
                "https://kubernetes.default.svc/",
            ],
            "redis_internal": [
                "redis://127.0.0.1:6379/",
            ],
        }

    # ---------------------------------------------------------
    # UI builder
    # ---------------------------------------------------------
    def _build_ui(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        # URL
        ttk.Label(top, text="Цільовий URL:").grid(row=0, column=0, sticky="w", padx=5)
        self.url_var = tk.StringVar(value=self.url)
        self.url_entry = ttk.Entry(top, textvariable=self.url_var, width=70)
        self.url_entry.grid(row=0, column=1, columnspan=3, sticky="we", padx=5)

        ttk.Button(top, text="Оновити URL", command=self.update_url).grid(
            row=0, column=4, sticky="w", padx=5
        )

        # Параметр
        ttk.Label(top, text="Параметр:").grid(row=1, column=0, sticky="w", padx=5)
        self.param_entry = ttk.Entry(top, width=20)
        self.param_entry.insert(0, "url")
        self.param_entry.grid(row=1, column=1, sticky="w", padx=5)

        # Значення
        ttk.Label(top, text="Базове значення:").grid(row=1, column=2, sticky="e", padx=5)
        self.value_entry = ttk.Entry(top, width=25)
        self.value_entry.insert(0, "")
        self.value_entry.grid(row=1, column=3, sticky="w", padx=5)

        # Категорія payload-ів
        ttk.Label(top, text="Категорія payload-ів:").grid(row=2, column=0, sticky="w", padx=5)
        self.category_var = tk.StringVar(self)
        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_var.set("Всі категорії")

        self.category_combo = ttk.Combobox(
            top,
            textvariable=self.category_var,
            values=categories,
            state="readonly",
        )
        self.category_combo.grid(row=2, column=1, sticky="w", padx=5)

        # Ліміт потоків
        ttk.Label(top, text="Макс. потоків:").grid(row=3, column=0, sticky="w", padx=5)
        self.workers_var = tk.IntVar(value=self.max_workers)
        workers_spin = ttk.Spinbox(
            top,
            from_=1,
            to=50,
            textvariable=self.workers_var,
            width=5,
            command=self._update_workers,
        )
        workers_spin.grid(row=3, column=1, sticky="w", padx=5)

        # Детальний лог
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Детальний лог", variable=self.verbose_var).grid(
            row=3, column=2, sticky="w", padx=5
        )

        # Buttons
        btn_frame = ttk.Frame(top)
        btn_frame.grid(row=3, column=3, columnspan=2, sticky="e", padx=5)

        ttk.Button(btn_frame, text="💉 Разовий запуск", command=self.run_tests).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="🔁 Цикл", command=self.start_loop).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="⛔ Зупинити", command=self.stop_loop).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="🧹 Очистити вивід", command=self.clear_output).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="📂 Вибрати payload-файл", command=self.choose_payload_file).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="🗑 Очистити лог артефактів", command=self.clear_artifact_log).pack(
            side="left", padx=3
        )

        # Output
        self.output = tk.Text(
            self,
            height=20,
            wrap="none",
            bg="black",
            fg="white",
            insertbackground="white",
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        # Теги
        self.output.tag_config("HIGH", foreground="lime")
        self.output.tag_config("INFO", foreground="yellow")
        self.output.tag_config("ERROR", foreground="red")

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _safe_log(self, data: Any) -> None:
        self.after(0, lambda: self._append_text(data))

    def _append_text(self, data: Any) -> None:
        if isinstance(data, tuple):
            text, tag = data
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", data)
        self.output.see("end")

    # ---------------------------------------------------------
    # Workers
    # ---------------------------------------------------------
    def _update_workers(self) -> None:
        value = self.workers_var.get()
        if value < 1:
            value = 1
        self.max_workers = value
        self.workers_var.set(value)
        self._safe_log(f"⚙️ Макс. потоків встановлено: {self.max_workers}\n")

    # ---------------------------------------------------------
    # URL update
    # ---------------------------------------------------------
    def update_url(self) -> None:
        self.url = self.url_var.get().strip()
        self._safe_log(f"🔄 URL оновлено: {self.url}\n")

    # ---------------------------------------------------------
    # Single run
    # ---------------------------------------------------------
    def run_tests(self) -> None:
        if not self.payloads:
            messagebox.showerror("Помилка", "Payload-и не завантажені")
            return

        if self.active_tests >= self.max_workers:
            self._safe_log("⚠️ Досягнуто ліміт потоків, дочекайтесь завершення\n")
            return

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param:
            self._safe_log("⚠️ Параметр не може бути порожнім\n")
            return

        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads.get(category, [])}

        self._safe_log(f"🚀 Запущено SSRF-тестування для {self.url} (param={param})\n")
        self.active_tests += 1

        # Запускаємо в фоне через UIQueueBridge
        def worker():
            tester = SSRFTester(
                base_url=self.url,
                param=param,
                base_value=base_value,
                payloads=selected_payloads,
                output_callback=self._on_test_finish,
            )
            tester.start()

        self._bridge.post_bg(worker)

    # ---------------------------------------------------------
    # Loop mode
    # ---------------------------------------------------------
    def start_loop(self) -> None:
        if self.loop_running:
            return
        if not self.payloads:
            self._safe_log("❌ Payload-и не завантажені — цикл не запущено\n")
            return

        self.loop_running = True
        self._safe_log("🔁 Цикл SSRF запущено\n")
        self._run_ssrf_cycle()

    def stop_loop(self) -> None:
        if self.loop_running:
            self._safe_log("⛔ Цикл зупинено\n")
        self.loop_running = False

    def _run_ssrf_cycle(self) -> None:
        if not self.loop_running:
            return

        if self.active_tests < self.max_workers:
            self._try_start_test_from_cycle()

        self.after(300, self._run_ssrf_cycle)

    def _try_start_test_from_cycle(self) -> bool:
        if not self.payloads:
            self._safe_log("⚠️ Цикл: payload-и не завантажені, запуск неможливий\n")
            return False

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param:
            self._safe_log("⚠️ Цикл: порожній параметр — тест не буде запущено\n")
            return False

        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            cat_payloads = self.payloads.get(category) or []
            if not cat_payloads:
                self._safe_log(f"⚠️ Цикл: у категорії '{category}' немає payload-ів\n")
                return False
            selected_payloads = {category: cat_payloads}

        tester = SSRFTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self._on_test_finish,
        )
        tester.start()
        self.active_tests += 1

        self._safe_log(
            f"🔁 Цикл: запущено SSRF-тест (param={param}, category={category}, активних={self.active_tests})\n"
        )
        return True

    def run_attack(self, url: str) -> Dict[str, Any]:
        """
        Запускає одну SSRF‑атаку і повертає артефакт:
        - category: ssrf_candidate
        - url: атакований URL
        - final_host: кінцевий хост
        - internal_port_scan: список портів
        """
        if not self._tester:
            self._tester = self._build_tester()

        self._attack_counter += 1
        attack_label = f"Attack #{self._attack_counter}"

        self.log(f"\n=== ⚡ {attack_label} → {url} ===\n", "INFO")

        # тут реальний SSRF через SSRFTester
        result = self._tester._run_test(url)

        result["category"] = "ssrf_candidate"
        result["action"] = "ssrf_attack"
        result["url"] = url
        result["payload_meta"] = {
            "attack_label": attack_label,
            "payload_value": url,
        }
        result["timestamp"] = datetime.now(timezone.utc).isoformat()

        severity = result.get("severity", "INFO").upper()
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            result["risk"] = severity.lower()
        else:
            result["risk"] = "info"

        return result

    # ---------------------------------------------------------
    # Callback from tester
    # ---------------------------------------------------------
    def _on_test_finish(self, result: Dict[str, Any]) -> None:
        self.active_tests = max(0, self.active_tests - 1)
        self.display_result(result)

    # ---------------------------------------------------------
    # Display result + ThreatConnector
    # ---------------------------------------------------------
    def display_result(self, result: Dict[str, Any]) -> None:
        if not result:
            self._safe_log("⚠️ Порожній результат від SSRFTester\n")
            return

        details = result.get("details", {}) or {}
        severity = result.get("severity") or details.get("severity") or "INFO"

        category = result.get("category", "?")
        payload = result.get("payload", "?")

        http_status = details.get("http_status", "?")
        resp_len = details.get("response_length")
        redirected_to_local = details.get("redirected_to_local", False)
        body_hit = details.get("body_hit", False)
        header_hit = details.get("header_hit", False)
        raw = details.get("raw") or ""

        len_part = f"(len={resp_len})" if isinstance(resp_len, (int, float)) else ""

        line = (
            f"[{category}] {payload} → {severity} "
            f"(HTTP {http_status}) {len_part} "
            f"(body={body_hit}, hdr={header_hit}, local={redirected_to_local})\n"
        )

        tag = "HIGH" if severity == "HIGH" else ("ERROR" if severity == "ERROR" else "INFO")
        self._safe_log((line, tag))

        if self.verbose_var.get() and raw:
            self._safe_log((f"RAW: {raw[:500]}\n", tag))

        # Threat artifact
        artifact: Dict[str, Any] = {
            "type": "SSRF",
            "module": "ssrf_tab",
            "url": self.url,
            "param": self.param_entry.get().strip(),
            "payload": payload,
            "category": category,
            "severity": severity,
            "http_status": http_status,
            "response_length": resp_len,
            "redirected_to_local": redirected_to_local,
            "body_hit": body_hit,
            "header_hit": header_hit,
            "source": "SSRF Scanner Pro",
        }

        try:
            norm = normalize_threat_artifact(artifact)
            emit_threat_event(norm)
        except Exception as e:
            self._safe_log(f"[ThreatConnector] Помилка нормалізації/відправки: {e}\n")

    # ---------------------------------------------------------
    # Clear output
    # ---------------------------------------------------------
    def clear_output(self) -> None:
        self.output.delete("1.0", "end")

    # ---------------------------------------------------------
    # Choose payload file
    # ---------------------------------------------------------
    def choose_payload_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Вибрати файл SSRF payload-ів",
            filetypes=[("JSON файли", "*.json"), ("Всі файли", "*.*")],
        )
        if not path:
            return

        self.payload_file = path
        self.payloads = self._load_payloads()

        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_combo["values"] = categories
        self.category_var.set("Всі категорії")

        self._safe_log(f"✅ Payload-и завантажено з: {path}\n")

    # ---------------------------------------------------------
    # Clear artifact log
    # ---------------------------------------------------------
    def clear_artifact_log(self) -> None:
        artifact_path = (
            settings.get("threat_intel.artifact_path")
            if isinstance(settings, dict)
            else getattr(settings, "THREAT_INTEL_ARTIFACT_PATH", "threat_artifacts.json")
        )

        try:
            os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump([], f)
            self._safe_log(f"✅ Лог артефактів очищено: {artifact_path}\n")
        except Exception as e:
            self._safe_log(f"❌ Помилка очищення: {e}\n")
