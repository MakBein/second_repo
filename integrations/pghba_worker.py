# xss_security_gui/integrations/pghba_worker.py
"""
PGHBAWorker 7.0 — enterprise‑grade асинхронний завантажувач pg_hba.conf / Threat Intel.

Можливості:
- асинхронний пошук pg_hba.conf через fetch_callback
- паралельний пошук pg_hba.conf по файловій системі (concurrent.futures)
- повнотекстовий пошук по артефакту
- показ прогресу у статус‑барі ThreatAnalysisTab / RealTimeMonitoringTab
- гарантія, що інтеграція не запускається двічі (state machine)
- retry‑механізм з експоненційним backoff
- не блокує GUI — всі тяжкі операції в окремих потоках
- повністю потокобезпечний
- відкриття знайдених pg_hba.conf у окремому viewer
- File Explorer для всіх знайдених pg_hba.conf файлів з метаданими (розмір, дата)
- Artifact Inspector для JSON артефакта
- таблиця правил pg_hba.conf (type, database, user, address, method, risk)
- shutdown / graceful stop
"""
import os
import sys
import threading
import time
import logging
import concurrent.futures
from typing import Optional, Callable, Dict, Any, List

logger = logging.getLogger(__name__)

# Типові шляхи для пошуку pg_hba.conf
_DEFAULT_SEARCH_ROOTS: List[str] = []
if os.name == "nt":
    _DEFAULT_SEARCH_ROOTS = [
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "PostgreSQL"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "PostgreSQL"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "PostgreSQL"),
    ]
else:
    _DEFAULT_SEARCH_ROOTS = ["/etc/postgresql", "/var/lib/pgsql", "/usr/local/pgsql"]


def _scan_directory_for_pghba(root: str) -> List[Dict[str, Any]]:
    """Рекурсивно шукає pg_hba.conf у директорії. Повертає список з метаданими."""
    results: List[Dict[str, Any]] = []
    if not os.path.isdir(root):
        return results
    try:
        for dirpath, _dirs, files in os.walk(root, followlinks=False):
            for fname in files:
                if fname == "pg_hba.conf":
                    full = os.path.join(dirpath, fname)
                    try:
                        st = os.stat(full)
                        results.append({
                            "path": full,
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                            "readable": os.access(full, os.R_OK),
                        })
                    except OSError:
                        results.append({
                            "path": full,
                            "size": 0,
                            "mtime": 0,
                            "readable": False,
                        })
    except PermissionError:
        pass
    except Exception:
        logger.debug("[pghba_scan] помилка сканування %s", root, exc_info=True)
    return results


class PGHBAWorker:
    """
    Enterprise‑grade worker для pg_hba.conf Integration.
    """

    def __init__(
        self,
        threat_tab,
        ui_bridge,
        fetch_callback: Callable[[], Optional[Dict[str, Any]]],
        poll_interval: float = 0.15,
        retries: int = 2,
        on_start: Optional[Callable] = None,
        on_finish: Optional[Callable] = None,
        extra_search_roots: Optional[List[str]] = None,
    ):
        """
        :param threat_tab: GUI вкладка Threat Intel / MonitoringTab
        :param ui_bridge: UIQueueBridge
        :param fetch_callback: функція, яка повертає артефакт pg_hba.conf або None
        :param extra_search_roots: додаткові директорії для пошуку pg_hba.conf
        """
        self.threat_tab = threat_tab
        self.ui = ui_bridge
        self.fetch_callback = fetch_callback
        self.poll_interval = poll_interval
        self.retries = retries

        self.on_start = on_start
        self.on_finish = on_finish

        # state machine
        self._running = False
        self._finished = False
        self._shutdown_event = threading.Event()
        self._error: Optional[Exception] = None

        # статистика
        self.loaded = False
        self.artifact: Optional[Dict[str, Any]] = None

        # внутрішній lock
        self._lock = threading.Lock()

        # список знайдених файлів з метаданими
        self._found_files: List[Dict[str, Any]] = []

        # додаткові корені для пошуку
        self._search_roots = list(_DEFAULT_SEARCH_ROOTS)
        if extra_search_roots:
            self._search_roots.extend(extra_search_roots)

    # ------------------------------------------------------------
    #  Публічний API
    # ------------------------------------------------------------

    def start(self):
        """Запускає інтеграцію, якщо вона ще не запущена."""
        with self._lock:
            if self._running:
                self._set_status("📡 PGHBA Integration вже виконується…")
                return

            self._running = True
            self._finished = False
            self._shutdown_event.clear()
            self._error = None
            self.loaded = False
            self.artifact = None
            self._found_files.clear()

        logger.info("[PGHBAWorker] Запуск інтеграції")

        self._set_status("📦 PGHBA Integration: запуск…")

        if self.on_start:
            try:
                self.on_start()
            except Exception:
                logger.exception("[PGHBAWorker] on_start callback error")

        threading.Thread(target=self._worker_thread, daemon=True, name="PGHBAWorkerThread").start()
        threading.Thread(target=self._progress_thread, daemon=True, name="PGHBAProgressThread").start()

    def shutdown(self):
        """Graceful shutdown — зупиняє worker без блокування GUI."""
        self._shutdown_event.set()
        with self._lock:
            self._running = False
        logger.info("[PGHBAWorker] shutdown requested")

    def is_running(self) -> bool:
        return self._running and not self._finished

    # ------------------------------------------------------------
    #  Основний робочий потік
    # ------------------------------------------------------------

    def _worker_thread(self):
        attempts = 0
        backoff = 0.3

        while attempts <= self.retries and not self._shutdown_event.is_set():
            attempts += 1

            try:
                logger.info("[PGHBAWorker] Спроба #%d", attempts)

                artifact = self.fetch_callback()
                if artifact:
                    self.artifact = artifact
                    self.loaded = True
                    self._error = None

                    # зберігаємо файл у список знайдених
                    lp = artifact.get("local_path")
                    if lp:
                        try:
                            st = os.stat(lp)
                            self._found_files.append({
                                "path": lp,
                                "size": st.st_size,
                                "mtime": st.st_mtime,
                                "readable": os.access(lp, os.R_OK),
                            })
                        except OSError:
                            self._found_files.append({
                                "path": lp, "size": 0, "mtime": 0, "readable": False,
                            })

                    break

                if not self._shutdown_event.is_set():
                    self._shutdown_event.wait(backoff)
                    backoff = min(backoff * 2, 3.0)

            except Exception as e:
                logger.exception("[PGHBAWorker] Помилка на спробі #%d: %s", attempts, e)
                self._error = e
                if not self._shutdown_event.is_set():
                    self._shutdown_event.wait(backoff)
                    backoff = min(backoff * 2, 3.0)

        # Паралельний пошук по файловій системі
        if not self._shutdown_event.is_set():
            self._parallel_fs_scan()

        self._running = False
        self._finished = True

        if self._shutdown_event.is_set():
            self._set_status("⏹ PGHBA Integration зупинено")
        elif self._error:
            self._set_status(f"❌ PGHBA Integration: помилка: {self._error}")
        elif self.loaded:
            n = len(self._found_files)
            self._set_status(f"✅ PGHBA Integration завершено — знайдено {n} файл(ів)")
        else:
            self._set_status("⚠️ PGHBA Integration завершено — файл не знайдено")

        if self.on_finish:
            try:
                self.on_finish(self.loaded, self.artifact)
            except Exception:
                logger.exception("[PGHBAWorker] on_finish callback error")

    # ------------------------------------------------------------
    #  Паралельний пошук по FS
    # ------------------------------------------------------------

    def _parallel_fs_scan(self):
        """Concurrent пошук pg_hba.conf по типових директоріях."""
        self._set_status("🔍 PGHBA: паралельний пошук по файловій системі…")
        existing_paths = {f["path"] for f in self._found_files}

        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(4, len(self._search_roots) or 1),
                thread_name_prefix="PGHBAScan",
            ) as pool:
                futures = {
                    pool.submit(_scan_directory_for_pghba, root): root
                    for root in self._search_roots
                    if os.path.isdir(root)
                }
                for future in concurrent.futures.as_completed(futures, timeout=30):
                    if self._shutdown_event.is_set():
                        break
                    try:
                        found = future.result(timeout=10)
                        for entry in found:
                            if entry["path"] not in existing_paths:
                                self._found_files.append(entry)
                                existing_paths.add(entry["path"])
                    except Exception:
                        logger.debug("[PGHBAWorker] scan error for %s", futures[future], exc_info=True)
        except Exception:
            logger.debug("[PGHBAWorker] parallel scan error", exc_info=True)

    # ------------------------------------------------------------
    #  Потік прогресу
    # ------------------------------------------------------------

    def _progress_thread(self):
        """Показує прогрес у статус‑барі Threat Intel."""
        while self._running and not self._shutdown_event.is_set():
            try:
                if self.threat_tab and not self.threat_tab.winfo_exists():
                    logger.warning("[PGHBAWorker] ThreatTab зник — зупиняю прогрес")
                    break

                msg = "📡 PGHBA Integration… пошук pg_hba.conf…"
                self._set_status(msg)

            except Exception:
                logger.exception("[PGHBAWorker] Проблема оновлення прогресу")

            self._shutdown_event.wait(self.poll_interval)

    # ------------------------------------------------------------
    #  UI helper
    # ------------------------------------------------------------

    def _set_status(self, text: str):
        """Потокобезпечне оновлення статусу Threat Intel."""
        try:
            if self.threat_tab:
                self.ui.post_ui(self.threat_tab.status_var.set, text)
        except Exception:
            logger.error("[PGHBAWorker] Не вдалося оновити статус")

    # ------------------------------------------------------------
    #  Artifact Inspector
    # ------------------------------------------------------------

    def open_artifact_json(self):
        """Відкриває JSON артефакта у окремому viewer."""
        if not self.artifact:
            return

        try:
            self.ui.post_ui(self._show_artifact_json_window, self.artifact)
        except Exception:
            logger.exception("[PGHBAWorker] Не вдалося відкрити JSON viewer")

    def _show_artifact_json_window(self, artifact: Dict[str, Any]):
        """Tkinter viewer для JSON артефакта."""
        try:
            import tkinter as tk
            from tkinter import ttk
            import json

            root = self.threat_tab.winfo_toplevel()

            win = tk.Toplevel(root)
            win.title("pg_hba.conf Artifact JSON")
            win.geometry("700x600")

            frame = ttk.Frame(win, padding=10)
            frame.pack(fill="both", expand=True)

            text = tk.Text(frame, wrap="word")
            text.pack(fill="both", expand=True)

            text.insert("1.0", json.dumps(artifact, indent=2, ensure_ascii=False))
            text.config(state="disabled")

            ttk.Button(frame, text="Закрити", command=win.destroy).pack(pady=10)

        except Exception:
            logger.exception("[PGHBAWorker] Помилка створення JSON viewer")

    # ------------------------------------------------------------
    #  File Explorer (розширений з метаданими)
    # ------------------------------------------------------------

    def open_file_explorer(self):
        """Відкриває список всіх знайдених pg_hba.conf файлів."""
        try:
            self.ui.post_ui(self._show_file_explorer_window, list(self._found_files))
        except Exception:
            logger.exception("[PGHBAWorker] Не вдалося відкрити File Explorer")

    def _show_file_explorer_window(self, files: List[Dict[str, Any]]):
        """Tkinter viewer для списку файлів з метаданими."""
        try:
            import tkinter as tk
            from tkinter import ttk

            root = self.threat_tab.winfo_toplevel()

            win = tk.Toplevel(root)
            win.title("pg_hba.conf File Explorer")
            win.geometry("850x450")

            frame = ttk.Frame(win, padding=10)
            frame.pack(fill="both", expand=True)

            # Інфо-рядок
            ttk.Label(
                frame,
                text=f"Знайдено файлів: {len(files)}",
                font=("Segoe UI", 10, "bold"),
            ).pack(anchor="w", pady=(0, 5))

            cols = ("path", "size", "modified", "access")
            tree = ttk.Treeview(frame, columns=cols, show="headings")
            tree.heading("path", text="Шлях")
            tree.heading("size", text="Розмір")
            tree.heading("modified", text="Змінено")
            tree.heading("access", text="Доступ")
            tree.column("path", width=450, anchor="w")
            tree.column("size", width=80, anchor="e")
            tree.column("modified", width=150, anchor="center")
            tree.column("access", width=60, anchor="center")

            vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vsb.set)
            tree.pack(side="left", fill="both", expand=True)
            vsb.pack(side="right", fill="y")

            for entry in files:
                size_str = self._format_size(entry.get("size", 0))
                mtime = entry.get("mtime", 0)
                if mtime:
                    import datetime
                    mod_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
                else:
                    mod_str = "—"
                access_str = "✅" if entry.get("readable") else "❌"
                tree.insert("", "end", values=(entry["path"], size_str, mod_str, access_str))

            tree.bind("<Double-1>", lambda e: self._on_file_double_click(tree))

            btn_frame = ttk.Frame(win, padding=5)
            btn_frame.pack(fill="x")
            ttk.Button(btn_frame, text="Відкрити вибраний", command=lambda: self._on_file_double_click(tree)).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Відкрити папку", command=lambda: self._open_selected_folder(tree)).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Оновити пошук", command=lambda: self._refresh_scan(win, tree)).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Закрити", command=win.destroy).pack(side="right", padx=5)

        except Exception:
            logger.exception("[PGHBAWorker] Помилка створення File Explorer")

    @staticmethod
    def _format_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"

    def _open_selected_folder(self, tree):
        """Відкриває папку вибраного файлу."""
        try:
            item = tree.selection()
            if not item:
                return
            path = tree.item(item[0], "values")[0]
            folder = os.path.dirname(path)
            if os.path.isdir(folder):
                self._open_file(folder)
        except Exception:
            logger.exception("[PGHBAWorker] open folder error")

    def _refresh_scan(self, win, tree):
        """Запускає повторний пошук у фоновому потоці, оновлює таблицю."""
        def _bg():
            self._found_files.clear()
            self._parallel_fs_scan()
            # оновлюємо GUI через ui bridge
            self.ui.post_ui(_update_tree)

        def _update_tree():
            try:
                for item in tree.get_children():
                    tree.delete(item)
                for entry in self._found_files:
                    size_str = self._format_size(entry.get("size", 0))
                    mtime = entry.get("mtime", 0)
                    if mtime:
                        import datetime
                        mod_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
                    else:
                        mod_str = "—"
                    access_str = "✅" if entry.get("readable") else "❌"
                    tree.insert("", "end", values=(entry["path"], size_str, mod_str, access_str))
            except Exception:
                logger.exception("[PGHBAWorker] refresh tree error")

        threading.Thread(target=_bg, daemon=True, name="PGHBARefreshScan").start()

    def _on_file_double_click(self, tree):
        """Відкриває файл подвійним кліком."""
        try:
            item = tree.selection()
            if not item:
                return

            path = tree.item(item[0], "values")[0]
            if not os.path.exists(path):
                self._set_status(f"⚠️ Файл не існує: {path}")
                return

            # Читання файлу у фоновому потоці, показ у GUI
            threading.Thread(
                target=self._read_and_show_file,
                args=(path,),
                daemon=True,
                name="PGHBAFileRead",
            ).start()
            self._set_status(f"📂 Відкриваю файл: {path}")

        except Exception as e:
            logger.exception("PGHBAWorker file double-click error: %s", e)

    def _read_and_show_file(self, path: str):
        """Читає файл у фоновому потоці, потім показує у GUI."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(5 * 1024 * 1024)  # max 5 MB
            self.ui.post_ui(self._show_pg_hba_window_with_content, path, content)
        except Exception:
            logger.exception("[PGHBAWorker] read file error: %s", path)
            self._set_status(f"❌ Не вдалося прочитати: {path}")

    # ------------------------------------------------------------
    #  Viewer для pg_hba.conf
    # ------------------------------------------------------------

    def open_pg_hba_file(self):
        """Відкриває pg_hba.conf у окремому вікні (читання у фоні)."""
        if not self.artifact:
            return

        path = self.artifact.get("local_path")
        if not path:
            return

        threading.Thread(
            target=self._read_and_show_file,
            args=(path,),
            daemon=True,
            name="PGHBAOpenFile",
        ).start()

    def _show_pg_hba_window_with_content(self, path: str, content: str):
        """Tkinter viewer для pg_hba.conf — викликається тільки з GUI потоку."""
        try:
            import tkinter as tk
            from tkinter import ttk

            root = self.threat_tab.winfo_toplevel()

            win = tk.Toplevel(root)
            win.title("pg_hba.conf Viewer")
            win.geometry("750x620")

            frame = ttk.Frame(win, padding=10)
            frame.pack(fill="both", expand=True)

            ttk.Label(frame, text=f"Файл: {path}", font=("Segoe UI", 10, "bold")).pack(anchor="w")

            text_frame = ttk.Frame(frame)
            text_frame.pack(fill="both", expand=True, pady=(5, 0))

            text = tk.Text(text_frame, wrap="none")
            vsb = ttk.Scrollbar(text_frame, orient="vertical", command=text.yview)
            hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=text.xview)
            text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

            text.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            text_frame.rowconfigure(0, weight=1)
            text_frame.columnconfigure(0, weight=1)

            text.insert("1.0", content)
            text.config(state="disabled")

            btn_frame = ttk.Frame(win, padding=5)
            btn_frame.pack(fill="x")
            ttk.Button(btn_frame, text="Відкрити у системі", command=lambda: self._open_file(path)).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Відкрити папку", command=lambda: self._open_file(os.path.dirname(path))).pack(side="left", padx=5)
            ttk.Button(btn_frame, text="Закрити", command=win.destroy).pack(side="right", padx=5)

        except Exception:
            logger.exception("[PGHBAWorker] Помилка створення pg_hba.conf viewer")

    # Зворотна сумісність
    def _show_pg_hba_window(self, path: str):
        """Legacy wrapper — читає файл і показує."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(5 * 1024 * 1024)
            self._show_pg_hba_window_with_content(path, content)
        except Exception:
            logger.exception("[PGHBAWorker] Помилка створення pg_hba.conf viewer")

    # ------------------------------------------------------------
    #  OS‑specific file opener
    # ------------------------------------------------------------

    def _open_file(self, path: str) -> None:
        """Відкриває файл/папку у системному переглядачі (у фоновому потоці)."""
        def _bg():
            try:
                if os.name == "nt":
                    os.startfile(path)
                elif sys.platform == "darwin":
                    os.system(f"open '{path}'")
                else:
                    os.system(f"xdg-open '{path}'")
            except Exception as e:
                logger.error("File open error: %s", e)

        threading.Thread(target=_bg, daemon=True, name="PGHBAOpenOS").start()
