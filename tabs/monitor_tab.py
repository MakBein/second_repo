# xss_security_gui/tabs/monitor_tab.py
import tkinter as tk
from tkinter import ttk
import webbrowser


class SuperCrawlerMonitorTab(ttk.Frame):
    """
    Вкладка моніторингу SuperCrawler — як у Burp/ZAP.
    Показує прогрес, статус, живі логи та дерево краулера.
    """

    def __init__(self, parent, root_url: str | None = None):
        super().__init__(parent)

        self.root_url = root_url or ""
        self._context_menu = None

        # Заголовок + верхня панель
        header = ttk.Frame(self)
        header.pack(fill="x", pady=5)

        ttk.Label(
            header,
            text="SuperCrawler Monitor",
            font=("Segoe UI", 14, "bold")
        ).pack(side="left", padx=5)

        # Кнопка Open Root (відкриває кореневий URL у браузері)
        ttk.Button(
            header,
            text="🌐 Open Root",
            command=self._open_root_in_browser
        ).pack(side="right", padx=5)

        # Статус
        self.status_label = ttk.Label(self, text="Очікування запуску SuperCrawler…")
        self.status_label.pack(fill="x", pady=5)

        # Прогрес‑бар
        self.progress = ttk.Progressbar(self, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(fill="x", pady=5)
        self.progress["value"] = 0

        # Дерево
        columns = ("url", "status")
        self.tree = ttk.Treeview(self, columns=columns, show="tree headings")
        self.tree.heading("#0", text="Node")
        self.tree.heading("url", text="URL")
        self.tree.heading("status", text="Status")

        self.tree.column("#0", width=180)
        self.tree.column("url", width=260)
        self.tree.column("status", width=100)

        self.tree.pack(fill="both", expand=True, pady=5)

        # Логи
        self.log = tk.Text(self, height=10, bg="#111", fg="#eee")
        self.log.pack(fill="x", expand=False, pady=5)

        self.log.insert("end", "[🕷️] SuperCrawler Monitor готовий.\n")
        self.log.see("end")

        # ====== Інтеракція: подвійний клік + контекстне меню ======
        self._init_context_menu()
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<Button-3>", self._on_tree_right_click)

    # ------------------------------------------------------------
    # API для main.py / SuperCrawlerRunner
    # ------------------------------------------------------------

    def set_status(self, text: str):
        try:
            self.status_label.config(text=text)
        except Exception:
            pass

    def set_progress(self, value: int):
        try:
            self.progress["value"] = value
        except Exception:
            pass

    def log_message(self, text: str):
        try:
            self.log.insert("end", text + "\n")
            self.log.see("end")
        except Exception:
            pass

    def clear_tree(self):
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass

    def add_tree_node(self, parent, label, url="", status=""):
        try:
            return self.tree.insert(parent, "end", text=label, values=(url, status))
        except Exception:
            return None

    def update_tree(self, nodes):
        try:
            self.clear_tree()

            def add_recursive(parent, node):
                item = self.tree.insert(
                    parent,
                    "end",
                    text=node.get("label", ""),
                    values=(node.get("url", ""), node.get("status", ""))
                )
                for child in node.get("children", []):
                    add_recursive(item, child)

            for n in nodes:
                add_recursive("", n)

        except Exception:
            pass

    # ------------------------------------------------------------
    # Контекстне меню + дії
    # ------------------------------------------------------------
    def _init_context_menu(self):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Відкрити", command=self._open_selected_in_browser)
        menu.add_command(label="Скопіювати", command=self._copy_selected_url)
        menu.add_command(label="Перейти", command=self._focus_selected_node)
        menu.add_command(label="Відкрити Root", command=self._open_root_in_browser)
        self._context_menu = menu

    def _get_selected_item(self):
        sel = self.tree.selection()
        if not sel:
            return None, None
        item_id = sel[0]
        values = self.tree.item(item_id, "values")
        url = values[0] if values else ""
        return item_id, url

    def _on_tree_double_click(self, event):
        # Double‑click → відкриває URL у браузері
        _, url = self._get_selected_item()
        if url:
            try:
                webbrowser.open(url)
            except Exception:
                self.log_message(f"[⚠️] Не вдалося відкрити URL: {url}")

    def _on_tree_right_click(self, event):
        # Правий клік → контекстне меню
        try:
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
            if self._context_menu:
                self._context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            if self._context_menu:
                self._context_menu.grab_release()

    def _open_selected_in_browser(self):
        _, url = self._get_selected_item()
        if url:
            try:
                webbrowser.open(url)
            except Exception:
                self.log_message(f"[⚠️] Не вдалося відкрити URL: {url}")

    def _copy_selected_url(self):
        _, url = self._get_selected_item()
        if url:
            try:
                self.clipboard_clear()
                self.clipboard_append(url)
                self.log_message(f"[📋] URL скопійовано: {url}")
            except Exception:
                self.log_message("[⚠️] Не вдалося скопіювати URL")

    def _focus_selected_node(self):
        item_id, _ = self._get_selected_item()
        if item_id:
            try:
                self.tree.see(item_id)
            except Exception:
                pass

    def _build_context_menu(self):
        """Створити контекстне меню."""
        self.menu = tk.Menu(self.tree, tearoff=0)
        self.menu.add_command(label="Відкрити в браузері", command=self._open_selected)
        self.menu.add_command(label="Скопіювати URL", command=self._copy_selected)

    def _show_context_menu(self, event):
        """Показати контекстне меню."""
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.menu.post(event.x_root, event.y_root)

    def _get_selected_url(self):
        """Отримати URL виділеного елемента."""
        item = self.tree.selection()
        if not item:
            return None
        return self.tree.item(item[0], "values")[0]

    def _open_selected(self):
        """Відкрити виділений URL."""
        url = self._get_selected_url()
        if url:
            webbrowser.open(url)

    def _copy_selected(self):
        """Скопіювати URL у буфер."""
        url = self._get_selected_url()
        if url:
            self.clipboard_clear()
            self.clipboard_append(url)

    def _open_root(self):
        """Відкрити кореневий URL."""
        root_items = self.tree.get_children("")
        if not root_items:
            return
        url = self.tree.item(root_items[0], "values")[0]
        if url:
            webbrowser.open(url)

    # ------------------------------------------------------------
    # Open Root button
    # ------------------------------------------------------------
    def _open_root_in_browser(self):
        url = self.root_url
        if not url:
            # fallback: спробувати взяти URL з першого root‑вузла
            roots = self.tree.get_children("")
            if roots:
                values = self.tree.item(roots[0], "values")
                if values:
                    url = values[0]
        if url:
            try:
                webbrowser.open(url)
                self.log_message(f"[🌐] Відкрито root URL: {url}")
            except Exception:
                self.log_message(f"[⚠️] Не вдалося відкрити root URL: {url}")
        else:
            self.log_message("[⚠️] Root URL невідомий")

