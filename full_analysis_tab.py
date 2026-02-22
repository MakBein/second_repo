# xss_security_gui/full_analysis_tab.py

from tkinter import ttk
from xss_security_gui.utils.threat_sender import ThreatSenderMixin


class FullAnalysisTab(ttk.Frame, ThreatSenderMixin):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)

        self.threat_tab = threat_tab  # ссылка на Threat Intel

        self.forms_table = ttk.Treeview(self, columns=("types", "placeholders", "names"))
        self.forms_table.heading("#0", text="Форма")
        self.forms_table.heading("types", text="Типы")
        self.forms_table.heading("placeholders", text="Placeholder’ы")
        self.forms_table.heading("names", text="Имена")
        self.forms_table.pack(fill="both", expand=True, pady=5)

        self.events_table = ttk.Treeview(self, columns=("event", "handler", "risk"))
        self.events_table.heading("#0", text="Элемент")
        self.events_table.heading("event", text="Событие")
        self.events_table.heading("handler", text="JS Handler")
        self.events_table.heading("risk", text="Риск")
        self.events_table.pack(fill="both", expand=True, pady=5)

        self.flow_table = ttk.Treeview(self, columns=("input", "event", "risk"))
        self.flow_table.heading("#0", text="Input")
        self.flow_table.heading("input", text="Поле")
        self.flow_table.heading("event", text="Событие")
        self.flow_table.heading("risk", text="Риск")
        self.flow_table.pack(fill="both", expand=True, pady=5)

    def load_structure(self, structure):
        if not isinstance(structure, dict):
            return

        # 🧩 Формы
        self.forms_table.delete(*self.forms_table.get_children())
        forms_summary = []
        for i, form in enumerate(structure.get("forms", [])):
            inputs = form.get("inputs", [form.get("input", {})])
            types = ", ".join(inp.get("type", "—") for inp in inputs)
            placeholders = ", ".join(inp.get("placeholder", "—") for inp in inputs)
            names = ", ".join(inp.get("name", "—") for inp in inputs)

            self.forms_table.insert("", "end", text=f"#{i+1}", values=(types, placeholders, names))
            forms_summary.append({"types": types, "placeholders": placeholders, "names": names})

        # 🧠 События
        self.events_table.delete(*self.events_table.get_children())
        events_summary = []
        for e in structure.get("events", []):
            self.events_table.insert("", "end", text=e.get("tag", "—"), values=(
                e.get("event", "—"),
                e.get("handler", "")[:100],
                e.get("risk_level", "—")
            ))
            events_summary.append({
                "tag": e.get("tag", "—"),
                "event": e.get("event", "—"),
                "handler": e.get("handler", ""),
                "risk": e.get("risk_level", "—")
            })

        # 🔄 Потоки
        self.flow_table.delete(*self.flow_table.get_children())
        flows_summary = []
        for form in structure.get("forms", []):
            input_name = "—"
            inputs = form.get("inputs", [])
            if inputs and isinstance(inputs, list):
                input_name = inputs[0].get("name", "—")
            elif "input" in form:
                input_name = form["input"].get("name", "—")

            for e in form.get("linked_events", []):
                self.flow_table.insert("", "end", text=input_name, values=(
                    input_name,
                    e.get("event", "—"),
                    e.get("risk_level", "—")
                ))
                flows_summary.append({
                    "input": input_name,
                    "event": e.get("event", "—"),
                    "risk": e.get("risk_level", "—")
                })

        # ✅ Новый формат Threat Intel
        self.send_to_threat_intel("full_analysis", {
            "forms": forms_summary,
            "events": events_summary,
            "flows": flows_summary
        })