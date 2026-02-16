# xss_security_gui/gui/mutator_tasks_panel.py
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QListWidgetItem

class MutatorTasksPanel(QWidget):
    def __init__(self, task_manager):
        super().__init__()
        self.task_manager = task_manager

        self.layout = QVBoxLayout(self)
        self.label = QLabel("Активные задачи мутатора:")
        self.list = QListWidget()

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.list)

        task_manager.task_added.connect(self.on_task_added)
        task_manager.task_finished.connect(self.on_task_finished)

    def on_task_added(self, task_id, payload):
        item = QListWidgetItem(f"🟡 {task_id[:8]} — {payload}")
        item.setData(32, task_id)
        self.list.addItem(item)

    def on_task_finished(self, task_id, result):
        for i in range(self.list.count()):
            item = self.list.item(i)
            if item.data(32) == task_id:
                if "error" in result:
                    item.setText(f"🔴 {task_id[:8]} — ошибка: {result['error']}")
                else:
                    item.setText(f"🟢 {task_id[:8]} — готово ({result['generated']} мутантов)")
                break