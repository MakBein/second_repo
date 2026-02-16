# xss_security_gui/mutator_task_manager.py
from PyQt5.QtCore import QObject, pyqtSignal
from concurrent.futures import ThreadPoolExecutor, Future
import uuid

class MutatorTaskManager(QObject):
    task_added = pyqtSignal(str, str)          # task_id, payload
    task_finished = pyqtSignal(str, dict)      # task_id, result

    def __init__(self):
        super().__init__()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.tasks: dict[str, Future] = {}

    def submit(self, fn, *args, **kwargs):
        task_id = str(uuid.uuid4())
        future = self.executor.submit(fn, *args, **kwargs)
        self.tasks[task_id] = future

        # GUI уведомление
        self.task_added.emit(task_id, args[1])  # args[1] = payload

        # callback
        future.add_done_callback(lambda f: self._on_done(task_id, f))
        return task_id

    def _on_done(self, task_id: str, future: Future):
        result = {}
        try:
            result = future.result()
        except Exception as e:
            result = {"error": str(e)}

        self.task_finished.emit(task_id, result)
        del self.tasks[task_id]