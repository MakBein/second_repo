from threading import Thread
Thread(target=monitor_log_thread, args=(self,), daemon=True).start()
