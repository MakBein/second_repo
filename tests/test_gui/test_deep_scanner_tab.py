import tkinter as tk

def test_deep_scanner_tab_render():
    from xss_security_gui.deep_scanner_tab import DeepScannerTab
    root = tk.Tk()
    tab = DeepScannerTab(root)
    tab.pack(fill="both", expand=True)

    # Обновляем окно, чтобы виджет считался отображённым
    root.update_idletasks()

    # Загружаем тестовый DOT-файл
    tab.load_data("tests/fixtures/large_crawl_graph.dot")

    # Проверяем, что graph_view создан
    assert isinstance(tab.graph_view, tk.Frame)

    # Проверяем, что количество узлов рассчитано
    assert tab.graph_view.node_count >= 0

    root.destroy()