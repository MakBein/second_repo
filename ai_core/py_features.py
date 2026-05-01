# py_features
import ast
from typing import Dict, Any
from pathlib import Path

def extract_py_features(code: str, path: Path) -> Dict[str, Any]:
    tree = ast.parse(code)
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]

    has_threads = any(isinstance(n, ast.Call) and getattr(getattr(n.func, "attr", ""), "") == "Thread" for n in ast.walk(tree))
    has_tk = "tkinter" in code or "ttk." in code
    has_network = any(k in code for k in ("requests.", "httpx.", "socket.", "urllib."))

    return {
        "file_name": path.name,
        "module_path": str(path),
        "num_functions": len(functions),
        "num_classes": len(classes),
        "has_threads": int(has_threads),
        "has_tk": int(has_tk),
        "has_network": int(has_network),
        "loc": len(code.splitlines()),
    }
