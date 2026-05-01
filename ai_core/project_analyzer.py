"""
AI Core 30.0 — project_analyzer.py (ENTERPRISE EDITION)

Можливості:
- Багатопоточне сканування Python-проєкту
- Кешування результатів аналізу по файлах
- Інкрементальний аналіз (через Git diff)
- Інтеграція з AI-моделями (py_risk_engine)
- Heatmap ризиків по файлах
- Експорт результатів у JSON / HTML / PDF
- Готово для GUI-панелі "Project Security Analyzer"
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable
import json
import time
import subprocess
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

from xss_security_gui.settings import BASE_DIR
from xss_security_gui.ai_core.py_features import extract_py_features
from xss_security_gui.ai_core.py_risk_engine import analyze_py_risk

try:
    from fpdf import FPDF
except Exception:
    FPDF = None  # PDF-експорт буде опційним


# ============================================================
#  Константи
# ============================================================

MAX_FILE_SIZE = 50 * 1024 * 1024   # 2 MB
SKIP_DIRS = {"venv", "__pycache__", ".git", ".idea", ".pytest_cache", ".mypy_cache"}

CACHE_DIR = BASE_DIR / ".ai_cache"
CACHE_FILE = CACHE_DIR / "project_analyzer_cache.json"

DEFAULT_MAX_WORKERS = 8


# ============================================================
#  Кеш
# ============================================================

def _load_cache() -> Dict[str, Any]:
    if not CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _file_cache_key(path: Path) -> str:
    try:
        stat = path.stat()
        return f"{stat.st_mtime_ns}:{stat.st_size}"
    except Exception:
        return "0:0"


# ============================================================
#  Git / інкрементальний аналіз
# ============================================================

def get_git_changed_files(root: Path | None = None) -> List[str]:
    """
    Повертає список змінених .py файлів відносно HEAD.
    Якщо Git недоступний — повертає порожній список.
    """
    root = root or BASE_DIR
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode != 0:
            return []
        files = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.endswith(".py"):
                files.append(line)
        return files
    except Exception:
        return []


# ============================================================
#  Допоміжні функції
# ============================================================

def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _safe_read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _analyze_single_file(
    path: Path,
    root: Path,
    cache: Dict[str, Any],
    use_cache: bool,
) -> Dict[str, Any]:
    rel_path = str(path.relative_to(root))
    cache_key = _file_cache_key(path)

    if use_cache:
        cached = cache.get(rel_path)
        if cached and cached.get("cache_key") == cache_key:
            return cached["result"]

    code = _safe_read(path)
    if not code:
        result = {
            "path": rel_path,
            "error": "empty_or_unreadable",
        }
    else:
        try:
            features = extract_py_features(code, path)
        except Exception as e:
            result = {
                "path": rel_path,
                "error": f"feature_error: {e}",
            }
        else:
            try:
                risk = analyze_py_risk(features)
            except Exception as e:
                result = {
                    "path": rel_path,
                    "features": features,
                    "error": f"risk_engine_error: {e}",
                }
            else:
                result = {
                    "path": rel_path,
                    "features": features,
                    "risk": risk,
                }

    # оновлюємо кеш
    cache[rel_path] = {
        "cache_key": cache_key,
        "result": result,
    }
    return result


# ============================================================
#  Основний аналіз проєкту
# ============================================================

def scan_project(
    root: Path | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    use_cache: bool = True,
    incremental: bool = False,
) -> List[Dict[str, Any]]:
    """
    Сканує Python-проєкт з:
    - багатопоточністю
    - кешуванням
    - опційним інкрементальним режимом (тільки змінені файли)
    """

    root = root or BASE_DIR
    cache = _load_cache() if use_cache else {}

    # Визначаємо список файлів
    all_files: List[Path] = []

    if incremental:
        changed = set(get_git_changed_files(root))
        changed_paths = [root / p for p in changed]
        for path in changed_paths:
            if path.exists() and path.suffix == ".py" and not _should_skip(path):
                all_files.append(path)
    else:
        for path in root.rglob("*.py"):
            if _should_skip(path):
                continue
            all_files.append(path)

    results: List[Dict[str, Any]] = []

    if not all_files:
        return results

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {
            executor.submit(_analyze_single_file, path, root, cache, use_cache): path
            for path in all_files
        }

        for future in as_completed(future_to_path):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                path = future_to_path[future]
                rel_path = str(path.relative_to(root))
                results.append({
                    "path": rel_path,
                    "error": f"fatal_error: {e}",
                })

    duration = time.time() - start_time

    # Сортуємо результати
    results.sort(key=lambda x: x["path"])

    # Зберігаємо кеш
    if use_cache:
        _save_cache(cache)

    # Можна додати службовий запис для GUI
    results.append({
        "_meta": {
            "root": str(root),
            "files_scanned": len(all_files),
            "duration_sec": round(duration, 3),
            "incremental": incremental,
            "cached": use_cache,
        }
    })

    return results


# ============================================================
#  Heatmap ризиків
# ============================================================

def build_risk_heatmap(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Формує heatmap по файлах:
    - path
    - risk_score (0..1)
    - risk_level
    """
    heatmap: List[Dict[str, Any]] = []

    for item in results:
        if "risk" not in item:
            continue
        risk = item["risk"] or {}
        score = float(risk.get("risk_score", 0.0))
        level = risk.get("risk_level", "info")
        heatmap.append({
            "path": item["path"],
            "risk_score": score,
            "risk_level": level,
        })

    heatmap.sort(key=lambda x: x["risk_score"], reverse=True)
    return heatmap


# ============================================================
#  Експорт: JSON / HTML / PDF
# ============================================================

def export_results_json(results: List[Dict[str, Any]], out_path: Path) -> None:
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def export_results_html(results: List[Dict[str, Any]], out_path: Path) -> None:
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)

        heatmap = build_risk_heatmap(results)
        rows = []
        for item in heatmap:
            color = "#4caf50"
            if item["risk_level"] == "medium":
                color = "#ff9800"
            elif item["risk_level"] == "high":
                color = "#f44336"

            rows.append(
                f"<tr>"
                f"<td>{item['path']}</td>"
                f"<td>{item['risk_score']:.3f}</td>"
                f"<td style='color:{color};font-weight:bold'>{item['risk_level']}</td>"
                f"</tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Project Security Analyzer</title>
<style>
body {{ font-family: Arial, sans-serif; background:#121212; color:#eee; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #444; padding: 6px 10px; font-size: 13px; }}
th {{ background: #222; }}
tr:nth-child(even) {{ background: #1a1a1a; }}
</style>
</head>
<body>
<h2>Project Security Analyzer — Risk Heatmap</h2>
<table>
<thead>
<tr>
<th>File</th>
<th>Risk score</th>
<th>Risk level</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""
        out_path.write_text(html, encoding="utf-8")
    except Exception:
        pass


def export_results_pdf(results: List[Dict[str, Any]], out_path: Path) -> None:
    if FPDF is None:
        return

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)

        heatmap = build_risk_heatmap(results)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=10)
        pdf.add_page()
        pdf.set_font("Arial", size=10)

        pdf.cell(0, 8, "Project Security Analyzer — Risk Report", ln=1)

        for item in heatmap:
            line = f"{item['risk_level'].upper():<6} {item['risk_score']:.3f}  {item['path']}"
            pdf.cell(0, 6, line, ln=1)

        pdf.output(str(out_path))
    except Exception:
        pass


# ============================================================
#  Дані для GUI-панелі "Project Security Analyzer"
# ============================================================

def build_gui_model(root: Path | None = None,
                    max_workers: int = DEFAULT_MAX_WORKERS,
                    use_cache: bool = True,
                    incremental: bool = False) -> Dict[str, Any]:
    """
    Повертає готову структуру для GUI:
    - files: список файлів з ризиками/помилками
    - heatmap: агрегований список по ризиках
    - meta: службова інформація
    """
    results = scan_project(
        root=root,
        max_workers=max_workers,
        use_cache=use_cache,
        incremental=incremental,
    )

    meta = {}
    if results and isinstance(results[-1], dict) and "_meta" in results[-1]:
        meta = results[-1]["_meta"]
        results = results[:-1]

    heatmap = build_risk_heatmap(results)

    return {
        "files": results,
        "heatmap": heatmap,
        "meta": meta,
    }


class ProjectAnalyzerRunner:
    """
    Асинхронний запуск важкого project scan для Tk GUI:
    - heavy scan у фоні
    - повернення результатів через queue + root.after(...)
    """

    def __init__(self, root, poll_ms: int = 120):
        self._root = root
        self._poll_ms = max(30, int(poll_ms))
        self._results: "queue.Queue[Tuple[str, Any, Optional[Exception], Optional[Callable], Optional[Callable]]]" = queue.Queue()
        self._active = True
        self._root.after(self._poll_ms, self._poll)

    def stop(self) -> None:
        self._active = False

    def analyze_async(
        self,
        *,
        root: Path | None = None,
        max_workers: int = DEFAULT_MAX_WORKERS,
        use_cache: bool = True,
        incremental: bool = False,
        on_done=None,
        on_error=None,
    ) -> str:
        task_id = f"PA-{int(time.time() * 1000)}"

        def _job():
            try:
                model = build_gui_model(
                    root=root,
                    max_workers=max_workers,
                    use_cache=use_cache,
                    incremental=incremental,
                )
                self._results.put((task_id, model, None, on_done, on_error))
            except Exception as e:
                self._results.put((task_id, None, e, on_done, on_error))

        threading.Thread(target=_job, daemon=True, name=f"ProjectAnalyzer-{task_id}").start()
        return task_id

    def _poll(self) -> None:
        try:
            while True:
                task_id, model, err, on_done, on_error = self._results.get_nowait()
                if err is None:
                    if callable(on_done):
                        try:
                            on_done(task_id, model)
                        except Exception:
                            pass
                else:
                    if callable(on_error):
                        try:
                            on_error(task_id, err)
                        except Exception:
                            pass
        except queue.Empty:
            pass
        finally:
            if self._active:
                self._root.after(self._poll_ms, self._poll)


