# xss_security_gui/batch_scanner.py
from crawler import crawl_site, save_outputs
from datetime import datetime
import os
import json
import csv
import time
import re
from typing import List, Dict, Any, Tuple, Union

from multiprocessing import Pool, TimeoutError, cpu_count

# === Универсальные пути внутри пакета ===
BASE_DIR = os.path.dirname(__file__)
LOGS_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(LOGS_DIR, "batch_sites")
REPORT_CSV = os.path.join(LOGS_DIR, "scan_report.csv")
FINAL_JSON = os.path.join(LOGS_DIR, "final_result.json")

# === Параметры фильтрации и паузы ===
FILTER_ONLY_GOV = True
FILTER_EXCLUDE_WWW = True
SLEEP_BETWEEN = 0.5  # между стартами процессов

# === Параметры параллелизма и таймаутов ===
MAX_PROCESSES = max(2, cpu_count() // 2)
PER_TARGET_TIMEOUT = 120  # секунд на один сайт


def ensure_dirs() -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_targets(path: str = os.path.join(BASE_DIR, "targets.txt")) -> List[str]:
    """
    Загружает цели из файла, применяет фильтры:
    - только .gov домены (если FILTER_ONLY_GOV=True)
    - исключает www (если FILTER_EXCLUDE_WWW=True)
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"targets.txt не найден: {path}")

    with open(path, encoding="utf-8") as f:
        raw = [line.strip() for line in f if line.strip().startswith("http")]
        targets: List[str] = []

        for url in raw:
            if FILTER_ONLY_GOV and not re.search(r"\.gov(\.|/|$)", url):
                continue
            if FILTER_EXCLUDE_WWW and "//www." in url:
                continue
            targets.append(url)

        return targets


def safe_domain_filename(url: str) -> str:
    """
    Преобразует URL в безопасное имя файла.
    """
    domain = url.replace("http://", "").replace("https://", "")
    domain = domain.replace("/", "_")
    return f"{domain}.json"


def write_json_result(url: str, data: Dict[str, Any]) -> str:
    """
    Сохраняет per‑target JSON в OUTPUT_DIR.
    Возвращает путь к файлу.
    """
    ensure_dirs()
    filename = os.path.join(OUTPUT_DIR, safe_domain_filename(url))
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return filename


def append_csv_report(rows: List[List[Any]]) -> None:
    """
    Добавляет строки в CSV‑отчёт. Заголовок пишется один раз.
    """
    ensure_dirs()
    header = [
        "URL", "Forms", "Scripts", "Links", "CMS", "Frameworks",
        "Tokens", "GraphQL", "SourceMaps", "Adaptive", "Score",
        "Status", "DurationSec"
    ]
    file_exists = os.path.exists(REPORT_CSV)

    with open(REPORT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(header)
        for row in rows:
            writer.writerow(row)


def normalize_node_result(result: Union[Dict[str, Any], Tuple[List[Dict[str, Any]], List[str]]]) -> Dict[str, Any]:
    """
    Унифицирует результат crawl_site:
    - если crawl_site возвращает один узел (dict) → возвращаем как есть
    - если возвращает (raw, pages) → собираем сводный узел
    """
    if isinstance(result, dict):
        return result

    if isinstance(result, tuple) and len(result) == 2:
        raw, pages = result

        forms = sum(len(n.get("forms", [])) for n in raw)
        scripts = sum(len(n.get("scripts", [])) for n in raw)
        links = sum(len(n.get("links", [])) for n in raw)
        adaptive = any(n.get("adaptive") for n in raw)
        tokens_list: List[str] = []
        graphql_count = 0
        sourcemaps_count = 0
        content_score = 0
        frameworks: List[str] = []
        ipv4_list: List[str] = []
        ipv6_list: List[str] = []

        for n in raw:
            tokens_list.extend(n.get("tokens", []))
            graphql_count += len(n.get("graphql", []))
            sourcemaps_count += len(n.get("sourcemaps", []))
            content_score += n.get("content_score", 0)
            frameworks.extend(n.get("frameworks", []) or [])
            ipv4_list.extend(n.get("ipv4", []))
            ipv6_list.extend(n.get("ipv6", []))

        # дедупликация списков
        def _dedupe(seq: List[Any]) -> List[Any]:
            return list(dict.fromkeys(seq))

        node = {
            "forms": forms,
            "scripts": scripts,
            "links": links,
            "pages": pages,
            "adaptive": adaptive,
            "tokens": _dedupe(tokens_list),
            "graphql": graphql_count,
            "sourcemaps": sourcemaps_count,
            "content_score": content_score,
            "cms": "-",
            "frameworks": _dedupe(frameworks),
            "ipv4": _dedupe(ipv4_list),
            "ipv6": _dedupe(ipv6_list),
        }
        return node

    return {"error": "unexpected_result_format"}


# === Обёртка для multiprocessing ===

def _scan_single_target(url: str) -> Dict[str, Any]:
    """
    Функция-обёртка для процесса:
    - вызывает crawl_site(url)
    - нормализует результат
    - возвращает dict с полями:
      { "url": ..., "node": ..., "error": None | str, "duration": float }
    """
    start_ts = time.time()
    try:
        result = crawl_site(url)
        node = normalize_node_result(result)
        duration = round(time.time() - start_ts, 2)
        return {
            "url": url,
            "node": node,
            "error": None,
            "duration": duration,
        }
    except Exception as e:
        duration = round(time.time() - start_ts, 2)
        return {
            "url": url,
            "node": {},
            "error": f"{type(e).__name__}: {e}",
            "duration": duration,
        }


def run_batch(file_path: str = os.path.join(BASE_DIR, "targets.txt")) -> None:
    """
    Пакетный обход целей (гибрид: multiprocessing + threads внутри краулера):
    - каждый сайт сканируется в отдельном процессе
    - внутри crawl_site уже может быть параллельный обход ссылок
    - сохраняет per‑target JSON
    - дополняет CSV‑отчёт
    - формирует финальный сводный JSON с агрегированными IPv4/IPv6/tokens
    """
    ensure_dirs()
    targets = load_targets(file_path)
    all_csv_rows: List[List[Any]] = []
    final_items: List[Dict[str, Any]] = []

    print(f"🔎 Всего отфильтровано целей: {len(targets)}")
    success_count = 0
    error_count = 0

    if not targets:
        print("⚠️ Нет целей для сканирования.")
        return

    aggregated_tokens: List[str] = []
    aggregated_ipv4: List[str] = []
    aggregated_ipv6: List[str] = []

    with Pool(processes=MAX_PROCESSES) as pool:
        async_results = []
        for idx, url in enumerate(targets, start=1):
            print(f"[{idx}/{len(targets)}] 🌐 Планируем обход: {url}")
            async_res = pool.apply_async(_scan_single_target, (url,))
            async_results.append((url, async_res))
            time.sleep(SLEEP_BETWEEN)

        for idx, (url, async_res) in enumerate(async_results, start=1):
            print(f"\n[{idx}/{len(targets)}] 🚀 Обработка результата: {url}")
            start_ts = time.time()
            try:
                res: Dict[str, Any] = async_res.get(timeout=PER_TARGET_TIMEOUT)
            except TimeoutError:
                err_msg = f"TimeoutError: превышен лимит {PER_TARGET_TIMEOUT}s"
                print(f"❌ Ошибка: {err_msg}")
                error_count += 1

                all_csv_rows.append([
                    url, 0, 0, 0, "-", "-", 0, 0, 0, "✘", 0,
                    "TIMEOUT", round(time.time() - start_ts, 2)
                ])

                try:
                    with open(os.path.join(LOGS_DIR, "batch_errors.log"), "a", encoding="utf-8") as errlog:
                        errlog.write(f"[{datetime.now().isoformat()}] {url} → {err_msg}\n")
                except Exception:
                    pass

                continue
            except Exception as e:
                err_msg = f"{type(e).__name__}: {e}"
                print(f"❌ Ошибка: {err_msg}")
                error_count += 1

                all_csv_rows.append([
                    url, 0, 0, 0, "-", "-", 0, 0, 0, "✘", 0,
                    "ERROR", round(time.time() - start_ts, 2)
                ])

                try:
                    with open(os.path.join(LOGS_DIR, "batch_errors.log"), "a", encoding="utf-8") as errlog:
                        errlog.write(f"[{datetime.now().isoformat()}] {url} → {err_msg}\n")
                except Exception:
                    pass

                continue

            node = res.get("node") or {}
            error = res.get("error")
            duration = res.get("duration", round(time.time() - start_ts, 2))

            if error:
                print(f"❌ Ошибка: {error}")
                error_count += 1

                all_csv_rows.append([
                    url, 0, 0, 0, "-", "-", 0, 0, 0, "✘", 0,
                    "ERROR", duration
                ])

                try:
                    with open(os.path.join(LOGS_DIR, "batch_errors.log"), "a", encoding="utf-8") as errlog:
                        errlog.write(f"[{datetime.now().isoformat()}] {url} → {error}\n")
                except Exception:
                    pass

                continue

            # Агрегация для Threat Intel / автоатак
            aggregated_tokens.extend(node.get("tokens", []))
            aggregated_ipv4.extend(node.get("ipv4", []))
            aggregated_ipv6.extend(node.get("ipv6", []))

            out_path = write_json_result(url, node)

            csv_row = [
                url,
                len(node.get("forms", [])),
                len(node.get("scripts", [])),
                len(node.get("links", [])),
                node.get("cms", "-"),
                ", ".join(node.get("frameworks", [])) if node.get("frameworks") else "-",
                len(node.get("tokens", [])),
                len(node.get("graphql", [])) if isinstance(node.get("graphql"), list) else node.get("graphql", 0),
                len(node.get("sourcemaps", [])) if isinstance(node.get("sourcemaps"), list) else node.get("sourcemaps", 0),
                "✅" if node.get("adaptive") else "✘",
                node.get("content_score", 0),
                "OK",
                duration,
            ]
            all_csv_rows.append(csv_row)
            final_items.append({"url": url, "result_path": out_path, "node": node})
            success_count += 1

    # Дедупликация агрегированных данных
    def _dedupe(seq: List[str]) -> List[str]:
        return list(dict.fromkeys(seq))

    aggregated_tokens = _dedupe(aggregated_tokens)
    aggregated_ipv4 = _dedupe(aggregated_ipv4)
    aggregated_ipv6 = _dedupe(aggregated_ipv6)

    if all_csv_rows:
        append_csv_report(all_csv_rows)
        print(f"\n📊 CSV-отчёт добавлен в {REPORT_CSV}")

    final_result = {
        "timestamp": datetime.now().isoformat(),
        "targets_count": len(targets),
        "success": success_count,
        "errors": error_count,
        "items": final_items,
        "filters": {
            "FILTER_ONLY_GOV": FILTER_ONLY_GOV,
            "FILTER_EXCLUDE_WWW": FILTER_EXCLUDE_WWW,
        },
        "sleep_between_sec": SLEEP_BETWEEN,
        "max_processes": MAX_PROCESSES,
        "per_target_timeout_sec": PER_TARGET_TIMEOUT,
        "aggregated": {
            "tokens": aggregated_tokens,
            "ipv4": aggregated_ipv4,
            "ipv6": aggregated_ipv6,
        },
    }

    with open(FINAL_JSON, "w", encoding="utf-8") as f:
        json.dump(final_result, f, indent=2, ensure_ascii=False)

    try:
        save_outputs(final_result)
    except TypeError as e:
        print(f"⚠️ save_outputs вызван с final_result, но возникла ошибка: {e}")
        print(f"ℹ️ Финальный JSON сохранён: {FINAL_JSON}")

    print("✅ Все сканы завершены.")
    print(f"📁 Артефакты: {OUTPUT_DIR}")
    print(f"📄 Сводка: {FINAL_JSON}")
    print(f"🧾 Отчёт: {REPORT_CSV}")


if __name__ == "__main__":
    run_batch()