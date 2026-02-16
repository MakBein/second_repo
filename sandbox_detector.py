# xss_security_gui/sandbox_detector.py
"""
SandboxDetector ULTRA 5.0

Модуль эвристического определения песочницы / анализа окружения.

Объединяет:
  • Системные признаки:
      - VM / Hypervisor / VirtualBox / VMware / Hyper-V / QEMU
      - Docker / контейнеры / CI (GitHub Actions, GitLab CI, Jenkins и т.д.)
      - Ограничения CPU / RAM / uptime
      - Файловые маркеры виртуализации и контейнеров
  • Сетевые признаки:
      - DNS/Network ограничения
  • JS-контекст:
      - headless / webdriver / пустые плагины
      - iframe sandbox / nested window
      - CSP / ограниченные вызовы
  • Категоризированный risk scoring:
      - system, network, js, csp, iframe, ci, container, vm, headless

Возвращает:
  {
    "sandboxed": bool,
    "score": int,
    "severity": "низкая|средняя|высокая",
    "indicators": [str],
    "categories": {str: int},
    "timestamp": float,
  }
"""

from __future__ import annotations

import os
import platform
import random
import socket
import time
import subprocess
from typing import Dict, List, Any, Tuple


# ============================================================
#  Системные эвристики
# ============================================================

def _check_vm_platform() -> List[str]:
    plat = platform.platform().lower()
    suspects = ["virtual", "vmware", "vbox", "qemu", "hyper-v", "xen", "kvm"]
    return [s for s in suspects if s in plat]


def _check_env_flags() -> List[str]:
    flags = []
    for var in [
        "RUNNING_IN_DOCKER",
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "TEAMCITY_VERSION",
        "TRAVIS",
        "CIRCLECI",
        "BUILDKITE",
    ]:
        if os.getenv(var):
            flags.append(var)
    return flags


def _check_docker_files() -> List[str]:
    hits = []
    if os.path.exists("/.dockerenv"):
        hits.append("/.dockerenv")
    if os.path.exists("/run/.containerenv"):
        hits.append("/run/.containerenv")
    cgroup_path = "/proc/1/cgroup"
    if os.path.exists(cgroup_path):
        try:
            with open(cgroup_path, encoding="utf-8") as f:
                data = f.read().lower()
                if "docker" in data or "kubepods" in data or "containerd" in data:
                    hits.append(cgroup_path)
        except Exception:
            pass
    return hits


def _check_vm_files() -> List[str]:
    hits = []
    candidates = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/proc/scsi/scsi",
    ]
    markers = ["virtualbox", "vmware", "qemu", "kvm", "hyper-v"]

    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                data = f.read().lower()
                if any(m in data for m in markers):
                    hits.append(path)
        except Exception:
            continue
    return hits


def _check_cpu_ram() -> Tuple[int, int]:
    """
    Возвращает (cpu_count, approx_ram_mb).
    RAM оцениваем грубо через /proc/meminfo (Linux) или 0, если недоступно.
    """
    cpu = os.cpu_count() or 1
    ram_mb = 0

    if os.name == "posix" and os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            # kB → MB
                            ram_mb = int(parts[1]) // 1024
                        break
        except Exception:
            pass

    return cpu, ram_mb


def _check_uptime_seconds() -> int:
    if os.name == "posix" and os.path.exists("/proc/uptime"):
        try:
            with open("/proc/uptime", encoding="utf-8") as f:
                val = f.read().split()[0]
                return int(float(val))
        except Exception:
            return 0
    return 0


# ============================================================
#  Сетевые эвристики
# ============================================================

def _check_network_restrictions() -> bool:
    """
    Простейшая проверка DNS/Network:
    если не можем резолвить example.com — подозрение на ограниченную сеть.
    """
    try:
        socket.gethostbyname("example.com")
        return False
    except Exception:
        return True


# ============================================================
#  JS / Headless / CSP / iframe эвристики
# ============================================================

def _check_headless_fingerprint(js_context: Dict[str, Any]) -> List[str]:
    indicators: List[str] = []

    plugins = js_context.get("navigator_plugins", None)
    if plugins is not None and len(plugins) == 0:
        indicators.append("navigator.plugins пустой")

    webdriver = js_context.get("navigator_webdriver", False)
    if webdriver:
        indicators.append("navigator.webdriver = true")

    languages = js_context.get("navigator_languages", [])
    if isinstance(languages, list) and len(languages) == 0:
        indicators.append("navigator.languages пустой")

    hw_conc = js_context.get("navigator_hardware_concurrency", None)
    if hw_conc is not None and hw_conc <= 2:
        indicators.append(f"низкий hardwareConcurrency: {hw_conc}")

    max_touch = js_context.get("navigator_max_touch_points", None)
    if max_touch is not None and max_touch == 0:
        indicators.append("maxTouchPoints = 0 (headless?)")

    return indicators


def _check_csp(js_context: Dict[str, Any]) -> List[str]:
    indicators: List[str] = []
    headers = js_context.get("headers", "") or ""
    headers_lower = headers.lower()

    if "content-security-policy" in headers:
        indicators.append("обнаружен заголовок CSP")

    if "sandbox" in headers_lower:
        indicators.append("CSP содержит sandbox")

    if "script-src 'none'" in headers_lower:
        indicators.append("CSP: script-src 'none'")

    if "frame-ancestors 'none'" in headers_lower:
        indicators.append("CSP: frame-ancestors 'none'")

    if "require-trusted-types-for 'script'" in headers_lower:
        indicators.append("CSP: require-trusted-types-for 'script'")

    return indicators


def _check_iframe_context(js_context: Dict[str, Any]) -> List[str]:
    indicators: List[str] = []

    iframe_attrs = js_context.get("iframe_attrs", "") or ""
    if "sandbox" in iframe_attrs:
        indicators.append("iframe имеет sandbox")

    window_hierarchy = js_context.get("window_hierarchy", "")
    if window_hierarchy == "nested":
        indicators.append("вложенное окно (iframe)")

    depth = js_context.get("window_depth", 0)
    if isinstance(depth, int) and depth >= 2:
        indicators.append(f"глубина вложенности окна: {depth}")

    return indicators


def _check_restricted_calls(js_context: Dict[str, Any]) -> List[str]:
    indicators: List[str] = []
    restricted = js_context.get("restricted_calls", []) or []
    for call in ["eval", "document.domain", "alert", "Function", "setTimeout"]:
        if call in restricted:
            indicators.append(f"заблокирован вызов: {call}")
    return indicators


# ============================================================
#  Основной детектор
# ============================================================

def detect_sandbox(js_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    SandboxDetector ULTRA 5.0

    js_context (опционально) может содержать:
      {
        "navigator_plugins": [...],
        "navigator_webdriver": bool,
        "navigator_languages": [...],
        "navigator_hardware_concurrency": int,
        "navigator_max_touch_points": int,
        "iframe_attrs": str,
        "headers": str,
        "restricted_calls": [...],
        "window_hierarchy": "nested" | "top",
        "window_depth": int,
      }
    """
    js_context = js_context or {}
    indicators: List[str] = []
    categories: Dict[str, int] = {
        "vm": 0,
        "container": 0,
        "ci": 0,
        "system": 0,
        "network": 0,
        "js": 0,
        "csp": 0,
        "iframe": 0,
        "headless": 0,
    }

    score = 0

    # --- JS / iframe / CSP / headless ---
    headless_indicators = _check_headless_fingerprint(js_context)
    if headless_indicators:
        indicators.extend(headless_indicators)
        categories["headless"] += 3
        score += 3

    csp_indicators = _check_csp(js_context)
    if csp_indicators:
        indicators.extend(csp_indicators)
        categories["csp"] += 2
        score += 2

    iframe_indicators = _check_iframe_context(js_context)
    if iframe_indicators:
        indicators.extend(iframe_indicators)
        categories["iframe"] += 3
        score += 3

    restricted_indicators = _check_restricted_calls(js_context)
    if restricted_indicators:
        indicators.extend(restricted_indicators)
        categories["js"] += 2
        score += 2

    # --- Системные признаки (VM/CI/Docker) ---
    vm_hits = _check_vm_platform()
    if vm_hits:
        indicators.append(f"подозрение на VM по платформе: {', '.join(vm_hits)}")
        categories["vm"] += 3
        score += 3

    vm_files = _check_vm_files()
    if vm_files:
        indicators.append(f"обнаружены VM-маркеры в файловой системе: {', '.join(vm_files)}")
        categories["vm"] += 3
        score += 3

    env_flags = _check_env_flags()
    if env_flags:
        indicators.append(f"обнаружены CI-переменные: {', '.join(env_flags)}")
        categories["ci"] += 3
        score += 3

    docker_hits = _check_docker_files()
    if docker_hits:
        indicators.append(f"обнаружены Docker/Container-маркеры: {', '.join(docker_hits)}")
        categories["container"] += 3
        score += 3

    # --- CPU / RAM / uptime ---
    cpu_count, ram_mb = _check_cpu_ram()
    uptime = _check_uptime_seconds()

    if cpu_count <= 2:
        indicators.append(f"низкое количество CPU: {cpu_count}")
        categories["system"] += 1
        score += 1

    if 0 < ram_mb <= 2048:
        indicators.append(f"низкий объём RAM: ~{ram_mb}MB")
        categories["system"] += 2
        score += 2

    if 0 < uptime <= 120:
        indicators.append(f"низкий uptime системы: {uptime} секунд")
        categories["system"] += 1
        score += 1

    # --- Сетевые ограничения ---
    if _check_network_restrictions():
        indicators.append("ограничения сети/DNS (example.com не резолвится)")
        categories["network"] += 2
        score += 2

    # --- Лёгкий шум, чтобы не быть детерминированным ---
    noise = random.choice([0, 0, 1])
    score += noise
    if noise:
        indicators.append("добавлен небольшой шум в оценку (anti-fingerprint)")

    # --- Итоговая оценка ---
    severity = "низкая"
    if score >= 9:
        severity = "высокая"
    elif score >= 5:
        severity = "средняя"

    sandboxed = score >= 5

    return {
        "sandboxed": sandboxed,
        "score": score,
        "severity": severity,
        "indicators": indicators,
        "categories": categories,
        "timestamp": time.time(),
    }