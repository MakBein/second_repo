# xss_security_gui/auto_recon/user_tracker.py
"""
User Tracker 2.0 — боевой трекер операций и контекста.
Функции:
• Захват информации о пользователе, хоста и среды
• Трэйсинг сессий и фаз операции (Red Team / Recon / Exploit)
• История операций, уязвимостей, ошибок, команд
• Kill Chain / MITRE ATT&CK трэйсинг
• Stealth / Encrypted logging режимы
"""

import json
import socket
import getpass
import os
import uuid
import datetime
import platform
from pathlib import Path
from typing import Dict, Any, Optional, List
import threading

import psutil  # для host fingerprint

from xss_security_gui.settings import LOG_DIR


class UserContext:
    """Контекст пользователя, хоста и сессии (боевой уровень)."""

    def __init__(self):
        # Базовый пользовательский контекст
        self.user_id = getpass.getuser()
        self.hostname = socket.gethostname()
        self.ip_address = self._get_ip_address()
        self.session_id = str(uuid.uuid4())[:8]
        self.session_start = datetime.datetime.now(datetime.UTC)
        self.platform = platform.system()
        self.python_version = platform.python_version()
        self.pid = os.getpid()
        self.environment = os.environ.get("ENV", "dev")

        # Red Team / Operation контекст
        self.operation_name = os.environ.get("OP_NAME", "default_op")
        self.phase = os.environ.get("OP_PHASE", "recon")  # recon / exploit / post / cleanup
        self.operator = os.environ.get("OPERATOR", self.user_id)
        self.operator_role = os.environ.get("OP_ROLE", "red_team")
        self.operator_clearance = os.environ.get("OP_CLEARANCE", "standard")

        # Host fingerprint (как у Beacon)
        self.cpu_count = psutil.cpu_count()
        self.memory_total = psutil.virtual_memory().total
        self.timezone = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo

    def _get_ip_address(self) -> str:
        """Определяет IP адрес машины (боевой, но безопасный)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def to_dict(self) -> Dict[str, Any]:
        """Преобразует контекст в словарь (для логов и отчётов)."""
        return {
            "user_id": self.user_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "session_start": self.session_start.isoformat(),
            "platform": self.platform,
            "python_version": self.python_version,
            "pid": self.pid,
            "environment": self.environment,
            "operation_name": self.operation_name,
            "phase": self.phase,
            "operator": self.operator,
            "operator_role": self.operator_role,
            "operator_clearance": self.operator_clearance,
            "cpu_count": self.cpu_count,
            "memory_total": self.memory_total,
            "timezone": str(self.timezone),
        }

    def __repr__(self) -> str:
        return (
            f"UserContext(user={self.user_id}, op={self.operation_name}, "
            f"phase={self.phase}, session={self.session_id}, ip={self.ip_address})"
        )


class UserTracker:
    """Боевой трекер пользовательских операций, атак и контекста."""

    def __init__(self, log_dir: Optional[Path] = None):
        # Базовый путь логов
        self.log_dir = log_dir or LOG_DIR / "auto_recon" / "users"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.context = UserContext()
        self.history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

        # Основные файлы логов
        self.user_log = self.log_dir / f"{self.context.user_id}_operations.ndjson"
        self.sessions_log = self.log_dir / "sessions.json"

        # Режимы Red Team
        self.stealth = os.environ.get("STEALTH_MODE", "false").lower() == "true"
        self.encrypt_logs = os.environ.get("ENCRYPT_LOGS", "false").lower() == "true"

        # Логирование начала сессии
        self._log_session_start()

    # ==========================
    #  Внутренние утилиты
    # ==========================
    def _write_entry(self, entry: Dict[str, Any]):
        """Пишет запись в лог с учётом stealth/encrypt режимов."""
        with self._lock:
            # Кэш в памяти
            self.history.append(entry)
            if len(self.history) > 2000:
                self.history = self.history[-1000:]

            if self.stealth:
                # В stealth режиме — только память, без диска
                return

            line = json.dumps(entry, ensure_ascii=False)

            # Здесь можно добавить реальное шифрование (AES-256, GCM и т.д.)
            if self.encrypt_logs:
                # Псевдо-шифрование (заглушка)
                line = line[::-1]

            with self.user_log.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def build_attack_surface(self, url: Optional[str] = None) -> Dict[str, Any]:
        """
        Строит полную карту поверхности атаки по событиям.
        Собирает endpoints, параметры, формы, cookies, headers, js_libs, cms, cdn, tls, server.
        """

        surface: Dict[str, Any] = {
            "url": url,
            "endpoints": [],
            "parameters": {},
            "forms": [],
            "cookies": [],
            "headers": [],
            "js_libs": [],
            "cms": None,
            "cdn": None,
            "tls": {},
            "server": None,
            "tech_stack": {},
            "asn": None,
            "geo": {},
            "mitre": [],
        }

        events = self.history

        for e in events:
            if url and e.get("url") != url:
                continue

            et = e.get("event")

            if et == "endpoint_discovered":
                ep = e.get("endpoint")
                if isinstance(ep, str):
                    surface["endpoints"].append(ep)

            elif et == "parameter_discovered":
                p = e.get("param")
                v = e.get("value")
                if isinstance(p, str):
                    surface["parameters"][p] = v

            elif et == "form_discovered":
                form = e.get("form")
                if isinstance(form, dict):
                    surface["forms"].append(form)

            elif et == "cookie_detected":
                cookie = e.get("cookie")
                if isinstance(cookie, dict):
                    surface["cookies"].append(cookie)

            elif et == "header_detected":
                header = e.get("header")
                if isinstance(header, dict):
                    surface["headers"].append(header)

            elif et == "js_libs":
                libs = e.get("libs")
                if isinstance(libs, list):
                    surface["js_libs"].extend([lib for lib in libs if isinstance(lib, str)])

            elif et == "cms_detected":
                cms = e.get("cms")
                if isinstance(cms, str):
                    surface["cms"] = cms

            elif et == "cdn_detected":
                cdn = e.get("cdn")
                if isinstance(cdn, str):
                    surface["cdn"] = cdn

            elif et == "tls_info":
                tls = e.get("tls")
                if isinstance(tls, dict):
                    surface["tls"] = tls

            elif et == "server_fingerprint":
                server = e.get("server")
                if isinstance(server, str):
                    surface["server"] = server

            elif et == "target_info":
                tech = e.get("tech_stack")
                if isinstance(tech, dict):
                    surface["tech_stack"] = tech

                asn = e.get("asn")
                if isinstance(asn, str):
                    surface["asn"] = asn

                geo = e.get("geo")
                if isinstance(geo, dict):
                    surface["geo"] = geo

        # === Дедупликация ===
        surface["endpoints"] = sorted(set(surface["endpoints"]))

        # Headers dedupe (safe)
        safe_headers = []
        for h in surface["headers"]:
            if isinstance(h, dict):
                safe_headers.append(tuple(sorted(h.items())))
        surface["headers"] = [dict(h) for h in set(safe_headers)]

        # Cookies dedupe (safe)
        safe_cookies = []
        for c in surface["cookies"]:
            if isinstance(c, dict):
                safe_cookies.append(tuple(sorted(c.items())))
        surface["cookies"] = [dict(c) for c in set(safe_cookies)]

        # === MITRE Mapping ===
        surface["mitre"] = []
        for ep in surface["endpoints"]:
            surface["mitre"].append({
                "endpoint": ep,
                "tactic": "TA0043",  # Reconnaissance
                "technique": "T1595",  # Active Scanning
                "subtechnique": "T1595.002"  # Vulnerability Scanning
            })

        return surface

    def _log_session_start(self):
        """Логирует начало сессии (как TeamServer)."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "session_start",
            **self.context.to_dict(),
        }
        self._write_entry(entry)

    # ==========================
    #  Основные трэйсеры
    # ==========================
    def track_operation(
        self,
        operation: str,
        details: Optional[Dict[str, Any]] = None,
        target: Optional[str] = None,
        status: str = "success",
    ) -> Dict[str, Any]:
        """
        Отслеживает операцию пользователя (scan, analyze, exploit, cleanup и т.д.).
        """
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "operation",
            "operation": operation,
            "target": target,
            "status": status,
            "details": details or {},
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_vulnerability_found(
        self,
        vuln_type: str,
        url: str,
        severity: str,
        payload: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cvss: Optional[float] = None,
        exploitable: bool = True,
        chainable: bool = False,
    ) -> Dict[str, Any]:
        """Отслеживает найденную уязвимость (Red Team уровень)."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "vulnerability_found",
            "vulnerability_type": vuln_type,
            "url": url,
            "severity": severity,
            "payload": payload,
            "details": details or {},
            "cvss": cvss,
            "exploitable": exploitable,
            "chainable": chainable,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_error(
        self,
        error_type: str,
        message: str,
        operation: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Отслеживает ошибки (боевой контекст)."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "error",
            "error_type": error_type,
            "message": message,
            "operation": operation,
            "target": target,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_exec(
        self,
        command: str,
        args: Optional[List[str]] = None,
        exit_code: Optional[int] = None,
        output: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Отслеживает выполнение команды (как Beacon / Agent)."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "exec",
            "command": command,
            "args": args or [],
            "exit_code": exit_code,
            "output": output,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_target_info(
            self,
            url: str,
            tech_stack: Optional[Dict[str, Any]] = None,
            waf: Optional[str] = None,
            asn: Optional[str] = None,
            geo: Optional[Dict[str, Any]] = None,
            tls: Optional[Dict[str, Any]] = None,
            cdn: Optional[str] = None,
            cms: Optional[str] = None,
            js_libs: Optional[List[str]] = None,
            server: Optional[str] = None,
            ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Отслеживает расширенную информацию о цели (Target Intelligence)."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "target_info",
            "url": url,
            "ip": ip,
            "server": server,
            "tech_stack": tech_stack or {},
            "waf": waf,
            "asn": asn,
            "geo": geo or {},
            "tls": tls or {},
            "cdn": cdn,
            "cms": cms,
            "js_libs": js_libs or [],
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_attack_chain(
            self,
            tactic: str,
            technique: str,
            subtechnique: Optional[str] = None,
            target: Optional[str] = None,
            phase: Optional[str] = None,
            status: str = "executed",
            risk: Optional[str] = None,
            exploitable: Optional[bool] = None,
            chainable: Optional[bool] = None,
            payload: Optional[str] = None,
            duration_ms: Optional[int] = None,
            details: Optional[Dict[str, Any]] = None,
            operator_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Боевой трекер этапов атаки (MITRE ATT&CK + Kill Chain).
        Используется для Recon → Initial Access → Execution → PrivEsc → Lateral Movement → Impact.
        """

        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "attack_chain",

            # MITRE ATT&CK
            "tactic": tactic,  # TA0001…TA0011
            "technique": technique,  # T1059, T1190, T1595…
            "subtechnique": subtechnique,  # T1059.001

            # Target context
            "target": target,
            "phase": phase or self.context.phase,

            # Execution metadata
            "status": status,  # executed / blocked / detected / failed
            "duration_ms": duration_ms,
            "payload": payload,

            # Risk & exploitability
            "risk": risk,
            "exploitable": exploitable,
            "chainable": chainable,

            # Operator metadata
            "operator_note": operator_note,

            # Additional details
            "details": details or {},

            # Full operator + host context
            **self.context.to_dict(),
        }

        self._write_entry(entry)
        return entry

    def add_note(
            self,
            text: str,
            target: Optional[str] = None,
            phase: Optional[str] = None,
            importance: str = "info",  # info / warning / critical
            tag: Optional[str] = None,  # recon / exploit / post / cleanup
            tactic: Optional[str] = None,  # TAxxxx
            technique: Optional[str] = None,  # Txxxx
    ) -> Dict[str, Any]:
        """
        Добавляет операторскую заметку (Red Team Ops уровень).
        Поддерживает MITRE, фазы операции, теги и важность.
        """

        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "operator_note",
            "text": text,
            "importance": importance,
            "tag": tag,
            "target": target,
            "phase": phase or self.context.phase,
            "tactic": tactic,
            "technique": technique,
            "operator": self.context.operator,
            **self.context.to_dict(),
        }

        self._write_entry(entry)
        return entry

    def rotate_session(
            self,
            reason: str,
            new_phase: Optional[str] = None,
            new_target: Optional[str] = None,
            opsec_mode: Optional[str] = None,  # low / medium / high
            payload_policy: Optional[str] = None,  # safe / aggressive / stealth
            operator: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ротирует session_id (Red Team Ops уровень).
        Поддерживает смену фазы, цели, оператора и OPSEC режима.
        """

        old_session = self.context.session_id
        self.context.session_id = str(uuid.uuid4())[:8]

        if new_phase:
            self.context.phase = new_phase

        if operator:
            self.context.operator = operator

        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "session_rotated",
            "old_session": old_session,
            "new_session": self.context.session_id,
            "reason": reason,
            "new_phase": new_phase or self.context.phase,
            "new_target": new_target,
            "opsec_mode": opsec_mode,
            "payload_policy": payload_policy,
            "operator": self.context.operator,
            **self.context.to_dict(),
        }

        self._write_entry(entry)
        return entry

    # ==========================
    #  История и отчёты
    # ==========================
    def get_user_history(
            self,
            limit: int = 200,
            event_types: Optional[List[str]] = None,
            phase: Optional[str] = None,
            target: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Возвращает историю событий с фильтрами (Red Team уровень).
        event_types: ["operation", "vulnerability_found", "attack_chain", ...]
        phase: recon / exploit / post / cleanup
        target: конкретный URL или хост
        """

        events = self.history[-limit:]

        if event_types:
            events = [e for e in events if e.get("event") in event_types]

        if phase:
            events = [e for e in events if e.get("phase") == phase]

        if target:
            events = [e for e in events if e.get("target") == target]

        return events

    def save_session_report(self) -> Path:
        """
        Сохраняет расширенный отчёт сессии (Red Team Ops уровень).
        Включает Kill Chain, MITRE, Target Intelligence, Vulnerabilities, Notes.
        """

        # Категоризация событий
        kill_chain = self.get_user_history(event_types=["attack_chain"], limit=1000)
        vulns = self.get_user_history(event_types=["vulnerability_found"], limit=1000)
        ops = self.get_user_history(event_types=["operation"], limit=1000)
        notes = self.get_user_history(event_types=["operator_note"], limit=1000)
        errors = self.get_user_history(event_types=["error"], limit=1000)
        target_info = self.get_user_history(event_types=["target_info"], limit=1000)
        exec_events = self.get_user_history(event_types=["exec"], limit=1000)
        rotations = self.get_user_history(event_types=["session_rotated"], limit=1000)

        session_report = {
            "user_context": self.context.to_dict(),
            "session_duration_sec": (
                    datetime.datetime.now(datetime.UTC) - self.context.session_start
            ).total_seconds(),
            "saved_at": datetime.datetime.now(datetime.UTC).isoformat(),

            # Основные категории
            "operations": ops,
            "vulnerabilities": vulns,
            "kill_chain": kill_chain,
            "target_intel": target_info,
            "exec_trace": exec_events,
            "notes": notes,
            "errors": errors,
            "session_rotations": rotations,

            # Статистика
            "stats": {
                "total_events": len(self.history),
                "operations": len(ops),
                "vulnerabilities": len(vulns),
                "kill_chain_events": len(kill_chain),
                "notes": len(notes),
                "errors": len(errors),
                "targets_profiled": len(target_info),
            },
        }

        filename = (
            f"session_{self.context.session_id}_"
            f"{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d_%H%M%S')}.json"
        )
        path = self.log_dir / filename

        with path.open("w", encoding="utf-8") as f:
            json.dump(session_report, f, indent=2, ensure_ascii=False)

        return path

    # ==========================
    #  Target Intelligence
    # ==========================

    def track_tls_info(self, url: str, tls: Dict[str, Any]):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "tls_info",
            "url": url,
            "tls": tls,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_cdn(self, url: str, cdn: str):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "cdn_detected",
            "url": url,
            "cdn": cdn,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_cms(self, url: str, cms: str):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "cms_detected",
            "url": url,
            "cms": cms,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_js_libs(self, url: str, libs: List[str]):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "js_libs",
            "url": url,
            "libs": libs,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_server(self, url: str, server: str):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "server_fingerprint",
            "url": url,
            "server": server,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    # ==========================
    #  Attack Surface
    # ==========================

    def track_attack_surface(self, url: str, surface: Dict[str, Any]):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "attack_surface",
            "url": url,
            "surface": surface,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_endpoint(self, url: str, endpoint: str):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "endpoint_discovered",
            "url": url,
            "endpoint": endpoint,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_parameter(self, url: str, param: str, value: Any):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "parameter_discovered",
            "url": url,
            "param": param,
            "value": value,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_form(self, url: str, form: Dict[str, Any]):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "form_discovered",
            "url": url,
            "form": form,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_cookie(self, url: str, cookie: Dict[str, Any]):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "cookie_detected",
            "url": url,
            "cookie": cookie,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry

    def track_header(self, url: str, header: Dict[str, Any]):
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": "header_detected",
            "url": url,
            "header": header,
            **self.context.to_dict(),
        }
        self._write_entry(entry)
        return entry


    def load_user_history(
            self,
            user_id: Optional[str] = None,
            limit: int = 2000,
            classify: bool = True,
            decrypt: bool = True,
    ) -> Dict[str, Any]:
        """
        Загружает и классифицирует историю событий (Red Team Ops уровень).
        Возвращает структурированный отчёт:
        - operations
        - vulnerabilities
        - kill_chain
        - target_intel
        - exec_trace
        - notes
        - errors
        - session_rotations
        """

        user_id = user_id or self.context.user_id
        user_log = self.log_dir / f"{user_id}_operations.ndjson"

        if not user_log.exists():
            return {
                "operations": [],
                "vulnerabilities": [],
                "kill_chain": [],
                "target_intel": [],
                "exec_trace": [],
                "notes": [],
                "errors": [],
                "session_rotations": [],
                "raw": [],
            }

        raw_events: List[Dict[str, Any]] = []

        try:
            with user_log.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    if decrypt and self.encrypt_logs:
                        line = line[::-1]  # псевдо-расшифровка

                    try:
                        raw_events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            # Ограничение
            raw_events = raw_events[-limit:]

            if not classify:
                return {"raw": raw_events}

            # ==========================
            #  Классификация событий
            # ==========================
            operations = []
            vulnerabilities = []
            kill_chain = []
            target_intel = []
            exec_trace = []
            notes = []
            errors = []
            session_rotations = []

            for e in raw_events:
                et = e.get("event")

                if et == "operation":
                    operations.append(e)
                elif et == "vulnerability_found":
                    vulnerabilities.append(e)
                elif et == "attack_chain":
                    kill_chain.append(e)
                elif et == "target_info":
                    target_intel.append(e)
                elif et == "exec":
                    exec_trace.append(e)
                elif et in ("note", "operator_note"):
                    notes.append(e)
                elif et == "error":
                    errors.append(e)
                elif et == "session_rotated":
                    session_rotations.append(e)

            return {
                "operations": operations,
                "vulnerabilities": vulnerabilities,
                "kill_chain": kill_chain,
                "target_intel": target_intel,
                "exec_trace": exec_trace,
                "notes": notes,
                "errors": errors,
                "session_rotations": session_rotations,
                "raw": raw_events,
            }

        except Exception:
            return {
                "operations": [],
                "vulnerabilities": [],
                "kill_chain": [],
                "target_intel": [],
                "exec_trace": [],
                "notes": [],
                "errors": [],
                "session_rotations": [],
                "raw": [],
            }


# Глобальный экземпляр (как TeamServer-level tracker)
_global_tracker = UserTracker()


def get_user_tracker() -> UserTracker:
    """Возвращает глобальный боевой tracker."""
    return _global_tracker


class OperationalContext:
    """Расширенный контекст атаки (Red Team Ops уровень)."""

    def __init__(self, user_ctx: UserContext):
        self.user = user_ctx
        self.current_target: Optional[str] = None
        self.current_phase: str = user_ctx.phase
        self.current_tactic: Optional[str] = None
        self.current_technique: Optional[str] = None
        self.current_subtechnique: Optional[str] = None
        self.opsec_mode: str = "medium"      # low / medium / high
        self.payload_policy: str = "safe"    # safe / aggressive / stealth
        self.threat_level: str = "unknown"   # low / medium / high / critical
        self.attack_surface: Dict[str, Any] = {}
        self.last_event: Optional[Dict[str, Any]] = None

    def to_dict(self):
        return {
            "user": self.user.to_dict(),
            "current_target": self.current_target,
            "current_phase": self.current_phase,
            "current_tactic": self.current_tactic,
            "current_technique": self.current_technique,
            "current_subtechnique": self.current_subtechnique,
            "opsec_mode": self.opsec_mode,
            "payload_policy": self.payload_policy,
            "threat_level": self.threat_level,
            "attack_surface": self.attack_surface,
            "last_event": self.last_event,
        }

_global_operational_context = OperationalContext(_global_tracker.context)

def get_user_context() -> OperationalContext:
    """Возвращает расширенный контекст атаки (Red Team Ops уровень)."""
    return _global_operational_context

def build_attack_surface(url: Optional[str] = None) -> Dict[str, Any]:
    """Глобальная обёртка для сборки поверхности атаки."""
    return _global_tracker.build_attack_surface(url)


__all__ = [
    "UserContext",
    "UserTracker",
    "OperationalContext",
    "get_user_tracker",
    "get_user_context",
    "build_attack_surface",
]






