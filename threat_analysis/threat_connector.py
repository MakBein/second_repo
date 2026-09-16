# xss_security_gui/threat_analysis/threat_connector.py
"""
    ThreatConnector 11.0 — Combat‑Grade Threat Pipeline Core
    ---------------------------------------------------------
    • Full Pipeline 11.0 normalization
    • async queue + batched writes
    • throttling per second
    • threat‑query API (delegates to backend)
    • LiveAttackMonitor / SecurityDashboardPanel / HistoryTab compatible
    """
import os
import json
import socket
import sqlite3
import uuid
import subprocess
import threading
import hashlib
import logging
import queue
from datetime import datetime, timezone
from time import time
from typing import Dict, Any, List, Optional
from queue import Queue, Empty
from urllib.parse import urlparse

import requests
import shodan

from xss_security_gui.threat_analysis.account_extractor import AccountExtractor

from xss_security_gui.threat_analysis.backends.base_backend import ThreatBackendBase
from xss_security_gui.threat_analysis.backends.sqlite_backend import SQLiteBackend
from xss_security_gui.threat_analysis.backends.elastic_backend import ElasticSearchBackend

LIVE_MONITOR_QUEUE: "queue.Queue[dict]" = queue.Queue()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)


def normalize_xss_artifact(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "category": entry.get("category", "unknown"),
        "context": entry.get("context", "unknown"),
        "payload": entry.get("payload", ""),
        "url": entry.get("url", "—"),
        "snippet": entry.get("snippet", ""),
        "risk": entry.get("risk", "medium"),
        "parameter": entry.get("parameter"),
        "method": entry.get("method"),
        "status_code": entry.get("status_code"),
        "reflected": entry.get("reflected"),
        "length": entry.get("length"),
        "full_response": entry.get("full_response"),
        "timestamp": entry.get("timestamp") or datetime.utcnow().isoformat(),
        "source": entry.get("source", "xss_engine"),
        "iid": entry.get("iid"),
        "ai_score": entry.get("ai_score"),
        "ai_label": entry.get("ai_label"),
        "context_confidence": entry.get("context_confidence"),
        "parent_url": entry.get("parent_url"),
        "chain": entry.get("chain"),
        "waf_detected": entry.get("waf_detected"),
        "waf_signature": entry.get("waf_signature"),
        "line": entry.get("line"),
        "column": entry.get("column"),
    }


class ThreatConnector:
    """
    ThreatConnector 11.0 — Combat‑Grade Threat Pipeline Core
    """

    def __init__(
        self,
        backend: ThreatBackendBase,
        batch_size: int = 50,
        flush_interval: float = 1.0,
        max_events_per_sec: int = 200,
    ):
        self.backend = backend
        self.log = logging.getLogger("ThreatConnector")
        self.log.setLevel(logging.INFO)

        self._hash_cache: set[str] = set()
        self._hash_lock = threading.Lock()
        self._load_initial_hashes()

        self._queue: "Queue[Dict[str, Any]]" = Queue()
        self._batch_size = max(1, batch_size)
        self._flush_interval = max(0.1, flush_interval)

        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="ThreatConnectorWorker",
            daemon=True,
        )
        self._worker_thread.start()

        # External integrations (optional)
        self.gui_handler = None
        self.siem_connector = None
        self.dlq = None

        # Optional enrichment cache
        self.enrichment_cache = {}

        # OpenPhish feed cache to avoid frequent network calls
        self._openphish_cache = {"ts": 0, "domains": set()}

        # Optional internal hosts correlation
        self.internal_hosts_handler = None

        self._max_events_per_sec = max_events_per_sec
        self._throttle_lock = threading.Lock()
        self._current_second = int(time())
        self._events_this_second = 0

        self.artifacts: List[Dict[str, Any]] = []

    def _load_initial_hashes(self) -> None:
        try:
            for a in self.backend.load_all():
                h = a.get("_hash")
                if h:
                    with self._hash_lock:
                        self._hash_cache.add(h)
        except Exception:
            self.log.warning("Failed to preload hashes from backend", exc_info=True)

    def _hash_artifact(self, module: str, target: str, result: Dict[str, Any]) -> str:
        h = hashlib.sha256()
        h.update(module.encode())
        h.update(target.encode())
        h.update(json.dumps(result, sort_keys=True, default=str).encode())
        return h.hexdigest()

    def _throttle(self) -> bool:
        now = int(time())
        with self._throttle_lock:
            if now != self._current_second:
                self._current_second = now
                self._events_this_second = 0
            if self._events_this_second >= self._max_events_per_sec:
                return False
            self._events_this_second += 1
            return True

    def ingest_artifact(self, artifact: Dict[str, Any]) -> None:
        try:
            module = artifact.get("module", "unknown")
            result = artifact.get("result", {}) or {}
            target = result.get("target") or module.lower()

            self.artifacts.append({
                "module": module,
                "target": target,
                "result": result,
            })

            self.emit(module, target, result)

            cb = getattr(self, "on_event", None)
            if callable(cb):
                cb("threat_connector_ingest_ultra", {
                    "module": module,
                    "target": target,
                    "result": result,
                })

        except Exception:
            self.log.error("[ThreatConnector] ingest_artifact error", exc_info=True)

    def emit(self, module: str, target: str, result: Dict[str, Any]) -> None:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        result = dict(result)
        result.setdefault("severity", "info")
        result.setdefault("category", module.lower())
        result.setdefault("tags", [])
        result.setdefault("source", "engine")

        h = self._hash_artifact(module, target, result)
        with self._hash_lock:
            if h in self._hash_cache:
                return
            self._hash_cache.add(h)

        artifact = {
            "_hash": h,
            "timestamp": timestamp,
            "module": module,
            "target": target,
            "result": result,
        }

        if not self._throttle():
            self.log.debug("ThreatConnector: throttled emit for %s → %s", module, target)
            return

        self._queue.put(artifact)

        try:
            event = {
                "module": module,
                "target": target,
                "severity": result.get("severity", "info"),
                "category": result.get("category", ""),
                "data": result,
                "timestamp": timestamp,
            }
            LIVE_MONITOR_QUEUE.put_nowait(event)
        except Exception:
            pass

    def _check_shodan(self, target: str) -> Optional[Dict]:
        """Check target against Shodan API with improved resolution and error handling."""
        try:
            shodan_api_key = os.getenv("SHODAN_API_KEY")
            if not shodan_api_key or not target:
                return None

            # Extract hostname (strip port) if URL provided
            hostname = target
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname or parsed.netloc

            ip = hostname
            # Try to resolve to an IP address (non-fatal)
            try:
                infos = socket.getaddrinfo(hostname, None)
                if infos:
                    ip = infos[0][4][0]
            except Exception:
                # resolution failed, continue using hostname
                pass

            api = shodan.Shodan(shodan_api_key)
            results = api.host(ip)

            # Extract relevant security information
            vulns = results.get('vulns') or {}
            ports = results.get('ports') or []
            org = results.get('org') or results.get('isp') or 'Unknown'
            asn = results.get('asn', 'Unknown')

            # Normalize vulnerabilities list
            cve_list = [v for v in (vulns if isinstance(vulns, (list, set, dict)) else []) if isinstance(v, str) and v.startswith('CVE-')]

            return {
                "shodan": {
                    "ip": ip,
                    "ports": ports,
                    "vulnerabilities": cve_list,
                    "organization": org,
                    "asn": asn,
                    "last_seen": results.get('last_update')
                },
                "source": "shodan"
            }

        except shodan.APIError as e:
            self.log.warning(f"Shodan API error for {target}: {e}")
            return None

        except Exception as e:
            self.log.error(f"Shodan check failed: {e}")
            return None

    def _check_openphish(self, artifact_data: Dict) -> Optional[Dict]:
        """Check against OpenPhish phishing database with simple caching and robust parsing."""
        try:
            ttl = int(os.getenv('OPENPHISH_TTL', '3600'))  # seconds
            now_ts = int(time())

            # Refresh cache if stale
            if (now_ts - self._openphish_cache.get('ts', 0)) > ttl or not self._openphish_cache.get('domains'):
                openphish_url = "https://openphish.com/feed.txt"
                try:
                    response = requests.get(openphish_url, timeout=10)
                    response.raise_for_status()
                    domains = set()
                    for line in response.text.splitlines():
                        v = line.strip()
                        if not v:
                            continue
                        # If feed contains full URLs, extract hostname
                        try:
                            d = urlparse(v).netloc or v
                            if d:
                                # strip possible ports
                                domains.add(d.split(':')[0])
                        except Exception:
                            domains.add(v)

                    self._openphish_cache['domains'] = domains
                    self._openphish_cache['ts'] = now_ts
                except Exception as e:
                    self.log.warning(f"OpenPhish fetch failed: {e}")

            phishing_domains = self._openphish_cache.get('domains', set())

            # Collect candidate URLs from artifact
            urls_to_check = []
            if isinstance(artifact_data.get('url'), str):
                urls_to_check.append(artifact_data['url'])
            if isinstance(artifact_data.get('js_files'), (list, tuple)):
                urls_to_check.extend([u for u in artifact_data.get('js_files') if isinstance(u, str)])

            matches = []
            for url in urls_to_check:
                try:
                    domain = urlparse(url).netloc.split(':')[0]
                except Exception:
                    domain = url
                if domain in phishing_domains:
                    matches.append(domain)

            if matches:
                return {
                    "openphish": {
                        "matches": sorted(set(matches)),
                        "severity": "high"
                    },
                    "source": "openphish"
                }

            return None

        except Exception as e:
            self.log.warning(f"OpenPhish check failed: {e}")
            return None

    def _check_urlhaus(self, target: str) -> Optional[Dict]:
        """Check URL against URLhaus malware database (robust handling)."""
        try:
            # Accept either full URL or domain
            if not target:
                return None

            urlhaus_api = "https://urlhaus-api.abuse.ch/v1/url/"
            payload = {'url': target, 'format': 'json'}

            try:
                response = requests.post(urlhaus_api, data=payload, timeout=10)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                # Some environments prefer GET with query param; fallback
                try:
                    response = requests.get(urlhaus_api, params=payload, timeout=10)
                    response.raise_for_status()
                    data = response.json()
                except Exception as ex:
                    self.log.warning(f"URLhaus request failed for {target}: {e} / {ex}")
                    return None

            # URLhaus returns query_status and possibly a 'urls' list in other endpoints
            status = data.get('query_status') or data.get('status')
            if status and status.lower() == 'ok':
                # handle different result shapes
                if data.get('result') == 'found' or data.get('data'):
                    payloads = data.get('payloads') or data.get('data') or []
                    threat_type = data.get('threat_type') or (payloads[0].get('threat') if payloads and isinstance(payloads, list) and isinstance(payloads[0], dict) else None)
                    reporter = data.get('reporter') or None
                    firstseen = data.get('firstseen') or None

                    return {
                        "urlhaus": {
                            "threat_type": threat_type,
                            "payloads": payloads,
                            "reporter": reporter,
                            "firstseen": firstseen
                        },
                        "source": "urlhaus"
                    }

            return None

        except Exception as e:
            self.log.warning(f"URLhaus check failed: {e}")
            return None

    def _block_ip(self, ip: str) -> bool:
        """Block IP with configurable mode. Defaults to simulated safe mode.

        BLOCK_MODE env var values:
          - simulate (default) : don't run privileged commands, only log
          - iptables            : attempt iptables rules on posix
          - netsh               : attempt Windows netsh rule
          - aws                 : attempt AWS NACL entry if AWS_NETWORK_ACL_ID present
        """
        try:
            if not ip:
                return False

            mode = os.getenv('BLOCK_MODE', 'simulate').lower()

            # Safety: default to simulate unless explicitly set
            if mode == 'simulate':
                self.log.info(f"[BLOCK_SIM] would block {ip} (simulate mode)")
                return True

            if mode == 'iptables':
                if os.name != 'posix':
                    self.log.warning('iptables mode requested but not posix platform')
                    return False
                try:
                    subprocess.run(["/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    subprocess.run(["/sbin/iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
                except FileNotFoundError:
                    # Fallback to sudo iptables if present
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)

            elif mode == 'netsh':
                if os.name != 'nt':
                    self.log.warning('netsh mode requested but not Windows platform')
                    return False
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                "name=BlockIP", "dir=in",
                                "action=block", f"remoteip={ip}"], check=True)

            elif mode == 'aws':
                # Requires AWS_NETWORK_ACL_ID and boto3 installed and credentials configured
                try:
                    import boto3
                    net_acl = os.getenv('AWS_NETWORK_ACL_ID')
                    if not net_acl:
                        self.log.warning('AWS_NETWORK_ACL_ID not set; cannot block in AWS')
                    else:
                        ec2 = boto3.client('ec2')
                        ec2.create_network_acl_entry(
                            NetworkAclId=net_acl,
                            RuleNumber=32767,
                            Protocol='-1',
                            RuleAction='deny',
                            Egress=False,
                            CidrBlock=f"{ip}/32"
                        )
                except Exception as e:
                    self.log.error(f"Failed to block IP via AWS: {e}")
                    return False

            else:
                self.log.warning(f'Unknown BLOCK_MODE: {mode}')
                return False

            # Optional: notify GUI or SIEM
            try:
                if hasattr(self, "gui_handler") and callable(getattr(self.gui_handler, 'update_threat', None)):
                    self.gui_handler.update_threat({"event": "ip_block", "ip": ip, "timestamp": datetime.utcnow().isoformat()})
            except Exception:
                pass

            try:
                if hasattr(self, "siem_connector") and callable(getattr(self.siem_connector, 'send', None)):
                    self.siem_connector.send({"event": "ip_block", "ip": ip, "timestamp": datetime.utcnow().isoformat()})
            except Exception:
                pass

            return True

        except subprocess.CalledProcessError as e:
            self.log.error(f"IP block command failed: {e}")
            return False
        except Exception as e:
            self.log.error(f"IP blocking failed: {e}")
            return False

    def add_artifact_batch(self, module_name: str, target: str, results: List[Dict[str, Any]]) -> None:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        for result in results:
            result.setdefault("severity", "info")
            result.setdefault("category", module_name.lower())
            result.setdefault("tags", [])
            result.setdefault("source", "engine")
            result.setdefault("timestamp", timestamp)

            if result.get("category") == "ssrf_candidate":
                result["type"] = "ssrf_event"
                result["group"] = "SSRF"
                result["risk"] = result.get("risk", result.get("severity", "info"))

                final_host = result.get("final_host")
                ports = result.get("internal_port_scan", [])
                if final_host:
                    try:
                        from xss_security_gui.threat_analysis.internal_hosts_tab import INTERNAL_HOSTS_TAB
                        INTERNAL_HOSTS_TAB.add_internal_host(final_host, ports)
                    except Exception as e:
                        self.log.warning(f"InternalHosts correlation failed: {e}")

            h = self._hash_artifact(module_name, target, result)
            with self._hash_lock:
                if h in self._hash_cache:
                    continue
                self._hash_cache.add(h)

            artifact = {
                "_hash": h,
                "timestamp": timestamp,
                "module": module_name,
                "target": target,
                "result": result,
            }

            if not self._throttle():
                self.log.debug("ThreatConnector: throttled add_artifact for %s → %s", module_name, target)
                continue

            self._queue.put(artifact)

            try:
                sev = result.get("severity", "info").upper()
                self.log.info(f"[TI] + Artifact ({module_name}) [{sev}] → {target}")
            except Exception:
                pass

    def add_artifact(self, art: Dict[str, Any]) -> None:
        """
        Enhanced threat intelligence artifact processing with:
        - Multiple threat intelligence backends
        - Local threat database storage
        - Real-time enrichment
        - Correlation analysis
        - Automated response triggers
        - Account Intelligence (email, password, phone, card)
        """
        try:
            # ============================================================
            # 1. Basic artifact validation and default enrichment
            # ============================================================
            if not isinstance(art, dict):
                raise ValueError("Artifact must be a dictionary")

            # Ensure required fields exist
            art.setdefault("module", "unknown")
            art.setdefault("target", "unknown")
            art.setdefault("timestamp", time.time())
            art.setdefault("risk", "medium")
            art.setdefault("status", "new")

            # Extract core fields
            module = art["module"]
            target = art["target"]
            result = art.get("result", {})
            risk_level = art.get("risk", "medium")
            source_ip = art.get("source_ip")
            user_agent = art.get("user_agent")

            # ============================================================
            # 2. Threat Intelligence Enrichment (VirusTotal, AbuseIPDB, etc.)
            # ============================================================
            threat_feeds = [
                self._check_virus_total(result),
                self._check_abuse_ipdb(source_ip),
                self._check_shodan(target),
                self._check_openphish(result),
                self._check_urlhaus(target)
            ]

            # Aggregate threat intelligence results
            threat_data = {
                "vt_score": next((f["score"] for f in threat_feeds if f and "score" in f), None),
                "abuse_ipdb": next((f for f in threat_feeds if f and isinstance(f, dict) and "abuse_ipdb" in f), None),
                "shodan": next((f for f in threat_feeds if f and isinstance(f, dict) and "shodan" in f), None),
                "openphish": next((f for f in threat_feeds if f and isinstance(f, dict) and "openphish" in f), None),
                "urlhaus": next((f for f in threat_feeds if f and isinstance(f, dict) and "urlhaus" in f), None)
            }

            # Attach enrichment data
            art["threat_intel"] = threat_data
            art["enriched"] = True

            # ============================================================
            # 2.1 Account Intelligence (email, password, phone, card)
            # ============================================================
            try:
                extractor = AccountExtractor(art)
                accounts = extractor.extract()

                if accounts:
                    best = max(accounts, key=lambda a: a.get("risk", 0))
                    art["email"] = best.get("email")
                    art["password"] = best.get("password")
                    art["phone"] = best.get("phone")
                    art["credit_card"] = best.get("credit_card")
                else:
                    art["email"] = None
                    art["password"] = None
                    art["phone"] = None
                    art["credit_card"] = None

            except Exception as e:
                self.log.error(f"AccountExtractor failed: {e}")
                art["email"] = None
                art["password"] = None
                art["phone"] = None
                art["credit_card"] = None

            # ============================================================
            # 3. Risk Assessment & Correlation
            # ============================================================
            risk_score = self._calculate_risk_score(art, threat_data)

            # Update risk level based on composite score
            if risk_score >= 8:
                art["risk"] = "critical"
            elif risk_score >= 6:
                art["risk"] = "high"
            elif risk_score >= 4:
                art["risk"] = "medium"
            else:
                art["risk"] = "low"

            # ============================================================
            # 4. Automated Response Triggers (SOC, firewall, watchlist)
            # ============================================================
            if art["risk"] in ["high", "critical"]:
                self._trigger_response(art)

            # ============================================================
            # 5. Storage & Distribution
            # ============================================================
            # Store artifact in local threat database (SQLite)
            self._store_threat(art)

            # ============================================================
            # 5.1 Live PII Update → RealTimeWatcher / GUI
            # ============================================================
            try:
                LIVE_MONITOR_QUEUE.put_nowait({
                    "event": "pii_update",
                    "email": art.get("email"),
                    "password": art.get("password"),
                    "phone": art.get("phone"),
                    "credit_card": art.get("credit_card"),
                    "timestamp": datetime.utcnow().isoformat()
                })
            except Exception:
                pass

            # Emit to ThreatConnector pipeline (DB + LiveMonitorQueue)
            self.emit(module, target, result)

            # Forward to SIEM if configured
            if hasattr(self, 'siem_connector'):
                self.siem_connector.send(art)

            # Update GUI if available
            if hasattr(self, 'gui_handler'):
                self.gui_handler.update_threat(art)

            self.log.info(
                f"[ThreatConnector] Processed artifact {art.get('id', 'unknown')} "
                f"with risk {art['risk']}"
            )

        except Exception as e:
            # ============================================================
            # 6. Error Handling + Dead Letter Queue
            # ============================================================
            self.log.error(f"[ThreatConnector] add_artifact error: {e}", exc_info=True)

            # Store failed artifacts in DLQ (dead letter queue)
            if hasattr(self, 'dlq'):
                self.dlq.add(art, str(e))

    def bulk(self, module: str, target: str, results: List[Dict[str, Any]]) -> None:
        """Backwards-compatible bulk ingestion.

        Delegates to add_artifact_batch which implements the project's batching
        and enrichment flow.
        """
        try:
            if not isinstance(results, list):
                raise ValueError("results must be a list of artifact dicts")

            # Normalize results items to dicts if necessary and delegate
            sanitized = []
            for r in results:
                if not isinstance(r, dict):
                    continue
                sanitized.append(r)

            if not sanitized:
                self.log.debug("bulk called with no valid artifacts")
                return

            self.add_artifact_batch(module, target, sanitized)
        except Exception as e:
            self.log.error(f"bulk ingestion failed: {e}", exc_info=True)

    def _check_virus_total(self, artifact_data: Dict) -> Optional[Dict]:
        """Check artifact against VirusTotal API."""
        try:
            vt_api_key = os.getenv("VT_API_KEY")
            if not vt_api_key:
                return None

            # Determine what to check based on artifact type
            if "url" in artifact_data:
                url_id = hashlib.sha256(artifact_data["url"].encode()).hexdigest()
                params = {"apikey": vt_api_key, "resource": url_id}
                response = requests.get(
                    "https://www.virustotal.com/api/v3/urls",
                    params=params
                )

            elif "ip" in artifact_data:
                params = {"apikey": vt_api_key, "ip": artifact_data["ip"]}
                response = requests.get(
                    "https://www.virustotal.com/api/v3/ip_addresses",
                    params=params
                )

            else:
                return None

            response.raise_for_status()
            data = response.json()

            return {
                "score": data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0),
                "source": "virustotal"
            }

        except Exception as e:
            self.log.warning(f"VirusTotal check failed: {e}")
            return None

    def _check_abuse_ipdb(self, ip: str) -> Optional[Dict]:
        """Check IP against AbuseIPDB."""
        try:
            api_key = os.getenv("ABUSEIPDB_API_KEY")
            if not api_key or not ip:
                return None

            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": api_key, "Accept": "application/json"}
            )

            response.raise_for_status()
            data = response.json()

            abuse_confidence = data.get("data", {}).get("abuseConfidenceScore", 0)

            return {
                "abuse_ipdb": {
                    "score": abuse_confidence,
                    "country": data.get("data", {}).get("countryCode"),
                    "isp": data.get("data", {}).get("isp")
                },
                "source": "abuseipdb"
            }

        except Exception as e:
            self.log.warning(f"AbuseIPDB check failed: {e}")
            return None

    def _calculate_risk_score(self, artifact: Dict, threat_data: Dict) -> float:
        """Calculate composite risk score (0–10)."""

        base_score = 0

        # Base risk from artifact
        risk_map = {"low": 1, "medium": 3, "high": 6, "critical": 10}
        base_score += risk_map.get(artifact.get("risk", "medium"), 3)

        # Add from threat intelligence
        if threat_data.get("vt_score", 0) > 5:
            base_score += 3

        if threat_data.get("abuse_ipdb", {}).get("score", 0) > 50:
            base_score += 2

        if threat_data.get("shodan", {}).get("vulnerabilities"):
            base_score += 2

        # Add for sensitive data types
        sensitive_types = ["secret_leak", "pii_leak", "suspicious_network"]
        if artifact.get("category") in sensitive_types:
            base_score += 2

        return min(base_score, 10)  # Cap at 10

    def _trigger_response(self, artifact: Dict) -> None:
        """Automated response triggers."""
        try:
            # Critical risk → immediate action
            if artifact["risk"] == "critical":
                if "source_ip" in artifact:
                    self._block_ip(artifact["source_ip"])  # Firewall block

                self._send_alert(artifact, "critical")  # SOC alert

            # High risk → watchlist + SOC alert
            elif artifact["risk"] == "high":
                self._add_to_watchlist(artifact)
                self._send_alert(artifact, "high")

        except Exception as e:
            self.log.error(f"Response trigger failed: {e}")

    def _send_alert(self, artifact: Dict, level: str) -> bool:
        """Send real security alert via multiple channels"""
        try:
            # Format timestamp safely
            ts = artifact.get('timestamp')
            try:
                # If timestamp is numeric
                from datetime import datetime
                if isinstance(ts, (int, float)):
                    ts_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    ts_str = str(ts)
            except Exception:
                ts_str = str(ts)

            alert_message = (
                f"🚨 SECURITY ALERT ({level.upper()}) 🚨\n"
                f"Module: {artifact.get('module', 'unknown')}\n"
                f"Target: {artifact.get('target', 'unknown')}\n"
                f"Category: {artifact.get('category', 'unknown')}\n"
                f"Risk: {artifact.get('risk', 'unknown')}\n"
                f"Details: {json.dumps(artifact.get('result', {}), indent=2)}\n"
                f"Timestamp: {ts_str}\n"
            )

            # 1. Email alert
            if hasattr(self, 'email_settings') and self.email_settings.get('enabled'):
                try:
                    import smtplib
                    from email.mime.text import MIMEText

                    msg = MIMEText(alert_message)
                    msg['Subject'] = f"Security Alert: {level.upper()} - {artifact.get('target', 'unknown')}"
                    msg['From'] = self.email_settings.get('from')
                    msg['To'] = ', '.join(self.email_settings.get('to', []))

                    smtp_server = self.email_settings.get('smtp_server')
                    smtp_port = self.email_settings.get('smtp_port', 25)

                    with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                        if self.email_settings.get('use_tls'):
                            server.starttls()
                        if self.email_settings.get('smtp_user'):
                            server.login(self.email_settings.get('smtp_user'), self.email_settings.get('smtp_pass'))
                        server.send_message(msg)
                except Exception as e:
                    self.log.error(f"Failed to send email alert: {e}")

            # 2. Slack webhook
            if hasattr(self, 'slack_webhook') and self.slack_webhook:
                try:
                    payload = {
                        "text": alert_message,
                        "username": "ThreatConnector",
                        "icon_emoji": ":rotating_light:"
                    }
                    requests.post(self.slack_webhook, json=payload, timeout=5)
                except Exception as e:
                    self.log.error(f"Failed to send Slack alert: {e}")

            # 3. PagerDuty integration
            if hasattr(self, 'pagerduty_integration') and self.pagerduty_integration.get('enabled'):
                try:
                    routing_key = self.pagerduty_integration.get('routing_key')
                    payload = {
                        "routing_key": routing_key,
                        "event_action": "trigger",
                        "payload": {
                            "summary": f"Security Alert: {level.upper()}",
                            "severity": level,
                            "source": "ThreatConnector",
                            "custom_details": artifact
                        }
                    }
                    requests.post(
                        "https://events.pagerduty.com/v2/enqueue",
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=5
                    )
                except Exception as e:
                    self.log.error(f"Failed to send PagerDuty alert: {e}")

            self.log.info(f"[ThreatConnector] Alert ({level}) sent successfully")
            return True
        except Exception as e:
            self.log.error(f"Failed to send alert: {e}")
            return False

    def _add_to_watchlist(self, artifact: Dict) -> bool:
        """Add to persistent watchlist with safe DB path and optional in-memory cache."""
        try:
            # Determine watchlist type based on artifact
            if artifact.get('category') == 'suspicious_network':
                watchlist_type = 'network'
            elif artifact.get('category') == 'secret_leak':
                watchlist_type = 'credentials'
            elif artifact.get('category') == 'pii_leak':
                watchlist_type = 'pii'
            else:
                watchlist_type = 'general'

            # Create watchlist entry
            entry = {
                "id": str(uuid.uuid4()),
                "target": artifact.get('target'),
                "type": watchlist_type,
                "risk": artifact.get('risk'),
                "timestamp": time(),
                "data": artifact.get('result', {}),
                "expiration": time() + (86400 * 30)  # 30 days default
            }

            # Ensure data directory exists and use project-local DB
            data_dir = os.path.join(BASE_DIR, 'data')
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, 'threat_intel.db')

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS watchlist (
                id TEXT PRIMARY KEY,
                target TEXT,
                type TEXT,
                risk TEXT,
                timestamp REAL,
                data TEXT,
                expiration REAL
            )
            ''')
            cursor.execute('''
            INSERT OR REPLACE INTO watchlist (id, target, type, risk, timestamp, data, expiration) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry['id'],
                entry['target'],
                entry['type'],
                entry['risk'],
                entry['timestamp'],
                json.dumps(entry['data']),
                entry['expiration']
            ))
            conn.commit()
            conn.close()

            # Also add to in-memory cache if available
            if hasattr(self, 'watchlist_cache') and isinstance(self.watchlist_cache, dict):
                try:
                    self.watchlist_cache[entry['id']] = entry
                except Exception:
                    pass

            # Trigger any automated actions based on watchlist type
            if watchlist_type == 'network' and isinstance(artifact.get('result', {}), dict) and 'source_ip' in artifact.get('result', {}):
                try:
                    self._block_ip(artifact['result']['source_ip'])
                except Exception:
                    pass

            self.log.info(f"[ThreatConnector] Added to {watchlist_type} watchlist: {artifact.get('target')}")
            return True
        except Exception as e:
            self.log.error(f"Failed to add to watchlist: {e}")
            return False

    def _store_threat(self, artifact: Dict) -> None:
        """Store artifact in local threat database (SQLite)."""
        try:
            conn = sqlite3.connect("threat_intel.db")
            cursor = conn.cursor()

            # Create table if not exists (extended with PII fields)
            cursor.execute("""
                           CREATE TABLE IF NOT EXISTS threats
                           (
                               id
                               TEXT
                               PRIMARY
                               KEY,
                               module
                               TEXT,
                               target
                               TEXT,
                               category
                               TEXT,
                               risk
                               TEXT,
                               status
                               TEXT,
                               data
                               TEXT,
                               timestamp
                               REAL,
                               threat_intel
                               TEXT,
                               email
                               TEXT,
                               password
                               TEXT,
                               phone
                               TEXT,
                               credit_card
                               TEXT
                           )
                           """)

            # Extract PII fields
            email = artifact.get("email")
            password = artifact.get("password")
            phone = artifact.get("phone")
            credit_card = artifact.get("credit_card")

            # Insert or update
            cursor.execute("""
                INSERT OR REPLACE INTO threats
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact.get("id"),
                artifact.get("module"),
                artifact.get("target"),
                artifact.get("category"),
                artifact.get("risk"),
                artifact.get("status"),
                json.dumps(artifact.get("result", {})),
                artifact.get("timestamp"),
                json.dumps(artifact.get("threat_intel", {})),
                email,
                password,
                phone,
                credit_card
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.log.error(f"Failed to store threat: {e}")

    def _worker_loop(self) -> None:
        batch: List[Dict[str, Any]] = []

        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=self._flush_interval)
                batch.append(item)

                if len(batch) >= self._batch_size:
                    self._flush_batch(batch)
                    batch = []
            except Empty:
                if batch:
                    self._flush_batch(batch)
                    batch = []
                continue
            except Exception:
                self.log.error("ThreatConnector worker loop error", exc_info=True)

        if batch:
            self._flush_batch(batch)

    def _flush_batch(self, batch: List[Dict[str, Any]]) -> None:
        try:
            for a in batch:
                try:
                    extractor = AccountExtractor(a)
                    accounts = extractor.extract()
                    if accounts:
                        res = a.get("result") or {}
                        res["extracted_accounts"] = accounts
                        a["result"] = res
                        self.log.info(f"[AccountExtractor] extracted {len(accounts)} accounts from {a.get('module')}")
                except Exception as e:
                    self.log.warning(f"[AccountExtractor] failed for {a.get('_hash')}: {e}")

            self.backend.add_batch(batch)

            self.log.info(f"[ThreatIntel] Flushed {len(batch)} artifacts")
            for a in batch:
                self.log.debug(f"[ThreatIntel] {a.get('module')} → {a.get('target')}")
        except Exception:
            self.log.error("Failed to flush batch to backend", exc_info=True)
        finally:
            batch.clear()

    def shutdown(self) -> None:
        self._stop_event.set()
        try:
            self._worker_thread.join(timeout=5)
        except Exception:
            self.log.warning("ThreatConnector shutdown join timeout/failed", exc_info=True)

    def load_all(self) -> List[Dict[str, Any]]:
        try:
            return self.backend.load_all()
        except Exception:
            self.log.error("Failed to load_all from backend", exc_info=True)
            return []

    def export_all(self) -> List[Dict[str, Any]]:
        try:
            return self.load_all()
        except Exception:
            self.log.error("Failed to export_all from backend", exc_info=True)
            return []

    def filter_by_module(self, module: str) -> List[Dict[str, Any]]:
        try:
            return self.backend.find_by_module(module)
        except Exception:
            self.log.error("Failed to filter_by_module", exc_info=True)
            return []

    def filter_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        data = self.load_all()
        return [a for a in data if (a.get("result") or {}).get("severity") == severity]

    def filter_by_target(self, target: str) -> List[Dict[str, Any]]:
        try:
            return self.backend.find_by_target(target)
        except Exception:
            self.log.error("Failed to filter_by_target", exc_info=True)
            return []

    def summary(self) -> Dict[str, Any]:
        try:
            return self.backend.stats()
        except Exception:
            self.log.error("Failed to summary from backend", exc_info=True)
            return {"total": 0, "by_module": {}}

    def query(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp",
        order_desc: bool = True,
    ) -> List[Dict[str, Any]]:
        try:
            return self.backend.query(
                category=category, risk=risk, module=module,
                search=search, limit=limit, offset=offset,
                order_by=order_by, order_desc=order_desc,
            )
        except Exception:
            self.log.error("Failed to query backend", exc_info=True)
            return []

    def count(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        try:
            return self.backend.count(
                category=category, risk=risk, module=module,
                search=search,
            )
        except Exception:
            self.log.error("Failed to count from backend", exc_info=True)
            return 0

    def generate_report(self) -> Dict[str, Any]:
        data = self.load_all()
        report = {
            "total": len(data),
            "by_module": {},
            "by_severity": {},
            "by_category": {},
            "by_source": {},
            "artifacts": data,
        }

        for a in data:
            mod = a.get("module", "unknown")
            res = a.get("result", {})
            sev = res.get("severity", "info")
            cat = res.get("category", "unknown")
            src = res.get("source", "unknown")

            report["by_module"][mod] = report["by_module"].get(mod, 0) + 1
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
            report["by_category"][cat] = report["by_category"].get(cat, 0) + 1
            report["by_source"][src] = report["by_source"].get(src, 0) + 1

        return report


def _build_backend_from_env() -> ThreatBackendBase:
    import os

    backend_type = os.environ.get("THREAT_BACKEND", "sqlite").lower()

    if backend_type == "sqlite":
        return SQLiteBackend()
    if backend_type == "elastic":
        url = os.environ.get("THREAT_ES_URL", "http://localhost:9200")
        index = os.environ.get("THREAT_ES_INDEX", "threat_intel")
        user = os.environ.get("THREAT_ES_USER")
        pwd = os.environ.get("THREAT_ES_PASS")
        return ElasticSearchBackend(url=url, index=index, username=user, password=pwd)

    return SQLiteBackend()


THREAT_CONNECTOR = ThreatConnector(_build_backend_from_env())


