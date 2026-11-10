# xss_security_gui/dom_parser/cache.py
"""
Multi-level caching system for DOMParser ULTRA 7.0
L1 Cache (LRU) + L2 Cache (Hash-based persistent)
"""

import hashlib
import json
import logging
import threading
import time
from functools import lru_cache
from typing import Any, Dict, Optional, Callable
from pathlib import Path
from collections import OrderedDict


class CacheEntry:
    """Запись в кэше с TTL"""

    def __init__(self, value: Any, ttl: float = None):
        self.value = value
        self.created_at = time.time()
        self.ttl = ttl
        self.access_count = 0
        self.last_accessed = self.created_at

    def is_expired(self) -> bool:
        """Проверить, истек ли TTL"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl

    def touch(self) -> None:
        """Обновить время последнего доступа"""
        self.last_accessed = time.time()
        self.access_count += 1


class L1Cache:
    """LRU Cache в памяти"""

    def __init__(self, max_size: int = 256, ttl: float = 3600.0):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.log = logging.getLogger("L1Cache")

    def get(self, key: str) -> Optional[Any]:
        """Получить значение из кэша"""
        with self._lock:
            entry = self.cache.get(key)
            if entry is None:
                self.misses += 1
                return None

            if entry.is_expired():
                del self.cache[key]
                self.misses += 1
                return None

            entry.touch()
            self.cache.move_to_end(key)
            self.hits += 1
            return entry.value

    def set(self, key: str, value: Any, ttl: float = None) -> None:
        """Установить значение в кэш"""
        with self._lock:
            if key in self.cache:
                del self.cache[key]

            if len(self.cache) >= self.max_size:
                # Удалить самый старый элемент
                self.cache.popitem(last=False)

            self.cache[key] = CacheEntry(value, ttl or self.ttl)

    def delete(self, key: str) -> None:
        """Удалить запись"""
        with self._lock:
            self.cache.pop(key, None)

    def clear(self) -> None:
        """Очистить кэш"""
        with self._lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, Any]:
        """Статистика кэша"""
        with self._lock:
            total = self.hits + self.misses
            hit_rate = self.hits / total if total > 0 else 0
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate,
            }


class L2Cache:
    """Персистентный хеш-индекс кэша (файловая система)"""

    def __init__(self, cache_dir: Path, max_size_mb: int = 100):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_mb = max_size_mb
        self.index_file = self.cache_dir / ".cache_index.json"
        self._lock = threading.RLock()
        self.log = logging.getLogger("L2Cache")
        self._load_index()

    def _hash_key(self, key: str) -> str:
        """Хешировать ключ для безопасной работы с файловой системой"""
        return hashlib.md5(key.encode()).hexdigest()

    def _load_index(self) -> None:
        """Загрузить индекс из файла"""
        try:
            if self.index_file.exists():
                with open(self.index_file, "r") as f:
                    self.index = json.load(f)
            else:
                self.index = {}
        except Exception as e:
            self.log.warning(f"Failed to load cache index: {e}")
            self.index = {}

    def _save_index(self) -> None:
        """Сохранить индекс в файл"""
        try:
            with open(self.index_file, "w") as f:
                json.dump(self.index, f)
        except Exception as e:
            self.log.warning(f"Failed to save cache index: {e}")

    def get(self, key: str) -> Optional[Any]:
        """Получить значение из L2 кэша"""
        with self._lock:
            hash_key = self._hash_key(key)
            if hash_key not in self.index:
                return None

            meta = self.index[hash_key]
            cache_file = self.cache_dir / hash_key

            if not cache_file.exists():
                del self.index[hash_key]
                self._save_index()
                return None

            # Проверить TTL
            if meta.get("ttl") and time.time() - meta["created_at"] > meta["ttl"]:
                cache_file.unlink()
                del self.index[hash_key]
                self._save_index()
                return None

            try:
                with open(cache_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.log.warning(f"Failed to read cache file {hash_key}: {e}")
                return None

    def set(self, key: str, value: Any, ttl: float = None) -> None:
        """Установить значение в L2 кэш"""
        with self._lock:
            hash_key = self._hash_key(key)
            cache_file = self.cache_dir / hash_key

            try:
                with open(cache_file, "w") as f:
                    json.dump(value, f)

                self.index[hash_key] = {
                    "key": key,
                    "created_at": time.time(),
                    "ttl": ttl,
                }
                self._save_index()
            except Exception as e:
                self.log.warning(f"Failed to write cache file {hash_key}: {e}")

    def clear(self) -> None:
        """Очистить кэш"""
        with self._lock:
            try:
                for cache_file in self.cache_dir.glob("*"):
                    if cache_file.name != ".cache_index.json":
                        cache_file.unlink()
                self.index.clear()
                self._save_index()
            except Exception as e:
                self.log.warning(f"Failed to clear cache: {e}")

    def size_mb(self) -> float:
        """Размер кэша в МБ"""
        total = 0
        for cache_file in self.cache_dir.glob("*"):
            if cache_file.name != ".cache_index.json":
                total += cache_file.stat().st_size
        return total / (1024 * 1024)


class DOMParserCache:
    """
    Комбинированный кэш с L1 (LRU) и L2 (файловый).
    """

    def __init__(
        self,
        max_size_l1: int = 256,
        cache_dir: Path = None,
        ttl: float = 3600.0,
        enabled: bool = True
    ):
        self.enabled = enabled
        self.l1 = L1Cache(max_size=max_size_l1, ttl=ttl) if enabled else None
        self.l2 = L2Cache(cache_dir or Path.cwd() / ".cache", max_size_mb=100) if enabled else None
        self.ttl = ttl
        self.log = logging.getLogger("DOMParserCache")

    def get(self, key: str) -> Optional[Any]:
        """Получить значение (сначала L1, потом L2)"""
        if not self.enabled:
            return None

        # L1
        value = self.l1.get(key)
        if value is not None:
            return value

        # L2
        value = self.l2.get(key)
        if value is not None:
            self.l1.set(key, value, self.ttl)
            return value

        return None

    def set(self, key: str, value: Any, ttl: float = None, l1_only: bool = False) -> None:
        """Установить значение в оба уровня кэша"""
        if not self.enabled:
            return

        ttl = ttl or self.ttl
        self.l1.set(key, value, ttl)

        if not l1_only:
            try:
                self.l2.set(key, value, ttl)
            except Exception:
                pass

    def delete(self, key: str) -> None:
        """Удалить из обоих уровней"""
        if not self.enabled:
            return
        self.l1.delete(key)
        # L2 удаление опционально (файл останется, но индекс обновится)

    def clear(self) -> None:
        """Очистить все уровни"""
        if not self.enabled:
            return
        self.l1.clear()
        self.l2.clear()

    def get_md5_hash(self, html: str) -> str:
        """Получить MD5 хеш HTML для кэширования по содержимому"""
        return hashlib.md5(html.encode()).hexdigest()

    def stats(self) -> Dict[str, Any]:
        """Статистика кэша"""
        if not self.enabled:
            return {"enabled": False}

        return {
            "enabled": True,
            "l1": self.l1.stats(),
            "l2_size_mb": self.l2.size_mb(),
            "l2_max_size_mb": self.l2.max_size_mb,
        }

