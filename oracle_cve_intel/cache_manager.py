from __future__ import annotations

import json
import hashlib
import time
from pathlib import Path
from typing import Any

from .config import CACHE_TTL, DEFAULT_CACHE_DIR


class CacheManager:
    def __init__(self, cache_dir: Path | str = DEFAULT_CACHE_DIR) -> None:
        self.cache_dir = Path(cache_dir)
        self.meta_file = self.cache_dir / "meta.json"

    def get(self, source: str, key: str) -> dict[str, Any] | None:
        path = self._entry_path(source, key)
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def set(self, source: str, key: str, data: dict[str, Any]) -> None:
        path = self._entry_path(source, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)

    def is_stale(self, source: str, key: str) -> bool:
        path = self._entry_path(source, key)
        if not path.exists():
            return True
        ttl = CACHE_TTL.get(source, 604800)
        return time.time() - path.stat().st_mtime > ttl

    def get_repo_path(self, repo_name: str) -> Path:
        return self.cache_dir / "detection_repos" / repo_name

    def detection_db_path(self) -> Path:
        return self.cache_dir / "detection_rules.sqlite"

    def needs_clone(self, repo_name: str) -> bool:
        repo_path = self.get_repo_path(repo_name)
        if not repo_path.exists():
            return True
        meta = self.load_meta()
        cloned_at = meta.get("repo_clones", {}).get(repo_name)
        if cloned_at is None:
            return True
        return time.time() - cloned_at > CACHE_TTL["detection_repos"]

    def record_clone(self, repo_name: str) -> None:
        meta = self.load_meta()
        meta.setdefault("repo_clones", {})[repo_name] = time.time()
        self.save_meta(meta)

    def load_meta(self) -> dict[str, Any]:
        if not self.meta_file.exists():
            return {}
        with self.meta_file.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def save_meta(self, meta: dict[str, Any]) -> None:
        self.meta_file.parent.mkdir(parents=True, exist_ok=True)
        with self.meta_file.open("w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=2, sort_keys=True)

    def _entry_path(self, source: str, key: str) -> Path:
        safe_key = key.replace("/", "_").replace(":", "_")
        if len(safe_key) > 120:
            digest = hashlib.sha256(safe_key.encode("utf-8")).hexdigest()[:24]
            safe_key = f"{safe_key[:80]}_{digest}"
        return self.cache_dir / source / f"{safe_key}.json"
