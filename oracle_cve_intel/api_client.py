from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class SourceError(Exception):
    """Base exception for external source failures."""


class SourceUnavailableError(SourceError):
    """Raised when an external source remains unavailable after retries."""


class OfflineModeError(SourceError):
    """Raised when live calls are disabled."""


class ApiClient:
    def __init__(self, offline: bool = False) -> None:
        self.offline = offline
        self._last_request_by_source: dict[str, float] = {}

    def get(self, url: str, params: dict[str, Any] | None = None, source_name: str = "default") -> dict[str, Any]:
        if self.offline:
            raise OfflineModeError(f"{source_name} unavailable in offline mode")

        full_url = f"{url}?{urlencode(params)}" if params else url
        delays = [0, 2, 4]
        last_error: Exception | None = None
        for delay in delays:
            if delay:
                time.sleep(delay)
            self._rate_limit(source_name)
            try:
                request = Request(full_url, headers={"User-Agent": "oracle-cve-intel/0.1"})
                with urlopen(request, timeout=30) as response:
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as exc:
                last_error = exc
                if exc.code == 429:
                    retry_after = int(exc.headers.get("Retry-After", "30"))
                    time.sleep(retry_after)
                    continue
                if exc.code < 500:
                    break
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc

        raise SourceUnavailableError(f"{source_name} unavailable: {last_error}")

    def get_html(self, url: str, source_name: str = "default") -> str:
        if self.offline:
            raise OfflineModeError(f"{source_name} unavailable in offline mode")
        delays = [0, 2, 4]
        last_error: Exception | None = None
        for delay in delays:
            if delay:
                time.sleep(delay)
            self._rate_limit(source_name)
            try:
                request = Request(url, headers={"User-Agent": "oracle-cve-intel/0.1"})
                with urlopen(request, timeout=30) as response:
                    return response.read().decode("utf-8", errors="replace")
            except HTTPError as exc:
                last_error = exc
                if exc.code == 429:
                    retry_after = int(exc.headers.get("Retry-After", "30"))
                    time.sleep(retry_after)
                    continue
                if exc.code < 500:
                    break
            except (URLError, TimeoutError) as exc:
                last_error = exc
        raise SourceUnavailableError(f"{source_name} unavailable: {last_error}")

    def _rate_limit(self, source_name: str) -> None:
        minimum_delay = 0.0
        key = source_name.lower()
        if key == "nvd":
            minimum_delay = 6.0
        elif key == "nvd_keyed":
            minimum_delay = 0.6
        elif key in {"html", "oracle"}:
            minimum_delay = 2.0
        elif key == "euvd":
            minimum_delay = 1.0

        if not minimum_delay:
            return
        last_request = self._last_request_by_source.get(key)
        now = time.time()
        if last_request is not None and now - last_request < minimum_delay:
            time.sleep(minimum_delay - (now - last_request))
        self._last_request_by_source[key] = time.time()
