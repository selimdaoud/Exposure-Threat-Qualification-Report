from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RunContext:
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    mock_providers: list[str] = field(default_factory=list)
    progress_callback: Callable[[str, str, str], None] | None = None

    def add_warning(self, stage: str, message: str) -> None:
        self.warnings.append(f"[{stage}] {message}")
        self.progress(stage, f"WARN - {message}", "warn")

    def add_error(self, stage: str, source: str, message: str) -> None:
        self.errors.append(f"[{stage}] {source}: {message}")

    def add_api_call(self, url: str, status: str, duration_ms: int, cache_hit: bool) -> None:
        self.api_calls.append(f"{status} {duration_ms}ms cache_hit={cache_hit} {url}")

    def progress(self, stage: str, message: str, level: str = "info") -> None:
        if self.progress_callback:
            self.progress_callback(stage, message, level)
