from __future__ import annotations

import json
import re
from dataclasses import replace

from .config import ALIAS_FILE, CPE_MAP_FILE
from .models import ConfidenceLevel, ProductRecord


def normalize(records: list[ProductRecord]) -> list[ProductRecord]:
    aliases = _load_json(ALIAS_FILE)
    cpe_map = _load_json(CPE_MAP_FILE)
    normalized: list[ProductRecord] = []
    for record in records:
        alias_key = _find_alias_key(record.raw_product_name, aliases)
        if alias_key:
            confidence = ConfidenceLevel.HIGH
        else:
            alias_key = _find_alias_key_fuzzy(record.raw_product_name, aliases, cpe_map)
            confidence = ConfidenceLevel.MEDIUM if alias_key else ConfidenceLevel.LOW
        normalized_name = aliases.get(alias_key, alias_key) if alias_key else record.raw_product_name
        cpe_prefix = cpe_map.get(normalized_name)
        if cpe_prefix is None:
            confidence = ConfidenceLevel.LOW

        version, version_confidence = normalize_version(record.raw_version)
        if version_confidence == ConfidenceLevel.UNKNOWN:
            confidence = ConfidenceLevel.UNKNOWN
        elif version_confidence == ConfidenceLevel.LOW and confidence == ConfidenceLevel.HIGH:
            confidence = ConfidenceLevel.LOW

        normalized.append(
            replace(
                record,
                normalized_product_name=normalized_name,
                cpe_prefix=cpe_prefix,
                normalized_version_for_cpe=version,
                normalization_confidence=confidence,
            )
        )
    return normalized


def normalize_version(raw_version: str) -> tuple[str | None, ConfidenceLevel]:
    version = raw_version.strip()
    lower = version.lower()
    if "cpu" in lower or "bundle" in lower or "patched to" in lower:
        return None, ConfidenceLevel.UNKNOWN

    ru_match = re.search(r"ru\s+(\d+(?:\.\d+)*)", lower)
    if ru_match:
        return _pad_version(ru_match.group(1)), ConfidenceLevel.LOW

    if re.fullmatch(r"\d+c", lower):
        return f"{lower[:-1]}.0.0.0.0", ConfidenceLevel.HIGH

    java_match = re.fullmatch(r"(\d+)u(\d+)", lower)
    if java_match:
        return f"{java_match.group(1)}.{java_match.group(2)}", ConfidenceLevel.HIGH

    if re.fullmatch(r"\d+(?:\.\d+)*", version):
        return _pad_version(version), ConfidenceLevel.HIGH

    return None, ConfidenceLevel.UNKNOWN


def _pad_version(version: str) -> str:
    parts = version.split(".")
    while len(parts) < 5:
        parts.append("0")
    return ".".join(parts[:5])


_NOISE = frozenset({"oracle", "the", "a", "an"})


def _find_alias_key(name: str, aliases: dict[str, str]) -> str | None:
    lower_name = name.lower()
    for key in aliases:
        if key.lower() == lower_name:
            return key
    return None


def _find_alias_key_fuzzy(name: str, aliases: dict[str, str], cpe_map: dict[str, str]) -> str | None:
    """Token-overlap fallback. Searches aliases first, then cpe_map canonical names directly."""
    name_tokens = _tokenize(name)
    if not name_tokens:
        return None

    # Build a combined candidate set: alias keys + cpe_map canonical names
    # We only need to check cpe_map names that are not already in aliases
    alias_keys = set(aliases)
    candidates = list(aliases)
    for canonical in cpe_map:
        if canonical not in alias_keys:
            candidates.append(canonical)

    best_key: str | None = None
    best_score = 0.0
    for key in candidates:
        key_tokens = _tokenize(key)
        if not key_tokens:
            continue
        overlap = len(name_tokens & key_tokens)
        score = overlap / min(len(name_tokens), len(key_tokens))
        if score > best_score:
            best_score = score
            best_key = key

    if best_score < 0.75 or best_key is None:
        return None

    return best_key


def _tokenize(name: str) -> frozenset[str]:
    tokens = re.sub(r"[^a-z0-9 ]", " ", name.lower()).split()
    return frozenset(t for t in tokens if t not in _NOISE and len(t) >= 2)


def _load_json(path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
