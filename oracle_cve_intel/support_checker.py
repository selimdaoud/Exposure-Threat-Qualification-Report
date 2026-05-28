from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import date
from functools import lru_cache

from .api_client import ApiClient, SourceError
from .cache_manager import CacheManager
from .config import ENDOFLIFE_BASE_URL, ORACLE_SUPPORT_DATES_FILE
from .models import ProductRecord, SupportStatus
from .runtime import RunContext


# ── endoflife.date fallback (products covered by that API) ────────────────

_SLUG_MAP: dict[str, tuple[str, int]] = {
    "Oracle Database": ("oracle-database", 1),
    "Oracle Java": ("oracle-jdk", 1),
    "MySQL": ("mysql", 2),
    "MySQL Community Server": ("mysql", 2),
    "Oracle Linux": ("oracle-linux", 1),
    "Oracle Solaris": ("solaris", 1),
    "Oracle VM VirtualBox": ("virtualbox", 1),
}


# ── Public entry point ─────────────────────────────────────────────────────

def check_support(
    products: list[ProductRecord],
    api_client: ApiClient,
    cache: CacheManager,
    run_ctx: RunContext,
) -> list[ProductRecord]:
    local_db = _load_local_db()
    cycles_cache: dict[str, list[dict]] = {}
    results: list[ProductRecord] = []

    for product in products:
        name = product.normalized_product_name or product.raw_product_name
        version = product.normalized_version_for_cpe or product.raw_version

        # ── 1. endoflife.date API (preferred for products it covers) ───────
        # endoflife.date has curated, accurate lifecycle data for a small set
        # of Oracle products. Use it first before the local JSON for those.
        entry = _SLUG_MAP.get(name)
        if entry:
            slug, cycle_parts = entry
            if slug not in cycles_cache:
                try:
                    cycles_cache[slug] = _fetch_cycles(slug, api_client, cache, run_ctx)
                except SourceError as exc:
                    run_ctx.add_warning("support", f"endoflife.date unavailable for {slug}: {exc}")
                    cycles_cache[slug] = []
            cycles = cycles_cache[slug]
            cycle = _match_cycle(version, cycles, cycle_parts)
            if cycle is not None:
                status, eol_date, notes = _determine_status(cycle)
                results.append(replace(product, support_status=status, eol_date=eol_date,
                                       support_notes=notes))
                continue
            # Cycle not found in endoflife.date — fall through to local JSON

        # ── 2. Oracle lifetime support JSON (covers the long tail) ─────────
        result = _check_local(product, name, version, local_db)
        if result is not None:
            results.append(result)
            continue

        # ── 3. Not covered by either source ───────────────────────────────
        results.append(replace(product, support_status=SupportStatus.UNKNOWN,
                               support_notes="not in Oracle support dates or endoflife.date"))

    return results


# ── Local JSON lookup ──────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_local_db() -> dict:
    if not ORACLE_SUPPORT_DATES_FILE.exists():
        return {}
    try:
        return json.loads(ORACLE_SUPPORT_DATES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _check_local(
    product: ProductRecord,
    name: str,
    version: str | None,
    db: dict,
) -> ProductRecord | None:
    products = db.get("products", {})
    releases = products.get(name)
    if releases is None:
        return None
    if not version:
        return None

    entry = _match_release(version, releases)
    if entry is None:
        return replace(
            product,
            support_status=SupportStatus.UNKNOWN,
            support_notes=f"version {product.raw_version} not found in Oracle support dates for {name}",
        )

    release_key, info = entry
    status, eol_date, notes = _status_from_entry(info, release_key, product.raw_version)
    return replace(product, support_status=status, eol_date=eol_date, support_notes=notes)


def _match_release(version: str, releases: dict) -> tuple[str, dict] | None:
    """
    Match a raw version string against the release keys in the JSON.

    Strategy (most → least specific):
      1. Exact key match
      2. Version is a prefix of the key   (e.g. "12.2" matches key "12.2.x")
      3. Key is a prefix of the version   (e.g. version "12.2.1.4" matches key "12.2.x")
      4. Major.minor match                (e.g. "12.2.1.4.0" → "12.2")
      5. Major-only match                 (e.g. "19c" → "19.x" or "19")
    """
    v = _normalise_version_key(version)

    # 1. Exact
    for key in releases:
        if _normalise_version_key(key) == v:
            return key, releases[key]

    # Build a list of (normalised_key, original_key) sorted most-specific first
    candidates = sorted(
        [(_normalise_version_key(k), k) for k in releases],
        key=lambda t: (-len(t[0].split(".")), t[0]),
    )

    # 2 & 3. Prefix matching (handles "12.2.x" wildcards)
    # Boundary guard: after the matched prefix the next character must be "."
    # or the string must end — prevents "1" matching "15.1.1.0.0".
    v_base = v.rstrip(".x*")
    for norm_key, orig_key in candidates:
        k_base = norm_key.rstrip(".x*")
        if not k_base or not v_base:
            continue
        if v_base.startswith(k_base) and (len(v_base) == len(k_base) or v_base[len(k_base)] == "."):
            return orig_key, releases[orig_key]
        if k_base.startswith(v_base) and (len(k_base) == len(v_base) or k_base[len(v_base)] == "."):
            return orig_key, releases[orig_key]

    # 4. Major.minor match
    parts = v.split(".")
    if len(parts) >= 2:
        mm = ".".join(parts[:2])
        for norm_key, orig_key in candidates:
            if norm_key.split(".")[0:2] == mm.split("."):
                return orig_key, releases[orig_key]

    # 5. Major-only (e.g. "19c" → "19")
    major = re.match(r"^(\d+)", v)
    if major:
        m = major.group(1)
        for norm_key, orig_key in candidates:
            if re.match(r"^" + re.escape(m) + r"([^0-9]|$)", norm_key):
                return orig_key, releases[orig_key]

    return None


def _normalise_version_key(v: str) -> str:
    """Strip footnotes, lowercase, collapse whitespace."""
    v = re.sub(r"\s*\d[\d,\s]*$", "", v.strip())   # remove trailing footnote markers
    v = re.sub(r"\s+", ".", v.strip().lower())       # spaces → dots
    v = re.sub(r"[^0-9a-z.*-]", "", v)              # keep only safe chars
    return v


def _status_from_entry(info: dict, release_key: str, raw_version: str) -> tuple[SupportStatus, str | None, str]:
    today = date.today()
    premier_end = _parse_date(info.get("premier_support_ends"))
    extended_end = _parse_date(info.get("extended_support_ends"))

    hard_eol = extended_end or premier_end

    if hard_eol is None:
        return (
            SupportStatus.SUPPORTED,
            None,
            f"{release_key}: fully supported (no end date in Oracle lifetime support data)",
        )

    if hard_eol <= today:
        return (
            SupportStatus.END_OF_LIFE,
            str(hard_eol),
            f"{release_key}: EOL since {hard_eol} (Oracle lifetime support data)",
        )

    if extended_end and premier_end and premier_end <= today:
        return (
            SupportStatus.EXTENDED_SUPPORT,
            str(extended_end),
            f"{release_key}: Premier Support ended {premier_end}, Extended Support until {extended_end}",
        )

    return (
        SupportStatus.SUPPORTED,
        str(hard_eol),
        f"{release_key}: supported until {hard_eol} (Oracle lifetime support data)",
    )


def _parse_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


# ── endoflife.date helpers (unchanged) ────────────────────────────────────

def _fetch_cycles(slug: str, api_client: ApiClient, cache: CacheManager, run_ctx: RunContext) -> list[dict]:
    cached = cache.get("endoflife", slug)
    if cached and not cache.is_stale("endoflife", slug):
        return cached["cycles"]
    url = f"{ENDOFLIFE_BASE_URL}/{slug}.json"
    data = api_client.get(url, source_name="endoflife")
    cycles = data if isinstance(data, list) else data.get("result", [])
    cache.set("endoflife", slug, {"cycles": cycles})
    run_ctx.add_api_call(url, "200", 0, False)
    return cycles


def _match_cycle(version: str, cycles: list[dict], preferred_parts: int) -> dict | None:
    parts = version.split(".")
    candidates: list[str] = []
    if preferred_parts and preferred_parts <= len(parts):
        candidates.append(".".join(parts[:preferred_parts]))
    for n in range(len(parts), 0, -1):
        prefix = ".".join(parts[:n])
        if prefix not in candidates:
            candidates.append(prefix)
    cycle_by_key = {str(c["cycle"]): c for c in cycles}
    for candidate in candidates:
        if candidate in cycle_by_key:
            return cycle_by_key[candidate]
    return None


def _determine_status(cycle: dict) -> tuple[SupportStatus, str | None, str]:
    today = date.today()
    cycle_name = str(cycle.get("cycle", ""))
    eol_date = _parse_date(cycle.get("eol"))
    extended_date = _parse_date(cycle.get("extendedSupport"))
    support_date = _parse_date(cycle.get("support"))
    hard_eol = extended_date or eol_date or support_date
    if hard_eol is None:
        return SupportStatus.SUPPORTED, None, f"cycle {cycle_name}: fully supported (no EOL date set)"
    if hard_eol <= today:
        return SupportStatus.END_OF_LIFE, str(hard_eol), f"cycle {cycle_name}: EOL since {hard_eol}"
    premier_end = eol_date or support_date
    if extended_date and premier_end and premier_end <= today:
        return (
            SupportStatus.EXTENDED_SUPPORT,
            str(extended_date),
            f"cycle {cycle_name}: Premier Support ended {premier_end}, Extended Support until {extended_date}",
        )
    return SupportStatus.SUPPORTED, str(hard_eol), f"cycle {cycle_name}: supported until {hard_eol}"
