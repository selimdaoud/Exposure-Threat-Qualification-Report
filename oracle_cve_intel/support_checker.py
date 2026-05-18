from __future__ import annotations

from dataclasses import replace
from datetime import date

from .api_client import ApiClient, SourceError
from .cache_manager import CacheManager
from .config import ENDOFLIFE_BASE_URL
from .models import ProductRecord, SupportStatus
from .runtime import RunContext


# Maps normalized product names to their endoflife.date API slug.
# The int is how many dot-separated version parts form the cycle key (0 = auto-detect).
_SLUG_MAP: dict[str, tuple[str, int]] = {
    "Oracle Database": ("oracle-database", 1),
    "Oracle Java": ("oracle-jdk", 1),
    "MySQL": ("mysql", 2),
    "MySQL Community Server": ("mysql", 2),
    "Oracle Linux": ("oracle-linux", 1),
    "Oracle Solaris": ("solaris", 1),
    "Oracle VM VirtualBox": ("virtualbox", 1),
}


def check_support(
    products: list[ProductRecord],
    api_client: ApiClient,
    cache: CacheManager,
    run_ctx: RunContext,
) -> list[ProductRecord]:
    cycles_cache: dict[str, list[dict]] = {}
    results: list[ProductRecord] = []

    for product in products:
        entry = _SLUG_MAP.get(product.normalized_product_name or "")
        if not entry:
            results.append(replace(product, support_status=SupportStatus.UNKNOWN, support_notes="not in endoflife.date"))
            continue

        slug, cycle_parts = entry
        if slug not in cycles_cache:
            try:
                cycles_cache[slug] = _fetch_cycles(slug, api_client, cache, run_ctx)
            except SourceError as exc:
                run_ctx.add_warning("support", f"endoflife.date unavailable for {slug}: {exc}")
                results.append(replace(product, support_status=SupportStatus.UNKNOWN, support_notes="API unavailable"))
                continue

        cycles = cycles_cache[slug]
        version = product.normalized_version_for_cpe
        if not version:
            results.append(replace(product, support_status=SupportStatus.UNKNOWN, support_notes="no normalized version"))
            continue

        cycle = _match_cycle(version, cycles, cycle_parts)
        if cycle is None:
            results.append(replace(
                product,
                support_status=SupportStatus.UNKNOWN,
                support_notes=f"version {product.raw_version} not found in endoflife.date for {slug}",
            ))
            continue

        status, eol_date, notes = _determine_status(cycle)
        results.append(replace(product, support_status=status, eol_date=eol_date, support_notes=notes))

    return results


def _fetch_cycles(slug: str, api_client: ApiClient, cache: CacheManager, run_ctx: RunContext) -> list[dict]:
    cached = cache.get("endoflife", slug)
    if cached and not cache.is_stale("endoflife", slug):
        return cached["cycles"]

    url = f"{ENDOFLIFE_BASE_URL}/{slug}.json"
    data = api_client.get(url, source_name="endoflife")
    # The API returns a list; wrap it for the cache dict interface.
    if isinstance(data, list):
        cycles = data
    else:
        cycles = data.get("result", [])

    cache.set("endoflife", slug, {"cycles": cycles})
    run_ctx.add_api_call(url, "200", 0, False)
    return cycles


def _match_cycle(version: str, cycles: list[dict], preferred_parts: int) -> dict | None:
    parts = version.split(".")

    # Build candidate prefixes from most-specific to least-specific.
    # If preferred_parts is set, try that length first.
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

    # `eol` = end of premier/standard support.
    # `extendedSupport` = end of paid extended support (Oracle-specific field).
    # `support` = end of active support (MySQL-style field, maps to the same concept as eol).
    eol_date = _parse_date(cycle.get("eol"))
    extended_date = _parse_date(cycle.get("extendedSupport"))
    support_date = _parse_date(cycle.get("support"))

    # Treat the latest available support end as the "hard EOL".
    hard_eol = extended_date or eol_date or support_date

    if hard_eol is None:
        return SupportStatus.SUPPORTED, None, f"cycle {cycle_name}: fully supported (no EOL date set)"

    if hard_eol <= today:
        return SupportStatus.END_OF_LIFE, str(hard_eol), f"cycle {cycle_name}: EOL since {hard_eol}"

    # Product still has coverage. Determine whether we're past premier support.
    premier_end = eol_date or support_date
    if extended_date and premier_end and premier_end <= today:
        return (
            SupportStatus.EXTENDED_SUPPORT,
            str(extended_date),
            f"cycle {cycle_name}: Premier Support ended {premier_end}, Extended Support until {extended_date}",
        )

    return SupportStatus.SUPPORTED, str(hard_eol), f"cycle {cycle_name}: supported until {hard_eol}"


def _parse_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None
