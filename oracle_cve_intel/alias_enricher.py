from __future__ import annotations

import json
import re

from .api_client import ApiClient, SourceError
from .cache_manager import CacheManager
from .config import ALIAS_FILE, CPE_MAP_FILE, NVD_CPE_DICT_URL
from .runtime import RunContext

_MAX_PAGES = 25
_PAGE_SIZE = 2000


class AliasEnricher:
    def __init__(self, api_client: ApiClient, cache: CacheManager, run_ctx: RunContext) -> None:
        self.api_client = api_client
        self.cache = cache
        self.run_ctx = run_ctx

    def enrich(self, dry_run: bool = False) -> dict[str, int]:
        """Fetch all Oracle products from NVD CPE dictionary and merge into cpe_map.json + product_aliases.json."""
        oracle_products = self._fetch_oracle_products()
        existing_cpe_map: dict[str, str] = _load_json(CPE_MAP_FILE)
        existing_aliases: dict[str, str] = _load_json(ALIAS_FILE)

        new_cpe_map = dict(existing_cpe_map)
        new_aliases = dict(existing_aliases)

        # Index existing CPE prefixes → canonical name
        prefix_to_canonical: dict[str, str] = {v: k for k, v in existing_cpe_map.items()}

        added_products = 0
        added_aliases = 0

        for cpe_prefix, nvd_title in oracle_products.items():
            if cpe_prefix in prefix_to_canonical:
                # Already mapped — add NVD title as alias pointing to existing canonical name
                canonical = prefix_to_canonical[cpe_prefix]
                if nvd_title != canonical and nvd_title not in new_aliases:
                    new_aliases[nvd_title] = canonical
                    added_aliases += 1
            elif nvd_title not in new_cpe_map:
                new_cpe_map[nvd_title] = cpe_prefix
                prefix_to_canonical[cpe_prefix] = nvd_title
                added_products += 1

        # For every canonical name in cpe_map, generate "without Oracle prefix" alias
        for canonical_name in list(new_cpe_map):
            if canonical_name.startswith("Oracle "):
                short = canonical_name[7:]
                if short and short not in new_aliases:
                    new_aliases[short] = canonical_name
                    added_aliases += 1

        stats = {"new_products": added_products, "new_aliases": added_aliases}
        self.run_ctx.progress(
            "aliases",
            f"Enrichment complete — {added_products} new products, {added_aliases} new aliases.",
        )

        if not dry_run:
            _write_json(CPE_MAP_FILE, new_cpe_map)
            _write_json(ALIAS_FILE, new_aliases)
            self.run_ctx.progress("aliases", f"Written: {CPE_MAP_FILE.name}, {ALIAS_FILE.name}")

        return stats

    def _fetch_oracle_products(self) -> dict[str, str]:
        """Return {cpe_prefix: canonical_title} for all non-deprecated Oracle CPEs."""
        cache_key = "oracle_cpe_products"
        cached = self.cache.get("nvd", cache_key)
        if cached and not self.cache.is_stale("nvd", cache_key):
            self.run_ctx.progress("aliases", f"Oracle CPE products loaded from cache ({len(cached)} entries).")
            return cached

        products: dict[str, str] = {}
        start = 0
        total: int | None = None

        for _ in range(_MAX_PAGES):
            if total is not None and start >= total:
                break
            self.run_ctx.progress("aliases", f"Fetching Oracle CPE dictionary page (startIndex={start}) ...")
            try:
                page = self.api_client.get(
                    NVD_CPE_DICT_URL,
                    {"cpeMatchString": "cpe:2.3:a:oracle:*", "resultsPerPage": _PAGE_SIZE, "startIndex": start},
                    "nvd",
                )
            except SourceError as exc:
                self.run_ctx.add_error("aliases", "NVD", str(exc))
                break

            if total is None:
                total = page.get("totalResults", 0)
                self.run_ctx.progress("aliases", f"NVD reports {total} Oracle CPE entries.")

            for item in page.get("products", []):
                cpe_entry = item.get("cpe", {})
                if cpe_entry.get("deprecated"):
                    continue
                cpe_name = cpe_entry.get("cpeName", "")
                prefix = _cpe_prefix(cpe_name)
                if not prefix or prefix in products:
                    continue
                title = _english_title(cpe_entry)
                if title:
                    products[prefix] = _strip_version(title)

            start += _PAGE_SIZE

        self.cache.set("nvd", cache_key, products)
        self.run_ctx.progress("aliases", f"Fetched {len(products)} unique Oracle product CPE prefixes.")
        return products


def _cpe_prefix(cpe_name: str) -> str:
    parts = cpe_name.split(":")
    return ":".join(parts[:5]) if len(parts) >= 5 else ""


def _english_title(cpe_entry: dict) -> str | None:
    for t in cpe_entry.get("titles", []):
        if t.get("lang") == "en":
            return t.get("title")
    titles = cpe_entry.get("titles", [])
    return titles[0].get("title") if titles else None


def _strip_version(title: str) -> str:
    # Remove trailing version strings like "12.1.0.1", "19c", "8u351", "11.2"
    return re.sub(r"\s+\d[\w.]*$", "", title).strip()


def _load_json(path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(dict(sorted(data.items())), f, indent=2, ensure_ascii=False)
        f.write("\n")
