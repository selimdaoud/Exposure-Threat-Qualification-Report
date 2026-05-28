#!/usr/bin/env python3
"""
Fetches Oracle lifetime support PDFs and extracts product support date data
into data/oracle_support_dates.json.

Usage (from v1/):
    python3 scripts/fetch_oracle_support_dates.py
    python3 scripts/fetch_oracle_support_dates.py --force      # ignore local PDF cache
    python3 scripts/fetch_oracle_support_dates.py --dry-run    # print JSON, do not write

Requires:
    pip install pdfplumber
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.request
from datetime import date, datetime
from pathlib import Path

try:
    import pdfplumber
except ImportError:
    sys.exit("pdfplumber is required: pip install pdfplumber")

# ── Paths ──────────────────────────────────────────────────────────────────

_ROOT        = Path(__file__).parent.parent
_DATA_DIR    = _ROOT / "data"
_CACHE_DIR   = _DATA_DIR / "cache" / "oracle_support_pdfs"
_OUTPUT_FILE = _DATA_DIR / "oracle_support_dates.json"

# ── Oracle PDF catalogue ───────────────────────────────────────────────────

_PDF_SOURCES: list[dict] = [
    {
        "category": "technology",
        "url": "https://www.oracle.com/us/assets/lifetime-support-technology-069183.pdf",
    },
    {
        "category": "middleware",
        "url": "https://www.oracle.com/us/assets/lifetime-support-middleware-069163.pdf",
    },
    {
        "category": "applications",
        "url": "https://www.oracle.com/us/assets/lifetime-support-applications-069216.pdf",
    },
    {
        "category": "os",
        "url": "https://www.oracle.com/a/ocom/docs/lifetime-support-policy-operating-system.pdf",
    },
]

# ── Product name normalisation ─────────────────────────────────────────────
# Maps lowercase substrings found in PDF section headers to our canonical names.
# Longer / more specific strings must come first.

_PRODUCT_NAME_MAP: list[tuple[str, str]] = [
    # ── Technology / Middleware ────────────────────────────────────────────
    ("oracle database",                                     "Oracle Database"),
    ("oracle weblogic server",                              "Oracle WebLogic Server"),
    ("weblogic server",                                     "Oracle WebLogic Server"),
    ("oracle fusion middleware",                            "Oracle Fusion Middleware"),
    ("fusion middleware",                                   "Oracle Fusion Middleware"),
    ("oracle forms",                                        "Oracle Forms"),
    ("oracle reports",                                      "Oracle Reports"),
    ("oracle soa suite",                                    "Oracle SOA Suite"),
    ("oracle service bus",                                  "Oracle Service Bus"),
    ("oracle business intelligence",                        "Oracle Business Intelligence"),
    ("oracle data integrator",                              "Oracle Data Integrator"),
    ("oracle identity governance",                          "Oracle Identity Governance"),
    ("oracle access manager",                               "Oracle Access Manager"),
    ("oracle unified directory",                            "Oracle Unified Directory"),
    ("oracle internet directory",                           "Oracle Internet Directory"),
    ("oracle directory server",                             "Oracle Directory Server"),
    ("oracle http server",                                  "Oracle HTTP Server"),
    ("oracle enterprise manager",                           "Oracle Enterprise Manager"),
    ("oracle apex",                                         "Oracle APEX"),
    ("application express",                                 "Oracle APEX"),
    ("oracle sql developer data modeler",                   "Oracle SQL Developer Data Modeler"),
    ("oracle sql developer",                                "Oracle SQL Developer"),
    ("oracle rest data services",                           "Oracle REST Data Services"),
    ("oracle essbase",                                      "Oracle Essbase"),
    ("essbase",                                             "Oracle Essbase"),
    ("oracle graalvm",                                      "Oracle GraalVM"),
    ("graalvm",                                             "Oracle GraalVM"),
    ("oracle java se",                                      "Oracle Java SE"),
    ("oracle jdk",                                          "Oracle Java SE"),
    ("java se",                                             "Oracle Java SE"),
    ("jdk",                                                 "Oracle Java SE"),
    ("oracle jrockit",                                      "Oracle JRockit"),
    ("jrockit",                                             "Oracle JRockit"),
    ("mysql",                                               "MySQL"),
    ("oracle linux",                                        "Oracle Linux"),
    ("oracle solaris",                                      "Oracle Solaris"),
    ("oracle vm",                                           "Oracle VM"),
    ("oracle virtualbox",                                   "Oracle VM VirtualBox"),
    ("virtualbox",                                          "Oracle VM VirtualBox"),
    ("oracle coherence",                                    "Oracle Coherence"),
    ("coherence",                                           "Oracle Coherence"),
    ("oracle tuxedo",                                       "Oracle Tuxedo"),
    ("tuxedo",                                              "Oracle Tuxedo"),
    ("oracle adf",                                          "Oracle ADF"),
    ("application development framework",                   "Oracle ADF"),
    # ── Applications ──────────────────────────────────────────────────────
    ("oracle e-business suite",                             "Oracle E-Business Suite"),
    ("e-business suite",                                    "Oracle E-Business Suite"),
    ("oracle peoplesoft",                                   "Oracle PeopleSoft"),
    ("peoplesoft",                                          "Oracle PeopleSoft"),
    ("oracle jd edwards",                                   "Oracle JD Edwards"),
    ("jd edwards",                                          "Oracle JD Edwards"),
    ("oracle siebel",                                       "Oracle Siebel CRM"),
    ("siebel",                                              "Oracle Siebel CRM"),
    ("oracle hyperion",                                     "Oracle Hyperion EPM"),
    ("hyperion",                                            "Oracle Hyperion EPM"),
    ("oracle enterprise performance management",            "Oracle Hyperion EPM"),
    ("oracle agile product lifecycle management",           "Oracle Agile PLM"),
    ("oracle agile product lifecycle",                      "Oracle Agile PLM"),
    ("agile product lifecycle",                             "Oracle Agile PLM"),
    ("oracle agile plm",                                    "Oracle Agile PLM"),
    ("oracle retail",                                       "Oracle Retail"),
    ("oracle utilities",                                    "Oracle Utilities"),
    ("oracle primavera",                                    "Oracle Primavera"),
    ("primavera",                                           "Oracle Primavera"),
    ("oracle demantra",                                     "Oracle Demantra"),
    ("demantra",                                            "Oracle Demantra"),
    ("oracle transportation management",                    "Oracle Transportation Management"),
    ("oracle atg",                                          "Oracle ATG Commerce"),
    ("oracle commerce",                                     "Oracle Commerce"),
    ("oracle endeca",                                       "Oracle Endeca"),
    ("endeca",                                              "Oracle Endeca"),
    ("oracle policy automation",                            "Oracle Policy Automation"),
    ("oracle user productivity kit",                        "Oracle User Productivity Kit"),
    ("oracle billing insight",                              "Oracle Billing Insight"),
    ("oracle health sciences",                              "Oracle Health Sciences"),
    ("oracle life science",                                 "Oracle Life Sciences"),
    ("oracle phase forward",                                "Oracle Phase Forward"),
    ("oracle financial services analytical",                "Oracle Financial Services (OFSAA)"),
    ("oracle financial services",                           "Oracle Financial Services"),
    ("oracle insurance",                                    "Oracle Insurance"),
    ("oracle banking",                                      "Oracle Banking"),
    ("oracle communications billing",                       "Oracle Communications BRM"),
    ("oracle communications",                               "Oracle Communications"),
    ("oracle micros",                                       "Oracle Hospitality"),
    ("oracle hospitality",                                  "Oracle Hospitality"),
    ("oracle fusion applications",                          "Oracle Fusion Applications"),
    ("oracle governance, risk",                             "Oracle GRC"),
    ("oracle application integration architecture",         "Oracle AIA"),
    ("oracle revenue management and billing",               "Oracle Revenue Management and Billing"),
    ("oracle activity based management",                    "Oracle Activity Based Management"),
    ("oracle adminserver",                                  "Oracle AdminServer"),
    ("oracle instantis",                                    "Oracle Instantis"),
    ("oracle skire",                                        "Oracle Skire"),
    ("oracle global knowledge",                             "Oracle Global Knowledge"),
    ("oracle student learning",                             "Oracle Student Learning"),
    ("oracle ilearning",                                    "Oracle iLearning"),
    ("oracle talari",                                       "Oracle Talari"),
    ("oracle lustre",                                       "Oracle Lustre"),
]

# ── Month name → number ────────────────────────────────────────────────────

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5,  "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10,"nov": 11, "dec": 12,
}

# ── Date parsing ───────────────────────────────────────────────────────────

def _parse_date(value: str | None) -> str | None:
    """Parse a date string like 'Dec 2027' or 'Apr 2026' → 'YYYY-MM-DD' (last day of month)."""
    if not value:
        return None
    v = value.strip()
    if not v or v.lower() in ("not available", "not applicable", "indefinite", "n/a", "tbd", ""):
        return None

    # Handle date ranges like "Dec 2011 – Feb 2015" — take the later date
    if "–" in v or "-" in v[4:]:
        parts = re.split(r"\s*[–-]\s*", v, maxsplit=1)
        dates = [_parse_single_date(p.strip()) for p in parts if p.strip()]
        valid = [d for d in dates if d]
        return max(valid) if valid else None

    return _parse_single_date(v)


def _parse_single_date(v: str) -> str | None:
    v = re.sub(r"\s+", " ", v.strip())
    # "Dec 2027" or "December 2027"
    m = re.match(r"([A-Za-z]+)\s+(\d{4})", v)
    if m:
        month_str = m.group(1)[:3].lower()
        month = _MONTHS.get(month_str)
        year = int(m.group(2))
        if month and 1990 <= year <= 2060:
            # Use last day of month as the support end date
            import calendar
            last_day = calendar.monthrange(year, month)[1]
            return f"{year}-{month:02d}-{last_day:02d}"
    # "2027-12-31" ISO already
    m2 = re.match(r"(\d{4})-(\d{2})-(\d{2})", v)
    if m2:
        return v[:10]
    return None


# ── Row utilities ──────────────────────────────────────────────────────────

def _compact(row: list) -> list[str]:
    """Return only non-None, non-empty-string cells from a row."""
    return [str(c).strip() for c in row if c is not None and str(c).strip()]


def _is_spacer(row: list) -> bool:
    return not any(c is not None and str(c).strip() for c in row)


def _is_header(row: list) -> bool:
    text = " ".join(_compact(row)).lower()
    return "release" in text and ("premier" in text or "support" in text or "ga date" in text)


def _is_section_title(row: list, n_cols: int) -> str | None:
    """
    Return the section title string if this row looks like a product section header,
    otherwise None.
    """
    cells = _compact(row)
    if len(cells) == 1:
        title = cells[0]
        # Must contain at least one letter and not look like a version or date
        if re.search(r"[A-Za-z]{3}", title) and not _is_header([title]):
            # Exclude footnote markers that are just digits
            if not re.fullmatch(r"\d+", title):
                return title
    # Wide tables sometimes have an empty first cell then the title
    if len(cells) == 2 and cells[0] == "":
        title = cells[1]
        if re.search(r"[A-Za-z]{3}", title) and not _is_header([title]):
            return title
    return None


# ── Column position mapping ────────────────────────────────────────────────

def _map_columns(header_rows: list[list]) -> dict[str, int]:
    """
    Given one or two header rows (possibly split across lines), return a
    dict mapping field name → column index.
    """
    # Merge two header rows into one text-per-column list
    max_cols = max((len(r) for r in header_rows), default=0)
    merged: list[str] = []
    for col in range(max_cols):
        parts = []
        for row in header_rows:
            if col < len(row) and row[col] is not None:
                parts.append(str(row[col]).replace("\n", " ").strip())
        merged.append(" ".join(p for p in parts if p).lower())

    result: dict[str, int] = {}
    for idx, text in enumerate(merged):
        if "release" in text and "release" not in result:
            result["release"] = idx
        elif ("ga" in text or "general availability" in text) and "ga" not in result:
            result["ga"] = idx
        elif "premier" in text and "premier" not in result:
            result["premier"] = idx
        elif "extended" in text and "extended" not in result:
            result["extended"] = idx
        elif "sustaining" in text and "sustaining" not in result:
            result["sustaining"] = idx

    return result


def _extract_cell(row: list, idx: int | None, window: int = 2) -> str | None:
    """Extract cell at idx, searching nearby columns to handle wide-format offsets."""
    if idx is None:
        return None
    for delta in range(window + 1):
        for i in ([idx + delta] if delta == 0 else [idx + delta, idx - delta]):
            if 0 <= i < len(row) and row[i] is not None:
                s = str(row[i]).strip()
                if s:
                    return s
    return None


# ── Section title normalisation ────────────────────────────────────────────

def _normalise_product_name(raw: str) -> str | None:
    """Map a raw PDF section header to a canonical product name, or None to skip."""
    # Strip footnote markers (superscript numbers/letters) and trailing punctuation
    cleaned = re.sub(r"\s*\d[\d,\s]*$", "", raw).strip()
    cleaned = re.sub(r"\s+releases?\s*$", "", cleaned, flags=re.IGNORECASE).strip()
    lower = cleaned.lower()

    for pattern, canonical in _PRODUCT_NAME_MAP:
        if pattern in lower:
            return canonical
    return None


# ── Version normalisation ──────────────────────────────────────────────────

def _normalise_version(raw: str) -> str | None:
    """
    Extract a clean version key from the Release cell.
    Handles:
      "12.2.1.4"              → "12.2.1.4"
      "Release 19c"           → "19c"
      "Oracle WebLogic 15.x"  → "15.x"   (product-name + version pattern)
      "9iAS R2 (9.0.2)"       → "9iAS R2 (9.0.2)"
    Returns None if the cell doesn't look like a version at all.
    """
    if not raw or len(raw) > 120:
        return None
    # Strip trailing footnote markers: "12.2.1 1,3" → "12.2.1"
    cleaned = re.sub(r"\s+\d[\d,\s]*$", "", raw.strip()).strip()
    # Direct version: starts with a digit
    if re.match(r"^\d", cleaned):
        return cleaned
    # "Release N" style
    m = re.match(r"^release\s+(.+)", cleaned, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # "Product Name X.Y.Z" — extract trailing version from suffix.
    # Matches: "Oracle WebLogic Server 15.x", "Fusion Middleware 14.1.x 1", etc.
    m = re.search(
        r"\b(\d[\d.x*c]+"  # version starts with digit, may include letters like "21c"
        r"(?:\s*\([\w\s]+\))?)"  # optional suffix like "(Innovation Release)"
        r"\s*$",
        cleaned,
        re.IGNORECASE,
    )
    if m:
        candidate = m.group(1).strip()
        if not re.match(r"^\d{4}$", candidate):  # reject bare years
            return candidate
    return None


# ── PDF parsing ────────────────────────────────────────────────────────────

def parse_pdf(pdf_bytes: bytes, category: str) -> list[dict]:
    """
    Parse a single PDF and return a flat list of records:
        {product, release, ga_date, premier_support_ends,
         extended_support_ends, sustaining_support_ends, category, source_title}
    """
    records: list[dict] = []

    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        current_product: str | None = None

        for page_num, page in enumerate(pdf.pages, start=1):
            tables = page.extract_tables()
            if not tables:
                continue

            for table in tables:
                col_map: dict[str, int] = {}
                header_buffer: list[list] = []
                pending_section: str | None = None

                for row in table:
                    if _is_spacer(row):
                        continue

                    # ── Section title detection ────────────────────────────
                    title = _is_section_title(row, len(row))
                    if title:
                        canonical = _normalise_product_name(title)
                        # Always update current_product — even to None.
                        # An unrecognised section title must stop data collection
                        # so rows from unknown products don't bleed into the
                        # previous product's bucket.
                        # col_map is preserved: sections in the same table share
                        # a single column layout defined at the top of the table.
                        current_product = canonical
                        pending_section = title
                        continue

                    # ── Header detection ───────────────────────────────────
                    if _is_header(row):
                        header_buffer.append(row)
                        col_map = _map_columns(header_buffer)
                        continue

                    # ── Data row ───────────────────────────────────────────
                    if not col_map:
                        continue

                    release_raw = _extract_cell(row, col_map.get("release"))
                    if not release_raw:
                        continue

                    # Many PDF tables embed the product name in the release cell,
                    # e.g. "Oracle WebLogic Server 15.x" or "Fusion Middleware 14.1.x".
                    # Use this to both set/update current_product and extract the version.
                    embedded_product = _normalise_product_name(release_raw)
                    if embedded_product:
                        current_product = embedded_product

                    version = _normalise_version(release_raw)
                    if not version or current_product is None:
                        continue

                    ga_raw       = _extract_cell(row, col_map.get("ga"))
                    premier_raw  = _extract_cell(row, col_map.get("premier"))
                    extended_raw = _extract_cell(row, col_map.get("extended"))

                    records.append({
                        "product":                current_product,
                        "release":                version,
                        "ga_date":                _parse_date(ga_raw),
                        "premier_support_ends":   _parse_date(premier_raw),
                        "extended_support_ends":  _parse_date(extended_raw),
                        "category":               category,
                    })

    return records


# ── HTTP fetch ─────────────────────────────────────────────────────────────

def _fetch_url(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "oracle-cve-intel/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _cache_path(url: str) -> Path:
    slug = re.sub(r"[^a-z0-9]", "_", url.lower())[-80:]
    return _CACHE_DIR / f"{slug}.pdf"


# ── Main ───────────────────────────────────────────────────────────────────

def build_support_dates(force: bool = False) -> dict:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    all_records: list[dict] = []
    source_meta: list[dict] = []

    for source in _PDF_SOURCES:
        url      = source["url"]
        category = source["category"]
        cached   = _cache_path(url)

        if cached.exists() and not force:
            print(f"[{category:12s}] Using cached PDF: {cached.name}")
            pdf_bytes = cached.read_bytes()
        else:
            print(f"[{category:12s}] Downloading {url} ...")
            try:
                pdf_bytes = _fetch_url(url)
                cached.write_bytes(pdf_bytes)
                print(f"[{category:12s}] Saved to {cached.name} ({len(pdf_bytes)//1024} KB)")
            except Exception as exc:
                print(f"[{category:12s}] WARN: failed to fetch {url}: {exc}")
                continue

        print(f"[{category:12s}] Parsing ...")
        records = parse_pdf(pdf_bytes, category)
        print(f"[{category:12s}] Extracted {len(records)} records.")
        all_records.extend(records)
        source_meta.append({"url": url, "category": category, "fetched_at": str(date.today())})

    # Deduplicate and group by product → release
    products: dict[str, dict[str, dict]] = {}
    for rec in all_records:
        product = rec["product"]
        release = rec["release"]
        if product not in products:
            products[product] = {}
        # Keep the entry with the most information (prefer non-None fields)
        existing = products[product].get(release)
        if existing is None or _record_score(rec) > _record_score(existing):
            products[product][release] = {
                "ga_date":               rec["ga_date"],
                "premier_support_ends":  rec["premier_support_ends"],
                "extended_support_ends": rec["extended_support_ends"],
                "category":              rec["category"],
            }

    # Sort each product's releases (newest first by version string)
    sorted_products = {
        product: dict(
            sorted(releases.items(), key=lambda kv: _version_sort_key(kv[0]), reverse=True)
        )
        for product, releases in sorted(products.items())
    }

    return {
        "_meta": {
            "generated_at": datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
            "sources":       source_meta,
            "record_count":  sum(len(v) for v in sorted_products.values()),
        },
        "products": sorted_products,
    }


def _record_score(rec: dict) -> int:
    """Count non-None date fields — used to prefer richer records on dedup."""
    return sum(
        1 for k in ("ga_date", "premier_support_ends", "extended_support_ends")
        if rec.get(k) is not None
    )


def _version_sort_key(version: str) -> tuple:
    """Sort versions numerically where possible."""
    parts = re.split(r"[.\s]", version)
    key = []
    for part in parts:
        m = re.match(r"^(\d+)", part)
        key.append(int(m.group(1)) if m else 0)
    return tuple(key)


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force",   action="store_true", help="Re-download PDFs even if cached")
    parser.add_argument("--dry-run", action="store_true", help="Print output JSON without writing to disk")
    args = parser.parse_args()

    data = build_support_dates(force=args.force)

    n_products = len(data["products"])
    n_releases = data["_meta"]["record_count"]
    print(f"\nExtracted {n_releases} release entries across {n_products} products.")

    if args.dry_run:
        print(json.dumps(data, indent=2))
        return

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _OUTPUT_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Written to {_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
