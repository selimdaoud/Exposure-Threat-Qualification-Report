from __future__ import annotations

import re
from html.parser import HTMLParser

from .api_client import ApiClient, SourceError
from .cache_manager import CacheManager
from .models import ConfidenceLevel, PatchReferenceRecord, ProductRecord
from .runtime import RunContext


_MONTH_NAMES = {
    "jan": "January", "feb": "February", "mar": "March", "apr": "April",
    "may": "May", "jun": "June", "jul": "July", "aug": "August",
    "sep": "September", "oct": "October", "nov": "November", "dec": "December",
}
_MONTH_ORDER = {m: i for i, m in enumerate(_MONTH_NAMES, 1)}

# Matches both CPU (quarterly) and CSPU (monthly) advisory URLs.
_ORACLE_CPU_RE = re.compile(
    r"oracle\.com.*/(?:security-alerts|technetwork/security-advisory)/c(?:s)?pu([a-z]{3})(\d{4})",
    re.IGNORECASE,
)


def _is_cspu(url: str) -> bool:
    return bool(re.search(r"/cspu", url, re.IGNORECASE))

# Maps normalized product name substrings (lowercase) to the <h4 id="AppendixXXX"> section
# found in Oracle CPU advisory HTML pages.
_PRODUCT_SECTION: dict[str, str] = {
    "e-business suite": "AppendixEBS",
    "database server": "AppendixDB",
    "oracle database": "AppendixDB",
    "fusion middleware": "AppendixFMW",
    "java se": "AppendixJAVA",
    "oracle java": "AppendixJAVA",
    "mysql": "AppendixMSQL",
    "oracle vm": "AppendixOVIR",
    "oracle virtualization": "AppendixOVIR",
    "oracle systems": "AppendixSUNS",
    "oracle solaris": "AppendixSUNS",
}


class OraclePatchResolver:
    def __init__(self, api_client: ApiClient, cache: CacheManager, run_ctx: RunContext) -> None:
        self.api_client = api_client
        self.cache = cache
        self.run_ctx = run_ctx

    def resolve(
        self,
        product: ProductRecord,
        cve_id: str,
        confidence: ConfidenceLevel,
        nvd_references: list[dict],
    ) -> PatchReferenceRecord | None:
        """Return an enriched PatchReferenceRecord using Oracle advisory URL extracted from NVD
        references, or None if no Oracle advisory URL is found."""
        advisory_url = _earliest_oracle_advisory_url(nvd_references)
        if not advisory_url:
            return None

        advisory_title = _title_from_url(advisory_url)
        product_name = product.normalized_product_name or product.raw_product_name
        component = self._advisory_component(advisory_url, cve_id, product_name)

        patch_availability_url = self._patch_availability_url(advisory_url, product_name)
        note_parts = [f"Patch included in {advisory_title}."]
        if component:
            note_parts.append(f"Affected component: {component}.")
        if not patch_availability_url:
            note_parts.append("Obtain the exact patch bundle from My Oracle Support (patch ID and fixed version require MOS access).")

        is_cspu = _is_cspu(advisory_url)
        return PatchReferenceRecord(
            source="Oracle CSPU advisory" if is_cspu else "Oracle CPU advisory",
            advisory_title=advisory_title,
            advisory_url=advisory_url,
            product=product_name,
            affected_versions=[product.raw_version],
            fixed_version=None,
            patch_id=None,
            patch_name=_patch_link_label(product_name, advisory_url),
            patch_availability_url=patch_availability_url,
            notes=" ".join(note_parts),
            confidence=confidence,
            patch_type="cspu" if is_cspu else "cpu",
        )

    def _patch_availability_url(self, advisory_url: str, product_name: str) -> str | None:
        advisory_id = _advisory_id_from_url(advisory_url)
        if not advisory_id:
            return None
        cache_key = f"patch_availability_{advisory_id}"
        data = self.cache.get("oracle_advisories", cache_key)
        if data is None or self.cache.is_stale("oracle_advisories", cache_key):
            try:
                html_content = self.api_client.get_html(_normalize_url(advisory_url), "oracle")
                data = {"entries": _parse_patch_availability(html_content)}
                self.cache.set("oracle_advisories", cache_key, data)
            except SourceError:
                return None
        entries = data.get("entries", [])
        product_lower = product_name.lower().removeprefix("oracle ").strip()
        for entry in entries:
            if product_lower in entry.get("product", "").lower():
                return entry.get("url")
        tokens = [t for t in re.split(r"\W+", product_lower) if len(t) > 3]
        best_url, best_score = None, 0
        for entry in entries:
            entry_lower = entry.get("product", "").lower()
            score = sum(1 for tok in tokens if tok in entry_lower)
            if score > best_score:
                best_score, best_url = score, entry.get("url")
        return best_url

    def bulk_confirm_wildcard_cves(
        self,
        refs_by_cve_id: dict[str, list[dict]],
        normalized_product_name: str,
        installed_version: str,
    ) -> tuple[dict[str, str], list[str]]:
        """Scan all post-2020 Oracle CPU advisory URLs referenced by the given wildcard CVEs.

        Returns ``(confirmed, scanned_urls)`` where:
        - ``confirmed`` maps CVE ID → advisory URL (first advisory that confirmed it, newest-first).
          Covers BOTH CVEs in the NVD wildcard set AND advisory-only CVEs not returned by NVD.
        - ``scanned_urls`` is the ordered list of advisory URLs that were scanned.

        If the NVD CVE references don't contain post-2020 advisory URLs, falls back to
        scanning the last 2 years of quarterly Oracle CPU advisories.

        Fetches each unique advisory only once (cached); filters rows by product section.
        """
        seen_urls: set[str] = set()
        all_urls: list[str] = []
        for refs in refs_by_cve_id.values():
            for ref in refs:
                m = _ORACLE_CPU_RE.search(ref.get("url", ""))
                if not m or int(m.group(2)) < 2017:
                    continue
                url = _normalize_url(ref["url"])
                if url not in seen_urls:
                    seen_urls.add(url)
                    all_urls.append(url)
        # Fall back to scanning post-2017 quarterly advisories when CVE refs have no post-2017 URLs.
        if not all_urls:
            for url in self._recent_advisory_urls_from_index():
                if url not in seen_urls:
                    seen_urls.add(url)
                    all_urls.append(url)
        # confirmed maps cve_id → first advisory URL that confirmed it (newest first)
        confirmed: dict[str, str] = {}
        for url in all_urls:
            for cve_id in self._confirmed_cve_ids_for_product(url, normalized_product_name, installed_version):
                if cve_id not in confirmed:
                    confirmed[cve_id] = url
        return confirmed, all_urls

    def _recent_advisory_urls_from_index(self, min_year: int = 2017) -> list[str]:
        """Return Oracle CPU (quarterly) + CSPU (monthly, from 2026) advisory URLs.

        CSPUs are released on the third Tuesday of each month. For the current month
        we only include the CSPU URL if that date has already passed.
        The Oracle security alerts index page is JavaScript-rendered so we generate
        the predictable URLs directly.
        """
        import datetime
        now = datetime.date.today()
        all_months = ["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"]
        quarters = [("jan", 1), ("apr", 4), ("jul", 7), ("oct", 10)]
        _CSPU_START_YEAR = 2026
        urls: list[str] = []
        for year in range(min_year, now.year + 1):
            for month_abbr, month_num in quarters:
                if year == now.year and month_num > now.month:
                    break
                urls.append(f"https://www.oracle.com/security-alerts/cpu{month_abbr}{year}.html")
            if year >= _CSPU_START_YEAR:
                for i, month_abbr in enumerate(all_months):
                    month_num = i + 1
                    if year == now.year and month_num > now.month:
                        break
                    # Only include if the third Tuesday of that month has passed
                    if year == now.year and month_num == now.month:
                        if now < _third_tuesday(year, month_num):
                            break
                    urls.append(f"https://www.oracle.com/security-alerts/cspu{month_abbr}{year}.html")
        urls.reverse()  # newest first
        return urls

    def _confirmed_cve_ids_for_product(
        self,
        advisory_url: str,
        normalized_product_name: str,
        installed_version: str,
    ) -> set[str]:
        rows = self._risk_matrix_rows(advisory_url)
        section_id = _product_section_id(normalized_product_name)
        confirmed: set[str] = set()
        for row in rows:
            if section_id is not None and row.get("section_id") != section_id:
                continue
            versions_str = row.get("versions")
            if not versions_str:
                continue
            if _version_in_oracle_range(installed_version, versions_str) is True:
                confirmed.add(row["cve_id"])
        return confirmed

    def check_affected(
        self,
        nvd_references: list[dict],
        cve_id: str,
        installed_version: str,
    ) -> bool | None:
        """Return True/False/None: confirmed affected / not affected / unknown.

        Uses the Oracle CPU advisory risk matrix to determine whether the installed
        version falls within the affected version range for the given CVE.
        Only works for post-2020 advisories; falls back to None for older ones.
        """
        advisory_url = _earliest_oracle_advisory_url(nvd_references)
        if not advisory_url:
            return None
        rows = self._risk_matrix_rows(advisory_url)
        matches = [r for r in rows if r.get("cve_id") == cve_id]
        if not matches:
            return None
        versions_str = next((r["versions"] for r in matches if r.get("versions")), None)
        if not versions_str:
            return None
        return _version_in_oracle_range(installed_version, versions_str)

    def _advisory_component(self, advisory_url: str, cve_id: str, product_name: str) -> str | None:
        advisory_id = _advisory_id_from_url(advisory_url)
        if not advisory_id:
            return None
        rows = self._risk_matrix_rows(advisory_url)
        product_lower = product_name.lower()
        for row in rows:
            if row.get("cve_id") == cve_id and product_lower in (row.get("product") or "").lower():
                return row.get("component")
        for row in rows:
            if row.get("cve_id") == cve_id:
                return row.get("component")
        return None

    def _risk_matrix_rows(self, advisory_url: str) -> list[dict]:
        advisory_id = _advisory_id_from_url(advisory_url)
        if not advisory_id:
            return []
        cache_key = f"advisory_matrix_{advisory_id}"
        data = self.cache.get("oracle_advisories", cache_key)
        if data is None or self.cache.is_stale("oracle_advisories", cache_key):
            try:
                html_content = self.api_client.get_html(_normalize_url(advisory_url), "oracle")
                data = {"rows": _parse_risk_matrix(html_content)}
                self.cache.set("oracle_advisories", cache_key, data)
            except SourceError:
                return []
        return data.get("rows", [])


def _third_tuesday(year: int, month: int) -> "datetime.date":
    import datetime
    first = datetime.date(year, month, 1)
    days_to_first_tuesday = (1 - first.weekday()) % 7
    return first + datetime.timedelta(days=days_to_first_tuesday + 14)


def _normalize_url(url: str) -> str:
    return re.sub(r"(?<=oracle\.com)/+", "/", url)


def _earliest_oracle_advisory_url(references: list[dict]) -> str | None:
    """Return the earliest Oracle CPU advisory URL from a list of NVD references."""
    seen: set[str] = set()
    candidates: list[tuple[int, int, str]] = []
    for ref in references:
        raw_url = ref.get("url", "")
        m = _ORACLE_CPU_RE.search(raw_url)
        if not m:
            continue
        url = _normalize_url(raw_url)
        if url in seen:
            continue
        seen.add(url)
        month = _MONTH_ORDER.get(m.group(1).lower(), 99)
        year = int(m.group(2))
        candidates.append((year, month, url))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][2]


def _patch_link_label(product_name: str, advisory_url: str) -> str:
    m = _ORACLE_CPU_RE.search(advisory_url)
    if m:
        month = _MONTH_NAMES.get(m.group(1).lower(), m.group(1).capitalize())
        year = m.group(2)
        kind = "CSPU" if _is_cspu(advisory_url) else "CPU"
        return f"{product_name} – Oracle {kind} advisory {month} {year}"
    return product_name


def _title_from_url(url: str) -> str:
    m = _ORACLE_CPU_RE.search(url)
    if m:
        month = _MONTH_NAMES.get(m.group(1).lower(), m.group(1).capitalize())
        year = m.group(2)
        kind = "Critical Security Patch Update" if _is_cspu(url) else "Critical Patch Update"
        return f"Oracle {kind} Advisory – {month} {year}"
    m2 = re.search(r"alert-([a-z0-9-]+)", url, re.IGNORECASE)
    if m2:
        return f"Oracle Security Alert – {m2.group(1).upper()}"
    return "Oracle Critical Patch Updates and Security Alerts"


def _advisory_id_from_url(url: str) -> str | None:
    m = re.search(r"(c(?:s)?pu)([a-z]{3}\d{4})", url, re.IGNORECASE)
    return f"{m.group(1).lower()}{m.group(2).lower()}" if m else None


def _product_section_id(product_name: str) -> str | None:
    lower = product_name.lower()
    for key, sid in _PRODUCT_SECTION.items():
        if key in lower:
            return sid
    return None


def _parse_risk_matrix(html_content: str) -> list[dict]:
    parser = _RiskMatrixParser()
    parser.feed(html_content)
    return parser.rows


def _parse_patch_availability(html_content: str) -> list[dict]:
    parser = _PatchAvailabilityParser()
    parser.feed(html_content)
    return parser.entries


def _parse_oracle_version(v: str) -> tuple[int, ...] | None:
    parts = v.strip().split(".")
    result: list[int] = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            return None
    return tuple(result) if result else None


def _version_in_oracle_range(installed: str, versions_str: str) -> bool | None:
    """Check if `installed` falls within any range in an Oracle advisory versions string.

    Oracle format: comma-separated segments, each "X.Y.Z-X.Y.W" (inclusive range)
    or a single "X.Y.Z". Brackets like [ECC] are skipped.
    Returns True (affected), False (not affected), None (unparseable).
    """
    # Strip padded trailing zeros so "12.1.1.0.0" compares cleanly against "12.1.1"
    stripped = installed.rstrip("0").rstrip(".") if "." in installed else installed
    inst = _parse_oracle_version(stripped) or _parse_oracle_version(installed)
    if inst is None:
        return None

    any_parseable = False
    for segment in re.split(r",", versions_str):
        segment = re.sub(r"\[.*?\]", "", segment).strip()  # remove [ECC 11-13] etc.
        if not segment:
            continue
        # Determine if it's a range (contains "-" after stripping bracket content)
        dash_pos = segment.find("-")
        if dash_pos > 0:
            lo = _parse_oracle_version(segment[:dash_pos].strip())
            hi = _parse_oracle_version(segment[dash_pos + 1:].strip())
            if lo is None or hi is None:
                continue
            any_parseable = True
            n = max(len(inst), len(lo), len(hi))
            pad = lambda t: t + (0,) * (n - len(t))  # noqa: E731
            if pad(lo) <= pad(inst) <= pad(hi):
                return True
        else:
            v = _parse_oracle_version(segment)
            if v is None:
                continue
            any_parseable = True
            n = max(len(inst), len(v))
            pad = lambda t: t + (0,) * (n - len(t))  # noqa: E731
            if pad(inst) == pad(v):
                return True

    return False if any_parseable else None


class _RiskMatrixParser(HTMLParser):
    """Parses post-2020 Oracle CPU advisory risk matrix tables.

    Scans all <table> elements. For tables whose first <thead> row contains a
    "Supported Versions Affected" column, extracts per-CVE rows:
      {cve_id, product, component, versions}

    Handles the two-row merged thead (colspan/rowspan) by reading only the first
    header row to locate column indices. Data rows are flat (no rowspan).
    """

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict] = []

        # Section tracking: updated by <h4 id="AppendixXXX"> outside tables
        self._current_section: str | None = None
        self._table_section: str | None = None

        # Per-table state (reset on <table>)
        self._in_table = False
        self._in_thead = False
        self._in_tbody = False
        self._thead_first_row_done = False
        self._col_pos = 0
        self._versions_col: int | None = None
        self._component_col: int | None = None
        self._product_col: int | None = None

        # Per-row state (reset on <tr>)
        self._in_row = False
        self._row_th: str = ""
        self._row_tds: list[str] = []

        # Per-cell state
        self._in_cell = False
        self._cell_tag = ""
        self._cell_buf: list[str] = []
        self._cell_colspan = 1

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr = dict(attrs)
        if tag == "h4" and not self._in_table:
            sid = attr.get("id", "")
            if sid.startswith("Appendix"):
                self._current_section = sid
            return
        if tag == "table":
            self._in_table = True
            self._table_section = self._current_section  # snapshot for this table
            self._in_thead = self._in_tbody = False
            self._thead_first_row_done = False
            self._col_pos = 0
            self._versions_col = self._component_col = self._product_col = None
            return
        if not self._in_table:
            return
        if tag == "thead":
            self._in_thead = True
        elif tag == "tbody":
            self._in_tbody = True
        elif tag == "tr":
            self._in_row = True
            self._col_pos = 0
            self._row_th = ""
            self._row_tds = []
        elif tag in ("th", "td") and self._in_row:
            self._in_cell = True
            self._cell_tag = tag
            self._cell_buf = []
            self._cell_colspan = int(attr.get("colspan", 1))

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._in_table = self._in_thead = self._in_tbody = self._in_row = self._in_cell = False
            return
        if tag == "thead":
            self._in_thead = False
        elif tag == "tbody":
            self._in_tbody = False
        elif tag == "tr" and self._in_row:
            self._in_row = False
            if self._in_thead and not self._thead_first_row_done:
                self._thead_first_row_done = True
            elif self._in_tbody and self._versions_col is not None:
                self._flush_row()
        elif tag in ("th", "td") and self._in_cell:
            self._in_cell = False
            text = " ".join(self._cell_buf).strip()
            if self._in_thead and not self._thead_first_row_done:
                lower = text.lower()
                if "supported versions" in lower or ("version" in lower and "affected" in lower):
                    self._versions_col = self._col_pos
                elif lower == "component":
                    self._component_col = self._col_pos
                elif lower == "product":
                    self._product_col = self._col_pos
                self._col_pos += self._cell_colspan
            elif self._in_tbody:
                if self._cell_tag == "th":
                    self._row_th = text
                else:
                    self._row_tds.append(text)

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            text = data.strip()
            if text and text != "\xa0":
                self._cell_buf.append(text)

    def _flush_row(self) -> None:
        m = re.search(r"CVE-\d{4}-\d+", self._row_th)
        if not m or self._versions_col is None:
            return
        cve_id = m.group(0)

        def _td(col: int | None) -> str | None:
            if col is None:
                return None
            idx = col - 1  # col 0 is the <th>; <td>s start at col 1
            return self._row_tds[idx] if 0 <= idx < len(self._row_tds) else None

        versions = _td(self._versions_col)
        self.rows.append({
            "cve_id": cve_id,
            "product": _td(self._product_col),
            "component": _td(self._component_col),
            "versions": versions if versions and versions.strip() != "\xa0" else None,
            "section_id": self._table_section,
        })


class _PatchAvailabilityParser(HTMLParser):
    """Parses the 'Patch Availability' table from an Oracle CPU advisory page.

    Targets the two-column table with headers 'Affected Products and Versions'
    and 'Patch Availability Document', extracting product text and MOS URL pairs.
    """

    def __init__(self) -> None:
        super().__init__()
        self.entries: list[dict] = []
        self._in_target_table = False
        self._in_row = False
        self._in_cell = False
        self._is_header_row = False
        self._current_row_cells: list[str] = []
        self._current_row_urls: list[str] = []
        self._current_cell_text: list[str] = []
        self._current_cell_url: str | None = None
        self._headers_confirmed = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr_dict = dict(attrs)
        if tag == "table":
            self._in_target_table = True
            self._headers_confirmed = False
        elif tag == "tr" and self._in_target_table:
            self._in_row = True
            self._is_header_row = False
            self._current_row_cells = []
            self._current_row_urls = []
        elif tag == "th" and self._in_row:
            self._in_cell = True
            self._is_header_row = True
            self._current_cell_text = []
            self._current_cell_url = None
        elif tag == "td" and self._in_row:
            self._in_cell = True
            self._current_cell_text = []
            self._current_cell_url = None
        elif tag == "a" and self._in_cell:
            href = attr_dict.get("href", "")
            if "support.oracle.com" in href or "oracle.com" in href:
                self._current_cell_url = href

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._in_target_table = False
            self._in_row = False
            self._in_cell = False
        elif tag == "tr" and self._in_row:
            self._in_row = False
            if self._is_header_row:
                combined = " ".join(self._current_row_cells).lower()
                self._headers_confirmed = "patch availability" in combined and "affected" in combined
            elif self._headers_confirmed and len(self._current_row_cells) >= 2:
                product = self._current_row_cells[0]
                url = next((u for u in self._current_row_urls if u), None)
                if product and url:
                    self.entries.append({"product": product, "url": url})
        elif tag in ("td", "th") and self._in_cell:
            self._in_cell = False
            self._current_row_cells.append(" ".join(self._current_cell_text).strip())
            self._current_row_urls.append(self._current_cell_url or "")

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            text = data.strip()
            if text:
                self._current_cell_text.append(text)
