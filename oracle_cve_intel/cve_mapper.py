from __future__ import annotations

from dataclasses import replace
from itertools import zip_longest
import re

from .api_client import ApiClient, SourceError
from .cache_manager import CacheManager
from .config import NVD_BASE_URL, NVD_CPE_DICT_URL, ORACLE_ALERTS_URL
from .oracle_patch_resolver import OraclePatchResolver
from .models import (
    AffectedStatus,
    ConfidenceLevel,
    CVERecord,
    FindingRecord,
    PatchReferenceRecord,
    ProductRecord,
    ReferenceRecord,
    Severity,
)
from .runtime import RunContext


class NvdCVEMapper:
    def __init__(self, api_client: ApiClient, cache: CacheManager, run_ctx: RunContext) -> None:
        self.api_client = api_client
        self.cache = cache
        self.run_ctx = run_ctx
        self.patch_resolver = OraclePatchResolver(api_client, cache, run_ctx)

    def map(self, records: list[ProductRecord]) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        total = len(records)
        for index, product in enumerate(records, start=1):
            product_name = product.normalized_product_name or product.raw_product_name
            if not product.cpe_prefix or not product.normalized_version_for_cpe:
                self.run_ctx.progress("map", f"[{index}/{total}] Skipping {product_name} {product.raw_version}: no CPE query available.", "warn")
                findings.append(_insufficient_mapping(product, "Product or version could not be resolved to a CPE query."))
                continue

            cpe_name = _build_cpe_name(product.cpe_prefix, product.normalized_version_for_cpe)
            self.run_ctx.progress("map", f"[{index}/{total}] Querying NVD for {product_name} {product.raw_version} ...")
            try:
                payload = self._fetch_nvd_cpe(cpe_name)
            except SourceError as exc:
                self.run_ctx.add_error("map", "NVD", str(exc))
                self.run_ctx.progress("map", f"[{index}/{total}] NVD unavailable for {product_name}; continuing.", "warn")
                findings.append(_insufficient_mapping(product, "NVD unavailable during CPE mapping."))
                continue

            vulnerabilities = payload.get("vulnerabilities", [])
            self.run_ctx.progress("map", f"[{index}/{total}] NVD returned {len(vulnerabilities)} CVEs for {product_name}.")
            if not vulnerabilities:
                self._warn_with_cpe_suggestions(product)
            if not vulnerabilities:
                findings.append(
                    FindingRecord(
                        product=product,
                        cve=CVERecord(
                            cve_id=f"NVD-NO-CVE-{product.input_id}",
                            description=f"NVD returned no CVEs for {product.normalized_product_name}.",
                            severity=Severity.INFORMATIONAL,
                        ),
                        affected_status=AffectedStatus.NOT_AFFECTED,
                        mapping_confidence=ConfidenceLevel.HIGH,
                        evidence_references=[
                            ReferenceRecord(
                                label=f"NVD CPE query returned zero results for {cpe_name}",
                                url="https://nvd.nist.gov/developers/vulnerabilities",
                                source="NVD",
                            )
                        ],
                        confidence_level=ConfidenceLevel.HIGH,
                    )
                )
                continue

            # Pre-pass: collect NVD references for all wildcard CVEs, then bulk-scan
            # each unique post-2020 Oracle advisory once (rather than once per CVE).
            refs_by_wildcard_cve: dict[str, list[dict]] = {}
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                status_tmp, _ = _affected_status(product, cve_data)
                if status_tmp == AffectedStatus.NVD_WILDCARD_NO_VERSIONS:
                    refs_by_wildcard_cve[cve_id] = cve_data.get("references", [])

            # confirmed_by_advisory: cve_id → advisory URL that confirmed it
            confirmed_by_advisory: dict[str, str] = {}
            advisory_urls_scanned: list[str] = []
            if refs_by_wildcard_cve and product.normalized_version_for_cpe:
                confirmed_by_advisory, advisory_urls_scanned = self.patch_resolver.bulk_confirm_wildcard_cves(
                    refs_by_wildcard_cve,
                    product.normalized_product_name or product.raw_product_name,
                    product.normalized_version_for_cpe,
                )
                if confirmed_by_advisory:
                    self.run_ctx.progress(
                        "map",
                        f"[{index}/{total}] Oracle advisory confirmed {len(confirmed_by_advisory)} CVEs "
                        f"for {product_name} {product.raw_version} "
                        f"({_advisory_date_range(advisory_urls_scanned)}).",
                    )

            nvd_cve_ids: set[str] = set()
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                nvd_cve_ids.add(cve_id)
                affected_status, confidence = _affected_status(product, cve_data)
                if (
                    affected_status == AffectedStatus.NVD_WILDCARD_NO_VERSIONS
                    and product.normalized_version_for_cpe
                ):
                    if cve_id in confirmed_by_advisory:
                        affected_status = AffectedStatus.CONFIRMED_AFFECTED
                        confidence = ConfidenceLevel.MEDIUM
                    # else: keep NVD_WILDCARD_NO_VERSIONS so the finding stays suppressed.
                cve = _cve_from_nvd(cve_data)
                evidence = [
                    ReferenceRecord(
                        label=f"NVD CPE query evidence for {cpe_name}",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        source="NVD",
                    ),
                    ReferenceRecord(
                        label="Oracle Critical Patch Updates",
                        url=ORACLE_ALERTS_URL,
                        source="Oracle",
                    ),
                ]
                if affected_status == AffectedStatus.NVD_WILDCARD_NO_VERSIONS:
                    evidence.append(
                        ReferenceRecord(
                            label="NVD uses wildcard CPE for this product — version range resolved from Oracle CPU advisory",
                            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            source="NVD",
                        )
                    )
                fixed_version = _fixed_version_from_configurations(product, cve_data)
                resolver_patch = self.patch_resolver.resolve(product, cve_id, confidence, cve_data.get("references", []))
                if resolver_patch and fixed_version and resolver_patch.fixed_version is None:
                    resolver_patch = replace(resolver_patch, fixed_version=fixed_version)
                patch_ref = resolver_patch or _oracle_patch_placeholder(product, cve_id, confidence, fixed_version)
                findings.append(
                    FindingRecord(
                        product=product,
                        cve=cve,
                        affected_status=affected_status,
                        mapping_confidence=confidence,
                        evidence_references=evidence,
                        patch_references=[patch_ref],
                        confidence_level=confidence,
                    )
                )

            # When the advisory scan ran but confirmed nothing AND NVD had no version-specific
            # data for this product (all CVEs were wildcard), create a visible informational
            # finding so the product card appears in the report with an explanation.
            all_nvd_are_wildcard = bool(refs_by_wildcard_cve) and len(refs_by_wildcard_cve) == len(vulnerabilities)
            if advisory_urls_scanned and not confirmed_by_advisory and all_nvd_are_wildcard:
                n = len(advisory_urls_scanned)
                date_range = _advisory_date_range(advisory_urls_scanned)
                warn_msg = (
                    f"{product_name} {product.raw_version}: scanned {n} Oracle CPU "
                    f"advisories ({date_range}), 0 CVEs confirmed for this version. "
                    "This product/version may not be covered by recent Oracle security patches."
                )
                self.run_ctx.add_warning("map", warn_msg)
                findings.append(
                    FindingRecord(
                        product=product,
                        cve=CVERecord(
                            cve_id=f"ADVISORY-SCAN-{product.input_id}",
                            description=warn_msg,
                            severity=Severity.INFORMATIONAL,
                        ),
                        affected_status=AffectedStatus.NOT_AFFECTED,
                        mapping_confidence=ConfidenceLevel.LOW,
                        evidence_references=[
                            ReferenceRecord(
                                label=f"Oracle CPU advisory scan — {n} advisories, {date_range}",
                                url=ORACLE_ALERTS_URL,
                                source="Oracle",
                            ),
                        ],
                        confidence_level=ConfidenceLevel.LOW,
                    )
                )

            # Create findings for advisory-confirmed CVEs not returned by NVD at all.
            advisory_only_ids = sorted(set(confirmed_by_advisory) - nvd_cve_ids)
            for cve_id in advisory_only_ids:
                advisory_url = confirmed_by_advisory[cve_id]
                advisory_refs = [{"url": advisory_url}]
                patch_ref = self.patch_resolver.resolve(
                    product, cve_id, ConfidenceLevel.MEDIUM, advisory_refs
                ) or _oracle_patch_placeholder(product, cve_id, ConfidenceLevel.MEDIUM)
                findings.append(
                    FindingRecord(
                        product=product,
                        cve=CVERecord(
                            cve_id=cve_id,
                            description=(
                                f"Confirmed by Oracle CPU advisory for {product_name} {product.raw_version}. "
                                "Full CVE details will be filled in by the enrichment phase."
                            ),
                            severity=Severity.INFORMATIONAL,
                        ),
                        affected_status=AffectedStatus.CONFIRMED_AFFECTED,
                        mapping_confidence=ConfidenceLevel.MEDIUM,
                        evidence_references=[
                            ReferenceRecord(
                                label=f"Oracle CPU advisory confirms {cve_id} for {product_name} {product.raw_version}",
                                url=advisory_url,
                                source="Oracle",
                            ),
                        ],
                        patch_references=[patch_ref],
                        confidence_level=ConfidenceLevel.MEDIUM,
                    )
                )
        return findings

    def _warn_with_cpe_suggestions(self, product: ProductRecord) -> None:
        prefix = product.cpe_prefix
        version = product.normalized_version_for_cpe or product.raw_version
        raw = product.raw_version
        major = version.split(".")[0]
        # De-padded form for exclusion (e.g. "12.1.0.0.0" → "12.1")
        stripped = version
        while stripped.endswith(".0"):
            stripped = stripped[:-2]
        match_string = f"{prefix}:{major}.*:*:*:*:*:*:*:*"
        cache_key = f"cpe_dict_{prefix}_{major}"
        cached = self.cache.get("nvd", cache_key)
        if cached and not self.cache.is_stale("nvd", cache_key):
            payload = cached
        else:
            try:
                payload = self.api_client.get(NVD_CPE_DICT_URL, {"cpeMatchString": match_string}, "nvd")
                self.cache.set("nvd", cache_key, payload)
            except SourceError:
                self.run_ctx.add_warning(
                    "map",
                    f"{product.normalized_product_name or product.raw_product_name} {raw}: "
                    "version not found in NVD — CPE dictionary unavailable to suggest alternatives.",
                )
                return
        exclude = {"*", "-", "", version, stripped, raw}
        known = []
        for entry in payload.get("products", []):
            cpe_name = entry.get("cpe", {}).get("cpeName", "")
            parts = cpe_name.split(":")
            if len(parts) > 5 and parts[5] not in exclude:
                known.append(parts[5])
        product_name = product.normalized_product_name or product.raw_product_name
        if known:
            closest = _closest_versions(version, list(dict.fromkeys(known)))
            self.run_ctx.add_warning(
                "map",
                f"{product_name} {raw}: version '{raw}' not found in NVD CPE dictionary. "
                f"Known versions for {product_name} {major}.x — did you mean: {', '.join(closest[:5])}?",
            )
        else:
            self.run_ctx.add_warning(
                "map",
                f"{product_name} {raw}: version '{raw}' not found in NVD CPE dictionary "
                f"and no known versions found for major version {major}.",
            )

    def _fetch_nvd_cpe(self, cpe_name: str) -> dict:
        cache_key = f"cpe_{cpe_name}"
        cached = self.cache.get("nvd", cache_key)
        if cached and not self.cache.is_stale("nvd", cache_key):
            self.run_ctx.progress("map", f"Cache hit for NVD CPE query {cpe_name}.")
            return cached
        self.run_ctx.progress("map", f"Fetching NVD CPE query {cpe_name}.")
        try:
            payload = self.api_client.get(NVD_BASE_URL, {"cpeName": cpe_name}, "nvd")
        except SourceError:
            if cached:
                self.run_ctx.add_warning("map", f"Using stale NVD cache for {cpe_name}")
                return cached
            raise
        # If the padded CPE returns no results or only wildcard matches, retry without
        # the trailing .0 added by version padding — NVD products differ in component count
        # (e.g. WebLogic uses 5-part versions, Oracle Database uses 4-part).
        if _should_retry_without_trailing_zero(payload, cpe_name):
            stripped_cpe = _strip_trailing_zero(cpe_name)
            self.run_ctx.progress("map", f"Retrying NVD query without trailing .0: {stripped_cpe}.")
            try:
                retry_payload = self.api_client.get(NVD_BASE_URL, {"cpeName": stripped_cpe}, "nvd")
                if retry_payload.get("totalResults", 0) > payload.get("totalResults", 0):
                    payload = retry_payload
                    self.run_ctx.add_api_call(f"{NVD_BASE_URL}?cpeName={stripped_cpe}", "ok", 0, False)
            except SourceError:
                pass
        self.cache.set("nvd", cache_key, payload)
        self.run_ctx.add_api_call(f"{NVD_BASE_URL}?cpeName={cpe_name}", "ok", 0, False)
        return payload


class MockCVEMapper:
    def map(self, records: list[ProductRecord]) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        for index, product in enumerate(records, start=1):
            if not product.cpe_prefix or not product.normalized_version_for_cpe:
                findings.append(
                    FindingRecord(
                        product=product,
                        cve=CVERecord(
                            cve_id=f"MOCK-NO-CPE-{index:03d}",
                            description="Product or version could not be mapped to a CPE. Live mapping is unavailable in mock mode.",
                            severity=Severity.INFORMATIONAL,
                        ),
                        affected_status=AffectedStatus.NOT_ENOUGH_VERSION_INFORMATION,
                        mapping_confidence=ConfidenceLevel.UNKNOWN,
                        evidence_references=[
                            ReferenceRecord(
                                label="Mock mapper insufficient CPE evidence",
                                url="https://nvd.nist.gov/products/cpe",
                                source="mock:cve_mapper",
                            )
                        ],
                        confidence_level=ConfidenceLevel.UNKNOWN,
                    )
                )
                continue

            findings.append(
                FindingRecord(
                    product=product,
                    cve=CVERecord(
                        cve_id=f"CVE-2024-{index:04d}",
                        description=f"Mock critical vulnerability affecting {product.normalized_product_name}.",
                        severity=Severity.CRITICAL if index % 2 else Severity.HIGH,
                        published_date=f"2023-{(index % 12) + 1:02d}-15",
                        references=[
                            ReferenceRecord(
                                label="NVD CVE detail",
                                url=f"https://nvd.nist.gov/vuln/detail/CVE-2024-{index:04d}",
                                source="NVD",
                            )
                        ],
                    ),
                    affected_status=AffectedStatus.CONFIRMED_AFFECTED,
                    mapping_confidence=ConfidenceLevel.HIGH,
                    evidence_references=[
                        ReferenceRecord(
                            label="Mock NVD CPE match evidence",
                            url=f"https://nvd.nist.gov/vuln/detail/CVE-2024-{index:04d}",
                            source="NVD",
                        ),
                        ReferenceRecord(
                            label="Oracle Critical Patch Updates",
                            url="https://www.oracle.com/security-alerts/",
                            source="Oracle",
                        ),
                    ],
                    patch_references=[
                        _mock_patch_reference(product, f"CVE-2024-{index:04d}", confirmed=True)
                    ],
                    confidence_level=ConfidenceLevel.HIGH,
                )
            )
            findings.append(
                FindingRecord(
                    product=product,
                    cve=CVERecord(
                        cve_id=f"CVE-2023-{index:04d}",
                        description=f"Mock potentially applicable vulnerability for {product.normalized_product_name}.",
                        severity=Severity.MEDIUM,
                        published_date=f"2022-{(index % 12) + 1:02d}-15",
                        references=[
                            ReferenceRecord(
                                label="NVD CVE detail",
                                url=f"https://nvd.nist.gov/vuln/detail/CVE-2023-{index:04d}",
                                source="NVD",
                            )
                        ],
                    ),
                    affected_status=AffectedStatus.POTENTIALLY_AFFECTED,
                    mapping_confidence=ConfidenceLevel.MEDIUM,
                    evidence_references=[
                        ReferenceRecord(
                            label="Mock NVD version range evidence",
                            url=f"https://nvd.nist.gov/vuln/detail/CVE-2023-{index:04d}",
                            source="NVD",
                        )
                    ],
                    patch_references=[
                        _mock_patch_reference(product, f"CVE-2023-{index:04d}", confirmed=False)
                    ],
                    confidence_level=ConfidenceLevel.MEDIUM,
                )
            )
        return findings


def _insufficient_mapping(product: ProductRecord, reason: str) -> FindingRecord:
    return FindingRecord(
        product=product,
        cve=CVERecord(
            cve_id=f"NO-CVE-{product.input_id}",
            description=reason,
            severity=Severity.INFORMATIONAL,
        ),
        affected_status=AffectedStatus.NOT_ENOUGH_VERSION_INFORMATION,
        mapping_confidence=ConfidenceLevel.UNKNOWN,
        evidence_references=[
            ReferenceRecord(
                label=reason,
                url="https://nvd.nist.gov/products/cpe",
                source="NVD",
            )
        ],
        confidence_level=ConfidenceLevel.UNKNOWN,
    )


def _build_cpe_name(cpe_prefix: str, version: str) -> str:
    return f"{cpe_prefix}:{version}:*:*:*:*:*:*:*"


def _strip_trailing_zero(cpe_name: str) -> str:
    suffix = ":*:*:*:*:*:*:*"
    if not cpe_name.endswith(suffix):
        return cpe_name
    core = cpe_name[: -len(suffix)]
    while core.endswith(".0"):
        core = core[:-2]
    return core + suffix


def _should_retry_without_trailing_zero(payload: dict, cpe_name: str) -> bool:
    if not cpe_name.endswith(".0:*:*:*:*:*:*:*"):
        return False
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return True
    for item in vulns:
        for cfg in item.get("cve", {}).get("configurations", []) or []:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    has_range = any(k in match for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
                    if has_range:
                        return False
    return True


def _all_wildcard_no_ranges(vulnerabilities: list[dict]) -> bool:
    if not vulnerabilities:
        return True
    for item in vulnerabilities:
        for cfg in item.get("cve", {}).get("configurations", []) or []:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    has_range = any(k in match for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
                    if has_range:
                        return False
    return True


def _closest_versions(target: str, versions: list[str]) -> list[str]:
    target_tuple = _parse_version(target) or (0,)
    def distance(v: str) -> int:
        t = _parse_version(v) or (0,)
        return sum(abs(a - b) for a, b in zip_longest(target_tuple, t, fillvalue=0))
    return sorted(versions, key=distance)


def _affected_status(product: ProductRecord, cve_data: dict) -> tuple[AffectedStatus, ConfidenceLevel]:
    version = product.normalized_version_for_cpe
    if not version:
        return AffectedStatus.NOT_ENOUGH_VERSION_INFORMATION, ConfidenceLevel.UNKNOWN
    configurations = cve_data.get("configurations") or []
    if not configurations:
        return AffectedStatus.NOT_ENOUGH_VERSION_INFORMATION, ConfidenceLevel.UNKNOWN

    any_ambiguous = False
    for configuration in configurations:
        matched, ambiguous = _configuration_matches(configuration, product.cpe_prefix or "", version)
        any_ambiguous = any_ambiguous or ambiguous
        if matched is True:
            return AffectedStatus.CONFIRMED_AFFECTED, ConfidenceLevel.HIGH
        if matched == "wildcard_only":
            any_ambiguous = True
    if any_ambiguous:
        return AffectedStatus.NVD_WILDCARD_NO_VERSIONS, ConfidenceLevel.LOW
    return AffectedStatus.NOT_AFFECTED, ConfidenceLevel.MEDIUM


def _configuration_matches(configuration: dict, cpe_prefix: str, version: str) -> tuple[bool | str | None, bool]:
    results = [_node_matches(node, cpe_prefix, version) for node in configuration.get("nodes", [])]
    return _combine("OR", results)


def _node_matches(node: dict, cpe_prefix: str, version: str) -> tuple[bool | str | None, bool]:
    results: list[tuple[bool | str | None, bool]] = []
    for match in node.get("cpeMatch", []):
        result = _cpe_match_applies(match, cpe_prefix, version)
        if result[0] is not False or result[1]:
            results.append(result)
    for child in node.get("children", []):
        results.append(_node_matches(child, cpe_prefix, version))
    matched, ambiguous = _combine(node.get("operator", "OR"), results)
    if node.get("negate"):
        matched = None if matched is None else not matched
    return matched, ambiguous


def _combine(operator: str, results: list[tuple[bool | str | None, bool]]) -> tuple[bool | str | None, bool]:
    if not results:
        return False, False
    ambiguous = any(item[1] for item in results)
    values = [item[0] for item in results]
    if operator == "AND":
        if any(value is False for value in values):
            return False, ambiguous
        if any(value is None for value in values):
            return None, True
        if any(value == "wildcard_only" for value in values):
            return "wildcard_only", True
        return True, ambiguous
    if any(value is True for value in values):
        return True, ambiguous
    if any(value == "wildcard_only" for value in values):
        return "wildcard_only", True
    if any(value is None for value in values):
        return None, True
    return False, ambiguous


def _cpe_match_applies(match: dict, cpe_prefix: str, version: str) -> tuple[bool | str | None, bool]:
    criteria = match.get("criteria", "")
    if not criteria.startswith(cpe_prefix):
        return False, False
    if match.get("vulnerable") is False:
        return False, False
    parsed_version = _parse_version(version)
    if parsed_version is None:
        return None, True

    range_keys = {
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    }
    if not any(key in match for key in range_keys):
        criteria_version = _criteria_version(criteria)
        if criteria_version in {"*", "-", ""}:
            return "wildcard_only", True
        parsed_criteria = _parse_version(criteria_version)
        if parsed_criteria is None:
            return None, True
        return _version_tuple(parsed_version) == _version_tuple(parsed_criteria), False

    for key in range_keys:
        if key not in match:
            continue
        bound = _parse_version(match[key])
        if bound is None:
            return None, True
        cmp_value = _compare_versions(parsed_version, bound)
        if key == "versionStartIncluding" and cmp_value < 0:
            return False, False
        if key == "versionStartExcluding" and cmp_value <= 0:
            return False, False
        if key == "versionEndIncluding" and cmp_value > 0:
            return False, False
        if key == "versionEndExcluding" and cmp_value >= 0:
            return False, False
    return True, False


def _parse_version(version: str) -> tuple[int, ...] | None:
    value = version.lower().strip()
    if re.fullmatch(r"\d+c", value):
        value = f"{value[:-1]}.0.0.0.0"
    value = value.replace("_", ".").replace("-", ".")
    java = re.fullmatch(r"(\d+)u(\d+)", value)
    if java:
        value = f"{java.group(1)}.{java.group(2)}"
    parts = value.split(".")
    parsed: list[int] = []
    for part in parts:
        if not part:
            continue
        match = re.match(r"^(\d+)", part)
        if not match:
            return None
        parsed.append(int(match.group(1)))
    return tuple(parsed) if parsed else None


def _version_tuple(version: tuple[int, ...]) -> tuple[int, ...]:
    return version + (0,) * (8 - len(version))


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    left_padded = _version_tuple(left)
    right_padded = _version_tuple(right)
    if left_padded < right_padded:
        return -1
    if left_padded > right_padded:
        return 1
    return 0


def _criteria_version(criteria: str) -> str:
    parts = criteria.split(":")
    return parts[5] if len(parts) > 5 else ""


def _cve_from_nvd(cve_data: dict) -> CVERecord:
    cve_id = cve_data.get("id", "UNKNOWN-CVE")
    description = _english_description(cve_data)
    severity, score, vector = _cvss_from_nvd(cve_data)
    references = [
        ReferenceRecord(
            label=_reference_label(reference),
            url=reference.get("url", ""),
            source=reference.get("source") or "NVD",
        )
        for reference in cve_data.get("references", [])
        if reference.get("url")
    ]
    references.insert(
        0,
        ReferenceRecord(
            label="NVD CVE detail",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            source="NVD",
        ),
    )
    raw_published = cve_data.get("published", "")
    return CVERecord(
        cve_id=cve_id,
        description=description,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cwe=_cwe_from_nvd(cve_data),
        references=references,
        published_date=raw_published[:10] if raw_published and len(raw_published) >= 10 else None,
    )


def _english_description(cve_data: dict) -> str | None:
    descriptions = cve_data.get("descriptions", [])
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value")
    return descriptions[0].get("value") if descriptions else None


def _cvss_from_nvd(cve_data: dict) -> tuple[Severity, float | None, str | None]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not values:
            continue
        # Prefer the NVD Primary score; fall back to first entry if no Primary exists.
        entry = next((v for v in values if v.get("type") == "Primary"), values[0])
        metric = entry.get("cvssData", {})
        base_severity = entry.get("baseSeverity") or metric.get("baseSeverity")
        return _severity_from_text(base_severity), metric.get("baseScore"), metric.get("vectorString")
    return Severity.INFORMATIONAL, None, None


def _severity_from_text(value: str | None) -> Severity:
    if not value:
        return Severity.INFORMATIONAL
    normalized = value.lower()
    if normalized in {item.value for item in Severity}:
        return Severity(normalized)
    return Severity.INFORMATIONAL


def _cwe_from_nvd(cve_data: dict) -> str | None:
    for weakness in cve_data.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")
            if value and value.startswith("CWE-"):
                return value
    return None


def _reference_label(reference: dict) -> str:
    tags = reference.get("tags") or []
    source = reference.get("source") or "NVD reference"
    return f"{source} ({', '.join(tags)})" if tags else source


def _fixed_version_from_configurations(product: ProductRecord, cve_data: dict) -> str | None:
    version = product.normalized_version_for_cpe
    if not version:
        return None
    cpe_prefix = product.cpe_prefix or ""
    parsed_version = _parse_version(version)
    if parsed_version is None:
        return None
    for configuration in cve_data.get("configurations") or []:
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("criteria", "").startswith(cpe_prefix):
                    continue
                if match.get("vulnerable") is False:
                    continue
                end_excl = match.get("versionEndExcluding")
                if end_excl:
                    bound = _parse_version(end_excl)
                    if bound and _compare_versions(parsed_version, bound) < 0:
                        return end_excl
                end_incl = match.get("versionEndIncluding")
                if end_incl:
                    bound = _parse_version(end_incl)
                    if bound and _compare_versions(parsed_version, bound) <= 0:
                        return end_incl
    return None


def _advisory_date_range(urls: list[str]) -> str:
    """Format a human-readable date range from a list of Oracle advisory URLs (newest-first)."""
    if not urls:
        return "unknown dates"
    months = {
        "jan": "January", "feb": "February", "mar": "March", "apr": "April",
        "may": "May", "jun": "June", "jul": "July", "aug": "August",
        "sep": "September", "oct": "October", "nov": "November", "dec": "December",
    }

    def _label(url: str) -> str:
        m = re.search(r"cpu([a-z]{3})(\d{4})", url, re.IGNORECASE)
        if not m:
            return url
        return f"{months.get(m.group(1).lower(), m.group(1).capitalize())} {m.group(2)}"

    # urls is newest-first; show oldest → newest chronologically
    return f"{_label(urls[-1])} – {_label(urls[0])}"


def _oracle_patch_placeholder(product: ProductRecord, cve_id: str, confidence: ConfidenceLevel, fixed_version: str | None = None) -> PatchReferenceRecord:
    return PatchReferenceRecord(
        source="Oracle CPU advisory",
        advisory_title="Oracle Critical Patch Updates and Security Alerts",
        advisory_url=ORACLE_ALERTS_URL,
        product=product.normalized_product_name or product.raw_product_name,
        affected_versions=[product.raw_version],
        fixed_version=fixed_version,
        patch_id=None,
        patch_name=None,
        notes=f"Real NVD mapping found {cve_id}. Verify the exact Oracle patch ID and fixed version in the linked CPU advisory for this product/version.",
        confidence=confidence,
    )


def _mock_patch_reference(product: ProductRecord, cve_id: str, confirmed: bool) -> PatchReferenceRecord:
    product_name = product.normalized_product_name or product.raw_product_name
    version = product.raw_version
    fixed_version = _mock_fixed_version(product.normalized_version_for_cpe or version)
    year = cve_id[4:8] if len(cve_id) >= 8 else "2024"
    advisory_url = f"https://www.oracle.com/security-alerts/cpuapr{year}.html"
    return PatchReferenceRecord(
        source="Oracle CPU mock",
        advisory_title=f"Oracle Critical Patch Update Advisory – April {year}",
        advisory_url=advisory_url,
        product=product_name,
        affected_versions=[version],
        fixed_version=fixed_version if confirmed else None,
        patch_id=f"MOCK-{_stable_patch_number(product_name, cve_id)}",
        patch_name=f"{product_name} security update for {cve_id}",
        notes="Mock patch reference. Real implementation must verify the exact patch ID and fixed version against the matching Oracle CPU table.",
        confidence=ConfidenceLevel.MEDIUM if confirmed else ConfidenceLevel.LOW,
    )


def _mock_fixed_version(version: str) -> str:
    parts = version.split(".")
    if parts and parts[-1].isdigit():
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    return f"{version} or later"


def _stable_patch_number(product_name: str, cve_id: str) -> int:
    value = sum((index + 1) * ord(char) for index, char in enumerate(f"{product_name}:{cve_id}"))
    return value % 900000 + 100000
