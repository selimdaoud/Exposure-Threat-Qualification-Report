from __future__ import annotations

from dataclasses import replace

from .api_client import ApiClient, SourceError
from .cache_manager import CacheManager
from .config import EPSS_URL, KEV_URL, NVD_BASE_URL
from .cve_mapper import _cve_from_nvd
from .models import CVERecord, FindingRecord, ReferenceRecord, Severity
from .runtime import RunContext


class RealCVEEnricher:
    def __init__(self, api_client: ApiClient, cache: CacheManager, run_ctx: RunContext) -> None:
        self.api_client = api_client
        self.cache = cache
        self.run_ctx = run_ctx

    def enrich(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        cve_ids = sorted({finding.cve.cve_id for finding in findings if finding.cve.cve_id.startswith("CVE-")})
        self.run_ctx.progress("enrich", f"Preparing enrichment for {len(cve_ids)} unique CVEs.")
        kev_ids = self._kev_ids()
        epss_scores = self._epss_scores(cve_ids)
        enriched: list[FindingRecord] = []
        total = len(findings)
        fallback_count = 0
        for index, finding in enumerate(findings, start=1):
            if not finding.cve.cve_id.startswith("CVE-"):
                enriched.append(finding)
                continue
            cve = finding.cve
            if _needs_nvd_enrichment(cve):
                fallback_count += 1
                if fallback_count == 1 or fallback_count % 25 == 0:
                    self.run_ctx.progress("enrich", f"NVD fallback enrichment {fallback_count} CVEs processed; currently {cve.cve_id} ({index}/{total}).")
                cve = self._enrich_from_nvd(cve)
            cve = replace(
                cve,
                kev_status=cve.cve_id in kev_ids,
                epss_score=epss_scores.get(cve.cve_id, cve.epss_score),
                references=_dedupe_refs(
                    cve.references
                    + [
                        ReferenceRecord(
                            label="CISA Known Exploited Vulnerabilities Catalog",
                            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            source="CISA KEV",
                        ),
                        ReferenceRecord(
                            label="FIRST EPSS API",
                            url=f"https://api.first.org/data/v1/epss?cve={cve.cve_id}",
                            source="FIRST EPSS",
                        ),
                    ]
                ),
            )
            enriched.append(replace(finding, cve=cve))
        self.run_ctx.progress("enrich", f"Enrichment complete for {len(enriched)} findings; NVD fallback used for {fallback_count}.")
        return enriched

    def _kev_ids(self) -> set[str]:
        cache_key = "known_exploited_vulnerabilities"
        payload = self.cache.get("kev", cache_key)
        if not payload or self.cache.is_stale("kev", cache_key):
            self.run_ctx.progress("enrich", "Fetching CISA KEV catalog ...")
            try:
                payload = self.api_client.get(KEV_URL, source_name="kev")
                self.cache.set("kev", cache_key, payload)
                self.run_ctx.add_api_call(KEV_URL, "ok", 0, False)
            except SourceError as exc:
                self.run_ctx.add_error("enrich", "CISA KEV", str(exc))
                if not payload:
                    return set()
                self.run_ctx.add_warning("enrich", "Using stale CISA KEV cache")
        else:
            self.run_ctx.progress("enrich", "Using cached CISA KEV catalog.")
        return {item.get("cveID") for item in payload.get("vulnerabilities", []) if item.get("cveID")}

    def _epss_scores(self, cve_ids: list[str]) -> dict[str, float]:
        if not cve_ids:
            return {}
        cache_key = "_".join(cve_ids)
        payload = self.cache.get("epss", cache_key)
        if not payload or self.cache.is_stale("epss", cache_key):
            self.run_ctx.progress("enrich", f"Fetching EPSS scores for {len(cve_ids)} CVEs ...")
            try:
                payload = self.api_client.get(EPSS_URL, {"cve": ",".join(cve_ids)}, "epss")
                self.cache.set("epss", cache_key, payload)
                self.run_ctx.add_api_call(f"{EPSS_URL}?cve={','.join(cve_ids)}", "ok", 0, False)
            except SourceError as exc:
                self.run_ctx.add_error("enrich", "EPSS", str(exc))
                if not payload:
                    return {}
                self.run_ctx.add_warning("enrich", "Using stale EPSS cache")
        else:
            self.run_ctx.progress("enrich", f"Using cached EPSS scores for {len(cve_ids)} CVEs.")
        scores: dict[str, float] = {}
        for item in payload.get("data", []):
            try:
                scores[item["cve"]] = float(item["epss"])
            except (KeyError, TypeError, ValueError):
                continue
        return scores

    def _enrich_from_nvd(self, cve: CVERecord) -> CVERecord:
        cache_key = f"cve_{cve.cve_id}"
        payload = self.cache.get("nvd", cache_key)
        if not payload or self.cache.is_stale("nvd", cache_key):
            self.run_ctx.progress("enrich", f"Fetching NVD-by-CVE fallback for {cve.cve_id} ...")
            try:
                payload = self.api_client.get(NVD_BASE_URL, {"cveId": cve.cve_id}, "nvd")
                self.cache.set("nvd", cache_key, payload)
                self.run_ctx.add_api_call(f"{NVD_BASE_URL}?cveId={cve.cve_id}", "ok", 0, False)
            except SourceError as exc:
                self.run_ctx.add_error("enrich", "NVD", str(exc))
                if not payload:
                    return cve
                self.run_ctx.add_warning("enrich", f"Using stale NVD cache for {cve.cve_id}")
        else:
            self.run_ctx.progress("enrich", f"Cache hit for NVD-by-CVE fallback {cve.cve_id}.")
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return cve
        nvd_cve = _cve_from_nvd(vulnerabilities[0].get("cve", {}))
        return replace(
            cve,
            description=cve.description or nvd_cve.description,
            severity=cve.severity if cve.severity != Severity.INFORMATIONAL else nvd_cve.severity,
            cvss_score=cve.cvss_score if cve.cvss_score is not None else nvd_cve.cvss_score,
            cvss_vector=cve.cvss_vector or nvd_cve.cvss_vector,
            cwe=cve.cwe or nvd_cve.cwe,
            published_date=cve.published_date or nvd_cve.published_date,
            references=_dedupe_refs(cve.references + nvd_cve.references),
        )


class MockCVEEnricher:
    def enrich(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        enriched: list[FindingRecord] = []
        for index, finding in enumerate(findings):
            cve = finding.cve
            cvss_score, vector = _score_for(cve.severity)
            enriched_cve = replace(
                cve,
                cvss_score=cvss_score,
                cvss_vector=vector,
                cwe=cve.cwe or "CWE-787",
                kev_status=index % 3 == 0 and cve.cve_id.startswith("CVE-"),
                epss_score=round(0.85 - (index * 0.07), 3) if cve.cve_id.startswith("CVE-") else None,
                oracle_advisory_ref=cve.oracle_advisory_ref or "Oracle Critical Patch Update mock advisory",
                references=cve.references
                + [
                    ReferenceRecord(
                        label="CISA Known Exploited Vulnerabilities Catalog",
                        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        source="CISA KEV",
                    ),
                    ReferenceRecord(
                        label="FIRST EPSS API",
                        url=f"https://api.first.org/data/v1/epss?cve={cve.cve_id}",
                        source="FIRST EPSS",
                    ),
                ],
            )
            enriched.append(replace(finding, cve=enriched_cve))
        return enriched


def _score_for(severity: Severity) -> tuple[float | None, str | None]:
    if severity == Severity.CRITICAL:
        return 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if severity == Severity.HIGH:
        return 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    if severity == Severity.MEDIUM:
        return 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
    if severity == Severity.LOW:
        return 3.7, "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"
    return None, None


def _needs_nvd_enrichment(cve: CVERecord) -> bool:
    return (
        not cve.description
        or cve.cvss_score is None
        or not cve.cvss_vector
        or cve.severity == Severity.INFORMATIONAL
    )


def _dedupe_refs(references: list[ReferenceRecord]) -> list[ReferenceRecord]:
    seen: set[tuple[str, str]] = set()
    deduped: list[ReferenceRecord] = []
    for reference in references:
        key = (reference.label, reference.url)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(reference)
    return deduped
