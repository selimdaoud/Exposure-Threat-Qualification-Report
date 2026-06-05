from __future__ import annotations

import argparse
import datetime
import json
import re
import sqlite3
import sys
import textwrap
from pathlib import Path

from .alias_enricher import AliasEnricher
from .api_client import ApiClient
from .cache_manager import CacheManager
from .cve_enrichment import MockCVEEnricher, RealCVEEnricher, fetch_cve_record
from .cve_mapper import MockCVEMapper, NvdCVEMapper
from .detection_mapper import DetectionDbMapper, DetectionIndexBuilder, MockDetectionMapper
from .input_parser import InputParserError, read_csv
from .models import AffectedStatus, CVERecord, FindingRecord, Severity
from .normalizer import normalize
from .oracle_patch_resolver import OraclePatchResolver
from .prioritizer import prioritize
from .support_checker import check_support
from .report import write_html, write_json
from .runtime import RunContext
from .threat_context import MockThreatContextEnricher, RealThreatContextEnricher


SEVERITY_ORDER = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return analyze(args)
    if args.command == "lookup-cve":
        return lookup_cve(args)
    if args.command == "detection-index":
        return detection_index(args)
    if args.command == "update-aliases":
        return update_aliases(args)
    parser.print_help()
    return 0


def analyze(args: argparse.Namespace) -> int:
    mock_providers = ["cve_mapper", "cve_enrichment", "threat_context", "detection_mapper"] if args.mock else []
    run_ctx = RunContext(mock_providers=mock_providers, progress_callback=progress)
    cache = CacheManager(args.cache)
    api_client = ApiClient(offline=args.offline)
    try:
        _, json_path, html_path = _report_paths(args)

        progress("input", f"Reading {args.input} ...")
        products = read_csv(args.input)
        progress("input", f"OK - {len(products)} products loaded.")

        progress("normalize", "Normalizing product names ...")
        products = normalize(products)
        alias_count = sum(1 for item in products if item.normalized_product_name != item.raw_product_name)
        ambiguous_count = sum(1 for item in products if item.cpe_prefix is None)
        progress("normalize", f"OK - {len(products)} products normalized ({alias_count} alias resolved, {ambiguous_count} ambiguous).")

        progress("support", "Checking Oracle support status via endoflife.date ...")
        if not args.offline:
            products = check_support(products, api_client, cache, run_ctx)
        eol_count = sum(1 for p in products if p.support_status.value == "end_of_life")
        ext_count = sum(1 for p in products if p.support_status.value == "extended_support")
        unknown_count = sum(1 for p in products if p.support_status.value == "unknown")
        progress("support", f"OK - {eol_count} EOL, {ext_count} extended support only, {unknown_count} unknown/not tracked.")

        progress("map", "Mapping products to CVEs (Oracle CPU + NVD) ...")
        mapper = MockCVEMapper() if args.mock else NvdCVEMapper(api_client, cache, run_ctx)
        findings = mapper.map(products)
        mapped_count = len([item for item in findings if item.cve.cve_id.startswith("CVE-")])
        confirmed = sum(1 for item in findings if item.affected_status == AffectedStatus.CONFIRMED_AFFECTED)
        potential = sum(1 for item in findings if item.affected_status == AffectedStatus.POTENTIALLY_AFFECTED)
        wildcard = sum(1 for item in findings if item.affected_status == AffectedStatus.NVD_WILDCARD_NO_VERSIONS)
        insufficient = sum(1 for item in findings if item.affected_status == AffectedStatus.NOT_ENOUGH_VERSION_INFORMATION)
        progress("map", f"OK - {mapped_count} CVEs mapped ({confirmed} confirmed, {potential} potentially affected, {wildcard} NVD wildcard/no versions, {insufficient} insufficient version data).")

        progress("enrich", "Enriching CVEs with CVSS / KEV / EPSS ...")
        findings = (MockCVEEnricher() if args.mock else RealCVEEnricher(api_client, cache, run_ctx)).enrich(findings)
        kev_count = sum(1 for item in findings if item.cve.kev_status)
        epss_count = sum(1 for item in findings if item.cve.epss_score is not None and item.cve.epss_score > 0.50)
        progress("enrich", f"OK - {len(findings)} CVEs enriched ({kev_count} KEV, {epss_count} EPSS > 0.50).")

        progress("threat", "Fetching threat context ...")
        findings = (MockThreatContextEnricher() if args.mock else RealThreatContextEnricher()).enrich(findings)
        context_count = sum(1 for item in findings if item.threat_context and item.threat_context.public_exploit)
        progress("threat", f"OK - threat context available for {context_count} CVEs, not found for {len(findings) - context_count}.")

        if args.skip_detection:
            progress("detect", "Skipping detection rule search (--skip-detection).")
            run_ctx.add_warning("detect", "Detection mapping skipped by --skip-detection")
            findings = _mark_detection_skipped(findings)
            progress("detect", f"OK - detection search skipped for {len(findings)} CVEs.")
        else:
            progress("detect", "Looking up detection rules in local DB ...")
            detection_db_exists = cache.detection_db_path().exists()
            findings = (MockDetectionMapper() if args.mock else DetectionDbMapper(cache, run_ctx)).find_rules(findings)
            covered = sum(1 for item in findings if not item.detection_gap)
            if args.mock or detection_db_exists:
                progress("detect", f"OK - detection logic found for {covered} CVEs, no coverage for {len(findings) - covered}.")
            else:
                progress("detect", f"OK - detection lookup skipped for {len(findings)} CVEs.")

        progress("prioritize", "Computing finding priorities ...")
        findings = prioritize(findings)
        findings = _filter_by_severity(findings, args.min_severity)
        report_findings, suppressed = _split_unconfirmed(findings, args.include_unconfirmed)
        counts = {name: sum(1 for item in report_findings if item.priority.value == name) for name in ["critical", "high", "medium", "low"]}
        progress("prioritize", f"OK - {counts['critical']} Critical, {counts['high']} High, {counts['medium']} Medium, {counts['low']} Low.")

        if json_path:
            progress("report", f"Writing findings to {json_path} ...")
            write_json(report_findings + suppressed, json_path)
            progress("report", "OK - JSON export written.")
        if html_path:
            progress("report", f"Writing HTML report to {html_path} ...")
            write_html(report_findings, html_path, run_ctx, suppressed, products, customer=args.customer, cache_dir=cache.cache_dir)
            progress("report", "OK - HTML report written.")
        log_path = (html_path or json_path or _report_path("report")).with_suffix(".log")
        progress("done", f"Run complete. Log written to {log_path}.")
        return 0
    except InputParserError as exc:
        progress("input", f"ERROR - {exc}")
        return 1
    except Exception as exc:
        progress("pipeline", f"ERROR - {exc}")
        return 2


def update_aliases(args: argparse.Namespace) -> int:
    run_ctx = RunContext(progress_callback=progress)
    cache = CacheManager(args.cache)
    api_client = ApiClient(offline=args.offline)
    try:
        progress("aliases", "Fetching Oracle product catalog from NVD CPE dictionary ...")
        stats = AliasEnricher(api_client, cache, run_ctx).enrich(dry_run=args.dry_run)
        if args.dry_run:
            progress("aliases", f"Dry run — would add {stats['new_products']} products and {stats['new_aliases']} aliases.")
        return 0
    except Exception as exc:
        progress("aliases", f"ERROR - {exc}")
        return 2


def detection_index(args: argparse.Namespace) -> int:
    run_ctx = RunContext(progress_callback=progress)
    cache = CacheManager(args.cache)
    try:
        progress("detect", "Preparing local detection rule index ...")
        db_path = DetectionIndexBuilder(cache, run_ctx, args.offline).build(refresh=args.refresh, rebuild=args.rebuild)
        progress("done", f"Detection index ready at {db_path}.")
        return 0
    except Exception as exc:
        progress("detect", f"ERROR - {exc}")
        return 2


def lookup_cve(args: argparse.Namespace) -> int:
    raw_ids = [c.strip().upper() for c in args.cve.split(",") if c.strip()]
    cve_ids: list[str] = []
    for cve_id in raw_ids:
        if not re.fullmatch(r"CVE-\d{4}-\d{1,7}", cve_id):
            progress("input", f"ERROR - '{cve_id}' is not a valid CVE ID (expected CVE-YYYY-NNNN).")
            return 1
        cve_ids.append(cve_id)
    if not cve_ids:
        progress("input", "ERROR - no CVE IDs provided.")
        return 1

    cache = CacheManager(args.cache)
    api_client = ApiClient(offline=args.offline)
    run_ctx = RunContext(progress_callback=progress)

    try:
        # KEV + EPSS — fetched once for all CVEs
        kev_ids: set[str] = set()
        epss_map: dict[str, float] = {}
        if not args.offline:
            enricher = RealCVEEnricher(api_client, cache, run_ctx)
            progress("enrich", "Fetching KEV catalog and EPSS scores ...")
            kev_ids = enricher._kev_ids()
            epss_map = enricher._epss_scores(cve_ids)

        # NVD — one call per CVE
        progress("nvd", f"Fetching NVD data for {len(cve_ids)} CVE(s) ...")
        cve_records = {cve_id: fetch_cve_record(cve_id, api_client, cache, run_ctx) for cve_id in cve_ids}

        # Oracle advisory scan — single pass over all advisories for all CVEs
        progress("cpu", f"Scanning Oracle CPU/CSPU advisories for {len(cve_ids)} CVE(s) ...")
        resolver = OraclePatchResolver(api_client, cache, run_ctx)
        all_advisory_hits = resolver.find_cves_in_advisories(cve_ids)

        # Detection rules — one DB query per CVE
        db_path = cache.detection_db_path()
        detection_db_exists = db_path.exists()
        if not detection_db_exists:
            progress("detect", "Detection DB not found. Run `detection-index --refresh` first.")
        all_rules = {
            cve_id: (_detection_rules_for_cve(cve_id, db_path) if detection_db_exists else [])
            for cve_id in cve_ids
        }

        # Assemble per-CVE result dicts
        results = [
            {
                "cve_id": cve_id,
                "cve_record": cve_records.get(cve_id),
                "kev": cve_id in kev_ids,
                "epss": epss_map.get(cve_id),
                "advisory_hits": all_advisory_hits.get(cve_id, []),
                "detection_rules": all_rules.get(cve_id, []),
            }
            for cve_id in cve_ids
        ]

        # Print the formatted report
        _print_cve_report(results, detection_db_exists)

        # JSON output
        if args.json:
            output: dict = {
                "cve_ids": cve_ids,
                "results": [
                    {
                        "cve_id": r["cve_id"],
                        "nvd": _cve_to_dict(r["cve_record"]) if r["cve_record"] else None,
                        "kev": r["kev"],
                        "epss": r["epss"],
                        "oracle_advisories": r["advisory_hits"],
                        "detection_rules": r["detection_rules"],
                    }
                    for r in results
                ],
            }
            json_path = _report_path(args.json)
            json_path.write_text(json.dumps(output, indent=2))
            progress("report", f"JSON written to {json_path}")

        return 0

    except Exception as exc:
        progress("lookup-cve", f"ERROR - {exc}")
        return 2


def progress(stage: str, message: str, level: str = "info") -> None:
    del level
    print(f"[{stage:<10}] {message}")


_REPORT_WIDTH = 72


def _print_cve_report(results: list[dict], detection_db_exists: bool) -> None:
    heavy = "═" * _REPORT_WIDTH
    light = "─" * _REPORT_WIDTH
    today = datetime.date.today().isoformat()
    count = len(results)
    label = f"CVE LOOKUP — {count} CVE{'s' if count != 1 else ''}"

    print()
    print(heavy)
    print(f"  {label}{today:>{_REPORT_WIDTH - len(label) - 2}}")
    print(heavy)

    for result in results:
        cve_id = result["cve_id"]
        cve = result["cve_record"]
        kev = result["kev"]
        epss = result["epss"]
        advisory_hits = result["advisory_hits"]
        rules = result["detection_rules"]

        print()
        severity_str = cve.severity.value.upper() if cve else "UNKNOWN"
        id_label = f"  {cve_id}"
        print(f"{id_label}{severity_str:>{_REPORT_WIDTH - len(id_label)}}")
        print("  " + light[: _REPORT_WIDTH - 2])

        if cve:
            meta: list[str] = []
            if cve.cvss_score is not None:
                meta.append(f"CVSS {cve.cvss_score}")
            if cve.published_date:
                meta.append(f"Published {cve.published_date}")
            if cve.cwe:
                meta.append(cve.cwe)
            if meta:
                print(f"  {' · '.join(meta)}")
        else:
            print("  Not found in NVD.")

        kev_str = "YES" if kev else "No"
        epss_str = f"{epss:.4f} ({epss * 100:.1f}%)" if epss is not None else "N/A"
        print(f"  KEV: {kev_str}  ·  EPSS: {epss_str}")

        if cve and cve.description:
            print()
            _print_wrapped(cve.description, indent=2, width=_REPORT_WIDTH)

        # Oracle advisories
        print()
        unique_count = len({h["advisory_url"] for h in advisory_hits})
        if advisory_hits:
            noun = "entry" if len(advisory_hits) == 1 else "entries"
            adv_noun = "advisory" if unique_count == 1 else "advisories"
            print(f"  Oracle Advisories  {len(advisory_hits)} {noun} in {unique_count} {adv_noun}:")
            for hit in advisory_hits:
                product = hit.get("product") or "Unknown Product"
                component = hit.get("component")
                versions = hit.get("versions")
                title = hit.get("advisory_title") or hit["advisory_url"]
                print(f"    ► {title}")
                detail = f"      {product}"
                if component:
                    detail += f" / {component}"
                if versions:
                    detail += f"  [{versions}]"
                print(detail)
        else:
            print("  Oracle Advisories  Not found in any scanned advisory.")

        # Detection rules
        print()
        if not detection_db_exists:
            print("  Detection Rules  DB not found — run `detection-index --refresh` first.")
        elif rules:
            rule_noun = "rule" if len(rules) == 1 else "rules"
            print(f"  Detection Rules  {len(rules)} {rule_noun} found:")
            for rule in rules[:10]:
                print(f"    ► [{rule['source']}]  {rule['rule_name']}  ({rule['rule_type']})")
            if len(rules) > 10:
                print(f"    … and {len(rules) - 10} more  (use --json for full list)")
        else:
            print("  Detection Rules  No rules found for this CVE.")

        print()
        print(heavy)

    # Summary
    sev_counts: dict[str, int] = {}
    for r in results:
        sev = r["cve_record"].severity.value if r["cve_record"] else "informational"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    sev_parts = [
        f"{sev_counts[s]} {s.capitalize()}"
        for s in ("critical", "high", "medium", "low", "informational")
        if sev_counts.get(s)
    ]
    kev_count = sum(1 for r in results if r["kev"])
    epss_high = sum(1 for r in results if r["epss"] is not None and r["epss"] >= 0.5)
    in_advisory = sum(1 for r in results if r["advisory_hits"])
    gap_count = sum(1 for r in results if not r["detection_rules"])

    print()
    noun = "CVE" if count == 1 else "CVEs"
    print(f"  SUMMARY  {count} {noun}  ·  {' · '.join(sev_parts)}")
    print(f"  {light[: _REPORT_WIDTH - 2]}")
    print(f"  KEV listed:          {kev_count}")
    print(f"  EPSS ≥ 0.5:          {epss_high}")
    print(f"  In Oracle advisory:  {in_advisory} of {count}")
    print(f"  Detection gap:       {gap_count} of {count}")
    print(heavy)
    print()


def _print_wrapped(text: str, indent: int, width: int) -> None:
    prefix = " " * indent
    for line in textwrap.wrap(text, width=width - indent):
        print(prefix + line)


def _detection_rules_for_cve(cve_id: str, db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT rules.rule_id, rules.rule_name, rules.rule_type,
                   rules.source, rules.url, rules.telemetry
            FROM rules
            JOIN rule_keys ON rule_keys.rule_id = rules.rule_id
            WHERE rule_keys.key = ?
            ORDER BY rules.source, rules.rule_name
            """,
            (cve_id.upper(),),
        ).fetchall()
        return [dict(row) for row in rows]


def _cve_to_dict(cve: CVERecord) -> dict:
    return {
        "cve_id": cve.cve_id,
        "description": cve.description,
        "severity": cve.severity.value,
        "cvss_score": cve.cvss_score,
        "cvss_vector": cve.cvss_vector,
        "cwe": cve.cwe,
        "published_date": cve.published_date,
        "references": [{"label": r.label, "url": r.url, "source": r.source} for r in cve.references],
    }


def _filter_by_severity(findings: list[FindingRecord], minimum: str) -> list[FindingRecord]:
    minimum_severity = Severity(minimum)
    minimum_value = SEVERITY_ORDER[minimum_severity]
    return [item for item in findings if SEVERITY_ORDER[item.cve.severity] >= minimum_value]


def _split_unconfirmed(findings: list[FindingRecord], include_unconfirmed: bool) -> tuple[list[FindingRecord], list[FindingRecord]]:
    if include_unconfirmed:
        return findings, []
    unconfirmed_statuses = {
        AffectedStatus.NOT_ENOUGH_VERSION_INFORMATION,
        AffectedStatus.NVD_WILDCARD_NO_VERSIONS,
    }
    report_findings = [item for item in findings if item.affected_status not in unconfirmed_statuses]
    suppressed = [item for item in findings if item.affected_status in unconfirmed_statuses]
    return report_findings, suppressed


def _mark_detection_skipped(findings: list[FindingRecord]) -> list[FindingRecord]:
    for finding in findings:
        finding.detection_rules = []
        finding.detection_gap = True
    return findings


def _report_path(path_value: str) -> Path:
    report_dir = Path("REPORT")
    path = Path(path_value)
    if path.is_absolute() or len(path.parts) > 1:
        resolved = path
    else:
        resolved = report_dir / path
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _report_paths(args: argparse.Namespace) -> tuple[Path | None, Path | None, Path | None]:
    if not args.json and not args.html:
        return None, _report_path("findings.json"), _report_path("report.html")
    json_path = _report_path(args.json) if args.json else None
    html_path = _report_path(args.html) if args.html else None
    return None, json_path, html_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oracle-cve-intel")
    subparsers = parser.add_subparsers(dest="command")
    analyze_parser = subparsers.add_parser("analyze", help="Analyze Oracle products and versions")
    analyze_parser.add_argument("--input", required=True)
    analyze_parser.add_argument("--json")
    analyze_parser.add_argument("--html")
    analyze_parser.add_argument("--cache", default="data/cache")
    analyze_parser.add_argument("--offline", action="store_true")
    analyze_parser.add_argument("--mock", action="store_true")
    analyze_parser.add_argument("--skip-detection", action="store_true")
    analyze_parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low")
    analyze_parser.add_argument("--include-unconfirmed", action="store_true")
    analyze_parser.add_argument("--customer", default="UNKNOWN_ORG", metavar="ORGANISATION")

    lookup_cve_parser = subparsers.add_parser("lookup-cve", help="Look up a CVE across Oracle advisories, NVD, and the local detection DB")
    lookup_cve_parser.add_argument("--cve", required=True, metavar="CVE-ID", help="CVE identifier, e.g. CVE-2024-12345")
    lookup_cve_parser.add_argument("--cache", default="data/cache")
    lookup_cve_parser.add_argument("--offline", action="store_true", help="Use cached data only; skip live KEV/EPSS/NVD calls")
    lookup_cve_parser.add_argument("--json", metavar="FILE", help="Write full results to a JSON file")

    index_parser = subparsers.add_parser("detection-index", help="Fetch detection rules and build the local lookup DB")
    index_parser.add_argument("--cache", default="data/cache")
    index_parser.add_argument("--refresh", action="store_true", help="Clone missing repositories and pull updates for existing repositories")
    index_parser.add_argument("--rebuild", action="store_true", help="Rebuild the SQLite index from local rule repositories")
    index_parser.add_argument("--offline", action="store_true", help="Use already-cloned repositories only")

    alias_parser = subparsers.add_parser("update-aliases", help="Enrich product_aliases.json and cpe_map.json from NVD CPE dictionary")
    alias_parser.add_argument("--cache", default="data/cache")
    alias_parser.add_argument("--offline", action="store_true", help="Use cached CPE data only")
    alias_parser.add_argument("--dry-run", action="store_true", help="Show what would be added without writing files")
    return parser


if __name__ == "__main__":
    sys.exit(main())
