from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .alias_enricher import AliasEnricher
from .api_client import ApiClient
from .cache_manager import CacheManager
from .cve_enrichment import MockCVEEnricher, RealCVEEnricher
from .cve_mapper import MockCVEMapper, NvdCVEMapper
from .detection_mapper import DetectionDbMapper, DetectionIndexBuilder, MockDetectionMapper
from .input_parser import InputParserError, read_csv
from .models import AffectedStatus, FindingRecord, Severity
from .normalizer import normalize
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


def progress(stage: str, message: str, level: str = "info") -> None:
    del level
    print(f"[{stage:<10}] {message}")


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
