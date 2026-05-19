from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import jinja2

from .config import TEMPLATES_DIR
from .models import AffectedStatus, FindingRecord, Priority, ProductRecord, SupportStatus, to_dict
from .runtime import RunContext

_TIER_LABELS: dict[str, str] = {
    "0": "Mission Critical",
    "1": "Critical",
    "2": "Important",
    "3": "Standard",
}

def _tier_label(tier: str | None) -> str:
    if not tier:
        return ""
    t = tier.strip()
    label = _TIER_LABELS.get(t, "")
    return f"Tier {t} — {label}" if label else f"Tier {t}"


# ── Public entry points ────────────────────────────────────────────────────

def write_report(
    findings: list[FindingRecord],
    output_path: Path | str,
    run_ctx: RunContext,
    suppressed_findings: list[FindingRecord] | None = None,
) -> None:
    output = Path(output_path)
    suppressed = suppressed_findings or []
    lines: list[str] = []
    lines.extend(_assessment_summary(findings))
    lines.extend(_top_findings(findings))
    lines.extend(_product_exposure_summary(findings))
    lines.extend(_threat_context_summary(findings))
    lines.extend(_detection_coverage_summary(findings))
    lines.extend(_detailed_findings(findings))
    lines.extend(_appendix(run_ctx, suppressed))
    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    write_run_log(output.with_suffix(".log"), findings, run_ctx)


def write_json(findings: list[FindingRecord], output_path: Path | str) -> None:
    output = Path(output_path)
    output.write_text(json.dumps([to_dict(item) for item in findings], indent=2), encoding="utf-8")


def write_html(
    findings: list[FindingRecord],
    output_path: Path | str,
    run_ctx: RunContext,
    suppressed_findings: list[FindingRecord] | None = None,
    all_products: list[ProductRecord] | None = None,
    customer: str = "UNKNOWN_ORG",
) -> None:
    output = Path(output_path)
    suppressed = suppressed_findings or []
    context = _build_html_context(findings, run_ctx, suppressed, all_products or [], customer=customer)
    template = _jinja_env().get_template("report.html.j2")
    output.write_text(template.render(**context), encoding="utf-8")


def write_run_log(path: Path, findings: list[FindingRecord], run_ctx: RunContext) -> None:
    lines = [
        "Oracle CVE Threat Enrichment CLI Run Log",
        f"timestamp={datetime.now().astimezone().isoformat()}",
        f"findings={len(findings)}",
        "",
        "API Calls",
    ]
    lines.extend(run_ctx.api_calls or ["none"])
    lines.extend(["", "Warnings"])
    lines.extend(run_ctx.warnings or ["none"])
    lines.extend(["", "Errors"])
    lines.extend(run_ctx.errors or ["none"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── TXT report sections ────────────────────────────────────────────────────

def _assessment_summary(findings: list[FindingRecord]) -> list[str]:
    counts = Counter(finding.priority for finding in findings)
    highest = findings[0] if findings else None
    return [
        "Assessment Summary",
        "==================",
        f"Total findings: {len(findings)}",
        f"Priority counts: Critical {counts[Priority.CRITICAL]}, High {counts[Priority.HIGH]}, Medium {counts[Priority.MEDIUM]}, Low {counts[Priority.LOW]}, Informational {counts[Priority.INFORMATIONAL]}",
        f"Highest priority finding: {_finding_title(highest) if highest else 'none'}",
        "",
    ]


def _top_findings(findings: list[FindingRecord]) -> list[str]:
    lines = ["Top Findings", "============", ""]
    for finding in findings[:10]:
        lines.extend(_finding_block(finding))
    if not findings:
        lines.append("No findings.")
    lines.append("")
    return lines


def _product_exposure_summary(findings: list[FindingRecord]) -> list[str]:
    by_product: dict[str, Counter] = defaultdict(Counter)
    for finding in findings:
        product = finding.product.normalized_product_name or finding.product.raw_product_name
        by_product[product][finding.cve.severity.value] += 1
    lines = ["Product Exposure Summary", "========================", ""]
    for product, counts in sorted(by_product.items()):
        parts = ", ".join(f"{severity}: {count}" for severity, count in sorted(counts.items()))
        lines.append(f"- {product}: {parts}")
    if not by_product:
        lines.append("No product exposure found.")
    lines.append("")
    return lines


def _threat_context_summary(findings: list[FindingRecord]) -> list[str]:
    public = sum(1 for item in findings if item.threat_context and item.threat_context.public_exploit)
    active = sum(1 for item in findings if item.threat_context and item.threat_context.active_exploitation)
    techniques = sorted(
        {
            _technique_link(technique)
            for item in findings
            if item.threat_context
            for technique in item.threat_context.attack_techniques
        }
    )
    return [
        "Threat Context Summary",
        "======================",
        f"Public exploit signal: {public}",
        f"Active exploitation signal: {active}",
        f"ATT&CK techniques: {', '.join(techniques) if techniques else 'none'}",
        "Threat actor, campaign, malware, and IOC fields are empty unless directly evidenced.",
        "",
    ]


def _detection_coverage_summary(findings: list[FindingRecord]) -> list[str]:
    covered = sum(1 for item in findings if not item.detection_gap)
    gaps = len(findings) - covered
    telemetry = sorted({t for item in findings for rule in item.detection_rules for t in rule.telemetry_required})
    return [
        "Detection Coverage Summary",
        "==========================",
        f"Detection logic found: {covered}",
        f"Detection gaps: {gaps}",
        f"Telemetry needed: {', '.join(telemetry) if telemetry else 'none'}",
        "",
    ]


def _detailed_findings(findings: list[FindingRecord]) -> list[str]:
    lines = ["Detailed Findings", "=================", ""]
    for finding in findings:
        lines.extend(_finding_block(finding))
    if not findings:
        lines.append("No detailed findings.")
    lines.append("")
    return lines


def _appendix(run_ctx: RunContext, suppressed_findings: list[FindingRecord]) -> list[str]:
    data_sources = (
        "mock NVD CPE mapping, mock CISA KEV, mock EPSS, mock threat context, mock detection rules"
        if run_ctx.mock_providers
        else "NVD CPE API, CISA KEV, FIRST EPSS, NVD references, local detection rule repositories"
    )
    lines = [
        "Appendix",
        "========",
        f"Data sources used: {data_sources}.",
        f"Provider mode: {_provider_mode(run_ctx)}",
        f"Warnings: {len(run_ctx.warnings)}",
        f"Errors: {len(run_ctx.errors)}",
        "Stale cache notes: stale cache usage is listed in warnings when present.",
        "Confidence notes: inferred ATT&CK mappings are low-confidence unless directly evidenced.",
        "",
        "NVD wildcard / no versions",
        "--------------------------",
    ]
    wildcard_findings = [f for f in suppressed_findings if f.affected_status == AffectedStatus.NVD_WILDCARD_NO_VERSIONS]
    other_suppressed = [f for f in suppressed_findings if f.affected_status != AffectedStatus.NVD_WILDCARD_NO_VERSIONS]
    if wildcard_findings:
        lines.append("These CVEs were returned by NVD through a wildcard product CPE without explicit affected versions.")
        lines.append("")
        for finding in wildcard_findings:
            lines.append(f"- {_finding_title(finding)} ({finding.mapping_confidence.value} confidence)")
    else:
        lines.append("none")
    lines.extend(["", "Other Suppressed Unconfirmed Findings", "------------------------------------"])
    if other_suppressed:
        for finding in other_suppressed:
            lines.append(f"- {_finding_title(finding)} ({finding.affected_status.value})")
    else:
        lines.append("none")
    lines.append("")
    return lines


# ── TXT helpers ────────────────────────────────────────────────────────────

def _finding_block(finding: FindingRecord) -> list[str]:
    rules = "; ".join(_rule_link(rule) for rule in finding.detection_rules) if finding.detection_rules else "none"
    techniques = (
        ", ".join(_technique_link(t) for t in finding.threat_context.attack_techniques)
        if finding.threat_context and finding.threat_context.attack_techniques
        else "none"
    )
    evidence = _reference_list(finding.evidence_references + finding.cve.references)
    patches = _patch_list(finding.patch_references)
    product = finding.product.normalized_product_name or finding.product.raw_product_name
    return [
        _finding_title(finding),
        f"  Product: {product} {finding.product.raw_version}",
        f"  Severity: {finding.cve.severity.value} CVSS {finding.cve.cvss_score if finding.cve.cvss_score is not None else 'n/a'}",
        f"  Affected status: {finding.affected_status.value} ({finding.mapping_confidence.value} confidence)",
        f"  Priority: {finding.priority.value} ({finding.priority_score})",
        f"  Why: {finding.priority_explanation}",
        f"  ATT&CK techniques: {techniques}",
        f"  Detection: {'gap' if finding.detection_gap else 'covered'}; rules: {rules}",
        f"  Patch: {patches}",
        f"  Evidence: {evidence}",
        f"  Recommended action: {finding.recommended_action}",
        "",
    ]


def _finding_title(finding: FindingRecord | None) -> str:
    if finding is None:
        return "none"
    return f"{finding.cve.cve_id} - {finding.cve.description or 'No description'}"


def _reference_list(references) -> str:
    if not references:
        return "none"
    seen: set[tuple[str, str]] = set()
    rendered: list[str] = []
    for reference in references:
        key = (reference.label, reference.url)
        if key in seen:
            continue
        seen.add(key)
        rendered.append(f"{reference.label} ({reference.url})")
    return "; ".join(rendered)


def _patch_list(patches) -> str:
    if not patches:
        return "none"
    rendered: list[str] = []
    for patch in patches:
        parts = [
            patch.patch_name or patch.advisory_title,
            f"patch ID {patch.patch_id}" if patch.patch_id else None,
            f"fixed version {patch.fixed_version}" if patch.fixed_version else None,
            f"advisory {patch.advisory_url}",
        ]
        rendered.append("; ".join(part for part in parts if part))
    return " | ".join(rendered)


def _technique_link(technique) -> str:
    return f"{technique.technique_id} {technique.name} ({technique.url})"


def _rule_link(rule) -> str:
    if rule.reference:
        return f"{rule.rule_name} [{rule.source}] ({rule.reference.url})"
    return f"{rule.rule_name} [{rule.source}]"


# ── HTML context building ──────────────────────────────────────────────────

def _jinja_env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=jinja2.StrictUndefined,
    )


def _build_html_context(
    findings: list[FindingRecord],
    run_ctx: RunContext,
    suppressed: list[FindingRecord],
    all_products: list[ProductRecord],
    customer: str = "UNKNOWN_ORG",
) -> dict:
    counts = Counter(f.priority for f in findings)
    covered = sum(1 for f in findings if not f.detection_gap)
    gap_count = len(findings) - covered
    kev_count = sum(1 for f in findings if f.cve.kev_status)
    eol_count = _count_unique_products_by_status(findings, SupportStatus.END_OF_LIFE)
    detection_skipped = any("Detection mapping skipped" in w for w in run_ctx.warnings)
    wildcard = [f for f in suppressed if f.affected_status == AffectedStatus.NVD_WILDCARD_NO_VERSIONS]
    other_suppressed = [f for f in suppressed if f.affected_status != AffectedStatus.NVD_WILDCARD_NO_VERSIONS]
    all_products_summary = _build_all_products_summary(all_products, findings)
    return {
        "customer": customer,
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
        "report_mode": "Mock provider report" if run_ctx.mock_providers else "Live provider report",
        "mock_providers": run_ctx.mock_providers,
        "total_findings": len(findings),
        "counts": {
            "critical": counts[Priority.CRITICAL],
            "high": counts[Priority.HIGH],
            "medium": counts[Priority.MEDIUM],
            "low": counts[Priority.LOW],
            "informational": counts[Priority.INFORMATIONAL],
        },
        "covered": covered,
        "gaps": gap_count,
        "gap_critical_high": sum(1 for f in findings if f.priority in (Priority.CRITICAL, Priority.HIGH) and f.detection_gap),
        "total_critical_high": sum(1 for f in findings if f.priority in (Priority.CRITICAL, Priority.HIGH)),
        "detection_skipped": detection_skipped,
        "eol_products_count": eol_count,
        "risk_posture": _build_risk_posture(
            findings,
            kev_count=kev_count,
            critical_count=counts[Priority.CRITICAL],
            high_count=counts[Priority.HIGH],
            eol_count=eol_count,
        ),
        "ext_products_count": _count_unique_products_by_status(findings, SupportStatus.EXTENDED_SUPPORT),
        "highest_summary": _highest_summary(findings[0] if findings else None),
        "products_summary": _build_products_summary(findings, detection_skipped, suppressed),
        "all_products_summary": all_products_summary,
        "executive_summary": _build_executive_summary(findings, all_products_summary),
        "threat_summary": _build_threat_summary(findings),
        "warnings": run_ctx.warnings,
        "warnings_count": len(run_ctx.warnings),
        "errors_count": len(run_ctx.errors),
        "provider_mode": _provider_mode(run_ctx),
        "wildcard_findings": wildcard,
        "other_suppressed_count": len(other_suppressed),
    }


def _build_products_summary(
    findings: list[FindingRecord],
    detection_skipped: bool,
    suppressed: list[FindingRecord] | None = None,
) -> list[dict]:
    machines: dict[str, dict[str, list[FindingRecord]]] = {}
    for f in findings:
        mid = f.product.machine_id or "unknown"
        pname = f.product.normalized_product_name or f.product.raw_product_name
        pkey = f"{pname}::{f.product.raw_version}"
        machines.setdefault(mid, {}).setdefault(pkey, []).append(f)

    # Include products whose findings are entirely suppressed (e.g. NVD wildcard CPEs)
    # so they still get a support card and patch list in the report.
    wildcard_machines: dict[str, dict[str, list[FindingRecord]]] = {}
    for f in (suppressed or []):
        mid = f.product.machine_id or "unknown"
        pname = f.product.normalized_product_name or f.product.raw_product_name
        pkey = f"{pname}::{f.product.raw_version}"
        if mid not in machines or pkey not in machines[mid]:
            wildcard_machines.setdefault(mid, {}).setdefault(pkey, []).append(f)

    result = []
    all_machine_ids = sorted(set(machines) | set(wildcard_machines))
    for machine_id in all_machine_ids:
        products = []
        all_pkeys = sorted(
            set(machines.get(machine_id, {})) | set(wildcard_machines.get(machine_id, {}))
        )
        for pkey in all_pkeys:
            if pkey in machines.get(machine_id, {}):
                group = machines[machine_id][pkey]
                priority_counts = Counter(f.priority for f in group)
                record = group[0].product
                pname = record.normalized_product_name or record.raw_product_name
                tl = _tier_label(record.tier)
                meta_parts = [v for v in [record.raw_version, tl] if v]
                products.append({
                    "name": pname,
                    "version": record.raw_version,
                    "tier": record.tier or "",
                    "tier_label": tl,
                    "meta": " · ".join(meta_parts),
                    "priority_counts": {p.value: priority_counts[p] for p in Priority},
                    "total": len(group),
                    "findings": [_finding_context(f, detection_skipped) for f in group],
                    "support_status": record.support_status.value,
                    "eol_date": record.eol_date,
                    "support_notes": record.support_notes,
                    "premier_end": _extract_premier_end(record.support_notes),
                    "patches": _collect_patches(group),
                    "wildcard_only": False,
                    "wildcard_count": 0,
                })
            else:
                group = wildcard_machines[machine_id][pkey]
                record = group[0].product
                pname = record.normalized_product_name or record.raw_product_name
                tl = _tier_label(record.tier)
                meta_parts = [v for v in [record.raw_version, tl] if v]
                products.append({
                    "name": pname,
                    "version": record.raw_version,
                    "tier": record.tier or "",
                    "tier_label": tl,
                    "meta": " · ".join(meta_parts),
                    "priority_counts": {p.value: 0 for p in Priority},
                    "total": 0,
                    "findings": [],
                    "support_status": record.support_status.value,
                    "eol_date": record.eol_date,
                    "support_notes": record.support_notes,
                    "premier_end": _extract_premier_end(record.support_notes),
                    "patches": _collect_patches(group),
                    "wildcard_only": True,
                    "wildcard_count": len(group),
                })
        machine_findings = [f for ps in machines.get(machine_id, {}).values() for f in ps]
        machine_priority_counts = Counter(f.priority for f in machine_findings)
        machine_owner = next((f.product.owner for f in machine_findings if f.product.owner), None)
        machine_tier = next((f.product.tier for f in machine_findings if f.product.tier), None)
        result.append({
            "machine_id": machine_id,
            "owner": machine_owner or "",
            "tier": machine_tier or "",
            "tier_label": _tier_label(machine_tier),
            "total": len(machine_findings),
            "priority_counts": {p.value: machine_priority_counts[p] for p in Priority},
            "products": products,
        })
    return result


def _finding_context(finding: FindingRecord, detection_skipped: bool) -> dict:
    product = finding.product.normalized_product_name or finding.product.raw_product_name
    techniques = finding.threat_context.attack_techniques if finding.threat_context else []
    evidence = finding.evidence_references + finding.cve.references
    detection_state = "skipped" if detection_skipped else ("gap" if finding.detection_gap else "covered")
    detection_label = "Detection skipped" if detection_skipped else ("Detection gap" if finding.detection_gap else "Covered")
    return {
        "finding": finding,
        "product": product,
        "techniques": techniques,
        "rules": finding.detection_rules,
        "patches": finding.patch_references,
        "evidence_primary": _primary_references(evidence),
        "evidence_overflow": _overflow_references(evidence),
        "detection_state": detection_state,
        "detection_label": detection_label,
        "search_text": _build_search_text(finding, product, techniques, evidence),
    }


def _build_search_text(finding: FindingRecord, product: str, techniques: list, evidence: list) -> str:
    patches = finding.patch_references
    rules = finding.detection_rules
    parts = [
        finding.cve.cve_id,
        finding.cve.description or "",
        product,
        finding.product.raw_version,
        finding.cve.severity.value,
        finding.priority.value,
        finding.affected_status.value,
        " ".join(f"{t.technique_id} {t.name} {t.url}" for t in techniques),
        " ".join(f"{r.rule_name} {r.source} {r.rule_type} {r.reference.url if r.reference else ''}" for r in rules),
        " ".join(f"{ref.label} {ref.url} {ref.source or ''}" for ref in evidence),
        " ".join(
            f"{p.source} {p.advisory_title} {p.advisory_url} {p.product}"
            f" {' '.join(p.affected_versions)} {p.fixed_version or ''}"
            f" {p.patch_id or ''} {p.patch_name or ''} {p.notes or ''}"
            for p in patches
        ),
    ]
    return " ".join(parts).lower()


def _build_threat_summary(findings: list[FindingRecord]) -> dict:
    public = sum(1 for f in findings if f.threat_context and f.threat_context.public_exploit)
    active = sum(1 for f in findings if f.threat_context and f.threat_context.active_exploitation)
    techniques = sorted({
        f"{t.technique_id} {t.name}"
        for f in findings
        if f.threat_context
        for t in f.threat_context.attack_techniques
    })
    return {
        "public_exploit": public,
        "active": active,
        "techniques": ", ".join(techniques) if techniques else "none",
    }


def _build_executive_summary(
    findings: list[FindingRecord],
    all_products_summary: list[dict],
) -> list[str]:
    n_products = len(all_products_summary)
    n_cves = len(findings)

    if n_cves == 0:
        return [
            f"The assessment covered {n_products} Oracle product{'s' if n_products != 1 else ''} "
            f"and identified no CVEs matching the configured severity threshold."
        ]

    critical = sum(1 for f in findings if f.priority.value == "critical")
    high = sum(1 for f in findings if f.priority.value == "high")
    kev = sum(1 for f in findings if f.cve.kev_status)
    active = sum(1 for f in findings if f.threat_context and f.threat_context.active_exploitation)
    gaps = sum(1 for f in findings if f.detection_gap)

    paragraphs: list[str] = []

    # ── Para 1: Scope + Severity + Threat signal ──────────────────────────
    para: list[str] = []
    para.append(
        f"The assessment covered {n_products} Oracle product{'s' if n_products != 1 else ''} "
        f"and identified {n_cves} CVE{'s' if n_cves != 1 else ''} requiring attention."
    )
    ch = critical + high
    if ch:
        severity_parts = [s for s in [
            f"{critical} {'are' if critical != 1 else 'is'} rated Critical" if critical else "",
            f"{high} {'are' if high != 1 else 'is'} rated High" if high else "",
        ] if s]
        para.append(f"Of these, {_oxford(severity_parts)}.")
    if kev or active:
        if kev == active and kev:
            para.append(
                f"This includes {kev} CVE{'s' if kev != 1 else ''} both listed in CISA's "
                f"Known Exploited Vulnerabilities catalog and confirmed actively exploited in the wild."
            )
        else:
            threat_bits = [s for s in [
                f"{kev} CVE{'s' if kev != 1 else ''} listed in CISA's Known Exploited Vulnerabilities catalog" if kev else "",
                f"{active} CVE{'s' if active != 1 else ''} confirmed actively exploited in the wild" if active else "",
            ] if s]
            para.append(f"This includes {_oxford(threat_bits)}.")
    paragraphs.append(" ".join(para))

    # ── Para 2: Highest-priority finding ─────────────────────────────────
    top = findings[0]
    top_product = top.product.normalized_product_name or top.product.raw_product_name
    support_clause = {
        "end_of_life": ", which is end-of-life",
        "extended_support": ", which is on Extended Support",
    }.get(top.product.support_status.value, "")
    paragraphs.append(
        f"The highest-priority finding is {top.cve.cve_id} (score {top.priority_score}) "
        f"affecting {top_product} {top.product.raw_version}{support_clause}."
    )

    # ── Para 3: Detection gaps ────────────────────────────────────────────
    if gaps == 0:
        paragraphs.append("Detection logic is available for all findings.")
    elif gaps == n_cves:
        paragraphs.append(
            f"No detection logic exists for any of the {n_cves} findings — "
            f"exploitation would go unnoticed by current tooling."
        )
    else:
        paragraphs.append(
            f"{gaps} of {n_cves} findings have no detection logic in place, "
            f"meaning exploitation would go unnoticed by current tooling."
        )

    # ── Para 4: Support health ────────────────────────────────────────────
    eol = [p for p in all_products_summary if p["support_status"] == "end_of_life"]
    ext = [p for p in all_products_summary if p["support_status"] == "extended_support"]
    _pv = lambda p: f"{p['name']} {p['version']}"  # noqa: E731
    if eol and ext:
        paragraphs.append(
            f"{_oxford([_pv(p) for p in eol])} {'are' if len(eol) != 1 else 'is'} end-of-life "
            f"and {_oxford([_pv(p) for p in ext])} {'are' if len(ext) != 1 else 'is'} on Extended Support — "
            f"patch availability may be limited or subject to additional fees."
        )
    elif eol:
        paragraphs.append(
            f"{_oxford([_pv(p) for p in eol])} {'are' if len(eol) != 1 else 'is'} end-of-life — "
            f"the vendor may not issue patches for identified vulnerabilities."
        )
    elif ext:
        paragraphs.append(
            f"{_oxford([_pv(p) for p in ext])} {'are' if len(ext) != 1 else 'is'} on Extended Support — "
            f"continued patch coverage requires an active Extended Support agreement."
        )
    elif all(p["support_status"] == "supported" for p in all_products_summary):
        paragraphs.append("All assessed products are within active Premier Support.")

    # ── Para 5: Call to action ────────────────────────────────────────────
    if critical and high:
        paragraphs.append(
            f"Immediate remediation is required for the {critical} Critical "
            f"finding{'s' if critical != 1 else ''}; the {high} High "
            f"finding{'s' if high != 1 else ''} should be addressed within standard patch SLA windows."
        )
    elif critical:
        paragraphs.append(
            f"Immediate remediation is required for the {critical} Critical "
            f"finding{'s' if critical != 1 else ''}."
        )
    elif high:
        paragraphs.append(
            f"The {high} High-priority finding{'s' if high != 1 else ''} "
            f"should be addressed within standard patch SLA windows."
        )

    return paragraphs


def _oxford(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _build_all_products_summary(
    products: list[ProductRecord],
    findings: list[FindingRecord],
) -> list[dict]:
    finding_counts: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        key = f"{f.product.normalized_product_name or f.product.raw_product_name}::{f.product.raw_version}"
        finding_counts[key][f.priority] += 1

    result = []
    seen: set[str] = set()
    for p in products:
        name = p.normalized_product_name or p.raw_product_name
        key = f"{name}::{p.raw_version}"
        if key in seen:
            continue
        seen.add(key)
        counts = finding_counts.get(key, Counter())
        result.append({
            "name": name,
            "version": p.raw_version,
            "machine_id": p.machine_id or "unknown",
            "tier": p.tier or "",
            "tier_label": _tier_label(p.tier),
            "support_status": p.support_status.value,
            "eol_date": p.eol_date,
            "premier_end": _extract_premier_end(p.support_notes),
            "total_findings": sum(counts.values()),
            "priority_counts": {pr.value: counts[pr] for pr in Priority},
        })
    return result


def _collect_patches(group: list[FindingRecord]) -> list[dict]:
    seen: set[str] = set()
    patches: list[dict] = []
    for f in group:
        for p in f.patch_references:
            key = p.patch_id or p.advisory_url or p.advisory_title
            if not key or key in seen:
                continue
            seen.add(key)
            patches.append({
                "source": p.source,
                "advisory_title": p.advisory_title,
                "advisory_url": p.advisory_url,
                "fixed_version": p.fixed_version,
                "patch_id": p.patch_id,
                "patch_name": p.patch_name,
                "patch_availability_url": p.patch_availability_url,
                "confidence": p.confidence.value,
            })
    return patches


def _extract_premier_end(notes: str | None) -> str | None:
    if not notes:
        return None
    m = re.search(r"Premier Support ended (\d{4}-\d{2}-\d{2})", notes)
    return m.group(1) if m else None


def _count_unique_products_by_status(findings: list[FindingRecord], status: SupportStatus) -> int:
    seen: set[str] = set()
    for f in findings:
        key = f"{f.product.normalized_product_name or f.product.raw_product_name}::{f.product.raw_version}"
        if f.product.support_status == status and key not in seen:
            seen.add(key)
    return len(seen)


def _build_risk_posture(
    findings: list[FindingRecord],
    kev_count: int,
    critical_count: int,
    high_count: int,
    eol_count: int,
) -> dict:
    _ch_priorities = {Priority.CRITICAL, Priority.HIGH}
    ch_findings = [f for f in findings if f.priority in _ch_priorities]
    ch_gap_count = sum(1 for f in ch_findings if f.detection_gap)
    ch_total = len(ch_findings)
    gap_pct = round(ch_gap_count / ch_total * 100) if ch_total else 0
    public_count = sum(1 for f in findings if f.threat_context and f.threat_context.public_exploit)

    _biz_critical_tiers = {"0", "1"}
    seen_eol_biz: set[str] = set()
    for f in findings:
        if f.product.support_status == SupportStatus.END_OF_LIFE:
            key = f"{f.product.normalized_product_name or f.product.raw_product_name}::{f.product.raw_version}"
            if (f.product.tier or "").strip() in _biz_critical_tiers and key not in seen_eol_biz:
                seen_eol_biz.add(key)
    eol_biz_critical_count = len(seen_eol_biz)

    if kev_count > 0 or (eol_biz_critical_count > 0 and critical_count > 0):
        level, css_class = "CRITICAL", "posture-critical"
    elif critical_count > 0 or public_count > 10:
        level, css_class = "HIGH", "posture-high"
    elif high_count > 0:
        level, css_class = "MODERATE", "posture-moderate"
    else:
        level, css_class = "LOW", "posture-low"

    seen_kev: set[str] = set()
    kev_ids: list[str] = []
    for f in findings:
        if f.cve.kev_status and f.cve.cve_id not in seen_kev:
            seen_kev.add(f.cve.cve_id)
            kev_ids.append(f.cve.cve_id)

    drivers: list[dict] = []
    if kev_count > 0:
        drivers.append({
            "icon": "⚑", "icon_class": "driver-icon-kev",
            "label": "KEV",
            "detail": f"{len(kev_ids)} CVE{'s' if len(kev_ids) != 1 else ''} actively exploited in the wild",
            "expandable_items": kev_ids,
            "expandable_item_class": "kev-id",
            "action": "Isolate affected assets and apply emergency patch immediately",
            "action_class": "action-arrow-urgent",
        })

    if ch_gap_count > 0 and ch_total > 0:
        drivers.append({
            "icon": "◉", "icon_class": "driver-icon-warn",
            "label": "Detection blind spot",
            "detail": f"{gap_pct}% of Critical/High findings lack a publicly known detection rule ({ch_gap_count} / {ch_total})",
            "action": "Validate and deploy SIEM / EDR detection rules this week",
            "action_class": "action-arrow-normal",
        })

    eol_names: list[str] = []
    seen_eol: set[str] = set()
    for f in findings:
        if f.product.support_status == SupportStatus.END_OF_LIFE:
            name = f.product.normalized_product_name or f.product.raw_product_name
            key = f"{name}::{f.product.raw_version}"
            if key not in seen_eol:
                seen_eol.add(key)
                suffix = f" (EOL {f.product.eol_date})" if f.product.eol_date else ""
                eol_names.append(f"{name} {f.product.raw_version}{suffix}")
    if eol_names:
        extra = f" (+{len(eol_names) - 1} more)" if len(eol_names) > 1 else ""
        drivers.append({
            "icon": "◉", "icon_class": "driver-icon-warn",
            "label": "EOL product",
            "detail": f"{eol_names[0]}{extra}",
            "action": "Open upgrade project with target date, assign named owner",
            "action_class": "action-arrow-normal",
        })

    if critical_count > 0:
        seen_crit: set[str] = set()
        crit_ids: list[str] = []
        for f in findings:
            if f.priority == Priority.CRITICAL and f.cve.cve_id not in seen_crit:
                seen_crit.add(f.cve.cve_id)
                crit_ids.append(f.cve.cve_id)
        drivers.append({
            "icon": "◉", "icon_class": "driver-icon-warn",
            "label": "Critical unmitigated",
            "detail": f"{critical_count} finding{'s' if critical_count != 1 else ''} with no patch applied",
            "expandable_items": crit_ids,
            "expandable_item_class": "crit-id",
            "action": "Assign remediation owners, set patch SLA, track in ticket system",
            "action_class": "action-arrow-normal",
        })

    tooltip_parts = []
    if kev_count > 0:
        tooltip_parts.append(f"{kev_count} KEV finding{'s' if kev_count != 1 else ''} present")
    if gap_pct > 0:
        tooltip_parts.append(f"{gap_pct}% detection gap")
    if eol_count > 0:
        tooltip_parts.append(f"{eol_count} EOL product{'s' if eol_count != 1 else ''} with unpatched vulnerabilities")
    tooltip = f"{level}: " + " · ".join(tooltip_parts) if tooltip_parts else level

    return {"level": level, "css_class": css_class, "drivers": drivers[:4], "tooltip": tooltip}


# ── Shared utilities ───────────────────────────────────────────────────────

def _highest_summary(finding: FindingRecord | None) -> str | None:
    if not finding:
        return None
    product = finding.product.normalized_product_name or finding.product.raw_product_name
    return f"{finding.cve.cve_id} · {finding.priority.value} · {product} · Score {finding.priority_score}"


def _provider_mode(run_ctx: RunContext) -> str:
    if run_ctx.mock_providers:
        return f"mock ({', '.join(run_ctx.mock_providers)})"
    return "live"


def _filter_references(references) -> list:
    _keep = (
        "nvd.nist.gov",
        "oracle.com/security-alerts",
        "cisa.gov",
    )
    seen_urls: set[str] = set()
    filtered = []
    for ref in references:
        url = (ref.url or "").lower()
        if not any(domain in url for domain in _keep):
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        filtered.append(ref)
    filtered.sort(key=_reference_rank)
    return filtered


def _primary_references(references) -> list:
    return _filter_references(references)


def _overflow_references(_references) -> list:
    return []


def _reference_rank(reference) -> tuple[int, str]:
    url = (reference.url or "").lower()
    if "nvd.nist.gov" in url:
        return (0, reference.label)
    if "oracle.com/security-alerts" in url:
        return (1, reference.label)
    if "cisa.gov" in url:
        return (2, reference.label)
    return (9, reference.label)
