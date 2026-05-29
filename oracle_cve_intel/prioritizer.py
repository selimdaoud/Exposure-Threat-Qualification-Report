from __future__ import annotations

from dataclasses import replace

from .models import AffectedStatus, FindingRecord, Priority, Severity, SupportStatus


SEVERITY_POINTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 30,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
    Severity.INFORMATIONAL: 0,
}


def score(finding: FindingRecord) -> tuple[int, str]:
    total = 0
    factors: list[str] = []

    severity_points = SEVERITY_POINTS[finding.cve.severity]
    if severity_points:
        total += severity_points
        factors.append(f"{finding.cve.severity.value} severity +{severity_points}")

    if finding.cve.kev_status:
        total += 30
        factors.append("KEV listed +30")

    if finding.threat_context and finding.threat_context.active_exploitation:
        total += 25
        factors.append("active exploitation +25")

    if finding.threat_context and finding.threat_context.public_exploit:
        total += 15
        factors.append("public exploit +15")

    if finding.cve.epss_score is not None:
        if finding.cve.epss_score >= 0.80:
            total += 15
            factors.append("EPSS >= 0.80 +15")
        elif finding.cve.epss_score >= 0.50:
            total += 10
            factors.append("EPSS >= 0.50 +10")
        elif finding.cve.epss_score >= 0.20:
            total += 5
            factors.append("EPSS >= 0.20 +5")

    if finding.affected_status == AffectedStatus.CONFIRMED_AFFECTED:
        total += 10
        factors.append("confirmed affected +10")
    elif finding.affected_status == AffectedStatus.POTENTIALLY_AFFECTED:
        total += 5
        factors.append("potentially affected +5")

    if any(getattr(pr, "patch_type", "cpu") == "cspu" for pr in finding.patch_references):
        total += 20
        factors.append("Oracle CSPU (emergency patch) +20")

    if finding.detection_gap:
        total += 10
        factors.append("no detection found +10")

    support = finding.product.support_status
    if support == SupportStatus.END_OF_LIFE:
        total += 15
        factors.append("product end-of-life +15")
    elif support == SupportStatus.EXTENDED_SUPPORT:
        total += 5
        factors.append("product extended support only +5")

    if total > 130:
        factors.append("score capped at 130")
        total = 130

    return total, "; ".join(factors) if factors else "No scoring factors fired"


def prioritize(findings: list[FindingRecord]) -> list[FindingRecord]:
    prioritized = []
    for finding in findings:
        priority_score, _ = score(finding)
        priority = _priority_for(priority_score)
        prioritized.append(
            replace(
                finding,
                priority_score=priority_score,
                priority=priority,
                priority_explanation=_build_narrative(finding),
                recommended_action=_recommended_action(priority, finding.detection_gap),
            )
        )
    return sorted(prioritized, key=lambda item: item.priority_score, reverse=True)


def _build_narrative(finding: FindingRecord) -> str:
    sentences: list[str] = []

    cvss = f" (CVSS {finding.cve.cvss_score:.1f})" if finding.cve.cvss_score is not None else ""
    sentences.append(
        f"This CVE carries a {finding.cve.severity.value} severity rating{cvss}."
    )

    exploitation: list[str] = []
    if finding.cve.kev_status:
        exploitation.append("listed in CISA's Known Exploited Vulnerabilities catalog")
    if finding.threat_context and finding.threat_context.active_exploitation:
        exploitation.append("confirmed actively exploited in the wild")
    if finding.threat_context and finding.threat_context.public_exploit:
        exploitation.append("associated with a publicly available exploit")
    if exploitation:
        sentences.append("It is " + _join_and(exploitation) + ".")

    cspu_patches = [pr for pr in finding.patch_references if getattr(pr, "patch_type", "cpu") == "cspu"]
    if cspu_patches:
        advisory = cspu_patches[0].advisory_title or "an Oracle CSPU advisory"
        sentences.append(
            f"Oracle issued an emergency Critical Security Patch Update (CSPU) for this CVE via {advisory}, "
            "indicating Oracle assessed it as too critical to wait for the next quarterly CPU. "
            "Apply this patch immediately."
        )

    if finding.cve.epss_score is not None:
        pct = f"{finding.cve.epss_score:.0%}"
        if finding.cve.epss_score >= 0.80:
            sentences.append(
                f"EPSS score of {pct} indicates a high probability of exploitation in the next 30 days."
            )
        elif finding.cve.epss_score >= 0.50:
            sentences.append(
                f"EPSS score of {pct} indicates a moderate-to-high exploitation probability."
            )
        elif finding.cve.epss_score >= 0.20:
            sentences.append(
                f"EPSS score of {pct} indicates a moderate exploitation probability."
            )

    if finding.affected_status == AffectedStatus.CONFIRMED_AFFECTED:
        sentences.append("The installed version is confirmed vulnerable.")
    elif finding.affected_status == AffectedStatus.POTENTIALLY_AFFECTED:
        sentences.append(
            "The installed version is potentially vulnerable — manual version confirmation is recommended."
        )

    if finding.detection_gap:
        sentences.append(
            "No detection rule exists for this CVE: exploitation would not be caught by current tooling."
        )
    else:
        sentences.append(
            "Detection logic is available and should be validated as deployed."
        )

    support = finding.product.support_status
    if support == SupportStatus.END_OF_LIFE:
        sentences.append(
            "The product is end-of-life — the vendor may not issue a patch for this vulnerability."
        )
    elif support == SupportStatus.EXTENDED_SUPPORT:
        sentences.append(
            "The product is on Extended Support — patches require an active Extended Support agreement."
        )

    return " ".join(sentences)


def _join_and(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _priority_for(score_value: int) -> Priority:
    if score_value >= 85:
        return Priority.CRITICAL
    if score_value >= 65:
        return Priority.HIGH
    if score_value >= 40:
        return Priority.MEDIUM
    if score_value >= 20:
        return Priority.LOW
    return Priority.INFORMATIONAL


def _recommended_action(priority: Priority, detection_gap: bool) -> str:
    if priority in {Priority.CRITICAL, Priority.HIGH} and detection_gap:
        return "Apply patch immediately. No detection logic found - hunt historical logs and deploy a rule before patching."
    if priority in {Priority.CRITICAL, Priority.HIGH}:
        return "Apply patch. Deploy available detection logic now."
    if priority == Priority.MEDIUM:
        return "Schedule patch. Validate detection coverage."
    return "Monitor. Patch in next maintenance cycle."
