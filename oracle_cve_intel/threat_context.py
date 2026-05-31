from __future__ import annotations

from dataclasses import replace

from .models import AttackTechniqueRecord, ConfidenceLevel, FindingRecord, ReferenceRecord, ThreatContextRecord
from .utils import dedupe_refs


class RealThreatContextEnricher:
    def enrich(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        enriched: list[FindingRecord] = []
        for finding in findings:
            references = finding.cve.references + finding.evidence_references
            exploit_refs = [reference for reference in references if _is_public_exploit_reference(reference)]
            techniques = _infer_attack_techniques(finding)
            context = ThreatContextRecord(
                cve_id=finding.cve.cve_id,
                public_exploit=bool(exploit_refs),
                active_exploitation=finding.cve.kev_status,
                exploit_references=exploit_refs,
                attack_techniques=techniques,
                confidence=_context_confidence(exploit_refs, finding.cve.kev_status, techniques),
                references=dedupe_refs(exploit_refs + _kev_reference(finding.cve.kev_status) + _technique_references(techniques)),
            )
            enriched.append(replace(finding, threat_context=context))
        return enriched


class MockThreatContextEnricher:
    def enrich(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        enriched: list[FindingRecord] = []
        for index, finding in enumerate(findings):
            if index % 2 == 0 and finding.cve.cve_id.startswith("CVE-"):
                context = ThreatContextRecord(
                    cve_id=finding.cve.cve_id,
                    public_exploit=True,
                    active_exploitation=finding.cve.kev_status,
                    attack_techniques=[
                        AttackTechniqueRecord(
                            technique_id="T1190",
                            name="Exploit Public-Facing Application",
                            url="https://attack.mitre.org/techniques/T1190/",
                            confidence=ConfidenceLevel.LOW,
                        )
                    ],
                    confidence=ConfidenceLevel.LOW,
                    references=_threat_references(finding.cve.cve_id, finding.cve.kev_status),
                )
            else:
                context = ThreatContextRecord(
                    cve_id=finding.cve.cve_id,
                    confidence=ConfidenceLevel.UNKNOWN,
                    references=[
                        ReferenceRecord(
                            label="Mock threat context lookup",
                            url="https://attack.mitre.org/",
                            source="mock:threat-context-not-found",
                        )
                    ],
                )
            enriched.append(replace(finding, threat_context=context))
        return enriched


def _threat_references(cve_id: str, kev_status: bool) -> list[ReferenceRecord]:
    references = [
        ReferenceRecord(
            label="NVD reference tags",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            source="NVD",
        ),
        ReferenceRecord(
            label="MITRE ATT&CK T1190",
            url="https://attack.mitre.org/techniques/T1190/",
            source="MITRE ATT&CK",
        ),
    ]
    if kev_status:
        references.append(
            ReferenceRecord(
                label="CISA KEV catalog",
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                source="CISA KEV",
            )
        )
    return references


def _is_public_exploit_reference(reference: ReferenceRecord) -> bool:
    url_lower = reference.url.lower()
    if "cisa.gov" in url_lower:
        return False
    label_lower = (reference.label or "").lower()
    if any(s in url_lower for s in ["exploit-db.com", "packetstormsecurity", "metasploit"]):
        return True
    if any(s in label_lower for s in ["exploit", "proof-of-concept", "proof of concept"]):
        return True
    if "github.com" in url_lower:
        return any(s in url_lower for s in ["exploit", "/poc", "proof-of-concept"])
    return False


def _infer_attack_techniques(finding: FindingRecord) -> list[AttackTechniqueRecord]:
    product = (finding.product.normalized_product_name or finding.product.raw_product_name).lower()
    description = (finding.cve.description or "").lower()
    server_terms = ["weblogic", "database", "e-business", "fusion middleware", "access manager", "identity manager"]
    exploit_terms = ["remote code execution", "rce", "authentication bypass", "deserialization", "remote attacker"]
    if any(term in product for term in server_terms) and any(term in description for term in exploit_terms):
        return [
            AttackTechniqueRecord(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                url="https://attack.mitre.org/techniques/T1190/",
                confidence=ConfidenceLevel.LOW,
            )
        ]
    return []


def _context_confidence(exploit_refs: list[ReferenceRecord], kev_status: bool, techniques: list[AttackTechniqueRecord]) -> ConfidenceLevel:
    if kev_status or exploit_refs:
        return ConfidenceLevel.MEDIUM
    if techniques:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.UNKNOWN


def _kev_reference(kev_status: bool) -> list[ReferenceRecord]:
    if not kev_status:
        return []
    return [
        ReferenceRecord(
            label="CISA KEV catalog",
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            source="CISA KEV",
        )
    ]


def _technique_references(techniques: list[AttackTechniqueRecord]) -> list[ReferenceRecord]:
    return [
        ReferenceRecord(
            label=f"MITRE ATT&CK {technique.technique_id}",
            url=technique.url,
            source="MITRE ATT&CK",
        )
        for technique in techniques
    ]

