from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class StringEnum(str, Enum):
    pass


class SupportStatus(StringEnum):
    SUPPORTED = "supported"
    EXTENDED_SUPPORT = "extended_support"
    END_OF_LIFE = "end_of_life"
    UNKNOWN = "unknown"


class AffectedStatus(StringEnum):
    CONFIRMED_AFFECTED = "confirmed_affected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    NVD_WILDCARD_NO_VERSIONS = "nvd_wildcard_no_versions"
    NOT_ENOUGH_VERSION_INFORMATION = "not_enough_version_information"
    NOT_AFFECTED = "not_affected"


class ConfidenceLevel(StringEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Severity(StringEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Priority(StringEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class ReferenceRecord:
    label: str
    url: str
    source: str | None = None


@dataclass
class AttackTechniqueRecord:
    technique_id: str
    name: str
    url: str
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN


@dataclass
class PatchReferenceRecord:
    source: str
    advisory_title: str
    advisory_url: str
    product: str
    affected_versions: list[str] = field(default_factory=list)
    fixed_version: str | None = None
    patch_id: str | None = None
    patch_name: str | None = None
    patch_availability_url: str | None = None
    notes: str | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN


@dataclass
class ProductRecord:
    input_id: str
    raw_product_name: str
    raw_version: str
    normalized_product_name: str | None = None
    cpe_prefix: str | None = None
    normalized_version_for_cpe: str | None = None
    machine_id: str | None = None
    notes: str | None = None
    owner: str | None = None
    criticality: str | None = None
    normalization_confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    support_status: SupportStatus = SupportStatus.UNKNOWN
    eol_date: str | None = None
    support_notes: str | None = None


@dataclass
class CVERecord:
    cve_id: str
    description: str | None = None
    severity: Severity = Severity.INFORMATIONAL
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    kev_status: bool = False
    epss_score: float | None = None
    oracle_advisory_ref: str | None = None
    references: list[ReferenceRecord] = field(default_factory=list)


@dataclass
class ThreatContextRecord:
    cve_id: str
    public_exploit: bool = False
    active_exploitation: bool = False
    exploit_references: list[ReferenceRecord] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    attack_techniques: list[AttackTechniqueRecord] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    references: list[ReferenceRecord] = field(default_factory=list)


@dataclass
class DetectionRuleRecord:
    rule_id: str
    rule_name: str
    rule_type: str
    source: str
    related_cve: str
    telemetry_required: list[str] = field(default_factory=list)
    attack_techniques: list[AttackTechniqueRecord] = field(default_factory=list)
    reference: ReferenceRecord | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN


@dataclass
class FindingRecord:
    product: ProductRecord
    cve: CVERecord
    affected_status: AffectedStatus
    mapping_confidence: ConfidenceLevel
    threat_context: ThreatContextRecord | None = None
    detection_rules: list[DetectionRuleRecord] = field(default_factory=list)
    detection_gap: bool = True
    priority: Priority = Priority.INFORMATIONAL
    priority_score: int = 0
    priority_explanation: str = ""
    recommended_action: str = ""
    evidence_references: list[ReferenceRecord] = field(default_factory=list)
    patch_references: list[PatchReferenceRecord] = field(default_factory=list)
    confidence_level: ConfidenceLevel = ConfidenceLevel.UNKNOWN


def to_dict(value: Any) -> Any:
    if isinstance(value, StringEnum):
        return value.value
    if isinstance(value, list):
        return [to_dict(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return {key: to_dict(item) for key, item in asdict(value).items()}
    return value
