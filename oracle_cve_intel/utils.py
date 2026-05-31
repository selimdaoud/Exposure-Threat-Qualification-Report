from __future__ import annotations

from oracle_cve_intel.models import ReferenceRecord


def dedupe_refs(references: list[ReferenceRecord]) -> list[ReferenceRecord]:
    seen: set[tuple[str, str]] = set()
    deduped: list[ReferenceRecord] = []
    for ref in references:
        key = (ref.label, ref.url)
        if key not in seen:
            seen.add(key)
            deduped.append(ref)
    return deduped
