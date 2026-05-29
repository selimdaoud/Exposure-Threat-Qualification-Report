from __future__ import annotations

import csv
from pathlib import Path

from .models import ProductRecord


class InputParserError(ValueError):
    pass


def read_csv(path: Path | str) -> list[ProductRecord]:
    csv_path = Path(path)
    if not csv_path.exists():
        raise InputParserError(f"Input file not found: {csv_path}")

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])
        required = {"product_name", "version"}
        missing = required - fieldnames
        if missing:
            raise InputParserError(f"Missing required CSV field(s): {', '.join(sorted(missing))}")

        records: list[ProductRecord] = []
        machine_counter = 0
        for index, row in enumerate(reader, start=2):
            product_name = (row.get("product_name") or "").strip()
            version = (row.get("version") or "").strip()
            if not product_name:
                raise InputParserError(f"Row {index}: product_name is required")
            if not version:
                raise InputParserError(f"Row {index}: version is required")
            machine_id = _clean(row.get("host") or row.get("machine_id"))
            if not machine_id:
                machine_counter += 1
                machine_id = f"host_{machine_counter:03d}"
            records.append(
                ProductRecord(
                    input_id=f"row-{index - 1:03d}",
                    raw_product_name=product_name,
                    raw_version=version,
                    machine_id=machine_id,
                    notes=_clean(row.get("notes")),
                    owner=_clean(row.get("owner")),
                    tier=_clean(row.get("tier") or row.get("criticality")),
                )
            )
    return records


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None
