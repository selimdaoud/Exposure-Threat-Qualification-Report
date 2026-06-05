# Architecture

## Overview

`oracle-cve-intel` is a pipeline tool that maps Oracle product installations to CVEs, enriches each finding with threat intelligence, and produces prioritised reports. It exposes four CLI subcommands:

| Command | Purpose |
|---|---|
| `analyze` | Full pipeline: products CSV → enriched, prioritised findings report |
| `lookup-cve` | Targeted lookup of a single CVE across NVD, Oracle advisories, and the detection DB |
| `detection-index` | Clone detection repositories and build the local SQLite rule index |
| `update-aliases` | Refresh the product alias and CPE mapping files from NVD |

---

## Data Model

All records are immutable Python dataclasses. Transformations use `dataclasses.replace()`. Every record that makes a factual claim carries a `ConfidenceLevel`.

### Enumerations

```
SupportStatus    SUPPORTED | EXTENDED_SUPPORT | END_OF_LIFE | UNKNOWN
AffectedStatus   CONFIRMED_AFFECTED | POTENTIALLY_AFFECTED |
                 NVD_WILDCARD_NO_VERSIONS | NOT_ENOUGH_VERSION_INFORMATION | NOT_AFFECTED
ConfidenceLevel  HIGH | MEDIUM | LOW | UNKNOWN
Severity         CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL   (sourced from NVD CVSS)
Priority         CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL   (pipeline-computed)
```

`Severity` and `Priority` are intentionally separate scales — they can diverge as scoring logic evolves without touching the external data model.

### Core Records

#### `ProductRecord`
Represents one row from the input CSV after normalisation.

| Field | Type | Description |
|---|---|---|
| `input_id` | `str` | Row identifier (e.g. `"row-001"`) |
| `raw_product_name` | `str` | Original name from CSV |
| `raw_version` | `str` | Original version from CSV |
| `normalized_product_name` | `str \| None` | After alias resolution |
| `cpe_prefix` | `str \| None` | e.g. `cpe:2.3:a:oracle:weblogic_server` |
| `normalized_version_for_cpe` | `str \| None` | 5-part padded version for NVD queries |
| `machine_id` | `str \| None` | Host identifier |
| `notes / owner / tier` | `str \| None` | Pass-through metadata from CSV |
| `normalization_confidence` | `ConfidenceLevel` | How certain the alias resolution is |
| `support_status` | `SupportStatus` | Lifecycle status |
| `eol_date` | `str \| None` | YYYY-MM-DD from endoflife.date |
| `support_notes` | `str \| None` | Human-readable status explanation |

#### `CVERecord`
Aggregates all data known about one CVE.

| Field | Type | Description |
|---|---|---|
| `cve_id` | `str` | e.g. `CVE-2024-12345` |
| `description` | `str \| None` | English description from NVD |
| `severity` | `Severity` | Derived from CVSS base score |
| `cvss_score` | `float \| None` | Base score |
| `cvss_vector` | `str \| None` | Full CVSS vector string |
| `cwe` | `str \| None` | e.g. `CWE-787` |
| `kev_status` | `bool` | In CISA Known Exploited Vulnerabilities catalog |
| `epss_score` | `float \| None` | FIRST EPSS probability (0–1) |
| `oracle_advisory_ref` | `str \| None` | Descriptive Oracle advisory reference |
| `published_date` | `str \| None` | YYYY-MM-DD from NVD |
| `references` | `list[ReferenceRecord]` | All source links |

#### `FindingRecord`
The central unit of the pipeline — one product × one CVE.

| Field | Type | Description |
|---|---|---|
| `product` | `ProductRecord` | The affected product |
| `cve` | `CVERecord` | The vulnerability |
| `affected_status` | `AffectedStatus` | How certain we are of affectedness |
| `mapping_confidence` | `ConfidenceLevel` | NVD/advisory matching confidence |
| `threat_context` | `ThreatContextRecord \| None` | Exploit and actor intelligence |
| `detection_rules` | `list[DetectionRuleRecord]` | Matching detection rules |
| `detection_gap` | `bool` | `True` if no rules cover this CVE |
| `priority` | `Priority` | Pipeline-computed risk priority |
| `priority_score` | `int` | Raw numeric score (0–130) |
| `priority_explanation` | `str` | Human-readable scoring rationale |
| `recommended_action` | `str` | Generated remediation guidance |
| `evidence_references` | `list[ReferenceRecord]` | NVD/Oracle evidence for this mapping |
| `patch_references` | `list[PatchReferenceRecord]` | Patch/advisory information |
| `confidence_level` | `ConfidenceLevel` | Overall finding confidence |

#### `PatchReferenceRecord`
Describes where and how to obtain a patch.

| Field | Type | Description |
|---|---|---|
| `source` | `str` | e.g. `"Oracle CPU advisory"` |
| `advisory_title` | `str` | Human-readable advisory name |
| `advisory_url` | `str` | URL of the advisory page |
| `product` | `str` | Product name |
| `affected_versions` | `list[str]` | Affected version strings |
| `fixed_version` | `str \| None` | First fixed version (from NVD `versionEndExcluding`) |
| `patch_id` | `str \| None` | MOS patch bundle ID if available |
| `patch_name` | `str \| None` | Descriptive name |
| `patch_availability_url` | `str \| None` | MOS patch availability document link |
| `notes` | `str \| None` | Additional context |
| `confidence` | `ConfidenceLevel` | |
| `patch_type` | `str` | `"cpu"` (quarterly) or `"cspu"` (monthly) |

#### `ThreatContextRecord`
Threat intelligence attached to a CVE.

| Field | Type | Notes |
|---|---|---|
| `public_exploit` | `bool` | Exploit code is publicly available |
| `active_exploitation` | `bool` | Observed in the wild |
| `exploit_references` | `list[ReferenceRecord]` | Links to exploit PoCs |
| `malware_families` | `list[str]` | |
| `campaigns / threat_actors / iocs` | `list[str]` | |
| `attack_techniques` | `list[AttackTechniqueRecord]` | MITRE ATT&CK mappings |
| `confidence` | `ConfidenceLevel` | |

#### `DetectionRuleRecord`

| Field | Type | Notes |
|---|---|---|
| `rule_id` | `str` | `"source:relative/path"` |
| `rule_name` | `str` | Extracted from rule title/name field |
| `rule_type` | `str` | `sigma`, `kql`, `yara`, `toml`, `suricata` |
| `source` | `str` | Repository name (e.g. `"SigmaHQ"`) |
| `related_cve` | `str` | CVE this rule covers |
| `telemetry_required` | `list[str]` | Log sources needed to use the rule |
| `attack_techniques` | `list[AttackTechniqueRecord]` | |
| `reference` | `ReferenceRecord \| None` | Link to rule file |

#### Supporting Records

```
ReferenceRecord          label, url, source
AttackTechniqueRecord    technique_id, name, url, confidence
```

---

## Pipeline: `analyze`

```
CSV input
    │
    ▼
input_parser.read_csv()
    │  ProductRecord list
    ▼
normalizer.normalize()
    │  Alias resolution → cpe_prefix + normalized_version_for_cpe
    ▼
support_checker.check_support()
    │  SupportStatus, eol_date via endoflife.date API / local JSON
    ▼
NvdCVEMapper.map()
    │  NVD CPE queries → FindingRecord list
    │  Oracle advisory scan for wildcard CVE confirmation
    ▼
RealCVEEnricher.enrich()
    │  CVSS fill-in, KEV status, EPSS scores
    ▼
RealThreatContextEnricher.enrich()
    │  Exploit references, MITRE techniques inferred from CVE metadata
    ▼
DetectionDbMapper.find_rules()
    │  SQLite DB lookup by CVE ID and MITRE technique IDs
    ▼
prioritizer.prioritize()
    │  Scoring → Priority, priority_score, recommended_action
    ▼
report.write_json() / write_html()
```

Each stage returns a new list of records rather than mutating in place.

---

## Lookup Mechanisms

### 1. NVD CPE Lookup (CVE mapping)

**Entry point:** `NvdCVEMapper.map()`

For each product:
1. Build a CPE name: `{cpe_prefix}:{normalized_version}:*:*:*:*:*:*:*`
2. Query `NVD_BASE_URL?cpeName=<cpe_name>` — returns all CVEs matching that CPE.
3. If the padded version returns only wildcard results, retry without the trailing `.0`.
4. For each returned CVE, call `_affected_status()` to determine whether the installed version falls within the NVD-specified version ranges.

**Version range logic** (`_cpe_match_applies`):
- `versionStartIncluding` / `versionStartExcluding` → lower bound check
- `versionEndIncluding` / `versionEndExcluding` → upper bound check
- Wildcard criteria (`*` or `-`) → `NVD_WILDCARD_NO_VERSIONS` status, triggers Oracle advisory confirmation

**NVD rate limit:** 6 seconds between calls (`ApiClient._rate_limit`).

---

### 2. Oracle Advisory Confirmation (wildcard CVE resolution)

**Entry point:** `OraclePatchResolver.bulk_confirm_wildcard_cves()`

When NVD uses wildcard CPEs for a product (no version ranges), the tool falls back to parsing Oracle CPU/CSPU advisory HTML pages to confirm affectedness:

1. Collect all Oracle advisory URLs from NVD references for the wildcard CVEs.
2. If none found, fall back to the generated list of recent quarterly CPUs and monthly CSPUs.
3. For each advisory URL, fetch the HTML and parse the risk matrix with `_RiskMatrixParser`.
4. Filter rows by product section (`AppendixDB`, `AppendixFMW`, etc.) and check whether the installed version falls within the advisory's affected version range (`_version_in_oracle_range`).
5. CVEs confirmed this way are promoted from `NVD_WILDCARD_NO_VERSIONS` → `CONFIRMED_AFFECTED`.

**Advisory URL generation** (`_recent_advisory_urls_from_index`):
- Quarterly CPUs from 2017 onwards: `cpujan{year}`, `cpuapr{year}`, `cpujul{year}`, `cpuoct{year}`
- Monthly CSPUs from 2026 onwards: `cspu{month}{year}` (only if the third Tuesday of that month has passed)

**Oracle rate limit:** 2 seconds between HTML fetches.

---

### 3. Single CVE Lookup

**Entry point:** `lookup-cve` CLI command

Combines three independent lookups for one CVE ID:

1. **NVD by CVE ID** — `GET NVD_BASE_URL?cveId={cve_id}` → description, severity, CVSS, CWE, references.
2. **KEV + EPSS** — CISA KEV catalog (bulk JSON) + FIRST EPSS API (per-CVE query).
3. **Oracle advisory scan** (`OraclePatchResolver.find_cve_in_advisories`) — scans all advisories from the CVE's publication year onward (year extracted from the CVE ID) and returns every risk-matrix row matching that CVE ID, including product, component, and affected versions.
4. **Detection DB** — direct SQLite query on `rule_keys.key = CVE_ID`.

---

### 4. Detection Rule Lookup

**Index build** (`DetectionIndexBuilder.build`):
1. Clone or pull five detection repositories (SigmaHQ, Elastic, Splunk, Azure Sentinel, Neo23x0).
2. Walk every `.yml`, `.yaml`, `.json`, `.kql`, `.toml`, `.yar`, `.yara`, `.rules` file.
3. Extract indexable keys: CVE IDs (`CVE-YYYY-NNNNN`) and MITRE ATT&CK technique IDs (`T1234`, `T1234.001`).
4. Upsert into SQLite: `rules` table (rule metadata) + `rule_keys` table (key → rule_id index).

**Runtime lookup** (`DetectionDbMapper._rules_for_finding`):
1. Query `rule_keys` by CVE ID first.
2. If no hit, fall back to MITRE technique IDs from `ThreatContextRecord.attack_techniques`.
3. Return up to `MAX_RULES_PER_FINDING = 10` rules.

---

### 5. Product Normalisation

**Entry point:** `normalizer.normalize()`

Two-pass resolution against `product_aliases.json` and `cpe_map.json`:

1. **Exact match** on normalised name (lowercased).
2. **Fuzzy match** using token overlap — requires ≥ 75% of the product name's tokens to match an alias key.

Version normalisation (`normalize_version`):
- Strips suffixes like `RU`, `BP`, `PSU`.
- Converts Java `1.8u281` → `1.8.281`.
- Handles Oracle's `12c` → `12.0.0.0.0` style notation.
- Pads all versions to 5 parts with trailing zeros.

---

### 6. Support Status Check

**Entry point:** `support_checker.check_support()`

Three-level resolution, in order:

1. **endoflife.date API** — matches product name to a known slug (e.g. `oracle-database` → `oracle-database`), then matches the version against active release cycles.
2. **Local JSON** (`data/oracle_support_dates.json`) — hand-curated Oracle-specific data; used when endoflife.date has no entry or is unavailable.
3. **UNKNOWN** — neither source could determine status.

Status outcomes: `SUPPORTED`, `EXTENDED_SUPPORT`, `END_OF_LIFE`, `UNKNOWN`.

---

## Priority Scoring

`prioritizer.score()` produces an integer score (0–130) which maps to a `Priority` level:

| Score | Priority |
|---|---|
| ≥ 85 | CRITICAL |
| ≥ 65 | HIGH |
| ≥ 40 | MEDIUM |
| ≥ 20 | LOW |
| < 20 | INFORMATIONAL |

**Scoring factors:**

| Factor | Points |
|---|---|
| Severity: CRITICAL / HIGH / MEDIUM / LOW | 40 / 30 / 15 / 5 |
| CISA KEV | +30 |
| Active exploitation | +25 |
| Public exploit | +15 |
| EPSS ≥ 0.80 | +15 |
| EPSS ≥ 0.50 | +10 |
| EPSS ≥ 0.20 | +5 |
| Confirmed affected (vs. potential) | +10 |
| Oracle CSPU (emergency patch) | +20 |
| Detection gap (no covering rule) | +10 |
| EOL product | +15 |
| Extended support only | +5 |

The host-level risk score (used in the HTML report matrix) is separate: it aggregates per-finding priority scores, applies per-signal bonuses (`HOST_SCORE_SIGNALS`), and multiplies by a business-criticality tier (`HOST_SCORE_TIER_MULTIPLIERS` 1.0–2.5×).

---

## Caching

All external data is cached as JSON files under `data/cache/{source}/{key}.json`. A `_meta.json` sidecar tracks write timestamps.

| Source key | TTL | Data cached |
|---|---|---|
| `nvd` | 7 days | CPE query results, CVE-by-ID lookups |
| `oracle_advisories` | 7 days | Advisory risk matrix rows, patch availability entries |
| `kev` | 1 day | Full CISA KEV catalog |
| `epss` | 7 days | EPSS score responses |
| `euvd` | 7 days | ENISA EUVD responses |
| `endoflife` | 1 day | endoflife.date cycle data |
| `detection_repos` | 7 days | Clone timestamps |

The detection rule index is a persistent SQLite database at `data/cache/detection_db/rules.db`.

---

## External Data Sources

| Source | URL | Used for |
|---|---|---|
| NVD CVEs API | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE-to-product mapping, CVE details |
| NVD CPEs API | `services.nvd.nist.gov/rest/json/cpes/2.0` | Product alias discovery |
| CISA KEV | `cisa.gov/…/known_exploited_vulnerabilities.json` | Exploitation status |
| FIRST EPSS | `api.first.org/data/v1/epss` | Exploitation probability |
| Oracle Security Alerts | `oracle.com/security-alerts/cpu*.html` | Advisory risk matrices, patch availability |
| endoflife.date | `endoflife.date/api` | Product lifecycle status |
| SigmaHQ / Elastic / Splunk / Azure Sentinel / Neo23x0 | GitHub | Detection rules |

---

## Infrastructure

### `ApiClient`
Single HTTP client for all external calls. Features:
- Retry loop with 0 / 2 / 4 second delays on 5xx and network errors.
- Per-source rate limiting enforced via `_last_request_by_source`.
- `offline=True` raises `OfflineModeError` immediately instead of making network calls.
- `get()` for JSON APIs, `get_html()` for advisory pages.

### `CacheManager`
Filesystem JSON cache with TTL awareness. Provides:
- `get(source, key)` / `set(source, key, data)` — JSON file read/write.
- `is_stale(source, key)` — compares write time against `CACHE_TTL[source]`.
- `detection_db_path()` — path to the SQLite detection index.
- `get_repo_path(slug)` — path to a cloned detection repository.

### `RunContext`
Execution context threaded through the pipeline. Accumulates:
- `warnings` — non-fatal issues (stale cache, missing version data).
- `errors` — source failures (NVD unavailable, clone failed).
- `api_calls` — audit log of all external requests made.
- `mock_providers` — list of stages replaced by mock implementations.
- `progress_callback` — callable for real-time progress output.

### Mock Implementations
Every external-touching class has a `Mock*` twin (`MockCVEMapper`, `MockCVEEnricher`, `MockThreatContextEnricher`, `MockDetectionMapper`) that returns deterministic synthetic data. The `--mock` flag enables all of them simultaneously, allowing the full pipeline to run without any network access or pre-built cache.
