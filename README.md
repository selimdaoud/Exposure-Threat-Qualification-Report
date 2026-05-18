# Oracle CVE Threat Enrichment Engine

Analyzes a list of Oracle products and versions, maps applicable CVEs, enriches
them with risk signals (KEV, EPSS, ATT&CK, detection rules), and generates
self-contained HTML and JSON reports.

## Quick Start

```bash
# First-time setup (interactive, guided)
python3 setup_first_run.py

# Run analysis
python3 -m oracle_cve_intel.cli analyze \
  --input examples/products.csv \
  --customer "Your Organisation" \
  --html report.html

# Open report
open REPORT/report.html
```

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.10+ | `python3 --version` |
| git | Required only for the detection index |
| Internet access | NVD, CISA KEV, EPSS, Oracle CPU advisories |
| ~500 MB free disk | Required only for the detection index |

Optional: [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
(free — increases rate limits).

## Installation

```bash
cd v1
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows

pip install -r requirements.txt

# Initialize product catalog (run once, then periodically)
python3 -m oracle_cve_intel.cli update-aliases

# Build detection index (optional, ~5–15 min, ~500 MB)
python3 -m oracle_cve_intel.cli detection-index --refresh --rebuild
```

## Input File Format

CSV with the following columns:

| Column | Required | Description |
|---|---|---|
| `product_name` | Yes | Oracle product name (e.g. `Oracle WebLogic Server`) |
| `version` | Yes | Installed version (e.g. `12.2.1.4`, `19.3`) |
| `machine_id` | Yes | Machine or host group identifier |
| `notes` | Yes | Free-text note (e.g. `Internet-facing`) |
| `owner` | No | Responsible owner or team |
| `criticality` | No | Business criticality (`low`, `medium`, `high`, `critical`) |

```csv
product_name,version,machine_id,notes,owner,criticality
Oracle WebLogic Server,12.2.1.4,web001,Internet-facing,platform,high
Oracle Database Server,19.3,db001,core database,dba,critical
Oracle E-Business Suite,12.2.10,ebs001,ERP production,finance,critical
```

Sample files: `examples/products.csv`, `examples/products3.csv`

## Main Command

```bash
python3 -m oracle_cve_intel.cli analyze \
  --input your_products.csv \
  --customer "Organisation Name" \
  --json findings.json \
  --html report.html
```

Output is always written under `REPORT/`:

```
REPORT/findings.json
REPORT/report.html
REPORT/report.log
```

### Common Flags

| Flag | Description |
|---|---|
| `--customer NAME` | Organisation name shown in the report header |
| `--min-severity LEVEL` | Filter to `low` / `medium` / `high` / `critical` |
| `--include-unconfirmed` | Include CVEs with generic or uncertain version mapping |
| `--skip-detection` | Skip detection rule lookup (faster) |
| `--offline` | Use cached data only, no network calls |
| `--mock` | Demo mode — synthetic data, not for real decisions |

## HTML Report Features

- Executive summary with Risk Posture rating and key drivers
- Full-text search and filters (priority, severity, KEV, exploit, detection)
- Expandable CVE cards with ATT&CK techniques, detection rules, patch references
- Machine-group view with owner attribution
- Separate section for products with no confirmed CVE

## Recommended Workflow

```bash
# 1. Keep product catalog current
python3 -m oracle_cve_intel.cli update-aliases

# 2. Keep detection index current
python3 -m oracle_cve_intel.cli detection-index --refresh --rebuild

# 3. Run analysis
python3 -m oracle_cve_intel.cli analyze \
  --input your_products.csv \
  --customer "Organisation Name"

# 4. Review REPORT/report.html — prioritize:
#    Critical > KEV = true > Public exploit > High EPSS > Internet-facing assets
```

## Troubleshooting

**Product not recognized (LOW confidence, no CVEs found)**
Run `python3 -m oracle_cve_intel.cli update-aliases`. If the product uses a
different name internally, add a manual alias in `data/product_aliases.json`:
```json
"My Internal Alias": "Canonical Oracle Name"
```

**Detection results are empty**
Check that `data/cache/detection_rules.sqlite` exists. If not:
```bash
python3 -m oracle_cve_intel.cli detection-index --refresh --rebuild
```

**Analysis is slow**
The first run scans up to 38 Oracle CPU advisories for products with generic
CPEs. Results are cached — subsequent runs are fast. For an immediate run:
```bash
python3 -m oracle_cve_intel.cli analyze --input ... --skip-detection
```

**Report shows "0 CVEs confirmed" for a product**
The installed version does not appear in any Oracle CPU advisory (2017–present).
The product/version is likely out of Oracle Premier or Extended Support.

**Patch References show a generic advisory link**
Expected for third-party CVEs (Apache, OpenSSL, etc.) that affect Oracle
products via a dependency. Check the Evidence References section instead.

## Full Documentation

See [MANUAL.txt](MANUAL.txt) for complete reference documentation (French).
