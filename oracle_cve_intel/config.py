from __future__ import annotations

import os
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
TEMPLATES_DIR = PACKAGE_ROOT / "templates"

NVD_API_KEY = os.getenv("NVD_API_KEY", None)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", None)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_DICT_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
EUVD_BASE_URL = "https://euvd.enisa.europa.eu/api/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
ORACLE_ALERTS_URL = "https://www.oracle.com/security-alerts/"
ENDOFLIFE_BASE_URL = "https://endoflife.date/api"

DETECTION_REPOS = {
    "SigmaHQ": "https://github.com/SigmaHQ/sigma",
    "Elastic": "https://github.com/elastic/detection-rules",
    "Splunk": "https://github.com/splunk/security_content",
    "Azure Sentinel": "https://github.com/Azure/Azure-Sentinel",
    "Neo23x0 signature-base": "https://github.com/Neo23x0/signature-base",
}

CACHE_TTL = {
    "kev": 86400,
    "nvd": 604800,
    "epss": 604800,
    "euvd": 604800,
    "oracle_advisories": 604800,
    "detection_repos": 604800,
    "endoflife": 86400,
}

DEFAULT_CACHE_DIR = PROJECT_ROOT / "data" / "cache"
ALIAS_FILE = PROJECT_ROOT / "data" / "product_aliases.json"
CPE_MAP_FILE = PROJECT_ROOT / "data" / "cpe_map.json"
ORACLE_SUPPORT_DATES_FILE = PROJECT_ROOT / "data" / "oracle_support_dates.json"
