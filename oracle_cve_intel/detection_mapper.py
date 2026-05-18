from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import re
import sqlite3
import subprocess
import time

from .cache_manager import CacheManager
from .config import DETECTION_REPOS
from .models import ConfidenceLevel, DetectionRuleRecord, FindingRecord, ReferenceRecord
from .runtime import RunContext


MAX_RULES_PER_FINDING = 10


class DetectionIndexBuilder:
    def __init__(self, cache: CacheManager, run_ctx: RunContext, offline: bool = False) -> None:
        self.cache = cache
        self.run_ctx = run_ctx
        self.offline = offline

    def build(self, refresh: bool = False, rebuild: bool = False) -> Path:
        repo_paths = self._prepare_repos(refresh)
        db_path = self.cache.detection_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.run_ctx.progress("detect", f"Building detection index at {db_path} ...")
        with sqlite3.connect(db_path) as conn:
            _init_db(conn, reset=rebuild)
            if rebuild:
                conn.execute("DELETE FROM rule_keys")
                conn.execute("DELETE FROM rules")
            indexed = 0
            total_files = 0
            for source, repo_path in repo_paths.items():
                self.run_ctx.progress("detect", f"Indexing {source} rules ...")
                for path in _iter_rule_files(repo_path):
                    total_files += 1
                    try:
                        text = path.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    rule = _rule_from_file(path, repo_path, source, text)
                    keys = _index_keys(text)
                    if not keys:
                        continue
                    _upsert_rule(conn, rule, keys)
                    indexed += 1
                    if indexed == 1 or indexed % 500 == 0:
                        self.run_ctx.progress("detect", f"Indexed {indexed} searchable rules from {total_files} scanned files.")
            conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("built_at", str(int(time.time()))))
            conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("rule_count", str(indexed)))
            conn.commit()
        self.run_ctx.progress("detect", f"Detection index complete: {indexed} searchable rules from {total_files} scanned files.")
        return db_path

    def _prepare_repos(self, refresh: bool) -> dict[str, Path]:
        available: dict[str, Path] = {}
        for name, url in DETECTION_REPOS.items():
            repo_path = self.cache.get_repo_path(_repo_slug(name))
            if not repo_path.exists():
                if self.offline:
                    self.run_ctx.add_warning("detect", f"{name} not cloned and offline mode is enabled")
                    self.run_ctx.progress("detect", f"{name} not cloned; unavailable in offline mode.", "warn")
                    continue
                try:
                    self.run_ctx.progress("detect", f"Cloning {name} detection repository ...")
                    repo_path.parent.mkdir(parents=True, exist_ok=True)
                    subprocess.run(["git", "clone", "--depth", "1", url, str(repo_path)], check=True, capture_output=True, text=True)
                    self.cache.record_clone(_repo_slug(name))
                    self.run_ctx.progress("detect", f"Clone complete for {name}.")
                except (OSError, subprocess.CalledProcessError) as exc:
                    self.run_ctx.add_error("detect", name, f"git clone failed: {exc}")
                    self.run_ctx.progress("detect", f"Clone failed for {name}; continuing.", "warn")
                    continue
            elif refresh and not self.offline:
                try:
                    self.run_ctx.progress("detect", f"Refreshing {name} detection repository ...")
                    subprocess.run(["git", "-C", str(repo_path), "pull", "--ff-only"], check=True, capture_output=True, text=True)
                    self.cache.record_clone(_repo_slug(name))
                    self.run_ctx.progress("detect", f"Refresh complete for {name}.")
                except (OSError, subprocess.CalledProcessError) as exc:
                    self.run_ctx.add_warning("detect", f"{name} git pull failed; using existing clone: {exc}")
                    self.run_ctx.progress("detect", f"Refresh failed for {name}; using existing clone.", "warn")
            else:
                self.run_ctx.progress("detect", f"Using cached detection repository for {name}.")
            available[name] = repo_path
        return available


class DetectionDbMapper:
    def __init__(self, cache: CacheManager, run_ctx: RunContext) -> None:
        self.cache = cache
        self.run_ctx = run_ctx

    def find_rules(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        db_path = self.cache.detection_db_path()
        if not db_path.exists():
            self.run_ctx.add_warning("detect", "Local detection DB not found; run `detection-index --refresh` to enable detection mapping")
            self.run_ctx.progress("detect", "Local detection DB not found. Run `detection-index --refresh` to enable detection mapping.", "warn")
            return [replace(finding, detection_rules=[], detection_gap=True) for finding in findings]

        enriched: list[FindingRecord] = []
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            for finding in findings:
                rules = self._rules_for_finding(conn, finding)
                enriched.append(replace(finding, detection_rules=rules, detection_gap=not bool(rules)))
        covered = sum(1 for finding in enriched if not finding.detection_gap)
        self.run_ctx.progress("detect", f"Detection DB lookup complete: {covered}/{len(enriched)} CVEs have matching rules.")
        return enriched

    def _rules_for_finding(self, conn: sqlite3.Connection, finding: FindingRecord) -> list[DetectionRuleRecord]:
        if not finding.cve.cve_id.startswith("CVE-"):
            return []

        cve_rules = self._rules_for_terms(conn, [finding.cve.cve_id], finding)
        if cve_rules:
            return cve_rules[:MAX_RULES_PER_FINDING]

        technique_terms = []
        if finding.threat_context:
            technique_terms = [technique.technique_id for technique in finding.threat_context.attack_techniques]
        return self._rules_for_terms(conn, technique_terms, finding)[:MAX_RULES_PER_FINDING]

    def _rules_for_terms(self, conn: sqlite3.Connection, terms: list[str], finding: FindingRecord) -> list[DetectionRuleRecord]:
        rules: list[DetectionRuleRecord] = []
        seen_ids: set[str] = set()
        for term in {term.upper() for term in terms if term}:
            rows = conn.execute(
                """
                SELECT rules.*
                FROM rules
                JOIN rule_keys ON rule_keys.rule_id = rules.rule_id
                WHERE rule_keys.key = ?
                ORDER BY rules.source, rules.path
                """,
                (term,),
            ).fetchall()
            for row in rows:
                rule_id = row["rule_id"]
                if rule_id in seen_ids:
                    continue
                seen_ids.add(rule_id)
                rules.append(_rule_from_row(row, finding))
                if len(rules) >= MAX_RULES_PER_FINDING:
                    return rules
        return rules


class MockDetectionMapper:
    def find_rules(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        enriched: list[FindingRecord] = []
        for index, finding in enumerate(findings):
            if index % 2 == 0 and finding.cve.cve_id.startswith("CVE-"):
                rule = DetectionRuleRecord(
                    rule_id=f"MOCK-SIGMA-{index + 1:03d}",
                    rule_name=f"Mock detection for {finding.cve.cve_id}",
                    rule_type="sigma",
                    source="SigmaHQ mock",
                    related_cve=finding.cve.cve_id,
                    telemetry_required=["web server logs", "application logs"],
                    attack_techniques=finding.threat_context.attack_techniques if finding.threat_context else [],
                    reference=ReferenceRecord(
                        label=f"Mock Sigma rule for {finding.cve.cve_id}",
                        url=f"https://github.com/SigmaHQ/sigma/search?q={finding.cve.cve_id}",
                        source="SigmaHQ mock",
                    ),
                    confidence=ConfidenceLevel.MEDIUM,
                )
                enriched.append(replace(finding, detection_rules=[rule], detection_gap=False))
            else:
                enriched.append(replace(finding, detection_rules=[], detection_gap=True))
        return enriched


def _iter_rule_files(repo_path: Path):
    extensions = {".yml", ".yaml", ".json", ".kql", ".toml", ".yar", ".yara", ".rules"}
    for path in repo_path.rglob("*"):
        if path.is_file() and path.suffix.lower() in extensions:
            yield path


def _init_db(conn: sqlite3.Connection, reset: bool = False) -> None:
    if reset:
        conn.execute("DROP TABLE IF EXISTS rule_keys")
        conn.execute("DROP TABLE IF EXISTS rules")
        conn.execute("DROP TABLE IF EXISTS metadata")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rules (
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            source TEXT NOT NULL,
            path TEXT NOT NULL,
            url TEXT NOT NULL,
            telemetry TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rule_keys (
            key TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            PRIMARY KEY (key, rule_id),
            FOREIGN KEY (rule_id) REFERENCES rules(rule_id) ON DELETE CASCADE
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_keys_key ON rule_keys(key)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )


def _upsert_rule(conn: sqlite3.Connection, rule: DetectionRuleRecord, keys: set[str]) -> None:
    reference_url = rule.reference.url if rule.reference else ""
    path = rule.rule_id.split(":", 1)[1] if ":" in rule.rule_id else rule.rule_id
    conn.execute(
        """
        INSERT OR REPLACE INTO rules(rule_id, rule_name, rule_type, source, path, url, telemetry)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (rule.rule_id, rule.rule_name, rule.rule_type, rule.source, path, reference_url, "\n".join(rule.telemetry_required)),
    )
    conn.execute("DELETE FROM rule_keys WHERE rule_id = ?", (rule.rule_id,))
    conn.executemany("INSERT OR IGNORE INTO rule_keys(key, rule_id) VALUES (?, ?)", [(key, rule.rule_id) for key in sorted(keys)])


def _index_keys(text: str) -> set[str]:
    cves = {match.upper() for match in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)}
    techniques = {match.upper() for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.IGNORECASE)}
    return cves | techniques


def _rule_from_row(row: sqlite3.Row, finding: FindingRecord) -> DetectionRuleRecord:
    telemetry = [item for item in row["telemetry"].split("\n") if item]
    return DetectionRuleRecord(
        rule_id=row["rule_id"],
        rule_name=row["rule_name"],
        rule_type=row["rule_type"],
        source=row["source"],
        related_cve=finding.cve.cve_id,
        telemetry_required=telemetry,
        attack_techniques=finding.threat_context.attack_techniques if finding.threat_context else [],
        reference=ReferenceRecord(
            label=f"{row['source']} rule {row['path']}",
            url=row["url"],
            source=row["source"],
        ),
        confidence=ConfidenceLevel.MEDIUM,
    )


def _rule_from_file(path: Path, repo_path: Path, source: str, text: str) -> DetectionRuleRecord:
    relative = path.relative_to(repo_path)
    rule_type = _rule_type(path)
    rule_name = _rule_name(path, text, rule_type)
    telemetry = _telemetry_required(text, rule_type)
    return DetectionRuleRecord(
        rule_id=f"{source}:{relative}",
        rule_name=rule_name,
        rule_type=rule_type,
        source=source,
        related_cve="",
        telemetry_required=telemetry,
        attack_techniques=[],
        reference=ReferenceRecord(
            label=f"{source} rule {relative}",
            url=_repo_file_url(source, relative),
            source=source,
        ),
        confidence=ConfidenceLevel.MEDIUM,
    )


def _rule_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".yml", ".yaml"}:
        return "sigma"
    if suffix == ".json":
        return "json"
    if suffix == ".kql":
        return "kql"
    if suffix == ".toml":
        return "toml"
    if suffix in {".yar", ".yara"}:
        return "yara"
    if suffix == ".rules":
        return "suricata"
    return "unknown"


def _rule_name(path: Path, text: str, rule_type: str) -> str:
    patterns = [
        r"(?m)^title:\s*['\"]?(.+?)['\"]?\s*$",
        r"(?m)^name:\s*['\"]?(.+?)['\"]?\s*$",
        r"(?m)^\s*name\s*=\s*['\"](.+?)['\"]",
        r"(?m)^\s*\"name\"\s*:\s*\"(.+?)\"",
        r"(?m)^rule\s+([A-Za-z0-9_]+)",
        r"(?m)^alert\s+\S+\s+\S+\s+\S+\s+\S+\s+\(msg:\"(.+?)\"",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip()
    if rule_type == "kql":
        for line in text.splitlines():
            if line.strip().startswith("//"):
                return line.strip("/ ").strip()
    return path.stem


def _telemetry_required(text: str, rule_type: str) -> list[str]:
    if rule_type == "sigma":
        product = _yaml_field(text, "product")
        service = _yaml_field(text, "service")
        telemetry = " ".join(part for part in [product, service] if part)
        return [telemetry] if telemetry else ["logs"]
    if rule_type == "kql":
        return ["Microsoft Sentinel / KQL logs"]
    if rule_type == "toml":
        return ["Elastic detection telemetry"]
    if rule_type == "yara":
        return ["file or memory scanning"]
    if rule_type == "suricata":
        return ["network IDS"]
    return ["rule-specific telemetry"]


def _yaml_field(text: str, field: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*['\"]?(.+?)['\"]?\s*$", text)
    return match.group(1).strip() if match else None


def _repo_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _repo_file_url(source: str, relative: Path) -> str:
    base = DETECTION_REPOS.get(source, "").removesuffix(".git")
    if not base:
        return str(relative)
    return f"{base}/blob/master/{relative.as_posix()}"
