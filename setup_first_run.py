#!/usr/bin/env python3
"""
Oracle CVE Threat Enrichment Engine — First-time setup
Run this script once before the first analysis.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

# ── ANSI colours (disabled on Windows without ANSI support) ───────────────────
_USE_COLOUR = sys.stdout.isatty() and os.name != "nt"

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

def bold(t: str)    -> str: return _c("1",    t)
def green(t: str)   -> str: return _c("92",   t)
def yellow(t: str)  -> str: return _c("93",   t)
def red(t: str)     -> str: return _c("91",   t)
def cyan(t: str)    -> str: return _c("96",   t)
def muted(t: str)   -> str: return _c("2",    t)


# ── Helpers ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent.resolve()

def header() -> None:
    print()
    print(bold("═" * 62))
    print(bold("  Oracle CVE Threat Enrichment Engine — First-time Setup"))
    print(bold("═" * 62))
    print(muted("  This script will guide you through the initial setup."))
    print(muted("  Each step asks for confirmation before taking action."))
    print()


def step_header(n: int, title: str) -> None:
    print(f"\n{bold(cyan(f'[Step {n}]'))} {bold(title)}")
    print("─" * 50)


def info(msg: str)    -> None: print(f"  {muted('·')} {msg}")
def ok(msg: str)      -> None: print(f"  {green('✔')} {msg}")
def warn(msg: str)    -> None: print(f"  {yellow('⚠')} {msg}")
def error(msg: str)   -> None: print(f"  {red('✖')} {msg}")
def skip(msg: str)    -> None: print(f"  {muted('–')} {msg} (skipped)")


def ask(prompt: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"\n  {prompt} {muted(hint)}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if answer == "":
        return default
    return answer in ("y", "yes")


def ask_value(prompt: str, default: str = "") -> str:
    hint = f"[{default}]" if default else ""
    try:
        value = input(f"\n  {prompt} {muted(hint)}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return value or default


def run(cmd: list[str], env: dict | None = None) -> bool:
    merged = {**os.environ, **(env or {})}
    result = subprocess.run(cmd, cwd=ROOT, env=merged)
    return result.returncode == 0


def python() -> str:
    return sys.executable


# ── Steps ─────────────────────────────────────────────────────────────────────

def step_prereqs() -> None:
    step_header(1, "System prerequisites")
    passed = True

    # Python version
    v = sys.version_info
    info(f"Python {v.major}.{v.minor}.{v.micro}  ({sys.executable})")
    if v < (3, 10):
        error("Python 3.10 or higher is required.")
        sys.exit(1)
    ok("Python 3.10+")

    # git (required to clone detection rule repos in Step 6)
    git_path = shutil.which("git")
    if git_path:
        ok(f"git found  ({git_path})")
    else:
        error("git is not installed or not on PATH.")
        warn("git is required to build the detection index (Step 6).")
        warn("Install from https://git-scm.com and re-run this script.")
        passed = False

    # free disk space — detection repos + SQLite index ≈ 500 MB
    free_mb = shutil.disk_usage(ROOT).free // (1024 * 1024)
    if free_mb >= 600:
        ok(f"Disk space: {free_mb:,} MB free")
    else:
        warn(f"Only {free_mb:,} MB free. The detection index requires ~500 MB.")
        warn("Consider freeing disk space before running Step 6.")

    # network — quick TCP probe to nvd.nist.gov:443
    try:
        s = socket.create_connection(("nvd.nist.gov", 443), timeout=5)
        s.close()
        ok("Network: nvd.nist.gov reachable")
    except OSError:
        warn("Cannot reach nvd.nist.gov — you may be offline.")
        warn("Steps 5, 6, and 7 require internet access.")

    if not passed:
        if not ask("Some prerequisites are missing. Continue anyway?", default=False):
            sys.exit(1)


def step_venv() -> None:
    step_header(2, "Virtual environment")
    venv_path = ROOT / ".venv"
    if venv_path.exists():
        ok(f"Virtual environment already exists at {muted('.venv/')}")
        return
    info("A virtual environment isolates this project's dependencies.")
    if not ask("Create a virtual environment in .venv/?"):
        skip("Virtual environment")
        warn("Skipping may cause dependency conflicts with other projects.")
        return
    ok("Creating virtual environment...") if run([python(), "-m", "venv", ".venv"]) else error("Failed to create virtual environment.")


def step_deps() -> None:
    step_header(3, "Install dependencies")
    req = ROOT / "requirements.txt"
    info(f"Will install packages listed in {muted('requirements.txt')}")
    if not ask("Install dependencies?"):
        skip("Dependency installation")
        warn("The engine will not run without its dependencies.")
        return
    venv_pip = ROOT / ".venv" / "bin" / "pip"
    pip_cmd = [str(venv_pip), "install", "-r", str(req)] if venv_pip.exists() \
              else [python(), "-m", "pip", "install", "-r", str(req)]
    if run(pip_cmd):
        ok("Dependencies installed.")
    else:
        error("Dependency installation failed. Check your network and try again.")


def step_nvd_key() -> tuple[str | None, bool]:
    step_header(4, "NVD API key (optional)")
    existing = os.environ.get("NVD_API_KEY", "")
    if existing:
        ok(f"NVD_API_KEY is already set in the environment.")
        return existing, False

    info("An NVD API key increases the rate limit for vulnerability lookups.")
    info("Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")
    info("The engine works without a key, but calls may be slower.")

    if not ask("Do you have an NVD API key to configure?", default=False):
        skip("NVD API key")
        return None, False

    key = ask_value("Paste your NVD API key")
    if not key:
        skip("NVD API key (empty input)")
        return None, False

    env_file = ROOT / ".env"
    if ask(f"Save key to {muted('.env')} for future sessions?"):
        existing_lines = env_file.read_text().splitlines() if env_file.exists() else []
        lines = [l for l in existing_lines if not l.startswith("NVD_API_KEY=")]
        lines.append(f"NVD_API_KEY={key}")
        env_file.write_text("\n".join(lines) + "\n")
        ok(f"Key saved to .env  (add 'source .env' to your shell profile to load it automatically)")
    else:
        info("Key will be used for this session only.")

    return key, True


def step_catalog(nvd_key: str | None) -> None:
    step_header(5, "Initialize product catalog")
    info("Downloads the Oracle product list from NVD and builds the local CPE map.")
    info("This is required for product name normalization during analysis.")
    info("Run time: ~1–2 minutes on first use (result is cached for 7 days).")

    if not ask("Initialize the product catalog now?"):
        skip("Product catalog")
        warn("Run  python3 -m oracle_cve_intel.cli update-aliases  before your first analysis.")
        return

    env = {"NVD_API_KEY": nvd_key} if nvd_key else {}
    venv_python = ROOT / ".venv" / "bin" / "python3"
    py = str(venv_python) if venv_python.exists() else python()

    if run([py, "-m", "oracle_cve_intel.cli", "update-aliases"], env=env):
        ok("Product catalog initialized.")
    else:
        error("Catalog initialization failed. Check your network connection.")


def step_detection(nvd_key: str | None) -> None:
    step_header(6, "Build detection rule index")
    info("Clones SigmaHQ and Elastic detection rule repositories and builds a")
    info("local SQLite index used to map CVEs to detection rules in reports.")
    warn("This step can take 5–15 minutes and requires ~500 MB of disk space.")
    info("You can skip it now and run it later:  python3 -m oracle_cve_intel.cli detection-index --refresh --rebuild")

    if not ask("Build the detection index now?", default=False):
        skip("Detection index")
        return

    venv_python = ROOT / ".venv" / "bin" / "python3"
    py = str(venv_python) if venv_python.exists() else python()
    env = {"NVD_API_KEY": nvd_key} if nvd_key else {}

    if run([py, "-m", "oracle_cve_intel.cli", "detection-index", "--refresh", "--rebuild"], env=env):
        ok("Detection index built.")
    else:
        error("Detection index build failed.")


def step_sample_report(nvd_key: str | None) -> None:
    step_header(7, "Generate sample report")
    info("Runs an analysis on the bundled sample CSV and opens the HTML report.")
    info(f"Input: {muted('examples/products.csv')}")
    info(f"Output: {muted('REPORT/report.html')}")

    if not ask("Generate a sample report?"):
        skip("Sample report")
        return

    customer = ask_value("Organisation name for the report", default="My Organisation")

    mock = ask(
        "Use mock mode? (fast, no network — good for testing the report layout)",
        default=False,
    )
    if mock:
        info("Mock mode: synthetic data will be used. Do not use for real patching decisions.")
    else:
        info("Live mode: will query NVD, KEV, EPSS, and Oracle CPU advisories.")

    venv_python = ROOT / ".venv" / "bin" / "python3"
    py = str(venv_python) if venv_python.exists() else python()
    env = {"NVD_API_KEY": nvd_key} if nvd_key else {}

    cmd = [
        py, "-m", "oracle_cve_intel.cli", "analyze",
        "--input", "examples/products.csv",
        "--customer", customer,
        "--html", "report.html",
        "--json", "findings.json",
    ]
    if mock:
        cmd.append("--mock")

    if run(cmd, env=env):
        report = ROOT / "REPORT" / "report.html"
        ok(f"Report written to {bold(str(report))}")
        if ask("Open the report in your browser?"):
            import webbrowser
            webbrowser.open(report.as_uri())
    else:
        error("Report generation failed.")


def summary() -> None:
    print()
    print(bold("═" * 62))
    print(bold("  Setup complete"))
    print(bold("═" * 62))
    print()
    print("  Standard analysis command:")
    print()
    print(cyan('    python3 -m oracle_cve_intel.cli analyze \\'))
    print(cyan('      --input your_products.csv \\'))
    print(cyan('      --customer "Your Organisation" \\'))
    print(cyan('      --html report.html'))
    print()
    print(muted("  See README.md for full documentation."))
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    header()
    step_prereqs()
    step_venv()
    step_deps()
    nvd_key, _ = step_nvd_key()
    step_catalog(nvd_key)
    step_detection(nvd_key)
    step_sample_report(nvd_key)
    summary()


if __name__ == "__main__":
    main()
