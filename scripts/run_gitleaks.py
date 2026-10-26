# scripts/run_gitleaks.py

import json
import subprocess
import sys
from pathlib import Path

# Project paths
ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "scan-results"

DIRECTORY_REPORT = RESULTS_DIR / "gitleaks-directory-results.json"
HISTORY_REPORT = RESULTS_DIR / "gitleaks-history-results.json"
COMBINED_REPORT = RESULTS_DIR / "gitleaks-results.json"
ERROR_REPORT = RESULTS_DIR / "gitleaks-scan-errors.json"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

combined_findings = []
scan_errors = []


def run_gitleaks_scan(scan_name, target, report_file):
    """Run Gitleaks and preserve findings without exposing secret values."""

    print(f"\n[GITLEAKS] Starting {scan_name} scan")
    print(f"[GITLEAKS] Target: {target}")

    # Remove stale output so a failed scan cannot reuse an old report.
    if report_file.exists():
        report_file.unlink()

    command = [
        "gitleaks",
        "dir" if scan_name == "directory" else "git",
        str(target),
        "--report-format", "json",
        "--report-path", str(report_file),
        "--exit-code", "0",
    ]

    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )

    except FileNotFoundError:
        message = "Gitleaks was not found. Install it or add it to PATH."
        scan_errors.append({"scan": scan_name, "error": message})
        print(f"[GITLEAKS] ERROR: {message}")
        return

    except subprocess.TimeoutExpired:
        message = "Gitleaks scan timed out."
        scan_errors.append({"scan": scan_name, "error": message})
        print(f"[GITLEAKS] ERROR: {message}")
        return

    except OSError as exc:
        message = str(exc)
        scan_errors.append({"scan": scan_name, "error": message})
        print(f"[GITLEAKS] ERROR: {message}")
        return

    if result.stderr.strip():
        print(result.stderr.strip())

    # Gitleaks normally writes findings to the report file, not stdout.
    if not report_file.exists():
        message = (
            f"No report file was created. Exit code: {result.returncode}."
        )
        scan_errors.append({"scan": scan_name, "error": message})
        print(f"[GITLEAKS] ERROR: {message}")
        return

    try:
        with report_file.open("r", encoding="utf-8-sig") as file:
            data = json.load(file)

        if not isinstance(data, list):
            raise ValueError("Expected Gitleaks JSON to contain an array.")

    except (json.JSONDecodeError, OSError, ValueError) as exc:
        message = f"Could not parse report: {exc}"
        scan_errors.append({"scan": scan_name, "error": message})
        print(f"[GITLEAKS] ERROR: {message}")
        return

    # Add source metadata but never copy detected secret values into
    # the combined report.
    for finding in data:
        combined_findings.append({
            "RuleID": finding.get("RuleID"),
            "Description": finding.get("Description"),
            "File": finding.get("File"),
            "StartLine": finding.get("StartLine"),
            "EndLine": finding.get("EndLine"),
            "StartColumn": finding.get("StartColumn"),
            "EndColumn": finding.get("EndColumn"),
            "Fingerprint": finding.get("Fingerprint"),
            "_ScanSource": scan_name,
        })

    print(f"[GITLEAKS] Report: {report_file}")
    print(f"[GITLEAKS] Findings: {len(data)}")

    # With --exit-code 0, findings alone should not fail this learning run.
    if result.returncode != 0:
        message = (
            f"Gitleaks returned unexpected exit code {result.returncode}."
        )
        scan_errors.append({"scan": scan_name, "error": message})
        print(f"[GITLEAKS] WARNING: {message}")


# Scan files in the working directory.
run_gitleaks_scan(
    scan_name="directory",
    target=ROOT,
    report_file=DIRECTORY_REPORT,
)

# Scan repository history for secrets that may have been committed earlier.
run_gitleaks_scan(
    scan_name="git-history",
    target=ROOT,
    report_file=HISTORY_REPORT,
)

# Always preserve combined results, even when one scan fails.
with COMBINED_REPORT.open("w", encoding="utf-8") as file:
    json.dump(combined_findings, file, indent=2)

if scan_errors:
    with ERROR_REPORT.open("w", encoding="utf-8") as file:
        json.dump(scan_errors, file, indent=2)
else:
    if ERROR_REPORT.exists():
        ERROR_REPORT.unlink()

print("\n[GITLEAKS] Combined report:", COMBINED_REPORT)
print("[GITLEAKS] Total findings:", len(combined_findings))

if scan_errors:
    print("[GITLEAKS] One or more scans failed. See:", ERROR_REPORT)
    sys.exit(1)

print("[GITLEAKS] Both scans completed successfully.")