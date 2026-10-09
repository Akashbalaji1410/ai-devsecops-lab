import json
from collections import Counter
from pathlib import Path

REPORT_FILE = Path("semgrep-results.json")


def format_list(value):
    """Format metadata that may be a string or a list."""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if value:
        return str(value)
    return "Not specified"


def main():
    if not REPORT_FILE.exists():
        print(f"Report not found: {REPORT_FILE}")
        print("Run the Semgrep scan first.")
        raise SystemExit(1)

    try:
        with REPORT_FILE.open("r", encoding="utf-8") as file:
            report = json.load(file)
    except json.JSONDecodeError as error:
        print(f"Invalid JSON report: {error}")
        raise SystemExit(1)

    findings = report.get("results", [])
    severity_counts = Counter()
    cwe_counts = Counter()

    print("=" * 75)
    print("SEMGREP SECURITY FINDINGS")
    print("=" * 75)
    print(f"Report: {REPORT_FILE}")
    print(f"Total findings: {len(findings)}")

    for number, finding in enumerate(findings, start=1):
        extra = finding.get("extra", {})
        metadata = extra.get("metadata") or {}
        location = finding.get("start") or {}

        rule_id = finding.get("check_id", "Unknown rule")
        file_path = finding.get("path", "Unknown file")
        line = location.get("line", "?")
        column = location.get("col", "?")
        severity = extra.get("severity", "UNKNOWN")
        message = extra.get("message", "No message provided")
        cwe = format_list(metadata.get("cwe"))

        severity_counts[severity] += 1

        cwes = metadata.get("cwe", [])
        if isinstance(cwes, str):
            cwes = [cwes]

        for cwe_id in cwes:
            cwe_counts[cwe_id] += 1

        print(f"\nFinding #{number}")
        print(f"  Vulnerability / Rule : {rule_id}")
        print(f"  File                 : {file_path}")
        print(f"  Location             : Line {line}, Column {column}")
        print(f"  Severity             : {severity}")
        print(f"  CWE                  : {cwe}")
        print(f"  Description          : {message}")

    print("\n" + "=" * 75)
    print("SUMMARY")
    print("=" * 75)

    print("\nFindings by severity:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")

    print("\nFindings by CWE:")
    if cwe_counts:
        for cwe_id, count in sorted(cwe_counts.items()):
            print(f"  {cwe_id}: {count}")
    else:
        print("  No CWE metadata found in the matched rules.")

    if not findings:
        print("\nNo findings matched the configured rules.")
        print("This does not prove that the repository is vulnerability-free.")


if __name__ == "__main__":
    main()