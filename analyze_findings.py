import json
from collections import Counter
from pathlib import Path

REPORT_FILE = Path("semgrep-results.json")


def main():
    if not REPORT_FILE.exists():
        print("Report not found. Run Semgrep first.")
        raise SystemExit(1)

    with REPORT_FILE.open(encoding="utf-8") as file:
        report = json.load(file)

    findings = report.get("results", [])
    severity_counts = Counter()
    cwe_counts = Counter()

    for finding in findings:
        extra = finding.get("extra", {})

        severity = extra.get("severity", "UNKNOWN")
        severity_counts[severity] += 1

        metadata = extra.get("metadata", {})
        cwes = metadata.get("cwe", [])

        if isinstance(cwes, str):
            cwes = [cwes]

        for cwe in cwes:
            cwe_counts[cwe] += 1

    print(f"Total findings: {len(findings)}")
    print("\nFindings by severity:")

    for severity, count in sorted(severity_counts.items()):
        print(f"{severity}: {count}")

    print("\nFindings by CWE:")

    for cwe, count in sorted(cwe_counts.items()):
        print(f"{cwe}: {count}")


if __name__ == "__main__":
    main()