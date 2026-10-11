
import argparse
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path


def load_sarif(file_path):
    """Load a SARIF JSON file or a ZIP containing a SARIF file."""
    if zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path) as archive:
            sarif_files = [
                name for name in archive.namelist()
                if name.lower().endswith(".sarif")
            ]

            if not sarif_files:
                raise ValueError("No .sarif file found inside the ZIP.")

            if len(sarif_files) > 1:
                print(
                    f"Multiple SARIF files found; using {sarif_files[0]}."
                )

            with archive.open(sarif_files[0]) as file:
                return json.load(file)

    with file_path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def get_severity(result, rule):
    """Get severity from the result or its rule definition."""
    properties = rule.get("properties", {})
    result_properties = result.get("properties", {})

    level = result.get("level")
    if level:
        return level.upper()

    severity = (
        result_properties.get("severity")
        or properties.get("security-severity")
        or properties.get("severity")
    )

    if severity is not None:
        return str(severity).upper()

    return "UNSPECIFIED"


def get_locations(result):
    """Extract file paths and line/column locations."""
    locations = []

    for item in result.get("locations", []):
        physical = item.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})

        locations.append({
            "file": artifact.get("uri", "Unknown file"),
            "line": region.get("startLine", "?"),
            "column": region.get("startColumn", "?"),
        })

    return locations or [{
        "file": "Unknown file",
        "line": "?",
        "column": "?",
    }]


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Gitleaks SARIF findings."
    )
    parser.add_argument(
        "report",
        help="Path to a .sarif file or ZIP containing a .sarif file",
    )
    args = parser.parse_args()

    report_path = Path(args.report)

    if not report_path.is_file():
        print(f"Report not found: {report_path}")
        raise SystemExit(1)

    try:
        sarif = load_sarif(report_path)
    except (OSError, ValueError, json.JSONDecodeError,
            zipfile.BadZipFile) as error:
        print(f"Could not read SARIF report: {error}")
        raise SystemExit(1)

    runs = sarif.get("runs", [])
    total = 0
    severity_counts = Counter()
    rule_counts = Counter()

    print("=" * 72)
    print("GITLEAKS SARIF ANALYSIS")
    print("=" * 72)

    for run in runs:
        tool = run.get("tool", {}).get("driver", {})
        rules = {
            rule.get("id"): rule
            for rule in tool.get("rules", [])
        }

        results = run.get("results", [])

        for result in results:
            total += 1
            rule_id = result.get("ruleId", "Unknown rule")
            rule = rules.get(rule_id, {})
            message_data = result.get("message", {})
            message = message_data.get("text", "No description provided")
            severity = get_severity(result, rule)

            severity_counts[severity] += 1
            rule_counts[rule_id] += 1

            print(f"\nFinding #{total}")
            print(f"  Rule        : {rule_id}")
            print(f"  Severity    : {severity}")
            print(f"  Description : {message}")

            for location in get_locations(result):
                print(f"  File        : {location['file']}")
                print(
                    f"  Location    : Line {location['line']}, "
                    f"Column {location['column']}"
                )

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total findings: {total}")

    print("\nFindings by severity:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")

    print("\nFindings by rule:")
    for rule_id, count in sorted(rule_counts.items()):
        print(f"  {rule_id}: {count}")

    if total == 0:
        print("\nNo findings were reported in the SARIF results.")
        print("This does not prove that the repository contains no secrets.")


if __name__ == "__main__":
    main()
