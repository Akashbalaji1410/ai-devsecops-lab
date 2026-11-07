
import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ASSET_VALUES = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25
}

EXPOSURE_VALUES = {
    "internet": 100,
    "internal": 50,
    "isolated": 0
}

SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0
}


def normalize(finding):
    if not isinstance(finding, dict):
        raise ValueError("Each finding must be an object.")

    required = ("finding_id", "source", "resource")

    for field in required:
        if not isinstance(finding.get(field), str):
            raise ValueError(f"Invalid or missing {field}")

        if not finding[field].strip():
            raise ValueError(f"Empty {field}")

    severity = str(
        finding.get("severity", "Info")
    ).capitalize()

    if severity not in SEVERITY_ORDER:
        raise ValueError("Unsupported severity")

    cvss = finding.get("cvss", 0)

    if type(cvss) not in (int, float) or not 0 <= cvss <= 10:
        raise ValueError("CVSS must be between 0 and 10")

    asset = str(
        finding.get("asset_criticality", "medium")
    ).lower()

    exposure = str(
        finding.get("exposure", "internal")
    ).lower()

    if asset not in ASSET_VALUES:
        raise ValueError("Invalid asset criticality")

    if exposure not in EXPOSURE_VALUES:
        raise ValueError("Invalid exposure")

    if type(finding.get("kev", False)) is not bool:
        raise ValueError("KEV must be boolean")

    if type(finding.get("fix_available", False)) is not bool:
        raise ValueError("fix_available must be boolean")

    return {
        "finding_id": finding["finding_id"].strip(),
        "source": finding["source"].strip(),
        "resource": finding["resource"].strip(),
        "severity": severity,
        "cvss": float(cvss),
        "kev": finding.get("kev", False),
        "asset_criticality": asset,
        "exposure": exposure,
        "fix_available": finding.get("fix_available", False),
        "title": finding.get("title", ""),
        "recommendation": finding.get("recommendation", "")
    }


def calculate_risk(finding):
    cvss_score = finding["cvss"] * 10
    exploit_score = 100 if finding["kev"] else 0
    asset_score = ASSET_VALUES[finding["asset_criticality"]]
    exposure_score = EXPOSURE_VALUES[finding["exposure"]]
    fix_score = 100 if finding["fix_available"] else 0

    score = round(
        0.40 * cvss_score
        + 0.25 * exploit_score
        + 0.15 * asset_score
        + 0.10 * exposure_score
        + 0.10 * fix_score
    )

    if score >= 80:
        priority = "P1"
    elif score >= 60:
        priority = "P2"
    elif score >= 40:
        priority = "P3"
    else:
        priority = "P4"

    return score, priority


def correlate(findings):
    grouped = {}

    for raw in findings:
        finding = normalize(raw)

        # Same identifier + resource = same issue in this lab.
        key = (
            finding["finding_id"].lower(),
            finding["resource"].lower()
        )

        if key not in grouped:
            grouped[key] = {
                **finding,
                "sources": [finding["source"]],
                "duplicate_count": 0
            }
            continue

        existing = grouped[key]

        if finding["source"] not in existing["sources"]:
            existing["sources"].append(finding["source"])

        existing["duplicate_count"] += 1

        # Preserve the highest observed severity.
        if (
            SEVERITY_ORDER[finding["severity"]]
            > SEVERITY_ORDER[existing["severity"]]
        ):
            existing["severity"] = finding["severity"]

        # Conservative handling of conflicting risk evidence.
        existing["cvss"] = max(
            existing["cvss"], finding["cvss"]
        )

        existing["kev"] = existing["kev"] or finding["kev"]

        existing["fix_available"] = (
            existing["fix_available"]
            or finding["fix_available"]
        )

        if (
            ASSET_VALUES[finding["asset_criticality"]]
            > ASSET_VALUES[existing["asset_criticality"]]
        ):
            existing["asset_criticality"] = (
                finding["asset_criticality"]
            )

        if (
            EXPOSURE_VALUES[finding["exposure"]]
            > EXPOSURE_VALUES[existing["exposure"]]
        ):
            existing["exposure"] = finding["exposure"]

    correlated = list(grouped.values())

    for finding in correlated:
        score, priority = calculate_risk(finding)

        finding["risk_score"] = score
        finding["priority"] = priority
        finding["status"] = "OPEN"

    correlated.sort(
        key=lambda f: (
            -f["risk_score"],
            -SEVERITY_ORDER[f["severity"]],
            f["finding_id"]
        )
    )

    return correlated


def analyze(data):
    if not isinstance(data, dict):
        raise ValueError("Input must be a JSON object.")

    if data.get("synthetic_data") is not True:
        raise ValueError("Only synthetic data is accepted.")

    findings = data.get("findings")

    if not isinstance(findings, list):
        raise ValueError("findings must be a list")

    correlated = correlate(findings)

    priority_counts = Counter(
        f["priority"] for f in correlated
    )

    severity_counts = Counter(
        f["severity"] for f in correlated
    )

    return {
        "tool": "custom-risk-correlation-engine",
        "synthetic_data": True,
        "environment": data.get(
            "environment", "synthetic-demo"
        ),
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "summary": {
            "raw_findings": len(findings),
            "unique_findings": len(correlated),
            "duplicates_removed": (
                len(findings) - len(correlated)
            ),
            "priority_counts": {
                p: priority_counts.get(p, 0)
                for p in ("P1", "P2", "P3", "P4")
            },
            "severity_counts": {
                s: severity_counts.get(s, 0)
                for s in (
                    "Critical", "High", "Medium", "Low", "Info"
                )
            }
        },
        "findings": correlated
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as file:
        data = json.load(file)

    report = analyze(data)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("Risk Correlation Assessment")
    print("---------------------------")
    print(
        f"Raw findings: "
        f"{report['summary']['raw_findings']}"
    )
    print(
        f"Unique findings: "
        f"{report['summary']['unique_findings']}"
    )
    print(
        f"Duplicates removed: "
        f"{report['summary']['duplicates_removed']}"
    )

    for priority, count in (
        report["summary"]["priority_counts"].items()
    ):
        print(f"{priority}: {count}")

    print(f"Report: {output}")


if __name__ == "__main__":
    main()
