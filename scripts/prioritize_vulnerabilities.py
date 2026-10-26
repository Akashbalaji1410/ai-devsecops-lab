import json
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "trivy-results.json"
INTEL_FILE = ROOT / "vulnerability-intelligence.json"
JSON_OUTPUT = ROOT / "vulnerability-prioritized.json"
PDF_OUTPUT = ROOT / "vulnerability-prioritized.pdf"


def load_json(path, default=None):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_cvss(vulnerability):
    scores = vulnerability.get("CVSS") or {}

    # Try common CVSS sources and versions.
    for source in ("nvd", "redhat", "ghsa"):
        entry = scores.get(source) or {}
        for key in ("V3Score", "V4Score", "V2Score"):
            value = entry.get(key)
            if isinstance(value, (int, float)) and 0 <= value <= 10:
                return float(value)

    return None


def calculate_priority(cvss, epss, kev, criticality, exposure):
    # Unknown CVSS is not treated as zero severity.
    score = (cvss or 0) * 4

    if kev is True:
        score += 25

    if isinstance(epss, (int, float)):
        if epss >= 0.70:
            score += 15
        elif epss >= 0.30:
            score += 10
        elif epss >= 0.10:
            score += 5

    score += {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
    }.get(str(criticality).lower(), 0)

    score += {
        "internet-facing": 10,
        "internal": 5,
        "isolated": 1,
    }.get(str(exposure).lower(), 0)

    score = round(min(score, 100), 1)

    if score >= 80:
        priority = "P1 - Urgent"
    elif score >= 60:
        priority = "P2 - High"
    elif score >= 35:
        priority = "P3 - Medium"
    else:
        priority = "P4 - Review"

    # An unknown CVSS score requires review even if other signals are low.
    if cvss is None:
        priority += " (CVSS unknown)"

    return score, priority


def main():
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    input_path = input_path.resolve()

    try:
        scan = load_json(input_path)
        if not isinstance(scan, dict):
            raise ValueError("Input JSON is missing or isn't a JSON object.")

        intel = load_json(INTEL_FILE, default={})
        if not isinstance(intel, dict):
            raise ValueError("Intelligence JSON must be an object keyed by CVE.")

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)

    findings = []
    result_count = 0

    for result in scan.get("Results") or []:
        result_count += 1
        target = result.get("Target", "Unknown target")

        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID", "Unknown ID")
            extra = intel.get(cve, {})

            epss = extra.get("epss")
            if not isinstance(epss, (int, float)) or not 0 <= epss <= 1:
                epss = None

            kev = extra.get("kev")
            if not isinstance(kev, bool):
                kev = None

            cvss = get_cvss(vuln)
            criticality = extra.get("asset_criticality", "unknown")
            exposure = extra.get("exposure", "unknown")

            score, priority = calculate_priority(
                cvss, epss, kev, criticality, exposure
            )

            findings.append({
                "target": target,
                "cve": cve,
                "package": vuln.get("PkgName", "Unknown package"),
                "installed_version": vuln.get("InstalledVersion", "Unknown"),
                "fixed_version": vuln.get("FixedVersion") or "Not provided",
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cvss": cvss,
                "epss": epss,
                "kev": kev,
                "asset_criticality": criticality,
                "exposure": exposure,
                "priority_score": score,
                "priority": priority,
                "title": vuln.get("Title") or vuln.get("Description") or "",
            })

    findings.sort(key=lambda item: item["priority_score"], reverse=True)

    report = {
        "input_file": str(input_path),
        "scan_results_count": result_count,
        "vulnerability_count": len(findings),
        "status": (
            "FINDINGS FOUND" if findings
            else "NO VULNERABILITIES REPORTED - VERIFY SCAN COVERAGE"
        ),
        "scoring_note": (
            "Educational prioritization heuristic; not an official CVSS score. "
            "EPSS and KEV are unknown until verified enrichment is supplied."
        ),
        "findings": findings,
    }

    JSON_OUTPUT.write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="SmallCell",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
        alignment=TA_LEFT,
        wordWrap="CJK",
    ))

    doc = SimpleDocTemplate(
        str(PDF_OUTPUT),
        pagesize=landscape(A4),
        rightMargin=10 * mm,
        leftMargin=10 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    story = [
        Paragraph("Trivy Vulnerability Prioritization Report", styles["Title"]),
        Spacer(1, 4 * mm),
        Paragraph(f"Status: {report['status']}", styles["Heading2"]),
        Paragraph(
            f"Targets in JSON: {result_count} | "
            f"Vulnerabilities: {len(findings)}",
            styles["BodyText"],
        ),
        Spacer(1, 3 * mm),
        Paragraph(
            "Priority score is an educational heuristic combining CVSS, "
            "verified EPSS/KEV intelligence, asset criticality and exposure. "
            "Unknown intelligence is not assumed to be negative evidence.",
            styles["BodyText"],
        ),
        Spacer(1, 5 * mm),
    ]

    rows = [[
        "Priority / Score", "CVE", "Severity", "Package",
        "Installed → Fixed", "CVSS", "EPSS", "KEV",
        "Asset / Exposure", "Target"
    ]]

    for item in findings:
        cell = lambda value: Paragraph(
            str(value).replace("&", "&amp;").replace("<", "&lt;"),
            styles["SmallCell"],
        )
        rows.append([
            cell(f"{item['priority']} / {item['priority_score']}"),
            cell(item["cve"]),
            cell(item["severity"]),
            cell(item["package"]),
            cell(f"{item['installed_version']} → {item['fixed_version']}"),
            cell(item["cvss"] if item["cvss"] is not None else "Unknown"),
            cell(f"{item['epss']:.3f}" if item["epss"] is not None else "Unknown"),
            cell({True: "Yes", False: "No", None: "Unknown"}[item["kev"]]),
            cell(f"{item['asset_criticality']} / {item['exposure']}"),
            cell(item["target"]),
        ])

    if not findings:
        story.append(Paragraph(
            "No vulnerability records were present in the input JSON. "
            "This is not proof that the target is secure. Check that Trivy "
            "scanned the intended target and recognized its manifests.",
            styles["BodyText"],
        ))
    else:
        table = Table(
            rows,
            repeatRows=1,
            colWidths=[28*mm, 25*mm, 16*mm, 25*mm, 34*mm,
                       13*mm, 13*mm, 12*mm, 28*mm, 35*mm],
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263746")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)

    story.extend([
        Spacer(1, 5 * mm),
        Paragraph("Recommended review actions", styles["Heading2"]),
        Paragraph(
            "Validate known exploitation and EPSS against authoritative sources; "
            "confirm asset exposure and business criticality; check the fixed "
            "version; then follow your team's remediation SLA and retest after "
            "patching.",
            styles["BodyText"],
        ),
    ])

    doc.build(story)

    print(f"JSON report: {JSON_OUTPUT}")
    print(f"PDF report:  {PDF_OUTPUT}")
    print(f"Vulnerabilities processed: {len(findings)}")


if __name__ == "__main__":
    main()