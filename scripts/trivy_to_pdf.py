
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

BASE = Path(__file__).resolve().parent.parent
INPUT = BASE / "trivy-results.json"
OUTPUT = BASE / "trivy-report.pdf"


def safe(value):
    text = str(value or "N/A")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate():
    if not INPUT.exists():
        raise FileNotFoundError(f"Report not found: {INPUT}")

    with INPUT.open(encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("Results") or []
    findings = []
    targets = []

    for result in results:
        target = result.get("Target", "Unknown target")
        result_type = result.get("Type", "Unknown")
        targets.append(f"{target} ({result_type})")

        for item in result.get("Vulnerabilities") or []:
            findings.append({
                "kind": "Vulnerability",
                "target": target,
                "id": item.get("VulnerabilityID", "N/A"),
                "severity": item.get("Severity", "UNKNOWN").upper(),
                "component": item.get("PkgName", "N/A"),
                "installed": item.get("InstalledVersion", "N/A"),
                "fixed": item.get("FixedVersion", "Not specified"),
                "details": item.get("Title") or item.get("Description") or "No description",
            })

        for item in result.get("Misconfigurations") or []:
            findings.append({
                "kind": "Misconfiguration",
                "target": target,
                "id": item.get("ID", "N/A"),
                "severity": item.get("Severity", "UNKNOWN").upper(),
                "component": item.get("Title", "Configuration issue"),
                "installed": "N/A",
                "fixed": "See resolution",
                "details": item.get("Message") or item.get("Description") or "No description",
            })

        for item in result.get("Secrets") or []:
            findings.append({
                "kind": "Secret",
                "target": target,
                "id": item.get("RuleID", "N/A"),
                "severity": item.get("Severity", "UNKNOWN").upper(),
                "component": item.get("Title", "Potential secret"),
                "installed": "N/A",
                "fixed": "Remove or rotate exposed credential",
                "details": item.get("Match") or item.get("Title") or "Potential secret detected",
            })

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D")
    ))
    styles.add(ParagraphStyle(
        name="CellSmall", parent=styles["BodyText"],
        fontSize=7, leading=9, wordWrap="CJK"
    ))

    doc = SimpleDocTemplate(
        str(OUTPUT), pagesize=landscape(A4),
        rightMargin=10*mm, leftMargin=10*mm,
        topMargin=12*mm, bottomMargin=12*mm
    )

    story = [
        Paragraph("Trivy Security Scan Report", styles["ReportTitle"]),
        Spacer(1, 4*mm),
        Paragraph(f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')}", styles["Normal"]),
        Paragraph(f"Scanned targets in report: {len(results)}", styles["Normal"]),
        Paragraph(f"Findings reported: {len(findings)}", styles["Normal"]),
        Spacer(1, 4*mm),
        Paragraph("Scan Targets", styles["Heading2"]),
    ]

    if targets:
        for target in targets:
            story.append(Paragraph(safe(target), styles["BodyText"]))
    else:
        story.append(Paragraph(
            "No scan targets were present in the JSON. This may indicate an unsupported target or an unsuccessful scan.",
            styles["BodyText"]
        ))

    story.extend([Spacer(1, 5*mm), Paragraph("Severity Summary", styles["Heading2"])])

    counts = Counter(f["severity"] for f in findings)
    summary = [["Severity", "Count"]]
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        summary.append([severity, counts.get(severity, 0)])
    summary.append(["TOTAL", len(findings)])

    table = Table(summary, colWidths=[45*mm, 25*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([table, Spacer(1, 5*mm)])

    if not results:
        story.append(Paragraph(
            "SCAN INCONCLUSIVE: No scan results were present. Do not interpret this as a clean scan.",
            styles["Heading2"]
        ))
    elif not findings:
        story.append(Paragraph(
            "No findings were reported in the scan results. This does not prove the target is completely secure.",
            styles["Heading2"]
        ))
    else:
        story.append(Paragraph("Finding Details", styles["Heading2"]))
        cell = styles["CellSmall"]
        rows = [[
            "Type", "Severity", "ID", "Component / Rule",
            "Installed", "Fixed / Remediation", "Target", "Details"
        ]]

        for f in findings:
            rows.append([
                Paragraph(safe(f["kind"]), cell),
                Paragraph(safe(f["severity"]), cell),
                Paragraph(safe(f["id"]), cell),
                Paragraph(safe(f["component"]), cell),
                Paragraph(safe(f["installed"]), cell),
                Paragraph(safe(f["fixed"]), cell),
                Paragraph(safe(f["target"]), cell),
                Paragraph(safe(f["details"]), cell),
            ])

        detail_table = Table(
            rows,
            colWidths=[20*mm, 18*mm, 25*mm, 33*mm,
                       22*mm, 35*mm, 35*mm, 85*mm],
            repeatRows=1
        )
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(detail_table)

    doc.build(story)
    print(f"PDF generated: {OUTPUT}")


if __name__ == "__main__":
    generate()
