
# scripts/normalize_all_findings.py

import json
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "scan-results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

TRIVY_FILE = RESULTS_DIR / "trivy-results.json"
GITLEAKS_FILE = RESULTS_DIR / "gitleaks-results.json"
GITLEAKS_SARIF_FILE = RESULTS_DIR / "results.sarif"

OUTPUT_JSON = RESULTS_DIR / "normalized-security-findings.json"
OUTPUT_PDF = RESULTS_DIR / "security-findings-report.pdf"

findings = []
source_status = {}
errors = []


def read_json(path):
    """Read a JSON file with UTF-8 and Windows-1252 fallback support."""
    path = Path(path)

    if not path.exists():
        return None, f"File not found: {path}"

    try:
        with path.open("r", encoding="utf-8-sig") as file:
            return json.load(file), None

    except UnicodeDecodeError as exc:
        try:
            with path.open("r", encoding="cp1252") as file:
                data = json.load(file)

            print(
                f"[WARNING] {path.name} decoded using Windows-1252. "
                "Check why the scanner output is not UTF-8."
            )
            return data, None

        except (UnicodeDecodeError, json.JSONDecodeError) as fallback_exc:
            return None, (
                f"Could not decode valid JSON from {path}. "
                f"UTF-8 error: {exc}. "
                f"Fallback error: {fallback_exc}"
            )

    except json.JSONDecodeError as exc:
        return None, (
            f"Invalid JSON in {path} at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        )

    except OSError as exc:
        return None, f"Could not read {path}: {exc}"


def text_value(value, default=""):
    """Convert values safely to strings."""
    if value is None:
        return default
    return str(value)


def add_finding(
    scanner,
    finding_id,
    title,
    severity,
    path="",
    line=None,
    message="",
    remediation="",
    source="",
    cve=None,
    package=None,
    installed_version=None,
    fixed_version=None,
    confidence=None,
):
    """Append one finding using the shared project schema."""
    findings.append({
        "scanner": scanner,
        "finding_id": text_value(finding_id, "UNKNOWN"),
        "title": text_value(title, "Untitled finding"),
        "severity": text_value(severity, "UNKNOWN").upper(),
        "path": text_value(path),
        "line": line,
        "message": text_value(message),
        "remediation": text_value(remediation),
        "source": text_value(source),
        "cve": text_value(cve) if cve else None,
        "package": text_value(package) if package else None,
        "installed_version": (
            text_value(installed_version) if installed_version else None
        ),
        "fixed_version": text_value(fixed_version) if fixed_version else None,
        "confidence": text_value(confidence) if confidence else None,
    })


def normalize_trivy():
    """Normalize Trivy vulnerabilities, misconfigurations, secrets and licenses."""
    data, error = read_json(TRIVY_FILE)

    if error:
        source_status["trivy"] = {
            "status": "missing_or_invalid",
            "error": error,
        }
        errors.append(error)
        return

    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
        error = "Trivy JSON does not contain a valid Results array."
        source_status["trivy"] = {"status": "invalid", "error": error}
        errors.append(error)
        return

    workflow = data.get("WorkflowMetadata") or {}
    workflow_status = workflow.get("status", "unknown")
    workflow_errors = workflow.get("errors", [])

    if workflow_status != "complete" or workflow_errors:
        errors.append("Trivy workflow is incomplete or reports scan errors.")

    count_before = len(findings)

    for result in data.get("Results", []):
        if not isinstance(result, dict):
            continue

        target = result.get("Target", "")
        source = result.get("_ScanSource", target or "filesystem")

        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
            package = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            title = vuln.get("Title") or f"{vuln_id} in {package}"

            add_finding(
                scanner="Trivy",
                finding_id=vuln_id,
                title=title,
                severity=vuln.get("Severity", "UNKNOWN"),
                path=target,
                message=vuln.get("Description", ""),
                remediation=(
                    f"Upgrade {package} from {installed} to {fixed}."
                    if package and fixed
                    else "Review the advisory and identify a supported fix."
                ),
                source=source,
                cve=vuln_id if vuln_id.startswith("CVE-") else None,
                package=package,
                installed_version=installed,
                fixed_version=fixed or None,
                confidence=vuln.get("PrimaryURL"),
            )

        for misconfig in result.get("Misconfigurations") or []:
            add_finding(
                scanner="Trivy",
                finding_id=misconfig.get("ID", "UNKNOWN"),
                title=misconfig.get("Title", "Configuration issue"),
                severity=misconfig.get("Severity", "UNKNOWN"),
                path=misconfig.get("FilePath") or target,
                line=(misconfig.get("CauseMetadata") or {}).get("StartLine"),
                message=misconfig.get("Message", ""),
                remediation=misconfig.get("Resolution", ""),
                source=source,
            )

        for secret in result.get("Secrets") or []:
            # Never include the detected secret value or matched text.
            add_finding(
                scanner="Trivy",
                finding_id=secret.get("RuleID", "UNKNOWN"),
                title=secret.get("Title", "Potential secret detected"),
                severity=secret.get("Severity", "UNKNOWN"),
                path=secret.get("Target") or target,
                line=secret.get("StartLine"),
                message="Potential secret detected. Value omitted from this report.",
                remediation=secret.get(
                    "Resolution",
                    "Rotate the credential if valid and remove it from source.",
                ),
                source=source,
            )

        for license_finding in result.get("Licenses") or []:
            add_finding(
                scanner="Trivy",
                finding_id=license_finding.get("Name", "LICENSE"),
                title=license_finding.get("Name", "License finding"),
                severity=license_finding.get("Severity", "UNKNOWN"),
                path=target,
                message=license_finding.get("Category", ""),
                remediation=(
                    "Review the license against your organization's policy."
                ),
                source=source,
            )

    source_status["trivy"] = {
        "status": workflow_status,
        "finding_count": len(findings) - count_before,
        "scan_count": len(workflow.get("scans", [])),
        "errors": workflow_errors,
    }


def normalize_gitleaks_json():
    """Normalize Gitleaks JSON without exposing secret values."""
    data, error = read_json(GITLEAKS_FILE)

    if error:
        source_status["gitleaks"] = {
            "status": "missing_or_invalid",
            "error": error,
        }
        errors.append(error)
        return

    if not isinstance(data, list):
        error = "Gitleaks JSON must be an array."
        source_status["gitleaks"] = {"status": "invalid", "error": error}
        errors.append(error)
        return

    count_before = len(findings)

    for item in data:
        if not isinstance(item, dict):
            continue

        # Never copy Secret, Match, or other credential-bearing fields.
        add_finding(
            scanner="Gitleaks",
            finding_id=item.get("RuleID", "UNKNOWN"),
            title=item.get("Description") or item.get(
                "RuleID", "Potential secret"
            ),
            severity=item.get("Severity", "UNKNOWN"),
            path=item.get("File", ""),
            line=item.get("StartLine"),
            message="Potential secret detected. Secret contents omitted.",
            remediation=(
                "Validate securely, revoke or rotate if real, then remove "
                "it from files and Git history."
            ),
            source=item.get("_ScanSource", "gitleaks"),
            confidence=item.get("Fingerprint"),
        )

    source_status["gitleaks"] = {
        "status": "loaded",
        "finding_count": len(findings) - count_before,
    }


def normalize_gitleaks_sarif():
    """Normalize Gitleaks SARIF when its JSON report is unavailable."""
    data, error = read_json(GITLEAKS_SARIF_FILE)

    if error:
        message = "Gitleaks JSON and SARIF reports are both unavailable."
        source_status["gitleaks"] = {
            "status": "missing",
            "error": message,
        }
        errors.append(message)
        return

    runs = data.get("runs", []) if isinstance(data, dict) else []

    if not runs:
        error = "Gitleaks SARIF has no runs."
        source_status["gitleaks"] = {"status": "invalid", "error": error}
        errors.append(error)
        return

    count_before = len(findings)

    for run in runs:
        driver = run.get("tool", {}).get("driver", {})
        rules = {
            rule.get("id"): rule
            for rule in driver.get("rules", [])
        }

        for item in run.get("results", []):
            rule_id = item.get("ruleId", "UNKNOWN")
            rule = rules.get(rule_id, {})
            locations = item.get("locations") or []

            physical = (
                locations[0].get("physicalLocation", {})
                if locations
                else {}
            )
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})

            short_description = rule.get("shortDescription") or {}

            add_finding(
                scanner="Gitleaks",
                finding_id=rule_id,
                title=short_description.get("text", rule_id),
                severity="UNKNOWN",
                path=artifact.get("uri", ""),
                line=region.get("startLine"),
                message="Potential secret detected. Secret contents omitted.",
                remediation=(
                    "Validate securely, revoke or rotate if real, then "
                    "remove it from files and Git history."
                ),
                source="gitleaks-sarif",
            )

    source_status["gitleaks"] = {
        "status": "loaded_from_sarif",
        "finding_count": len(findings) - count_before,
    }


# ------------------------------------------------------------
# Run normalization
# ------------------------------------------------------------

normalize_trivy()

# Prefer Gitleaks JSON. Use SARIF only when the JSON file is absent.
if GITLEAKS_FILE.exists():
    normalize_gitleaks_json()
else:
    normalize_gitleaks_sarif()


# ------------------------------------------------------------
# Build summaries
# ------------------------------------------------------------

severity_summary = {}
scanner_summary = {}

for finding in findings:
    severity = finding["severity"]
    scanner = finding["scanner"]

    severity_summary[severity] = severity_summary.get(severity, 0) + 1
    scanner_summary[scanner] = scanner_summary.get(scanner, 0) + 1


overall_status = (
    "incomplete"
    if errors or any(
        item.get("status") in {
            "missing_or_invalid",
            "invalid",
            "missing",
        }
        for item in source_status.values()
    )
    else "inputs_loaded_coverage_unverified"
)

output = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "status": overall_status,
    "finding_count": len(findings),
    "scanner_summary": scanner_summary,
    "severity_summary": severity_summary,
    "source_status": source_status,
    "errors": errors,
    "findings": findings,
}

# JSON is generated first and retained as the machine-readable output.
with OUTPUT_JSON.open("w", encoding="utf-8") as file:
    json.dump(output, file, indent=2)

print(f"[NORMALIZER] JSON saved: {OUTPUT_JSON}")
print(f"[NORMALIZER] Findings: {len(findings)}")
print(f"[NORMALIZER] Status: {overall_status}")


# ------------------------------------------------------------
# Generate human-readable PDF report
# ------------------------------------------------------------

styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name="ReportTitle",
    parent=styles["Title"],
    alignment=TA_CENTER,
    fontSize=18,
    leading=22,
    spaceAfter=10,
))

styles.add(ParagraphStyle(
    name="FindingHeading",
    parent=styles["Heading3"],
    fontSize=10,
    leading=13,
    spaceBefore=8,
    spaceAfter=4,
))

styles.add(ParagraphStyle(
    name="SmallText",
    parent=styles["BodyText"],
    fontSize=8,
    leading=10,
    wordWrap="CJK",
))

document = SimpleDocTemplate(
    str(OUTPUT_PDF),
    pagesize=A4,
    rightMargin=15 * mm,
    leftMargin=15 * mm,
    topMargin=15 * mm,
    bottomMargin=15 * mm,
)

story = [
    Paragraph("Unified Security Findings Report", styles["ReportTitle"]),
    Paragraph(
        f"Generated: {escape(output['generated_at'])}",
        styles["BodyText"],
    ),
    Spacer(1, 5 * mm),
    Paragraph(
        f"Report status: <b>{escape(overall_status)}</b>",
        styles["BodyText"],
    ),
    Paragraph(
        f"Total normalized findings: <b>{len(findings)}</b>",
        styles["BodyText"],
    ),
    Spacer(1, 4 * mm),
    Paragraph("Scanner Summary", styles["Heading2"]),
]

summary_rows = [["Scanner", "Finding count"]]

for scanner, count in sorted(scanner_summary.items()):
    summary_rows.append([scanner, str(count)])

if len(summary_rows) == 1:
    summary_rows.append(["No findings loaded", "0"])

summary_table = Table(summary_rows, colWidths=[90 * mm, 55 * mm])
summary_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("PADDING", (0, 0), (-1, -1), 5),
]))

story.extend([summary_table, Spacer(1, 4 * mm)])

story.append(Paragraph("Severity Summary", styles["Heading2"]))

severity_rows = [["Severity", "Finding count"]]

for severity, count in sorted(severity_summary.items()):
    severity_rows.append([severity, str(count)])

if len(severity_rows) == 1:
    severity_rows.append(["No findings loaded", "0"])

severity_table = Table(severity_rows, colWidths=[90 * mm, 55 * mm])
severity_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("PADDING", (0, 0), (-1, -1), 5),
]))

story.extend([severity_table, Spacer(1, 4 * mm)])

story.append(Paragraph("Input Status", styles["Heading2"]))

for scanner, info in source_status.items():
    story.append(Paragraph(
        f"<b>{escape(scanner)}</b>: "
        f"{escape(text_value(info.get('status')))}",
        styles["SmallText"],
    ))

    if info.get("error"):
        story.append(Paragraph(
            f"Error: {escape(text_value(info['error']))}",
            styles["SmallText"],
        ))

if errors:
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Warnings and Errors", styles["Heading2"]))

    for error in errors:
        story.append(Paragraph(
            f"• {escape(error)}",
            styles["SmallText"],
        ))

story.append(PageBreak())
story.append(Paragraph("Finding Details", styles["Heading2"]))

if not findings:
    story.append(Paragraph(
        "No findings were loaded. This does not prove the project is clean. "
        "Check scan status, input files and scanner coverage.",
        styles["BodyText"],
    ))

for index, finding in enumerate(findings, start=1):
    story.append(Paragraph(
        f"{index}. {escape(finding['title'])}",
        styles["FindingHeading"],
    ))

    fields = [
        ("Scanner", finding["scanner"]),
        ("Finding ID", finding["finding_id"]),
        ("Severity", finding["severity"]),
        ("Location", finding["path"] or "Not provided"),
        ("Line", text_value(finding["line"], "Not provided")),
        ("Source", finding["source"] or "Not provided"),
        ("CVE", finding["cve"] or "Not provided"),
        ("Package", finding["package"] or "Not provided"),
        (
            "Installed version",
            finding["installed_version"] or "Not provided",
        ),
        ("Fixed version", finding["fixed_version"] or "Not provided"),
        ("Message", finding["message"] or "Not provided"),
        (
            "Remediation",
            finding["remediation"] or "Review the scanner guidance.",
        ),
    ]

    for label, value in fields:
        story.append(Paragraph(
            f"<b>{escape(label)}:</b> "
            f"{escape(text_value(value))}",
            styles["SmallText"],
        ))

    story.append(Spacer(1, 3 * mm))

document.build(story)

print(f"[NORMALIZER] PDF report saved: {OUTPUT_PDF}")

if overall_status == "incomplete":
    print(
        "[NORMALIZER] WARNING: One or more inputs or scans are incomplete."
    )
