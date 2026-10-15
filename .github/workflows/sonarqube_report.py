import os
from pathlib import Path

import requests
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

SONAR_URL = "https://sonarcloud.io"
PROJECT_KEY = os.environ["SONAR_PROJECT_KEY"]
TOKEN = os.environ["SONAR_TOKEN"]

output = Path("reports/sonarqube-report.pdf")
output.parent.mkdir(parents=True, exist_ok=True)

response = requests.get(
    f"{SONAR_URL}/api/issues/search",
    params={
        "componentKeys": PROJECT_KEY,
        "types": "VULNERABILITY",
        "ps": 100,
    },
    auth=(TOKEN, ""),
    timeout=30,
)
response.raise_for_status()

issues = response.json().get("issues", [])

styles = getSampleStyleSheet()
story = [
    Paragraph("SonarQube Cloud Security Report", styles["Title"]),
    Spacer(1, 12),
    Paragraph(f"Project: {PROJECT_KEY}", styles["Normal"]),
    Paragraph(f"Vulnerability findings returned: {len(issues)}", styles["Normal"]),
    Spacer(1, 12),
]

for issue in issues:
    severity = issue.get("severity", "UNKNOWN")
    message = issue.get("message", "No description")
    component = issue.get("component", "Unknown file")
    line = issue.get("line", "N/A")

    story.append(
        Paragraph(
            f"<b>{severity}</b> — {component}:{line}<br/>{message}",
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 8))

if not issues:
    story.append(
        Paragraph("No vulnerability issues returned by the API.", styles["BodyText"])
    )

SimpleDocTemplate(str(output), pagesize=A4).build(story)
print(f"Created PDF: {output}")