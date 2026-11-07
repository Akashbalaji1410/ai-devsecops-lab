
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


SCANNERS = {
    "semgrep-results": "Semgrep",
    "gitleaks-results": "Gitleaks",
    "trivy-results": "Trivy",
    "sonarqube-status": "SonarQube Cloud",
    "python-test-results": "Custom Python Tests"
}


def load_status(directory):
    path = directory / "status.json"

    if not path.exists():
        return {
            "execution_status": "missing",
            "error": "No status artifact found"
        }

    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "execution_status": "invalid",
            "error": str(exc)
        }


def generate_summary(root):
    results = []

    for artifact_name, scanner in SCANNERS.items():
        directory = root / artifact_name
        status = load_status(directory)

        results.append({
            "scanner": scanner,
            "execution_status": status.get(
                "execution_status", "unknown"
            ),
            "artifact_available": directory.exists(),
            "details": status.get("note") or status.get("error")
        })

    return {
        "tool": "ai-devsecops-ci-summary",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanners": results,
        "summary": {
            "total_scanners": len(results),
            "successful": sum(
                item["execution_status"] == "success"
                for item in results
            ),
            "failed": sum(
                item["execution_status"] == "failure"
                for item in results
            ),
            "other": sum(
                item["execution_status"]
                not in ("success", "failure")
                for item in results
            )
        }
    }


def write_markdown(report, output):
    lines = [
        "| Scanner | Execution Status | Artifact |",
        "|---|---|---|"
    ]

    for item in report["scanners"]:
        lines.append(
            f"| {item['scanner']} | "
            f"{item['execution_status']} | "
            f"{'Yes' if item['artifact_available'] else 'No'} |"
        )

    output.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    report = generate_summary(Path(args.input))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    write_markdown(
        report,
        output.with_suffix(".md")
    )

    print(
        json.dumps(report["summary"], indent=2)
    )


if __name__ == "__main__":
    main()
