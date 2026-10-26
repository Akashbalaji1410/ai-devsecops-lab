# scripts/run_trivy_all.py

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "scan-results"
OUTPUT_FILE = RESULTS_DIR / "trivy-results.json"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

combined_results = []
scan_records = []
errors = []


def run_scan(name, source, command):
    """Run one Trivy scan and preserve its JSON output and execution status."""
    print(f"\n[TRIVY] Starting: {name}")

    record = {
        "name": name,
        "source": source,
        "command": command,
        "status": "failed",
        "return_code": None,
        "error": None,
    }

    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )

        record["return_code"] = completed.returncode

        if completed.stderr.strip():
            print(completed.stderr.strip())

        if completed.stdout.strip():
            try:
                result = json.loads(completed.stdout)

                if isinstance(result, dict):
                    for item in result.get("Results", []):
                        item["_ScanSource"] = source
                    combined_results.extend(result.get("Results", []))
                    record["status"] = (
                        "complete" if completed.returncode == 0 else "failed"
                    )
                else:
                    record["error"] = "Trivy output was not a JSON object."
            except json.JSONDecodeError as exc:
                record["error"] = f"Invalid JSON output: {exc}"
        else:
            record["error"] = "Trivy produced no JSON output."

        if completed.returncode != 0:
            record["error"] = record["error"] or (
                f"Trivy exited with code {completed.returncode}."
            )

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        record["error"] = str(exc)

    if record["error"]:
        errors.append({"scan": name, "error": record["error"]})
        print(f"[TRIVY] {name}: {record['error']}")
    else:
        print(f"[TRIVY] {name}: {record['status']}")

    scan_records.append(record)


# 1. Scan source files and dependency manifests for vulnerabilities/secrets.
run_scan(
    name="filesystem",
    source="filesystem",
    command=[
        "trivy", "fs",
        "--scanners", "vuln,secret",
        "--format", "json",
        "--skip-dirs", str(ROOT / ".git"),
        "--skip-dirs", str(ROOT / ".venv"),
        "--skip-dirs", str(RESULTS_DIR),
        str(ROOT),
    ],
)

# 2. Scan Dockerfiles and other supported configuration files for misconfigurations.
run_scan(
    name="configuration",
    source="configuration",
    command=[
        "trivy", "config",
        "--format", "json",
        "--skip-dirs", str(ROOT / ".git"),
        "--skip-dirs", str(ROOT / ".venv"),
        "--skip-dirs", str(RESULTS_DIR),
        str(ROOT),
    ],
)

# 3. Discover locally available Docker images and scan each image.
try:
    docker = subprocess.run(
        ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    if docker.returncode != 0:
        errors.append({
            "scan": "docker-image-discovery",
            "error": docker.stderr.strip() or "Docker image discovery failed.",
        })
        scan_records.append({
            "name": "docker-image-discovery",
            "source": "docker",
            "status": "failed",
            "return_code": docker.returncode,
            "error": docker.stderr.strip() or "Docker image discovery failed.",
        })
    else:
        images = sorted({
            line.strip()
            for line in docker.stdout.splitlines()
            if line.strip() and "<none>" not in line
        })

        if not images:
            message = "No tagged local Docker images found; image scanning was skipped."
            print(f"[TRIVY] {message}")
            errors.append({"scan": "docker-images", "error": message})
            scan_records.append({
                "name": "docker-images",
                "source": "docker",
                "status": "skipped",
                "return_code": None,
                "error": message,
            })
        else:
            for image in images:
                run_scan(
                    name=f"image:{image}",
                    source=f"image:{image}",
                    command=[
                        "trivy", "image",
                        "--scanners", "vuln,secret",
                        "--format", "json",
                        image,
                    ],
                )

except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
    errors.append({"scan": "docker-image-discovery", "error": str(exc)})
    scan_records.append({
        "name": "docker-image-discovery",
        "source": "docker",
        "status": "failed",
        "return_code": None,
        "error": str(exc),
    })

# A nonzero scan exit or skipped image coverage means the overall run is incomplete.
overall_status = (
    "complete"
    if scan_records
    and all(record["status"] == "complete" for record in scan_records)
    and not errors
    else "incomplete"
)

output = {
    "SchemaVersion": 2,
    "CreatedAt": datetime.now(timezone.utc).isoformat(),
    "ArtifactName": str(ROOT),
    "Results": combined_results,
    "WorkflowMetadata": {
        "status": overall_status,
        "scans": scan_records,
        "errors": errors,
    },
}

with OUTPUT_FILE.open("w", encoding="utf-8") as file:
    json.dump(output, file, indent=2)

print(f"\n[TRIVY] Combined JSON saved to: {OUTPUT_FILE}")
print(f"[TRIVY] Workflow status: {overall_status}")
print(f"[TRIVY] Result sections: {len(combined_results)}")

if overall_status != "complete":
    raise SystemExit(1)