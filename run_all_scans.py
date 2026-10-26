
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Main project directory
PROJECT_DIR = Path(__file__).resolve().parent

# Folder containing your four Python scripts
SCRIPTS_DIR = PROJECT_DIR / "scripts"

# Replace these with your actual Python filenames
PYTHON_FILES = [
    "run_gitleaks.py",
    "run_trivy_all.py",
    "normalize_all_findings.py",
]


def run_script(filename):
    script_path = SCRIPTS_DIR / filename

    print("\n" + "=" * 60)
    print(f"Running: {filename}")
    print("=" * 60)

    if not script_path.is_file():
        print(f"ERROR: Script not found: {script_path}")
        return False

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(PROJECT_DIR),
            check=False
        )

        if result.returncode == 0:
            print(f"SUCCESS: {filename}")
            return True

        print(
            f"FAILED: {filename} "
            f"(exit code: {result.returncode})"
        )
        return False

    except OSError as error:
        print(f"ERROR: {error}")
        return False


def main():
    start_time = datetime.now()
    results = {}

    print("AI DevSecOps - Scan Automation")
    print(f"Project: {PROJECT_DIR}")
    print(f"Scripts: {SCRIPTS_DIR}")

    for filename in PYTHON_FILES:
        results[filename] = run_script(filename)

    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)

    for filename, success in results.items():
        print(f"{filename}: {'SUCCESS' if success else 'FAILED'}")

    print(f"\nDuration: {datetime.now() - start_time}")

    if all(results.values()):
        print("All scripts completed successfully.")
    else:
        print("One or more scripts failed. Review the errors above.")


if __name__ == "__main__":
    main()
