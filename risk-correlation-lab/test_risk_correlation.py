
import copy
import json
import unittest
from pathlib import Path

from risk_correlation import (
    analyze,
    calculate_risk,
    correlate,
    normalize
)


BASE = Path(__file__).resolve().parent


def load_fixture():
    with (
        BASE / "data" / "synthetic_findings.json"
    ).open(encoding="utf-8") as file:
        return json.load(file)


class TestRiskCorrelation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = load_fixture()
        cls.report = analyze(cls.data)

    def test_raw_count(self):
        self.assertEqual(
            self.report["summary"]["raw_findings"], 6
        )

    def test_unique_count(self):
        self.assertEqual(
            self.report["summary"]["unique_findings"], 5
        )

    def test_duplicate_count(self):
        self.assertEqual(
            self.report["summary"]["duplicates_removed"], 1
        )

    def test_sources_preserved(self):
        finding = next(
            f for f in self.report["findings"]
            if f["finding_id"] == "CVE-2099-0001"
        )
        self.assertEqual(len(finding["sources"]), 2)

    def test_risk_score(self):
        finding = normalize(self.data["findings"][0])
        score, priority = calculate_risk(finding)

        self.assertEqual(score, 92)
        self.assertEqual(priority, "P1")

    def test_highest_priority_first(self):
        self.assertEqual(
            self.report["findings"][0]["priority"], "P1"
        )

    def test_sorted_descending(self):
        scores = [
            f["risk_score"]
            for f in self.report["findings"]
        ]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_severity_counts(self):
        self.assertEqual(
            self.report["summary"]["severity_counts"],
            {
                "Critical": 3,
                "High": 2,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            }
        )

    def test_reject_non_synthetic(self):
        with self.assertRaises(ValueError):
            analyze({"synthetic_data": False, "findings": []})

    def test_reject_missing_findings(self):
        with self.assertRaises(ValueError):
            analyze({"synthetic_data": True})

    def test_invalid_cvss(self):
        bad = copy.deepcopy(self.data["findings"][0])
        bad["cvss"] = 11

        with self.assertRaises(ValueError):
            normalize(bad)

    def test_invalid_exposure(self):
        bad = copy.deepcopy(self.data["findings"][0])
        bad["exposure"] = "unknown"

        with self.assertRaises(ValueError):
            normalize(bad)

    def test_same_id_different_resources(self):
        first = copy.deepcopy(self.data["findings"][0])
        second = copy.deepcopy(first)
        second["resource"] = "another-app/requirements.txt"

        self.assertEqual(
            len(correlate([first, second])), 2
        )

    def test_conflicting_severity(self):
        first = copy.deepcopy(self.data["findings"][0])
        second = copy.deepcopy(first)
        second["severity"] = "Critical"

        merged = correlate([first, second])
        self.assertEqual(merged[0]["severity"], "Critical")

    def test_empty_findings(self):
        report = analyze({
            "synthetic_data": True,
            "findings": []
        })
        self.assertEqual(
            report["summary"]["unique_findings"], 0
        )


if __name__ == "__main__":
    unittest.main()

