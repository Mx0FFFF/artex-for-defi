import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from evaluate import score  # noqa: E402


class EvaluateTests(unittest.TestCase):
    def test_case_outcomes_keep_unfinished_work_separate_from_completed_controls(self):
        case_ids = ["clear", "flagged", "partial", "stopped", "legacy", "absent", "unspecified"]
        cases = [
            {"case_id": cid, "split": "sealed_test", "protocol_family": "sample", "expected_root_causes": []}
            for cid in case_ids
        ]
        case_runs = [
            {"case_id": "clear", "status": "completed"},
            {"case_id": "flagged", "status": "completed"},
            {"case_id": "partial", "status": "incomplete"},
            {"case_id": "stopped", "status": "blocked"},
            {"case_id": "unspecified"},
        ]
        predictions = [
            {"case_id": "flagged", "finding_id": "a", "status": "confirmed"},
            {"case_id": "partial", "finding_id": "b", "status": "confirmed"},
            {"case_id": "legacy", "finding_id": "c", "status": "blocked"},
        ]
        metrics = score(cases, predictions, case_runs)["metrics"]
        result = metrics["sealed_test"]
        self.assertEqual(result["clean_cases_in_manifest"], 7)
        self.assertEqual(result["clean_case_false_positive_rate"], 2 / 7)
        self.assertEqual(result["case_runs"], {
            "by_status": {"completed": 2, "incomplete": 1, "blocked": 1, "unknown": 2, "missing": 1},
            "completion_rate": 2 / 7,
            "completed_clean_cases": 2,
            "completed_clean_cases_with_false_positive": 1,
            "completed_clean_case_false_positive_rate": 0.5,
        })
        self.assertIsNone(metrics["development"]["case_runs"]["completion_rate"])
        self.assertIsNone(metrics["development"]["case_runs"]["completed_clean_case_false_positive_rate"])

    def test_legacy_report_does_not_establish_completion(self):
        case = {"case_id": "sample", "split": "sealed_test", "protocol_family": "sample", "expected_root_causes": []}
        for predictions, expected_status in [
            ([{"case_id": "sample", "finding_id": "f", "status": "confirmed"}], "unknown"),
            ([], "missing"),
        ]:
            with self.subTest(status=expected_status):
                runs = score([case], predictions)["metrics"]["sealed_test"]["case_runs"]
                self.assertEqual(runs["by_status"][expected_status], 1)
                self.assertEqual(runs["completion_rate"], 0.0)
                self.assertIsNone(runs["completed_clean_case_false_positive_rate"])

    def test_invalid_case_run_records_are_rejected(self):
        case = {"case_id": "sample", "split": "sealed_test", "protocol_family": "sample", "expected_root_causes": []}
        for runs in (
            None, ["sample"], [{"case_id": "other"}], [{"case_id": "sample", "status": "typo"}],
            [{"case_id": "sample", "status": None}], [{"case_id": "sample"}, {"case_id": "sample"}],
        ):
            with self.subTest(runs=runs), self.assertRaises(ValueError):
                score([case], [], runs)

    def test_positive_and_safe_controls_penalize_duplicate_and_false_report(self):
        cases = [
            {"case_id": "vuln", "split": "development", "protocol_family": "vault-v1", "expected_root_causes": ["donation"]},
            {"case_id": "patched", "split": "development", "protocol_family": "vault-v1", "expected_root_causes": []},
        ]
        predictions = [
            {"case_id": "vuln", "finding_id": "f1", "status": "confirmed", "adjudicated_root_cause_id": "donation"},
            {"case_id": "vuln", "finding_id": "f2", "status": "confirmed", "adjudicated_root_cause_id": "donation"},
            {"case_id": "patched", "finding_id": "f3", "status": "confirmed", "adjudicated_root_cause_id": None},
            {"case_id": "patched", "finding_id": "h1", "status": "hypothesis", "adjudicated_root_cause_id": None},
        ]
        result = score(cases, predictions)["metrics"]["development"]
        self.assertEqual(result["true_positive_findings"], 1)
        self.assertEqual(result["false_positive_findings"], 2)
        self.assertEqual(result["duplicate_reported_findings"], 1)
        self.assertEqual(result["precision"], 1 / 3)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["clean_case_false_positive_rate"], 1.0)

    def test_empty_denominators_are_undefined_and_family_leakage_rejected(self):
        clean = [{"case_id": "clean", "split": "sealed_test", "protocol_family": "amm", "expected_root_causes": []}]
        result = score(clean, [])["metrics"]["sealed_test"]
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])
        self.assertEqual(result["clean_case_false_positive_rate"], 0.0)
        leaked = clean + [{"case_id": "other", "split": "development", "protocol_family": "amm", "expected_root_causes": ["rounding"]}]
        with self.assertRaisesRegex(ValueError, "leaks across splits"):
            score(leaked, [])
        root_cause_leak = [
            {"case_id": "v1", "split": "development", "protocol_family": "vault-a", "expected_root_causes": ["a"], "leakage_groups": ["donation-family"]},
            {"case_id": "v2", "split": "sealed_test", "protocol_family": "vault-b", "expected_root_causes": ["b"], "leakage_groups": ["donation-family"]},
        ]
        with self.assertRaisesRegex(ValueError, "exploit/root-cause family"):
            score(root_cause_leak, [])

    def test_nonfinite_cost_or_duration_is_rejected(self):
        cases = [{"case_id": "c", "split": "development", "protocol_family": "p", "expected_root_causes": ["r"]}]
        for invalid in (float("nan"), float("inf"), float("-inf")):
            prediction = {"case_id": "c", "finding_id": "f", "status": "confirmed", "cost_usd": invalid}
            with self.assertRaisesRegex(ValueError, "nonnegative"):
                score(cases, [prediction])


if __name__ == "__main__":
    unittest.main()
