#!/usr/bin/env python3
"""Reject empty or incomplete fault-harness evidence before accepting a run."""
import copy
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "bench/run_h3_soak.py"
spec = importlib.util.spec_from_file_location("h3_soak_runner", path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.valid = {
            "pass": True, "requests_started": 12, "requests_passed": 12,
            "rounds": 1, "clean_rounds": 1, "retry_required": True, "retry_replies": 3,
            "clients": 3, "requests_per_client_per_round": 4,
            "slow_overlap_short_started": 9, "slow_overlap_short_completed": 9,
            "final": {"connections": 0, "tombstones": 0, "routes": 0,
                      "reserved_payload_bytes": 0, "queued_bytes": 0},
        }

    def test_nonempty_complete(self):
        self.assertIsNone(runner.validate_summary(self.valid))

    def test_missing_top_level_field(self):
        for field in self.valid:
            with self.subTest(field=field):
                data = copy.deepcopy(self.valid)
                del data[field]
                self.assertIsNotNone(runner.validate_summary(data))

    def test_missing_final_account(self):
        for field in self.valid["final"]:
            with self.subTest(field=field):
                data = copy.deepcopy(self.valid)
                del data["final"][field]
                self.assertIsNotNone(runner.validate_summary(data))

    def test_residual_or_invalid_account(self):
        for field in self.valid["final"]:
            for value in (1, -1, False, "0", None):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.valid)
                    data["final"][field] = value
                    self.assertIsNotNone(runner.validate_summary(data))

    def test_empty_workload_or_unobserved_retry(self):
        for field in ("requests_started", "requests_passed", "rounds", "clean_rounds", "retry_replies"):
            for value in (0, -1, None, "12", False):
                with self.subTest(field=field, value=value):
                    data = copy.deepcopy(self.valid)
                    data[field] = value
                    self.assertIsNotNone(runner.validate_summary(data))

    def test_slow_overlap_minimum_and_limits(self):
        data = copy.deepcopy(self.valid)
        data["slow_overlap_short_completed"] = 3
        self.assertIsNone(runner.validate_summary(data))
        for field, value in (("slow_overlap_short_completed", 2),
                             ("slow_overlap_short_completed", 10),
                             ("slow_overlap_short_completed", False),
                             ("slow_overlap_short_started", 8),
                             ("clients", 0), ("requests_per_client_per_round", 1)):
            with self.subTest(field=field, value=value):
                data = copy.deepcopy(self.valid)
                data[field] = value
                self.assertIsNotNone(runner.validate_summary(data))

    def test_false_success(self):
        for field, value in (("pass", False), ("retry_required", False), ("requests_passed", 11),
                             ("clean_rounds", 2), ("final", {}), ("final", [])):
            with self.subTest(field=field, value=value):
                data = copy.deepcopy(self.valid)
                data[field] = value
                self.assertIsNotNone(runner.validate_summary(data))


if __name__ == "__main__":
    unittest.main()
