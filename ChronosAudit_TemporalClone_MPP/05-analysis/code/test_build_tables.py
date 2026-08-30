import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_tables.py")


def load_module():
    spec = importlib.util.spec_from_file_location("build_tables", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PublicationTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_builds_primary_table_from_summary_without_manual_numbers(self):
        summary = {
            "cohort": {"n_cases": 10, "chains": {"ethereum": 6, "bsc": 4}},
            "temporal_eligibility": {
                "eligible_1h": {"n": 10, "denominator": 10, "proportion": 1.0, "wilson_95_low": 0.72, "wilson_95_high": 1.0},
                "eligible_24h": {"n": 9, "denominator": 10, "proportion": 0.9, "wilson_95_low": 0.60, "wilson_95_high": 0.98},
                "eligible_7d": {"n": 8, "denominator": 10, "proportion": 0.8, "wilson_95_low": 0.49, "wilson_95_high": 0.94},
                "eligible_30d": {"n": 7, "denominator": 10, "proportion": 0.7, "wilson_95_low": 0.40, "wilson_95_high": 0.89},
            },
            "identity_abstractions": {
                "chain_address": {"unique_identities": 10, "duplicate_groups": 0, "duplicate_rows": 0, "maximum_group_size": 1, "cross_address_duplicate_groups": 0, "cross_address_duplicate_rows": 0, "cross_chain_duplicate_groups": 0, "cross_chain_duplicate_rows": 0},
                "address_only": {"unique_identities": 10, "duplicate_groups": 0, "duplicate_rows": 0, "maximum_group_size": 1, "cross_address_duplicate_groups": 0, "cross_address_duplicate_rows": 0, "cross_chain_duplicate_groups": 0, "cross_chain_duplicate_rows": 0},
                "runtime_bytecode": {"unique_identities": 8, "duplicate_groups": 2, "duplicate_rows": 4, "maximum_group_size": 2, "cross_address_duplicate_groups": 2, "cross_address_duplicate_rows": 4, "cross_chain_duplicate_groups": 1, "cross_chain_duplicate_rows": 2},
                "metadata_stripped_bytecode": {"unique_identities": 7, "duplicate_groups": 2, "duplicate_rows": 5, "maximum_group_size": 3, "cross_address_duplicate_groups": 2, "cross_address_duplicate_rows": 5, "cross_chain_duplicate_groups": 1, "cross_chain_duplicate_rows": 3},
            },
            "proxy_linkage": {
                "implementation_slot": {"n": 2, "denominator": 10, "proportion": 0.2, "wilson_95_low": 0.06, "wilson_95_high": 0.51},
                "admin_slot": {"n": 1, "denominator": 10, "proportion": 0.1, "wilson_95_low": 0.02, "wilson_95_high": 0.40},
                "beacon_slot": {"n": 0, "denominator": 10, "proportion": 0.0, "wilson_95_low": 0.0, "wilson_95_high": 0.28},
                "eip1167_target": {"n": 1, "denominator": 10, "proportion": 0.1, "wilson_95_low": 0.02, "wilson_95_high": 0.40},
                "any_proxy_indicator": {"n": 3, "denominator": 10, "proportion": 0.3, "wilson_95_low": 0.11, "wilson_95_high": 0.60},
            },
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary_path = root / "summary.json"
            output_dir = root / "tables"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            results_dir = root / "results"
            self.module.build_tables(summary_path, output_dir, results_dir=results_dir)

            with (output_dir / "t4-primary-results.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            eligible_24h = next(row for row in rows if row["metric"] == "eligible_24h")
            self.assertEqual(eligible_24h["n"], "9")
            self.assertEqual(eligible_24h["percent"], "90.0")
            self.assertTrue((output_dir / "t1-strongest-prior-art.csv").exists())
            self.assertTrue((output_dir / "t8-negative-findings.csv").exists())
            self.assertTrue((results_dir / "primary-results.csv").exists())
            self.assertTrue((results_dir / "robustness-and-boundaries.csv").exists())
            with (results_dir / "primary-results.csv").open(newline="", encoding="utf-8") as handle:
                canonical = list(csv.DictReader(handle))
            eligible_24h_canonical = next(row for row in canonical if row["estimand"] == "eligible_24h_percent")
            self.assertEqual(eligible_24h_canonical["claim_id"], "C004")
            self.assertEqual(eligible_24h_canonical["effect_estimate"], "90.0")


if __name__ == "__main__":
    unittest.main()
