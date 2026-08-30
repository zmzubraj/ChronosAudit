import csv
import importlib.util
import json
import math
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("derive_mpp_results.py")


def load_module():
    spec = importlib.util.spec_from_file_location("derive_mpp_results", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def case_payload(
    case_id,
    *,
    chain="ethereum",
    address="0x0000000000000000000000000000000000000001",
    lead_hours=24.0,
    runtime_hash="runtime-a",
    stripped_hash="stripped-a",
    implementation=None,
    admin=None,
    beacon=None,
    eip1167_target=None,
):
    def cell(value):
        return {
            "status": "consensus",
            "value": value,
            "observations": [
                {"provider_family": "alchemy", "result": "0x0"},
                {"provider_family": "infura", "result": "0x0"},
            ],
        }

    incident = 1_700_000_000
    cutoff = incident - round(lead_hours * 3600)
    return {
        "case_id": case_id,
        "status": "VERIFIED",
        "strict_snapshot_closed": True,
        "strict_snapshot": {
            "case_id": case_id,
            "chain": chain,
            "address": address,
            "strict_snapshot_closed": True,
            "provider_families": ["alchemy", "infura"],
            "cutoff_lead_hours": lead_hours,
            "deployment_timestamp": cutoff - 86_400,
            "prediction_cutoff_timestamp": cutoff,
            "incident_timestamp": incident,
            "blockers": [],
            "snapshot": {
                "runtime_bytecode_sha256": runtime_hash,
                "metadata_stripped_bytecode_sha256": stripped_hash,
                "metadata_status": "metadata_not_recognized",
                "implementation": cell(implementation),
                "admin": cell(admin),
                "beacon": cell(beacon),
                "beacon_implementation": {
                    "status": "not_applicable",
                    "value": None,
                    "observations": [],
                },
                "eip1167_target": eip1167_target,
            },
        },
    }


class TemporalCloneAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_landmark_eligibility_uses_deployment_age_and_is_inclusive(self):
        eligible = self.module.landmark_eligibility(168.0)
        self.assertEqual(
            eligible,
            {"eligible_1h": True, "eligible_24h": True, "eligible_7d": True, "eligible_30d": False},
        )

    def test_percentile_uses_linear_r7_interpolation(self):
        values = [0.0, 10.0, 20.0, 30.0]
        self.assertEqual(self.module.percentile_linear(values, 0.25), 7.5)
        self.assertEqual(self.module.percentile_linear(values, 0.50), 15.0)
        self.assertAlmostEqual(self.module.percentile_linear(values, 0.90), 27.0)

    def test_wilson_interval_contains_observed_proportion(self):
        low, high = self.module.wilson_interval(2, 3)
        self.assertLess(low, 2 / 3)
        self.assertGreater(high, 2 / 3)
        self.assertTrue(math.isclose(low, 0.2076596008, rel_tol=1e-8))

    def test_end_to_end_outputs_identity_and_proxy_summaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases_dir = root / "cases"
            output_dir = root / "output"
            cases_dir.mkdir()

            payloads = [
                case_payload(
                    "c1",
                    address="0x0000000000000000000000000000000000000001",
                    lead_hours=1,
                    runtime_hash="runtime-shared",
                    stripped_hash="stripped-shared",
                    implementation="0x00000000000000000000000000000000000000aa",
                ),
                case_payload(
                    "c2",
                    address="0x0000000000000000000000000000000000000002",
                    lead_hours=168,
                    runtime_hash="runtime-shared",
                    stripped_hash="stripped-shared",
                    eip1167_target="0x00000000000000000000000000000000000000bb",
                ),
                case_payload(
                    "c3",
                    chain="bsc",
                    address="0x0000000000000000000000000000000000000002",
                    lead_hours=720,
                    runtime_hash="runtime-unique",
                    stripped_hash="stripped-shared",
                ),
            ]
            for payload in payloads:
                (cases_dir / f"{payload['case_id']}.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )

            summary = self.module.run_analysis(cases_dir, output_dir, expected_count=3)

            self.assertEqual(summary["cohort"]["n_cases"], 3)
            self.assertEqual(summary["temporal_eligibility"]["eligible_1h"]["n"], 3)
            self.assertEqual(summary["temporal_eligibility"]["eligible_24h"]["n"], 3)
            self.assertEqual(summary["temporal_eligibility"]["eligible_7d"]["n"], 2)
            self.assertEqual(summary["temporal_eligibility"]["eligible_30d"]["n"], 1)
            self.assertEqual(summary["identity_abstractions"]["chain_address"]["duplicate_rows"], 0)
            self.assertEqual(summary["identity_abstractions"]["address_only"]["duplicate_rows"], 2)
            self.assertEqual(summary["identity_abstractions"]["runtime_bytecode"]["duplicate_rows"], 2)
            self.assertEqual(summary["identity_abstractions"]["metadata_stripped_bytecode"]["duplicate_rows"], 3)
            self.assertEqual(summary["proxy_linkage"]["any_proxy_indicator"]["n"], 2)

            with (output_dir / "analysis_cases.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["case_id"] for row in rows], ["c1", "c2", "c3"])
            self.assertTrue((output_dir / "input-manifest.csv").exists())
            self.assertTrue((output_dir / "identity-groups.csv").exists())
            self.assertTrue((output_dir / "results-summary.json").exists())

    def test_invalid_provider_set_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases_dir = root / "cases"
            cases_dir.mkdir()
            payload = case_payload("c1")
            payload["strict_snapshot"]["provider_families"] = ["alchemy"]
            (cases_dir / "c1.json").write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "provider_families"):
                self.module.run_analysis(cases_dir, root / "output", expected_count=1)


if __name__ == "__main__":
    unittest.main()
