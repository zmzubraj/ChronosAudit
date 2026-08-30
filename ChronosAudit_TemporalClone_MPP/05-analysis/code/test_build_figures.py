import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_figures.py")


def load_module():
    spec = importlib.util.spec_from_file_location("build_figures", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FigureBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_writes_three_self_contained_vector_figures(self):
        summary = {
            "cohort": {"n_cases": 2},
            "temporal_eligibility": {
                key: {"n": n, "denominator": 2, "proportion": n / 2, "wilson_95_low": 0.1, "wilson_95_high": 0.9 if n < 2 else 1.0}
                for key, n in (("eligible_1h", 2), ("eligible_24h", 2), ("eligible_7d", 1), ("eligible_30d", 1))
            },
            "identity_abstractions": {
                key: {"duplicate_rows": duplicate, "unique_identities": unique}
                for key, duplicate, unique in (
                    ("chain_address", 0, 2),
                    ("address_only", 0, 2),
                    ("runtime_bytecode", 2, 1),
                    ("metadata_stripped_bytecode", 2, 1),
                )
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary_path = root / "summary.json"
            cases_path = root / "cases.csv"
            output_dir = root / "figures"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            with cases_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["deployment_to_incident_hours"])
                writer.writeheader()
                writer.writerows([{"deployment_to_incident_hours": 25}, {"deployment_to_incident_hours": 800}])

            self.module.build_figures(summary_path, cases_path, output_dir)

            paths = sorted(output_dir.glob("*.svg"))
            self.assertEqual(len(paths), 3)
            self.assertIn("<svg", paths[0].read_text(encoding="utf-8"))
            self.assertIn('fill="white"', paths[0].read_text(encoding="utf-8"))
            self.assertIn("30 days", (output_dir / "figure1-temporal-eligibility.svg").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
