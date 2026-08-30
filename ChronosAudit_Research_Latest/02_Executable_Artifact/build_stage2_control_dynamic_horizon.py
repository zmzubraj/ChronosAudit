from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_dynamic_horizon import (
    assign_dynamic_horizons,
    fit_dynamic_horizon_model,
    validate_cutoff_safe_pair_features,
    validate_reference_latency_cohort,
    verify_final_pair_feature_binding,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build non-authorizing DYNAMIC_HORIZON_V1 artifacts.")
    parser.add_argument("--reference-cohort", type=Path, required=True)
    parser.add_argument("--pair-features", type=Path, required=True)
    parser.add_argument("--pair-feature-manifest", type=Path, required=True)
    parser.add_argument("--design-spec", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    reference_source = args.reference_cohort.expanduser().resolve(strict=True)
    pair_source = args.pair_features.expanduser().resolve(strict=True)
    pair_manifest_source = args.pair_feature_manifest.expanduser().resolve(strict=True)
    design_source = args.design_spec.expanduser().resolve(strict=True)
    output = args.output_dir.expanduser().resolve(strict=False)
    if output.exists():
        raise ValueError("dynamic horizon output directory already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        pair_binding = verify_final_pair_feature_binding(
            pair_features_path=pair_source,
            pair_feature_manifest_path=pair_manifest_source,
        )
        pair_feature_manifest = json.loads(
            pair_manifest_source.read_text(encoding="utf-8")
        )
        reference, reference_report = validate_reference_latency_cohort(
            pd.read_csv(reference_source, keep_default_na=False, low_memory=False)
        )
        identities = set(zip(reference["chain"], reference["contract_address"], strict=True))
        pairs, feature_report = validate_cutoff_safe_pair_features(
            pd.read_csv(pair_source, keep_default_na=False, low_memory=False),
            reference_identities=identities,
        )
        model = fit_dynamic_horizon_model(reference)
        assignments, assignment_report = assign_dynamic_horizons(pairs, model)
        spec = {
            "schema_version": "chronosaudit.control_dynamic_horizon_spec.v1",
            "status": "IMPLEMENTED_AWAITING_SIGNED_USER_APPROVAL",
            "method": "DYNAMIC_HORIZON_V1",
            "design_spec_sha256": _sha256_file(design_source),
            "pair_feature_manifest_sha256": pair_binding[
                "pair_feature_manifest_sha256"
            ],
            "quantile_probability": 0.95,
            "minimum_stratum_rows": 30,
            "minimum_stratum_events": 20,
            "bootstrap_replicates": 1000,
            "bootstrap_minimum_usable_replicates": 900,
            "hierarchy": ["EXACT", "ARCHITECTURE_PROTOCOL", "CHAIN", "GLOBAL"],
            "assignment_rounding": "CEIL_BOUNDED_SECONDS_DIVIDED_BY_86400",
            "outcome_blind": True,
            "selection_authorized": False,
            "qualification_authorized": False,
            "counter_authority": False,
        }
        _write_json(temporary / "dynamic_horizon_spec.json", spec)
        reference.to_csv(temporary / "reference_latency_cohort.csv", index=False)
        reference_report["source_csv_sha256"] = _sha256_file(reference_source)
        reference_report["normalized_csv_sha256"] = _sha256_file(
            temporary / "reference_latency_cohort.csv"
        )
        _write_json(temporary / "reference_cohort_manifest.json", reference_report)
        feature_report["source_csv_sha256"] = _sha256_file(pair_source)
        feature_report["pair_feature_binding"] = pair_binding
        feature_report["pair_feature_manifest"] = pair_feature_manifest
        feature_report["pair_feature_manifest_sha256"] = pair_binding[
            "pair_feature_manifest_sha256"
        ]
        feature_report["pair_feature_upstream_artifacts"] = pair_feature_manifest[
            "upstream_artifacts"
        ]
        feature_report["assignment_report"] = assignment_report
        _write_json(temporary / "cutoff_safe_feature_manifest.json", feature_report)
        _write_json(temporary / "dynamic_horizon_model.json", model)
        assignments.to_csv(temporary / "dynamic_horizon_assignments.csv", index=False)
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print(json.dumps({"decision": "DYNAMIC_HORIZON_ARTIFACTS_BUILT_NON_AUTHORIZING", "output_dir": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
