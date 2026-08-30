from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_dynamic_horizon import (
    assign_dynamic_horizons,
    validate_cutoff_safe_pair_features,
    validate_reference_latency_cohort,
    verify_dynamic_horizon_artifacts,
    verify_signed_dynamic_horizon_approval,
)

PAIR_COLUMNS = [
    "positive_case_id", "positive_record_sha256", "chain", "control_address",
    "candidate_control_row_sha256", "prediction_cutoff_time_utc", "mechanism_family",
    "protocol_family", "architecture_proxy_pattern", "code_pattern_family",
    "code_size_bytes", "complexity_class", "contract_age_days_at_cutoff",
    "source_verified_at_cutoff", "feature_vector_sha256",
]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify DYNAMIC_HORIZON_V1 artifacts and detached approval signature without granting control authority.")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--design-spec", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    args = parser.parse_args()
    artifact_dir = args.artifact_dir.expanduser().resolve(strict=True)
    output = artifact_dir / "dynamic_horizon_verification.json"
    if output.exists() or output.is_symlink():
        raise ValueError("dynamic horizon verification already exists")
    reference, _ = validate_reference_latency_cohort(
        pd.read_csv(artifact_dir / "reference_latency_cohort.csv", keep_default_na=False, low_memory=False)
    )
    supplied_assignments = pd.read_csv(
        artifact_dir / "dynamic_horizon_assignments.csv", keep_default_na=False, low_memory=False
    )
    pairs, _ = validate_cutoff_safe_pair_features(supplied_assignments[PAIR_COLUMNS])
    model = json.loads((artifact_dir / "dynamic_horizon_model.json").read_text(encoding="utf-8"))
    feature_manifest = json.loads(
        (artifact_dir / "cutoff_safe_feature_manifest.json").read_text(encoding="utf-8")
    )
    embedded_pair_manifest = feature_manifest.get("pair_feature_manifest")
    if not isinstance(embedded_pair_manifest, dict):
        raise ValueError("pair feature manifest binding missing")
    embedded_material = {
        key: value for key, value in embedded_pair_manifest.items()
        if key != "manifest_sha256"
    }
    embedded_internal_hash = hashlib.sha256(
        json.dumps(
            embedded_material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    if embedded_pair_manifest.get("manifest_sha256") != embedded_internal_hash:
        raise ValueError("embedded pair feature manifest self hash invalid")
    _, assignment_report = assign_dynamic_horizons(pairs, model)
    artifact_verification = verify_dynamic_horizon_artifacts(
        reference_frame=reference,
        pair_frame=pairs,
        model=model,
        assignments=supplied_assignments,
        assignment_report=assignment_report,
    )
    approval_verification = verify_signed_dynamic_horizon_approval(
        approval_record_path=artifact_dir / "user_approval_record.json",
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        expected_design_spec_sha256=_sha256_file(args.design_spec.expanduser().resolve(strict=True)),
        expected_dynamic_horizon_spec_sha256=_sha256_file(artifact_dir / "dynamic_horizon_spec.json"),
        expected_reference_cohort_sha256=_sha256_file(artifact_dir / "reference_latency_cohort.csv"),
        expected_model_sha256=str(model["model_sha256"]),
        expected_pair_feature_manifest_sha256=str(
            feature_manifest["pair_feature_manifest_sha256"]
        ),
    )
    report = {
        "schema_version": "chronosaudit.control_dynamic_horizon_gate_verification.v1",
        "decision": "DYNAMIC_HORIZON_GATE_VERIFIED_NON_AUTHORIZING",
        "artifact_verification": artifact_verification,
        "approval_verification": approval_verification,
        "pair_feature_manifest_sha256": feature_manifest[
            "pair_feature_manifest_sha256"
        ],
        "pair_feature_manifest_internal_sha256": embedded_internal_hash,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "source_acquisition_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
