from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_dynamic_horizon import (
    build_dynamic_horizon_approval_record,
    canonical_dynamic_horizon_signed_payload,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the canonical DYNAMIC_HORIZON_V1 author-approval payload.")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--design-spec", type=Path, required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--approved-at-utc", required=True)
    args = parser.parse_args()
    artifact_dir = args.artifact_dir.expanduser().resolve(strict=True)
    design = args.design_spec.expanduser().resolve(strict=True)
    output = artifact_dir / "user_approval_record.json"
    if output.exists() or output.is_symlink():
        raise ValueError("user approval record already exists")
    model_path = artifact_dir / "dynamic_horizon_model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    feature_manifest = json.loads(
        (artifact_dir / "cutoff_safe_feature_manifest.json").read_text(encoding="utf-8")
    )
    record = build_dynamic_horizon_approval_record(
        principal=args.principal,
        approved_at_utc=args.approved_at_utc,
        design_spec_sha256=_sha256_file(design),
        dynamic_horizon_spec_sha256=_sha256_file(artifact_dir / "dynamic_horizon_spec.json"),
        reference_cohort_sha256=_sha256_file(artifact_dir / "reference_latency_cohort.csv"),
        model_sha256=str(model["model_sha256"]),
        pair_feature_manifest_sha256=str(
            feature_manifest["pair_feature_manifest_sha256"]
        ),
    )
    output.write_bytes(canonical_dynamic_horizon_signed_payload(record))
    print(json.dumps({"decision": "DYNAMIC_HORIZON_APPROVAL_PAYLOAD_BUILT_AWAITING_OFFLINE_SIGNATURE", "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
