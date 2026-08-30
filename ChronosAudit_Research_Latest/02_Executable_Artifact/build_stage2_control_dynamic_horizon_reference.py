from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_dynamic_horizon import (
    build_reference_latency_cohort_from_verified_snapshots,
    fit_dynamic_horizon_model,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the non-authorizing DYNAMIC_HORIZON_V1 reference-side package."
    )
    parser.add_argument("--positive-projection", type=Path, required=True)
    parser.add_argument("--verified-projection", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    output = args.output_dir.expanduser().resolve(strict=False)
    if output.exists():
        raise ValueError("dynamic horizon reference output directory already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        cohort, cohort_manifest = build_reference_latency_cohort_from_verified_snapshots(
            positive_projection_path=args.positive_projection,
            verified_projection_path=args.verified_projection,
            snapshot_root=args.snapshot_root,
        )
        model = fit_dynamic_horizon_model(cohort)
        cohort_path = temporary / "reference_latency_cohort.csv"
        cohort.to_csv(cohort_path, index=False)
        cohort_manifest["normalized_csv_sha256"] = _sha256_file(cohort_path)
        _write_json(temporary / "reference_cohort_manifest.json", cohort_manifest)
        _write_json(temporary / "dynamic_horizon_model.json", model)

        artifact_names = (
            "reference_latency_cohort.csv",
            "reference_cohort_manifest.json",
            "dynamic_horizon_model.json",
        )
        package_manifest = {
            "schema_version": "chronosaudit.control_dynamic_horizon_reference_package.v1",
            "decision": "DYNAMIC_HORIZON_REFERENCE_PACKAGE_VERIFIED_NON_AUTHORIZING",
            "method": "DYNAMIC_HORIZON_V1",
            "deduplication_policy": cohort_manifest["deduplication_policy"],
            "reference_row_count": len(cohort),
            "event_observed_count": int(cohort["event_observed"].sum()),
            "model_sha256": model["model_sha256"],
            "artifact_sha256": {
                name: _sha256_file(temporary / name) for name in artifact_names
            },
            "local_test_signing_eligible": True,
            "selection_authorized": False,
            "qualification_authorized": False,
            "counter_authority": False,
        }
        _write_json(temporary / "reference_package_manifest.json", package_manifest)
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    print(
        json.dumps(
            {
                "decision": "DYNAMIC_HORIZON_REFERENCE_PACKAGE_VERIFIED_NON_AUTHORIZING",
                "output_dir": str(output),
                "reference_row_count": len(cohort),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
