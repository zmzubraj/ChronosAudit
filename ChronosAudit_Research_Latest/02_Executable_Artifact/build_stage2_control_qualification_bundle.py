from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_qualification_bundle import (
    assemble_control_qualification_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a portable, independently reverifiable Stage 2 signed "
            "control-qualification bundle and exact qualified projection."
        )
    )
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--candidate-rows", type=Path, required=True)
    parser.add_argument("--check-rows", type=Path, required=True)
    parser.add_argument("--positive-cases", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--expected-positive-rows", type=int, default=417)
    parser.add_argument("--controls-per-positive", type=int, default=10)
    args = parser.parse_args()

    result = assemble_control_qualification_bundle(
        bundle_root=args.bundle_root,
        candidate_rows_path=args.candidate_rows,
        check_rows_path=args.check_rows,
        positive_cases_path=args.positive_cases,
        evidence_root=args.evidence_root,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
        expected_positive_rows=args.expected_positive_rows,
        controls_per_positive=args.controls_per_positive,
    )
    print(
        json.dumps(
            {
                "decision": "CONTROL_QUALIFICATION_BUNDLE_BUILT",
                "manifest_path": str(result["manifest_path"]),
                "projection_path": str(result["projection_path"]),
                "qualified_rows": result["verification"]["qualified_rows"],
                "counter_authority": True,
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
