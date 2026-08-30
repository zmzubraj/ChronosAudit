from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_denominator_expansion_admission import (
    build_denominator_expansion_admission_projection,
)


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, path)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a non-authorizing denominator expansion admission projection.")
    parser.add_argument("--specification", type=Path, required=True)
    parser.add_argument("--implementation-approval", type=Path, required=True)
    parser.add_argument("--authority-bridge-manifest", type=Path, required=True)
    parser.add_argument("--reserve-queue", type=Path, required=True)
    parser.add_argument("--reserve-queue-manifest", type=Path, required=True)
    parser.add_argument("--source-import-verification", type=Path, required=True)
    parser.add_argument("--effective-source", type=Path, nargs=2, action="append", required=True, metavar=("MANIFEST", "COMPLETE_CSV"))
    parser.add_argument("--trace-deployment-projection", type=Path)
    parser.add_argument("--capacity-audit", type=Path, required=True)
    parser.add_argument("--outcome-blind-attestation", type=Path, required=True)
    parser.add_argument("--expected-case-count", type=int, default=417)
    parser.add_argument("--controls-per-positive", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    projection = build_denominator_expansion_admission_projection(
        specification_path=args.specification,
        implementation_approval_path=args.implementation_approval,
        authority_bridge_manifest_path=args.authority_bridge_manifest,
        reserve_queue_path=args.reserve_queue,
        reserve_queue_manifest_path=args.reserve_queue_manifest,
        source_import_verification_path=args.source_import_verification,
        effective_sources=[tuple(value) for value in args.effective_source],
        trace_deployment_projection_path=args.trace_deployment_projection,
        capacity_audit_path=args.capacity_audit,
        outcome_blind_attestation_path=args.outcome_blind_attestation,
        expected_case_count=args.expected_case_count,
        controls_per_positive=args.controls_per_positive,
    )
    _write(args.output.expanduser().resolve(strict=False), projection)
    print(json.dumps({key: projection[key] for key in (
        "decision", "admitted_row_count", "maximum_assignable_controls",
        "denominator_qualifies", "counter_authority", "projection_sha256",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
