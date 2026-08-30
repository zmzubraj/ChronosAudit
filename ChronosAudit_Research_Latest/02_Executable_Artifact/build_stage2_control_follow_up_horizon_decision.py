from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_follow_up_horizon import (
    build_follow_up_horizon_decision,
    build_follow_up_horizon_request,
    canonical_horizon_signed_payload,
)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build, but do not sign, the exact Stage 2 follow-up-horizon "
            "decision payload after an accountable methods owner supplies the "
            "scientific decision and its three evidence files."
        )
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--positive-projection", type=Path, required=True)
    parser.add_argument("--signer-principal", required=True)
    parser.add_argument("--decided-at-utc", required=True)
    parser.add_argument("--horizon-days", type=int, required=True)
    parser.add_argument("--administrative-censoring-cutoff-utc", required=True)
    parser.add_argument("--outcome-source-plan", type=Path, required=True)
    parser.add_argument("--censoring-rules", type=Path, required=True)
    parser.add_argument(
        "--pre-freeze-outcome-inspection-attestation", type=Path, required=True
    )
    parser.add_argument("--output-decision", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.policy,
            args.positive_projection,
            args.outcome_source_plan,
            args.censoring_rules,
            args.pre_freeze_outcome_inspection_attestation,
        )
    }
    decision_output = args.output_decision.expanduser().resolve(strict=False)
    signing_output = args.output_signing_payload.expanduser().resolve(strict=False)
    if decision_output == signing_output:
        raise ValueError("decision and signing-payload outputs must differ")
    if decision_output in inputs or signing_output in inputs:
        raise ValueError("outputs must not overwrite inputs")

    request = build_follow_up_horizon_request(
        policy_path=args.policy,
        positive_projection_path=args.positive_projection,
    )
    decision = build_follow_up_horizon_decision(
        request=request,
        signer_principal=args.signer_principal,
        decided_at_utc=args.decided_at_utc,
        horizon_days=args.horizon_days,
        administrative_censoring_cutoff_utc=(
            args.administrative_censoring_cutoff_utc
        ),
        outcome_source_plan_path=args.outcome_source_plan,
        censoring_rules_path=args.censoring_rules,
        pre_freeze_outcome_inspection_attestation_path=(
            args.pre_freeze_outcome_inspection_attestation
        ),
    )
    decision_bytes = (json.dumps(decision, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    signing_payload = canonical_horizon_signed_payload(decision)
    _atomic_write(decision_output, decision_bytes)
    _atomic_write(signing_output, signing_payload)
    result = {
        "decision": decision,
        "decision_file_sha256": hashlib.sha256(decision_bytes).hexdigest(),
        "signing_payload_sha256": hashlib.sha256(signing_payload).hexdigest(),
        "signature_namespace": "chronosaudit-stage2-control-horizon-v1",
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "signature_created": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
