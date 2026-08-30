from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_follow_up_horizon import (
    build_follow_up_horizon_request,
    verify_follow_up_horizon_decision,
)


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a detached-OpenSSH-signed Stage 2 follow-up-horizon "
            "decision without qualifying any control row."
        )
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--positive-projection", type=Path, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--outcome-source-plan", type=Path, required=True)
    parser.add_argument("--censoring-rules", type=Path, required=True)
    parser.add_argument(
        "--pre-freeze-outcome-inspection-attestation", type=Path, required=True
    )
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()
    sources = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.policy,
            args.positive_projection,
            args.decision,
            args.signature,
            args.allowed_signers,
            args.outcome_source_plan,
            args.censoring_rules,
            args.pre_freeze_outcome_inspection_attestation,
        )
    }
    output = args.output_report.expanduser().resolve(strict=False)
    if output in sources:
        raise ValueError("horizon verification output must not overwrite an input")
    request = build_follow_up_horizon_request(
        policy_path=args.policy, positive_projection_path=args.positive_projection
    )
    report = verify_follow_up_horizon_decision(
        request=request,
        decision_path=args.decision,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
        outcome_source_plan_path=args.outcome_source_plan,
        censoring_rules_path=args.censoring_rules,
        pre_freeze_outcome_inspection_attestation_path=(
            args.pre_freeze_outcome_inspection_attestation
        ),
    )
    _atomic_write_json(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
