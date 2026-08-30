from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_qualification_approval import (
    build_control_qualification_approval_request,
    verify_control_qualification_approval,
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
            "Verify signed Stage 2 control-qualification authority and emit a "
            "separate qualified-control projection."
        )
    )
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
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--output-qualified-controls", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.candidate_rows,
            args.check_rows,
            args.positive_cases,
            args.approval,
            args.signature,
            args.allowed_signers,
        )
    }
    outputs = {
        args.output_verification.expanduser().resolve(strict=False),
        args.output_qualified_controls.expanduser().resolve(strict=False),
    }
    if len(outputs) != 2 or inputs & outputs:
        raise ValueError("verification outputs must differ and must not overwrite inputs")
    request = build_control_qualification_approval_request(
        candidate_rows_path=args.candidate_rows,
        check_rows_path=args.check_rows,
        positive_cases_path=args.positive_cases,
        evidence_root=args.evidence_root,
        expected_positive_rows=args.expected_positive_rows,
        controls_per_positive=args.controls_per_positive,
    )
    result = verify_control_qualification_approval(
        request=request,
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
    _atomic_write(
        args.output_verification.expanduser().resolve(strict=False),
        (json.dumps(result["verification"], indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )
    _atomic_write(
        args.output_qualified_controls.expanduser().resolve(strict=False),
        result["qualified_control_projection"].to_csv(index=False).encode("utf-8"),
    )
    print(json.dumps(result["verification"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
