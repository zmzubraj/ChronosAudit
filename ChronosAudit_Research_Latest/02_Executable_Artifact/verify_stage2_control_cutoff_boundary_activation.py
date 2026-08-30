from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_activation import (
    verify_boundary_activation,
)


def _load(path: Path, label: str) -> dict[str, object]:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ValueError(f"{label}_not_ordinary")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label}_not_ordinary")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label}_root_invalid")
    return payload


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the detached local-test signature for the exact range-bound "
            "Stage 2 cutoff-block RPC activation."
        )
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        args.request.expanduser().resolve(strict=True),
        args.approval.expanduser().resolve(strict=True),
        args.signature.expanduser().resolve(strict=True),
        args.allowed_signers.expanduser().resolve(strict=True),
    }
    output = args.output_verification.expanduser().resolve(strict=False)
    if output in inputs:
        raise ValueError("verification_output_must_not_overwrite_input")
    result = verify_boundary_activation(
        request=_load(args.request, "request"),
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    _atomic_write(output, result)
    print(
        json.dumps(
            {
                "decision": result["decision"],
                "verification_sha256": result["verification_sha256"],
                "boundary_target_count": result["boundary_target_count"],
                "range_scope_count": result["range_scope_count"],
                "maximum_request_count": result["maximum_request_count"],
                "rpc_authorized": result["rpc_authorized"],
                "selection_authorized": result["selection_authorized"],
                "stage_promotion_authorized": result["stage_promotion_authorized"],
                "recovery3_mutation_authorized": result[
                    "recovery3_mutation_authorized"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
