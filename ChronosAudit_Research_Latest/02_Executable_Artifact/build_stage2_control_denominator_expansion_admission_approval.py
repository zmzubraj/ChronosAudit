from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_denominator_expansion_admission_approval import (
    build_denominator_expansion_admission_approval,
    canonical_signed_payload,
)


def _stage(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink(): raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(data); temporary = Path(handle.name); handle.flush(); os.fsync(handle.fileno())
    return temporary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an accountable denominator-admission approval payload without signing it.")
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--projection-verification", type=Path, required=True)
    parser.add_argument("--signer-identity-binding", type=Path, required=True)
    parser.add_argument("--signer-public-key", type=Path, required=True)
    parser.add_argument("--signer-principal", required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()
    approval = build_denominator_expansion_admission_approval(
        projection_path=args.projection,
        projection_verification_path=args.projection_verification,
        signer_identity_binding_path=args.signer_identity_binding,
        signer_public_key_path=args.signer_public_key,
        signer_principal=args.signer_principal,
    )
    outputs = [args.output_approval.expanduser().resolve(strict=False), args.output_signing_payload.expanduser().resolve(strict=False)]
    if outputs[0] == outputs[1]: raise ValueError("outputs_must_be_distinct")
    staged = [
        (outputs[0], _stage(outputs[0], (json.dumps(approval, indent=2, sort_keys=True) + "\n").encode())),
        (outputs[1], _stage(outputs[1], canonical_signed_payload(approval))),
    ]
    try:
        for output, temporary in staged: os.replace(temporary, output)
    finally:
        for _, temporary in staged: temporary.unlink(missing_ok=True)
    print(json.dumps({"decision": approval["decision"], "counter_authority": True, "selection_authorized": False}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
