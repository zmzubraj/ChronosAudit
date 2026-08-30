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
    verify_denominator_expansion_admission_approval,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify accountable denominator expansion admission authority.")
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--projection-verification", type=Path, required=True)
    parser.add_argument("--signer-identity-binding", type=Path, required=True)
    parser.add_argument("--signer-public-key", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verification = verify_denominator_expansion_admission_approval(
        projection_path=args.projection,
        projection_verification_path=args.projection_verification,
        signer_identity_binding_path=args.signer_identity_binding,
        signer_public_key_path=args.signer_public_key,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    output = args.output.expanduser().resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink(): raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
        handle.write(json.dumps(verification, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name); handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, output)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
