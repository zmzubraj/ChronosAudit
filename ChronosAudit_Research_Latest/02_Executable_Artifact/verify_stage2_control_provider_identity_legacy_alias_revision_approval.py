from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_revision_approval import (
    verify_legacy_alias_identity_revision_approval,
)


def _stage(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    return temporary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify an accountable local-test provider-identity revision "
            "signature and project only its non-RPC identity artifacts."
        )
    )
    parser.add_argument("--revision-request", type=Path, required=True)
    parser.add_argument("--revision-verification", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--output-registry-fragment", type=Path, required=True)
    parser.add_argument("--output-identity-verification", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        args.revision_request.expanduser().resolve(strict=True),
        args.revision_verification.expanduser().resolve(strict=True),
        args.approval.expanduser().resolve(strict=True),
        args.signature.expanduser().resolve(strict=True),
        args.allowed_signers.expanduser().resolve(strict=True),
    }
    outputs = [
        args.output_verification.expanduser().resolve(strict=False),
        args.output_registry_fragment.expanduser().resolve(strict=False),
        args.output_identity_verification.expanduser().resolve(strict=False),
    ]
    if len(set(outputs)) != 3 or set(outputs) & inputs:
        raise ValueError("outputs_must_be_distinct_and_not_overwrite_inputs")

    result = verify_legacy_alias_identity_revision_approval(
        revision_request_path=args.revision_request,
        revision_verification_path=args.revision_verification,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    payloads = [
        result["verification"],
        result["provider_registry_fragment"],
        result["provider_identity_verification"],
    ]
    staged = [
        (output, _stage(output, payload))
        for output, payload in zip(outputs, payloads, strict=True)
    ]
    try:
        for output, temporary in staged:
            os.replace(temporary, output)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)
    print(json.dumps(result["verification"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
