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
    build_legacy_alias_identity_revision_approval,
    canonical_signed_payload,
)


def _stage(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(data)
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    return temporary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the exact local-test provider-identity revision approval and "
            "canonical signing payload. This does not sign, authorize RPC, or "
            "change Stage 2 counters."
        )
    )
    parser.add_argument("--revision-request", type=Path, required=True)
    parser.add_argument("--revision-verification", type=Path, required=True)
    parser.add_argument("--reviewer-principal", required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()

    revision = args.revision_request.expanduser().resolve(strict=True)
    revision_verification = args.revision_verification.expanduser().resolve(
        strict=True
    )
    approval_output = args.output_approval.expanduser().resolve(strict=False)
    payload_output = args.output_signing_payload.expanduser().resolve(strict=False)
    sources = {revision, revision_verification}
    outputs = {approval_output, payload_output}
    if len(outputs) != 2 or outputs & sources:
        raise ValueError("outputs_must_be_distinct_and_not_overwrite_inputs")

    approval = build_legacy_alias_identity_revision_approval(
        revision_request_path=revision,
        revision_verification_path=revision_verification,
        reviewer_principal=args.reviewer_principal,
    )
    approval_data = (
        json.dumps(approval, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    payload_data = canonical_signed_payload(approval)
    staged = [
        (approval_output, _stage(approval_output, approval_data)),
        (payload_output, _stage(payload_output, payload_data)),
    ]
    try:
        for output, temporary in staged:
            os.replace(temporary, output)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "decision": approval["decision"],
                "provider_identity_revision_authorized": True,
                "rpc_authorized": False,
                "selection_authorized": False,
                "counter_authority": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
