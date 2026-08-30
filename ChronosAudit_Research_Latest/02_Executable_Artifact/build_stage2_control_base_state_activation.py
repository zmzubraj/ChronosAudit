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

from chronosaudit_stage2.public_acquisition.control_base_state_activation import (
    SIGNATURE_NAMESPACE,
    build_base_state_activation_approval,
    build_base_state_activation_request,
    canonical_signed_payload,
)


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the exact unsigned Phase 1 base-state activation."
    )
    parser.add_argument("--capability-verification", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--base-state-targets", type=Path, required=True)
    parser.add_argument("--activation-start-utc", required=True)
    parser.add_argument("--activation-expires-utc", required=True)
    parser.add_argument("--retry-limit", type=int, default=2)
    parser.add_argument("--signer-principal", required=True)
    parser.add_argument("--output-request", type=Path, required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()
    request = build_base_state_activation_request(
        capability_verification_path=args.capability_verification,
        provider_registry_path=args.provider_registry,
        base_state_targets_path=args.base_state_targets,
        activation_start_utc=args.activation_start_utc,
        activation_expires_utc=args.activation_expires_utc,
        retry_limit=args.retry_limit,
    )
    approval = build_base_state_activation_approval(
        request=request, signer_principal=args.signer_principal
    )
    request_bytes = (json.dumps(request, indent=2, sort_keys=True) + "\n").encode()
    approval_bytes = (json.dumps(approval, indent=2, sort_keys=True) + "\n").encode()
    signing_bytes = canonical_signed_payload(approval)
    outputs = [
        args.output_request.expanduser().resolve(strict=False),
        args.output_approval.expanduser().resolve(strict=False),
        args.output_signing_payload.expanduser().resolve(strict=False),
    ]
    if len(set(outputs)) != 3:
        raise ValueError("activation_outputs_invalid")
    for path, payload in zip(
        outputs, (request_bytes, approval_bytes, signing_bytes), strict=True
    ):
        _atomic(path, payload)
    print(
        json.dumps(
            {
                "request_sha256": request["request_sha256"],
                "approval_file_sha256": hashlib.sha256(approval_bytes).hexdigest(),
                "signing_payload_sha256": hashlib.sha256(signing_bytes).hexdigest(),
                "signature_namespace": SIGNATURE_NAMESPACE,
                "base_state_target_count": request["base_state_target_count"],
                "rpc_call_scope_count": request["rpc_call_scope_count"],
                "maximum_request_count": request["maximum_request_count"],
                "rpc_authorized": False,
                "derived_address_reads_authorized": False,
                "selection_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
