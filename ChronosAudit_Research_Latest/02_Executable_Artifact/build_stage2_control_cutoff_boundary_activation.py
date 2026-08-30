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

from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_activation import (
    SIGNATURE_NAMESPACE,
    build_boundary_activation_approval,
    build_boundary_activation_request,
    canonical_signed_payload,
)


def _atomic_write(path: Path, payload: bytes) -> None:
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
        description=(
            "Build the exact unsigned range-bound Stage 2 cutoff-block RPC "
            "activation and canonical signing payload."
        )
    )
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--capability", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--activation-start-utc", required=True)
    parser.add_argument("--activation-expires-utc", required=True)
    parser.add_argument("--retry-limit", type=int, default=1)
    parser.add_argument("--signer-principal", required=True)
    parser.add_argument("--output-request", type=Path, required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        args.requirements.expanduser().resolve(strict=True),
        args.capability.expanduser().resolve(strict=True),
        args.provider_registry.expanduser().resolve(strict=True),
    }
    outputs = {
        args.output_request.expanduser().resolve(strict=False),
        args.output_approval.expanduser().resolve(strict=False),
        args.output_signing_payload.expanduser().resolve(strict=False),
    }
    if len(outputs) != 3 or inputs & outputs:
        raise ValueError("activation_outputs_invalid")
    request = build_boundary_activation_request(
        requirements_path=args.requirements,
        capability_path=args.capability,
        provider_registry_path=args.provider_registry,
        activation_start_utc=args.activation_start_utc,
        activation_expires_utc=args.activation_expires_utc,
        retry_limit=args.retry_limit,
    )
    approval = build_boundary_activation_approval(
        request=request, signer_principal=args.signer_principal
    )
    request_bytes = (json.dumps(request, indent=2, sort_keys=True) + "\n").encode()
    approval_bytes = (json.dumps(approval, indent=2, sort_keys=True) + "\n").encode()
    signing_bytes = canonical_signed_payload(approval)
    _atomic_write(args.output_request.expanduser().resolve(strict=False), request_bytes)
    _atomic_write(args.output_approval.expanduser().resolve(strict=False), approval_bytes)
    _atomic_write(
        args.output_signing_payload.expanduser().resolve(strict=False), signing_bytes
    )
    print(
        json.dumps(
            {
                "request_sha256": request["request_sha256"],
                "request_file_sha256": hashlib.sha256(request_bytes).hexdigest(),
                "approval_file_sha256": hashlib.sha256(approval_bytes).hexdigest(),
                "signing_payload_sha256": hashlib.sha256(signing_bytes).hexdigest(),
                "signature_namespace": SIGNATURE_NAMESPACE,
                "boundary_target_count": request["boundary_target_count"],
                "range_scope_count": request["range_scope_count"],
                "maximum_request_count": request["maximum_request_count"],
                "rpc_authorized": False,
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
