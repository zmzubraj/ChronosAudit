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

from chronosaudit_stage2.public_acquisition.control_provider_identity_approval import (
    build_control_provider_identity_approval,
    build_control_provider_identity_approval_request,
    canonical_signed_payload,
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
            "Build the exact unsigned accountable provider-identity approval and "
            "canonical signing payload. This does not authorize RPC or selection."
        )
    )
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--capture-index", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--reviewer-principal", required=True)
    parser.add_argument("--review-start-utc", required=True)
    parser.add_argument("--review-expires-utc", required=True)
    parser.add_argument("--output-request", type=Path, required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        args.review.expanduser().resolve(strict=True),
        args.provider_registry.expanduser().resolve(strict=True),
        args.capture_index.expanduser().resolve(strict=True),
    }
    outputs = {
        args.output_request.expanduser().resolve(strict=False),
        args.output_approval.expanduser().resolve(strict=False),
        args.output_signing_payload.expanduser().resolve(strict=False),
    }
    if len(outputs) != 3:
        raise ValueError("request, approval, and signing-payload outputs must differ")
    if inputs & outputs:
        raise ValueError("outputs must not overwrite inputs")
    request = build_control_provider_identity_approval_request(
        review_path=args.review,
        provider_registry_path=args.provider_registry,
        capture_index_path=args.capture_index,
        evidence_root=args.evidence_root,
    )
    approval = build_control_provider_identity_approval(
        request=request,
        reviewer_principal=args.reviewer_principal,
        review_start_utc=args.review_start_utc,
        review_expires_utc=args.review_expires_utc,
    )
    request_bytes = (json.dumps(request, indent=2, sort_keys=True) + "\n").encode("utf-8")
    approval_bytes = (json.dumps(approval, indent=2, sort_keys=True) + "\n").encode("utf-8")
    signing_bytes = canonical_signed_payload(approval)
    _atomic_write(args.output_request.expanduser().resolve(strict=False), request_bytes)
    _atomic_write(args.output_approval.expanduser().resolve(strict=False), approval_bytes)
    _atomic_write(
        args.output_signing_payload.expanduser().resolve(strict=False), signing_bytes
    )
    print(
        json.dumps(
            {
                "request": request,
                "approval": approval,
                "request_file_sha256": hashlib.sha256(request_bytes).hexdigest(),
                "approval_file_sha256": hashlib.sha256(approval_bytes).hexdigest(),
                "signing_payload_sha256": hashlib.sha256(signing_bytes).hexdigest(),
                "signature_namespace": (
                    "chronosaudit-stage2-control-provider-identity-review-v1"
                ),
                "signature_created": False,
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
