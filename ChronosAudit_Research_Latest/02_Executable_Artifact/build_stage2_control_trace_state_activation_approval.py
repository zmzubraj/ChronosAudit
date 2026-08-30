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

from chronosaudit_stage2.public_acquisition.control_trace_state_activation import (
    SIGNATURE_NAMESPACE,
    build_trace_state_activation_approval,
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
            "Build the exact unsigned local-test Stage 2 trace/state RPC approval "
            "and canonical signing payload."
        )
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--signer-principal", required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()
    request_path = args.request.expanduser().resolve(strict=True)
    approval_path = args.output_approval.expanduser().resolve(strict=False)
    signing_path = args.output_signing_payload.expanduser().resolve(strict=False)
    if len({request_path, approval_path, signing_path}) != 3:
        raise ValueError("request, approval, and signing payload paths must differ")
    request = json.loads(request_path.read_text(encoding="utf-8"))
    approval = build_trace_state_activation_approval(
        request=request, signer_principal=args.signer_principal
    )
    approval_bytes = (json.dumps(approval, indent=2, sort_keys=True) + "\n").encode()
    signing_bytes = canonical_signed_payload(approval)
    _atomic_write(approval_path, approval_bytes)
    _atomic_write(signing_path, signing_bytes)
    print(json.dumps({
        "approval_file_sha256": hashlib.sha256(approval_bytes).hexdigest(),
        "signing_payload_sha256": hashlib.sha256(signing_bytes).hexdigest(),
        "signature_namespace": SIGNATURE_NAMESPACE,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
