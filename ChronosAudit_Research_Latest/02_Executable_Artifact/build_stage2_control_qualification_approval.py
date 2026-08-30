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
    build_control_qualification_approval,
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
            "Build an unsigned, request-bound Stage 2 control-qualification "
            "approval and its canonical signing payload."
        )
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--authority-principal", required=True)
    parser.add_argument("--approval-start-utc", required=True)
    parser.add_argument("--approval-expires-utc", required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()

    request_path = args.request.expanduser().resolve(strict=True)
    outputs = {
        args.output_approval.expanduser().resolve(strict=False),
        args.output_signing_payload.expanduser().resolve(strict=False),
    }
    if len(outputs) != 2 or request_path in outputs:
        raise ValueError("approval outputs must differ and must not overwrite the request")
    request = json.loads(request_path.read_text(encoding="utf-8"))
    approval = build_control_qualification_approval(
        request=request,
        authority_principal=args.authority_principal,
        approval_start_utc=args.approval_start_utc,
        approval_expires_utc=args.approval_expires_utc,
    )
    _atomic_write(
        args.output_approval.expanduser().resolve(strict=False),
        (json.dumps(approval, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _atomic_write(
        args.output_signing_payload.expanduser().resolve(strict=False),
        canonical_signed_payload(approval),
    )
    print(json.dumps(approval, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
