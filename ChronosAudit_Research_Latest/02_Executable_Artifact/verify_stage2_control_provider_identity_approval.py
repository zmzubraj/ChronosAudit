from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_approval import (
    build_control_provider_identity_approval_request,
    verify_control_provider_identity_approval,
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
            "Verify an accountable provider-identity signature and emit separate "
            "non-RPC registry and identity-report projections."
        )
    )
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--capture-index", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--output-registry-projection", type=Path, required=True)
    parser.add_argument("--output-identity-report", type=Path, required=True)
    args = parser.parse_args()

    source_paths = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.review,
            args.provider_registry,
            args.capture_index,
            args.approval,
            args.signature,
            args.allowed_signers,
        )
    }
    output_paths = {
        args.output_verification.expanduser().resolve(strict=False),
        args.output_registry_projection.expanduser().resolve(strict=False),
        args.output_identity_report.expanduser().resolve(strict=False),
    }
    if len(output_paths) != 3:
        raise ValueError("verification projection outputs must differ")
    if source_paths & output_paths:
        raise ValueError("outputs must not overwrite inputs")
    request = build_control_provider_identity_approval_request(
        review_path=args.review,
        provider_registry_path=args.provider_registry,
        capture_index_path=args.capture_index,
        evidence_root=args.evidence_root,
    )
    result = verify_control_provider_identity_approval(
        request=request,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    _atomic_write(
        args.output_verification.expanduser().resolve(strict=False),
        (json.dumps(result["verification"], indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _atomic_write(
        args.output_registry_projection.expanduser().resolve(strict=False),
        yaml.safe_dump(result["provider_registry_projection"], sort_keys=False).encode("utf-8"),
    )
    _atomic_write(
        args.output_identity_report.expanduser().resolve(strict=False),
        (json.dumps(result["provider_identity_verification"], indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(json.dumps(result["verification"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
