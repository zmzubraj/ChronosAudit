from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_base_state_activation import (
    build_base_state_activation_request,
    verify_base_state_activation,
)


def _atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild and verify the exact Phase 1 base-state activation."
    )
    parser.add_argument("--capability-verification", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--base-state-targets", type=Path, required=True)
    parser.add_argument("--activation-start-utc", required=True)
    parser.add_argument("--activation-expires-utc", required=True)
    parser.add_argument("--retry-limit", type=int, default=2)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    args = parser.parse_args()
    request = build_base_state_activation_request(
        capability_verification_path=args.capability_verification,
        provider_registry_path=args.provider_registry,
        base_state_targets_path=args.base_state_targets,
        activation_start_utc=args.activation_start_utc,
        activation_expires_utc=args.activation_expires_utc,
        retry_limit=args.retry_limit,
    )
    verification = verify_base_state_activation(
        request=request,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    _atomic(args.output_verification.expanduser().resolve(strict=False), verification)
    print(
        json.dumps(
            {
                "decision": verification["decision"],
                "verification_sha256": verification["verification_sha256"],
                "base_state_target_count": verification["base_state_target_count"],
                "rpc_call_scope_count": verification["rpc_call_scope_count"],
                "maximum_request_count": verification["maximum_request_count"],
                "rpc_authorized": verification["rpc_authorized"],
                "derived_address_reads_authorized": verification[
                    "derived_address_reads_authorized"
                ],
                "selection_authorized": verification["selection_authorized"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
