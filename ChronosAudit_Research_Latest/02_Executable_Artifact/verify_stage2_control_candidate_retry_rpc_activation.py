from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_activation import (
    build_control_candidate_retry_rpc_activation_request,
    verify_control_candidate_rpc_activation,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify fresh exact activation for candidate PARTIAL retries."
    )
    for name in (
        "queue",
        "retry-manifest",
        "provider-registry",
        "provider-identity-verification",
        "candidate-rpc-capability-verification",
        "approval",
        "signature",
        "allowed-signers",
        "output-report",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    args = parser.parse_args()
    request = build_control_candidate_retry_rpc_activation_request(
        queue_path=args.queue,
        retry_manifest_path=args.retry_manifest,
        provider_registry_path=args.provider_registry,
        provider_identity_verification_path=args.provider_identity_verification,
        candidate_rpc_capability_verification_path=args.candidate_rpc_capability_verification,
    )
    report = verify_control_candidate_rpc_activation(
        request=request,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    output = args.output_report.expanduser().resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("output_report_symlink")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output.parent, delete=False
    ) as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
