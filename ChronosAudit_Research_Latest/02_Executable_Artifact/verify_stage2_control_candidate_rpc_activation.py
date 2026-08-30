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
    build_control_candidate_rpc_activation_request,
    verify_control_candidate_rpc_activation,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify an accountable signature granting bounded deployment RPC "
            "for one exact Stage 2 control reserve queue."
        )
    )
    for name in (
        "queue",
        "queue-manifest",
        "query-plan",
        "chunk-plan",
        "positive-projection",
        "authority-projection",
        "import-manifest",
        "provider-registry",
        "provider-identity-verification",
        "approval",
        "signature",
        "allowed-signers",
        "output-report",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--block-window", type=Path)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    args = parser.parse_args()
    source_paths = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.queue,
            args.queue_manifest,
            args.query_plan,
            args.chunk_plan,
            args.positive_projection,
            args.authority_projection,
            args.import_manifest,
            args.provider_registry,
            args.provider_identity_verification,
            args.approval,
            args.signature,
            args.allowed_signers,
            *([args.block_window] if args.block_window else []),
        )
    }
    output = args.output_report.expanduser().resolve(strict=False)
    if output in source_paths:
        raise ValueError("activation report must not overwrite an input")
    request = build_control_candidate_rpc_activation_request(
        queue_path=args.queue,
        queue_manifest_path=args.queue_manifest,
        query_plan_path=args.query_plan,
        chunk_plan_path=args.chunk_plan,
        positive_projection_path=args.positive_projection,
        authority_projection_path=args.authority_projection,
        import_manifest_path=args.import_manifest,
        provider_registry_path=args.provider_registry,
        provider_identity_verification_path=args.provider_identity_verification,
        block_window_path=args.block_window,
    )
    report = verify_control_candidate_rpc_activation(
        request=request,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    _atomic_write(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
