from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_trace_state_activation import (
    build_trace_only_activation_request,
)
from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay import (
    TraceSourceRoot,
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
            "Build a non-authorizing activation request for exact Stage 2 "
            "trace RPC calls before cutoff-state target derivation."
        )
    )
    parser.add_argument("--capability-report", type=Path, required=True)
    parser.add_argument("--capability-raw-root", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--trace-targets", type=Path, required=True)
    parser.add_argument("--activation-start-utc", required=True)
    parser.add_argument("--activation-expires-utc", required=True)
    parser.add_argument("--retry-limit", type=int, default=2)
    parser.add_argument("--retry-specification", type=Path)
    parser.add_argument("--retry-spec-approval", type=Path)
    parser.add_argument("--retry-original-targets", type=Path)
    parser.add_argument("--retry-original-activation-request", type=Path)
    parser.add_argument("--retry-original-activation-approval", type=Path)
    parser.add_argument("--retry-original-activation-signature", type=Path)
    parser.add_argument("--retry-original-activation-allowed-signers", type=Path)
    parser.add_argument("--retry-original-activation-verification", type=Path)
    parser.add_argument("--retry-expected-principal", default="zmzubraj")
    parser.add_argument("--retry-source-root", type=Path, action="append", default=[])
    parser.add_argument("--output-request", type=Path, required=True)
    args = parser.parse_args()
    sources = {
        path.expanduser().resolve(strict=True)
        for path in (
            args.capability_report,
            args.provider_registry,
            args.trace_targets,
        )
    }
    output = args.output_request.expanduser().resolve(strict=False)
    if output in sources:
        raise ValueError("activation request must not overwrite an input")
    retry_inputs = None
    target_payload = json.loads(args.trace_targets.read_text(encoding="utf-8"))
    if target_payload.get("schema_version") == "stage2_control_trace_retry_targets.v1":
        required = (
            args.retry_specification,
            args.retry_spec_approval,
            args.retry_original_targets,
            args.retry_original_activation_request,
            args.retry_original_activation_approval,
            args.retry_original_activation_signature,
            args.retry_original_activation_allowed_signers,
            args.retry_original_activation_verification,
        )
        if any(value is None for value in required) or len(args.retry_source_root) != 3:
            raise ValueError("retry_reconstruction_inputs_required")
        sources = []
        for root in args.retry_source_root:
            signatures = sorted(root.glob("interrupted-checkpoint-signing-payload-*.json.sig"))
            if len(signatures) != 1:
                raise ValueError("source_checkpoint_signature_ambiguous")
            sources.append(TraceSourceRoot(
                root / "checkpoint.json",
                signatures[0],
                args.retry_original_activation_allowed_signers,
                args.retry_expected_principal,
            ))
        retry_inputs = {
            "specification_path": args.retry_specification,
            "spec_approval_path": args.retry_spec_approval,
            "original_targets_path": args.retry_original_targets,
            "activation_request_path": args.retry_original_activation_request,
            "activation_approval_path": args.retry_original_activation_approval,
            "activation_signature_path": args.retry_original_activation_signature,
            "activation_allowed_signers_path": args.retry_original_activation_allowed_signers,
            "activation_verification_path": args.retry_original_activation_verification,
            "activation_expected_principal": args.retry_expected_principal,
            "sources": sources,
        }
    request = build_trace_only_activation_request(
        capability_report_path=args.capability_report,
        capability_raw_root=args.capability_raw_root,
        provider_registry_path=args.provider_registry,
        trace_targets_path=args.trace_targets,
        activation_start_utc=args.activation_start_utc,
        activation_expires_utc=args.activation_expires_utc,
        retry_limit=args.retry_limit,
        retry_reconstruction_inputs=retry_inputs,
    )
    _atomic_write(output, request)
    print(json.dumps(request, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
