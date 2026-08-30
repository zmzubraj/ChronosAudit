from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay import (
    TraceSourceRoot,
    build_trace_completion_overlay,
)


def _signed_root(root: Path, allowed: Path, principal: str) -> TraceSourceRoot:
    signatures = sorted(root.glob("*checkpoint-signing-payload-*.json.sig"))
    if len(signatures) != 1:
        raise ValueError("checkpoint_signature_ambiguous")
    return TraceSourceRoot(root / "checkpoint.json", signatures[0], allowed, principal)


def _atomic_new(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise ValueError("output_exists_or_not_ordinary")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--specification", type=Path, required=True)
    parser.add_argument("--spec-approval", type=Path, required=True)
    parser.add_argument("--original-targets", type=Path, required=True)
    parser.add_argument("--original-activation-request", type=Path, required=True)
    parser.add_argument("--original-activation-approval", type=Path, required=True)
    parser.add_argument("--original-activation-signature", type=Path, required=True)
    parser.add_argument("--original-activation-allowed-signers", type=Path, required=True)
    parser.add_argument("--original-activation-verification", type=Path, required=True)
    parser.add_argument("--original-source-root", type=Path, action="append", required=True)
    parser.add_argument("--retry-targets", type=Path, required=True)
    parser.add_argument("--retry-targets-verification", type=Path, required=True)
    parser.add_argument("--retry-activation-request", type=Path, required=True)
    parser.add_argument("--retry-activation-approval", type=Path, required=True)
    parser.add_argument("--retry-activation-signature", type=Path, required=True)
    parser.add_argument("--retry-activation-allowed-signers", type=Path, required=True)
    parser.add_argument("--retry-activation-verification", type=Path, required=True)
    parser.add_argument("--retry-root", type=Path, required=True)
    parser.add_argument("--expected-principal", default="zmzubraj")
    parser.add_argument("--retry-verification-time-utc", required=True)


def reconstruction(args: argparse.Namespace) -> dict[str, object]:
    if len(args.original_source_root) != 3:
        raise ValueError("exactly_three_source_roots_required")
    sources = [
        _signed_root(root, args.original_activation_allowed_signers, args.expected_principal)
        for root in args.original_source_root
    ]
    retry_inputs = {
        "specification_path": args.specification,
        "spec_approval_path": args.spec_approval,
        "original_targets_path": args.original_targets,
        "activation_request_path": args.original_activation_request,
        "activation_approval_path": args.original_activation_approval,
        "activation_signature_path": args.original_activation_signature,
        "activation_allowed_signers_path": args.original_activation_allowed_signers,
        "activation_verification_path": args.original_activation_verification,
        "activation_expected_principal": args.expected_principal,
        "sources": sources,
    }
    return {
        "retry_targets_path": args.retry_targets,
        "retry_targets_verification_path": args.retry_targets_verification,
        "retry_reconstruction_inputs": retry_inputs,
        "retry_activation_request_path": args.retry_activation_request,
        "retry_activation_approval_path": args.retry_activation_approval,
        "retry_activation_signature_path": args.retry_activation_signature,
        "retry_activation_allowed_signers_path": args.retry_activation_allowed_signers,
        "retry_activation_verification_path": args.retry_activation_verification,
        "retry_activation_expected_principal": args.expected_principal,
        "retry_source": _signed_root(args.retry_root, args.retry_activation_allowed_signers, args.expected_principal),
        "retry_verification_time_utc": args.retry_verification_time_utc,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a complete non-authorizing trace provenance overlay.")
    add_arguments(parser)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_trace_completion_overlay(**reconstruction(args))
    _atomic_new(args.output, payload)
    print(json.dumps({
        "decision": payload["decision"],
        "completed_target_count": payload["completed_target_count"],
        "overlay_sha256": payload["overlay_sha256"],
        "rpc_authorized": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
