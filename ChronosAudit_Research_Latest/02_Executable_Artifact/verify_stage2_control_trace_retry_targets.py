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
    verify_trace_retry_targets,
)


def _source(root: Path, allowed_signers: Path, principal: str) -> TraceSourceRoot:
    signatures = sorted(root.glob("interrupted-checkpoint-signing-payload-*.json.sig"))
    if len(signatures) != 1:
        raise ValueError("source_checkpoint_signature_ambiguous")
    return TraceSourceRoot(root / "checkpoint.json", signatures[0], allowed_signers, principal)


def _atomic_write_new(path: Path, payload: dict[str, object]) -> None:
    candidate = path.expanduser()
    candidate.parent.mkdir(parents=True, exist_ok=True)
    if candidate.is_symlink() or candidate.exists():
        raise ValueError("output_exists_or_not_ordinary")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=candidate.parent, delete=False) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, candidate)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently reconstruct the non-authorizing trace retry subset.")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--specification", type=Path, required=True)
    parser.add_argument("--spec-approval", type=Path, required=True)
    parser.add_argument("--original-targets", type=Path, required=True)
    parser.add_argument("--activation-request", type=Path, required=True)
    parser.add_argument("--activation-approval", type=Path, required=True)
    parser.add_argument("--activation-signature", type=Path, required=True)
    parser.add_argument("--activation-allowed-signers", type=Path, required=True)
    parser.add_argument("--activation-verification", type=Path, required=True)
    parser.add_argument("--expected-principal", default="zmzubraj")
    parser.add_argument("--verification-time-utc", default="2026-08-25T00:00:00Z")
    parser.add_argument("--source-root", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.source_root) != 3:
        raise ValueError("exactly_three_source_roots_required")
    report = verify_trace_retry_targets(
        artifact_path=args.artifact,
        specification_path=args.specification,
        spec_approval_path=args.spec_approval,
        original_targets_path=args.original_targets,
        activation_request_path=args.activation_request,
        activation_approval_path=args.activation_approval,
        activation_signature_path=args.activation_signature,
        activation_allowed_signers_path=args.activation_allowed_signers,
        activation_verification_path=args.activation_verification,
        activation_expected_principal=args.expected_principal,
        sources=[_source(root, args.activation_allowed_signers, args.expected_principal) for root in args.source_root],
        verification_time_utc=args.verification_time_utc,
    )
    _atomic_write_new(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
