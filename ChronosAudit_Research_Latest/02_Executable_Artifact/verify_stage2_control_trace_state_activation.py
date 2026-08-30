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
    build_trace_state_activation_request,
    verify_trace_state_activation,
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
            "Rebuild the exact Stage 2 trace/state request and verify its detached "
            "local-test RPC activation signature."
        )
    )
    parser.add_argument("--capability-report", type=Path, required=True)
    parser.add_argument("--capability-raw-root", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--trace-targets", type=Path, required=True)
    parser.add_argument("--state-targets", type=Path, required=True)
    parser.add_argument("--activation-start-utc", required=True)
    parser.add_argument("--activation-expires-utc", required=True)
    parser.add_argument("--retry-limit", type=int, default=2)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()
    request = build_trace_state_activation_request(
        capability_report_path=args.capability_report,
        capability_raw_root=args.capability_raw_root,
        provider_registry_path=args.provider_registry,
        trace_targets_path=args.trace_targets,
        state_targets_path=args.state_targets,
        activation_start_utc=args.activation_start_utc,
        activation_expires_utc=args.activation_expires_utc,
        retry_limit=args.retry_limit,
    )
    report = verify_trace_state_activation(
        request=request,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    output = args.output_report.expanduser().resolve(strict=False)
    sources = {
        path.expanduser().resolve(strict=True)
        for path in (
            args.capability_report,
            args.provider_registry,
            args.trace_targets,
            args.state_targets,
            args.approval,
            args.signature,
            args.allowed_signers,
        )
    }
    if output in sources:
        raise ValueError("activation verification must not overwrite an input")
    _atomic_write(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
