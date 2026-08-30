from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_reserve_deployment_projection import (
    build_reserve_deployment_projection,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate the signed reserve checkpoint's receipt-proven deployment "
            "records and an optional complete trace projection. This does not "
            "authorize selection, qualification, or counters."
        )
    )
    parser.add_argument("--acquisition-summary", type=Path, required=True)
    parser.add_argument("--signature-verification", type=Path, required=True)
    parser.add_argument("--acquisition-ledger", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--trace-deployment-projection", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = build_reserve_deployment_projection(
        acquisition_summary_path=args.acquisition_summary,
        signature_verification_path=args.signature_verification,
        acquisition_ledger_path=args.acquisition_ledger,
        candidate_root=args.candidate_root,
        trace_deployment_projection_path=args.trace_deployment_projection,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, payload)
    print(
        json.dumps(
            {
                "complete": payload["complete"],
                "record_count": payload["record_count"],
                "receipt_record_count": payload["receipt_record_count"],
                "trace_record_count": payload["trace_record_count"],
                "pending_trace_count": payload["pending_trace_count"],
                "projection_sha256": payload["projection_sha256"],
                "counter_authority": False,
                "selection_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
