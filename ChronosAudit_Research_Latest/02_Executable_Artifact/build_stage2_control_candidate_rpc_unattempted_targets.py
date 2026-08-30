from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_retry_targets import (
    build_control_candidate_rpc_unattempted_targets,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze exact candidate scopes absent from a source RPC terminal ledger."
    )
    parser.add_argument("--original-queue", type=Path, required=True)
    parser.add_argument("--run-manifest", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--event-ledger", type=Path, required=True)
    parser.add_argument("--request-ledger", type=Path, required=True)
    parser.add_argument("--output-queue", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--chain", action="append", dest="required_chains")
    args = parser.parse_args()
    result = build_control_candidate_rpc_unattempted_targets(
        original_queue_path=args.original_queue,
        run_manifest_path=args.run_manifest,
        summary_path=args.summary,
        event_ledger_path=args.event_ledger,
        request_ledger_path=args.request_ledger,
        output_queue_path=args.output_queue,
        output_manifest_path=args.output_manifest,
        required_chains=args.required_chains,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
