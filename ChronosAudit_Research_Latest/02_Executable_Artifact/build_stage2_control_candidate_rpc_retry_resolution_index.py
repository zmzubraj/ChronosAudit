from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_retry_resolution import (
    build_control_candidate_rpc_retry_resolution_index,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify completed candidate retries into a non-authorizing resolution index."
    )
    for name in (
        "retry-queue",
        "retry-targets-manifest",
        "retry-run-manifest",
        "retry-summary",
        "retry-event-ledger",
        "output",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--prior-index", type=Path)
    parser.add_argument(
        "--allow-partial-run",
        action="store_true",
        help="Index only verified COMPLETE events from a mixed COMPLETE/PARTIAL run.",
    )
    args = parser.parse_args()
    result = build_control_candidate_rpc_retry_resolution_index(
        retry_queue_path=args.retry_queue,
        retry_targets_manifest_path=args.retry_targets_manifest,
        retry_run_manifest_path=args.retry_run_manifest,
        retry_summary_path=args.retry_summary,
        retry_event_ledger_path=args.retry_event_ledger,
        output_path=args.output,
        prior_index_path=args.prior_index,
        allow_partial_run=args.allow_partial_run,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
