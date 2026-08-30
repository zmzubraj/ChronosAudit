from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_effective_reconciliation import (
    build_control_candidate_effective_reconciliation,
)


def _source(value: str) -> tuple[Path, Path]:
    queue, separator, root = value.partition("::")
    if not separator or not queue or not root:
        raise argparse.ArgumentTypeError("source must be QUEUE_PATH::ACQUISITION_ROOT")
    return Path(queue), Path(root)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile immutable control-candidate acquisition ledgers."
    )
    parser.add_argument("--initial-queue", type=Path, required=True)
    parser.add_argument(
        "--source",
        action="append",
        type=_source,
        required=True,
        help="Repeat in immutable overlay order as QUEUE_PATH::ACQUISITION_ROOT.",
    )
    parser.add_argument("--output-complete", type=Path, required=True)
    parser.add_argument("--output-rejected", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_control_candidate_effective_reconciliation(
        initial_queue_path=args.initial_queue,
        source_runs=args.source,
        output_complete_path=args.output_complete,
        output_rejected_path=args.output_rejected,
        output_manifest_path=args.output_manifest,
    )
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
