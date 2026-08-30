from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_historical_candidate_queue import (
    build_historical_candidate_queue,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the non-authorizing Stage 2 historical reserve queue."
    )
    for name in (
        "query-plan",
        "inventory",
        "inventory-manifest",
        "chunk-plan",
        "chunk-manifest",
        "import-manifest",
        "source-root",
        "receipt-root",
        "positive-projection",
        "authority-projection",
        "output-queue",
        "output-manifest",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--block-window", type=Path)
    args = parser.parse_args()
    report = build_historical_candidate_queue(
        query_plan_path=args.query_plan,
        inventory_path=args.inventory,
        inventory_manifest_path=args.inventory_manifest,
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
        import_manifest_path=args.import_manifest,
        source_root=args.source_root,
        receipt_root=args.receipt_root,
        positive_projection_path=args.positive_projection,
        authority_projection_path=args.authority_projection,
        output_queue_path=args.output_queue,
        output_manifest_path=args.output_manifest,
        block_window_path=args.block_window,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
