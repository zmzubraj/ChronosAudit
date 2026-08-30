from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_block_window_resolution import (
    resolve_control_block_windows,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve local-test control block windows.")
    parser.add_argument("--chunk-plan", type=Path, required=True)
    parser.add_argument("--source-import-manifest", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=16)
    args = parser.parse_args()
    report = resolve_control_block_windows(
        chunk_plan_path=args.chunk_plan,
        source_import_manifest_path=args.source_import_manifest,
        output_csv_path=args.output_csv,
        output_manifest_path=args.output_manifest,
        receipt_root=args.receipt_root,
        workers=args.workers,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
