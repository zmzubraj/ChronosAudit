from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_historical_expansion_query_plan import (
    build_historical_expansion_query_plan,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze a non-authorizing Stage 2 historical expansion query plan."
    )
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--inventory-manifest", type=Path, required=True)
    parser.add_argument("--chunk-plan", type=Path, required=True)
    parser.add_argument("--chunk-manifest", type=Path, required=True)
    parser.add_argument("--historical-end-exclusive", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = build_historical_expansion_query_plan(
        inventory_path=args.inventory,
        inventory_manifest_path=args.inventory_manifest,
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
        historical_end_exclusive=args.historical_end_exclusive,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(args.output), **plan}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
