from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_historical_expansion_query_plan import (
    verify_historical_expansion_query_plan,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a persisted non-authorizing Stage 2 historical query plan."
    )
    parser.add_argument("--query-plan", type=Path, required=True)
    parser.add_argument("--chunk-plan", type=Path, required=True)
    parser.add_argument("--chunk-manifest", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()
    report = verify_historical_expansion_query_plan(
        query_plan_path=args.query_plan,
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
    )
    output = args.output_report.expanduser().resolve(strict=False)
    sources = {
        args.query_plan.expanduser().resolve(strict=True),
        args.chunk_plan.expanduser().resolve(strict=True),
        args.chunk_manifest.expanduser().resolve(strict=True),
    }
    if output in sources:
        raise ValueError("verification output must not overwrite an input")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output.parent, delete=False
    ) as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
