from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_historical_candidate_queue import (
    verify_historical_candidate_queue,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a frozen non-authorizing Stage 2 historical reserve queue."
    )
    for name in (
        "queue",
        "manifest",
        "query-plan",
        "chunk-plan",
        "positive-projection",
        "authority-projection",
        "import-manifest",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--block-window", type=Path)
    parser.add_argument("--output-report", type=Path)
    args = parser.parse_args()
    report = verify_historical_candidate_queue(
        queue_path=args.queue,
        manifest_path=args.manifest,
        query_plan_path=args.query_plan,
        chunk_plan_path=args.chunk_plan,
        positive_projection_path=args.positive_projection,
        authority_projection_path=args.authority_projection,
        import_manifest_path=args.import_manifest,
        block_window_path=args.block_window,
    )
    if args.output_report:
        output = args.output_report.expanduser().resolve(strict=False)
        sources = {
            value.expanduser().resolve(strict=True)
            for value in (
                args.queue,
                args.manifest,
                args.query_plan,
                args.chunk_plan,
                args.positive_projection,
                args.authority_projection,
                args.import_manifest,
                *([args.block_window] if args.block_window else []),
            )
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
