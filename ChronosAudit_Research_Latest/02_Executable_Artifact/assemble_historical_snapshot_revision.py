#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.historical_snapshot_revision_run import (
    assemble_historical_snapshot_revision,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble a sealed historical snapshot revision offline.")
    parser.add_argument("--parent-run-root", required=True)
    parser.add_argument("--parent-report-root", required=True)
    parser.add_argument("--candidate-run-root", required=True)
    parser.add_argument("--candidate-report-root", required=True)
    parser.add_argument("--finalization-root", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    try:
        result = assemble_historical_snapshot_revision(
            parent_run_root=args.parent_run_root,
            parent_report_root=args.parent_report_root,
            candidate_run_root=args.candidate_run_root,
            candidate_report_root=args.candidate_report_root,
            finalization_root=args.finalization_root,
            output_dir=args.output_dir,
        )
    except Exception:
        print(
            json.dumps(
                {
                    "error": "historical_snapshot_revision_assembly_failed",
                    "code": "assembly_failed",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
