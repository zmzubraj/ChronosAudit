from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_historical_source_import import (
    verify_historical_source_import,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify exact Stage 2 historical source files and receipts."
    )
    parser.add_argument("--query-plan", type=Path, required=True)
    parser.add_argument("--import-manifest", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()
    report = verify_historical_source_import(
        query_plan_path=args.query_plan,
        import_manifest_path=args.import_manifest,
        source_root=args.source_root,
        receipt_root=args.receipt_root,
    )
    output = args.output_report.expanduser().resolve(strict=False)
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
