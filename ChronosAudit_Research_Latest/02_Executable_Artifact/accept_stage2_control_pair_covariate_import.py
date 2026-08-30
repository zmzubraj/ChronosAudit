from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_pair_covariate_import import (
    build_updated_import_ledger,
)


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Append one independently verified Stage 2 pair-covariate batch to "
            "a hash-chained acceptance ledger. This does not authorize selection."
        )
    )
    parser.add_argument("--verification-report", type=Path, required=True)
    parser.add_argument("--batch-manifest", type=Path, required=True)
    parser.add_argument("--evidence-csv", type=Path, required=True)
    parser.add_argument("--accepted-at-utc", required=True)
    parser.add_argument("--existing-ledger", type=Path)
    parser.add_argument("--output-ledger", type=Path, required=True)
    args = parser.parse_args()

    sources = {
        args.verification_report.expanduser().resolve(strict=True),
        args.batch_manifest.expanduser().resolve(strict=True),
        args.evidence_csv.expanduser().resolve(strict=True),
    }
    if args.existing_ledger:
        sources.add(args.existing_ledger.expanduser().resolve(strict=True))
    output = args.output_ledger.expanduser().resolve(strict=False)
    if output in sources:
        raise ValueError(
            "output ledger must be a distinct review artifact; do not overwrite inputs"
        )

    ledger = build_updated_import_ledger(
        verification_report_path=args.verification_report,
        batch_manifest_path=args.batch_manifest,
        evidence_csv_path=args.evidence_csv,
        accepted_at_utc=args.accepted_at_utc,
        existing_ledger_path=args.existing_ledger,
    )
    _atomic_write_json(output, ledger)
    summary = {
        "decision": "VERIFIED_BATCH_APPENDED_TO_REVIEW_LEDGER",
        "selection_authorized": False,
        "accepted_batch_count": ledger["accepted_batch_count"],
        "accepted_pair_count": ledger["accepted_pair_count"],
        "head_entry_sha256": ledger["head_entry_sha256"],
        "output_ledger": str(output),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
