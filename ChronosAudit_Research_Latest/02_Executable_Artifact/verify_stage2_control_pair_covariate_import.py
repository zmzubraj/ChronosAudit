from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_pair_covariate_import import (
    verify_control_pair_covariate_batch,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_csv(path: Path, frame: pd.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        frame.to_csv(handle, index=False)
        temporary = Path(handle.name)
    os.replace(temporary, path)


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
            "Verify a pair-specific Stage 2 covariate evidence batch against "
            "the frozen scope, raw receipts, and optional accepted-import ledger."
        )
    )
    parser.add_argument("--pair-scope", type=Path, required=True)
    parser.add_argument("--evidence-csv", type=Path, required=True)
    parser.add_argument("--batch-manifest", type=Path, required=True)
    parser.add_argument("--raw-evidence-root", type=Path, required=True)
    parser.add_argument("--accepted-ledger", type=Path)
    parser.add_argument("--output-verified-csv", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()

    source_paths = {
        args.pair_scope.expanduser().resolve(strict=True),
        args.evidence_csv.expanduser().resolve(strict=True),
        args.batch_manifest.expanduser().resolve(strict=True),
    }
    if args.accepted_ledger:
        source_paths.add(args.accepted_ledger.expanduser().resolve(strict=True))
    output_csv = args.output_verified_csv.expanduser().resolve(strict=False)
    output_report = args.output_report.expanduser().resolve(strict=False)
    if output_csv == output_report:
        raise ValueError("verified CSV and report outputs must be distinct")
    if {output_csv, output_report} & source_paths:
        raise ValueError("verification outputs must not overwrite source artifacts")

    verified, report = verify_control_pair_covariate_batch(
        pair_scope_path=args.pair_scope,
        evidence_csv_path=args.evidence_csv,
        batch_manifest_path=args.batch_manifest,
        raw_evidence_root=args.raw_evidence_root,
        accepted_ledger_path=args.accepted_ledger,
    )
    _atomic_write_csv(output_csv, verified)
    report["output"] = {"path": str(output_csv), "sha256": _sha256_file(output_csv)}
    _atomic_write_json(output_report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
