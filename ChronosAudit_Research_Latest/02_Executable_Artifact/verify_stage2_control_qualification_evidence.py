from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_qualification_evidence import (
    verify_control_qualification_evidence_batch,
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
            "Verify a hash-bound Stage 2 eight-check control qualification evidence "
            "batch. A successful report remains non-authorizing."
        )
    )
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--checks", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()

    candidate_path = args.candidates.expanduser().resolve(strict=True)
    check_path = args.checks.expanduser().resolve(strict=True)
    evidence_root = args.evidence_root.expanduser().resolve(strict=True)
    output_path = args.output_report.expanduser().resolve(strict=False)
    if output_path in {candidate_path, check_path}:
        raise ValueError("verification output must not overwrite an input")

    report = verify_control_qualification_evidence_batch(
        candidate_rows=pd.read_csv(candidate_path),
        check_rows=pd.read_csv(check_path),
        evidence_root=evidence_root,
    )
    _atomic_write_json(output_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
