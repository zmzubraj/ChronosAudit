from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_qualification_approval import (
    build_control_qualification_approval_request,
)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the exact non-authorizing Stage 2 control-qualification "
            "approval request."
        )
    )
    parser.add_argument("--candidate-rows", type=Path, required=True)
    parser.add_argument("--check-rows", type=Path, required=True)
    parser.add_argument("--positive-cases", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--expected-positive-rows", type=int, default=417)
    parser.add_argument("--controls-per-positive", type=int, default=10)
    parser.add_argument("--output-request", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        value.expanduser().resolve(strict=True)
        for value in (args.candidate_rows, args.check_rows, args.positive_cases)
    }
    output = args.output_request.expanduser().resolve(strict=False)
    if output in inputs:
        raise ValueError("request output must not overwrite an input")
    request = build_control_qualification_approval_request(
        candidate_rows_path=args.candidate_rows,
        check_rows_path=args.check_rows,
        positive_cases_path=args.positive_cases,
        evidence_root=args.evidence_root,
        expected_positive_rows=args.expected_positive_rows,
        controls_per_positive=args.controls_per_positive,
    )
    encoded = (json.dumps(request, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(output, encoded)
    print(encoded.decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
