from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.qualification import preflight_control_inputs


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed preflight for the Stage 2 matched-control inputs."
    )
    parser.add_argument("--positives", type=Path, required=True)
    parser.add_argument("--denominator", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    positives_path = args.positives.resolve(strict=True)
    denominator_path = args.denominator.resolve(strict=True)
    if positives_path.is_symlink() or denominator_path.is_symlink():
        raise ValueError("control preflight inputs must be ordinary files, not symlinks")

    report = preflight_control_inputs(
        pd.read_csv(positives_path, dtype=str, keep_default_na=False, low_memory=False),
        pd.read_csv(denominator_path, dtype=str, keep_default_na=False, low_memory=False),
    )
    report["inputs"] = {
        "positives": {"path": str(positives_path), "sha256": _sha256_file(positives_path)},
        "denominator": {"path": str(denominator_path), "sha256": _sha256_file(denominator_path)},
    }
    if args.output:
        _atomic_write_json(args.output.resolve(), report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["decision"] == "READY_FOR_CANDIDATE_SELECTION" else 3


if __name__ == "__main__":
    raise SystemExit(main())
