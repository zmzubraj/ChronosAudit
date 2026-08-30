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

from chronosaudit_stage2.public_acquisition.control_denominator_authority_bridge import (
    build_control_denominator_authority_bridge,
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
            "Build an additive Stage 2 control denominator authority projection "
            "from the sealed Recovery3 verified projection."
        )
    )
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--verification-report", type=Path, required=True)
    parser.add_argument("--final-seal", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()

    source_paths = {
        args.projection.expanduser().resolve(strict=True),
        args.verification_report.expanduser().resolve(strict=True),
        args.final_seal.expanduser().resolve(strict=True),
    }
    output_csv = args.output_csv.expanduser().resolve(strict=False)
    output_manifest = args.output_manifest.expanduser().resolve(strict=False)
    if output_csv in source_paths or output_manifest in source_paths:
        raise ValueError("bridge outputs must not overwrite Recovery3 source artifacts")
    if output_csv == output_manifest:
        raise ValueError("bridge CSV and manifest outputs must be different files")

    bridged, manifest = build_control_denominator_authority_bridge(
        projection_path=args.projection,
        verification_report_path=args.verification_report,
        final_seal_path=args.final_seal,
    )
    _atomic_write_csv(output_csv, bridged)
    manifest["output"] = {
        "path": str(output_csv),
        "sha256": _sha256_file(output_csv),
    }
    _atomic_write_json(output_manifest, manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
