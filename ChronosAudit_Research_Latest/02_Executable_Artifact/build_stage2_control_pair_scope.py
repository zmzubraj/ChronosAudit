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

from chronosaudit_stage2.public_acquisition.control_pair_scope import (
    build_control_pair_acquisition_scope,
    build_denominator_expansion_requirements,
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
            "Freeze the deployment-only positive-control pair scope requiring "
            "covariate evidence at each positive prediction cutoff."
        )
    )
    parser.add_argument("--positives", type=Path, required=True)
    parser.add_argument("--authority-denominator", type=Path, required=True)
    parser.add_argument("--deployment-window-days", type=int, default=30)
    parser.add_argument("--controls-per-positive", type=int, default=10)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-expansion-requirements", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()

    positives_path = args.positives.expanduser().resolve(strict=True)
    denominator_path = args.authority_denominator.expanduser().resolve(strict=True)
    output_csv = args.output_csv.expanduser().resolve(strict=False)
    expansion_output = args.output_expansion_requirements.expanduser().resolve(strict=False)
    output_manifest = args.output_manifest.expanduser().resolve(strict=False)
    output_paths = {output_csv, expansion_output, output_manifest}
    if len(output_paths) != 3:
        raise ValueError("pair scope outputs must be three distinct files")
    if output_paths & {positives_path, denominator_path}:
        raise ValueError("pair scope outputs must not overwrite source artifacts")

    positives = pd.read_csv(
        positives_path, dtype=str, keep_default_na=False, low_memory=False
    )
    denominator = pd.read_csv(
        denominator_path, dtype=str, keep_default_na=False, low_memory=False
    )
    scope, manifest = build_control_pair_acquisition_scope(
        positives=positives,
        denominator=denominator,
        deployment_window_days=args.deployment_window_days,
        controls_per_positive=args.controls_per_positive,
    )
    expansion, expansion_manifest = build_denominator_expansion_requirements(
        positives=positives,
        scope=scope,
        deployment_window_days=args.deployment_window_days,
        controls_per_positive=args.controls_per_positive,
    )
    _atomic_write_csv(output_csv, scope)
    _atomic_write_csv(expansion_output, expansion)
    manifest["inputs"] = {
        "positives": {"path": str(positives_path), "sha256": _sha256_file(positives_path)},
        "authority_denominator": {
            "path": str(denominator_path),
            "sha256": _sha256_file(denominator_path),
        },
    }
    manifest["output"] = {"path": str(output_csv), "sha256": _sha256_file(output_csv)}
    manifest["expansion_requirements"] = expansion_manifest
    manifest["outputs"] = {
        "pair_scope": {"path": str(output_csv), "sha256": _sha256_file(output_csv)},
        "expansion_requirements": {
            "path": str(expansion_output),
            "sha256": _sha256_file(expansion_output),
        },
    }
    _atomic_write_json(output_manifest, manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
