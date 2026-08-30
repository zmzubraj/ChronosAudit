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

from chronosaudit_stage2.public_acquisition.control_covariate_projection import (
    build_denominator_covariate_projection,
    build_positive_covariate_projection,
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
            "Project only frozen, evidence-supported Stage 2 control covariates. "
            "Unsupported fields remain blank and selection remains unauthorized."
        )
    )
    parser.add_argument("--positives", type=Path, required=True)
    parser.add_argument("--verified-projection", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--authority-denominator", type=Path, required=True)
    parser.add_argument("--positive-output", type=Path, required=True)
    parser.add_argument("--denominator-output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    args = parser.parse_args()

    source_paths = {
        args.positives.expanduser().resolve(strict=True),
        args.verified_projection.expanduser().resolve(strict=True),
        args.authority_denominator.expanduser().resolve(strict=True),
    }
    args.snapshot_root.expanduser().resolve(strict=True)
    output_paths = {
        args.positive_output.expanduser().resolve(strict=False),
        args.denominator_output.expanduser().resolve(strict=False),
        args.manifest_output.expanduser().resolve(strict=False),
    }
    if len(output_paths) != 3:
        raise ValueError("covariate projection outputs must be three distinct files")
    if source_paths & output_paths:
        raise ValueError("covariate projections must not overwrite source artifacts")

    positives, positive_manifest = build_positive_covariate_projection(
        positives_path=args.positives,
        verified_projection_path=args.verified_projection,
        snapshot_root=args.snapshot_root,
    )
    denominator, denominator_manifest = build_denominator_covariate_projection(
        authority_projection_path=args.authority_denominator
    )

    positive_output = args.positive_output.expanduser().resolve(strict=False)
    denominator_output = args.denominator_output.expanduser().resolve(strict=False)
    manifest_output = args.manifest_output.expanduser().resolve(strict=False)
    _atomic_write_csv(positive_output, positives)
    _atomic_write_csv(denominator_output, denominator)

    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_covariate_projection_bundle.v1",
        "decision": "PARTIAL_COVARIATE_PROJECTION",
        "selection_authorized": False,
        "positive_projection": positive_manifest,
        "denominator_projection": denominator_manifest,
        "outputs": {
            "positive_projection": {
                "path": str(positive_output),
                "sha256": _sha256_file(positive_output),
            },
            "denominator_projection": {
                "path": str(denominator_output),
                "sha256": _sha256_file(denominator_output),
            },
        },
    }
    _atomic_write_json(manifest_output, manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
