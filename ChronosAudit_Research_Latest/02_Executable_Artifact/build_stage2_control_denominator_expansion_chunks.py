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

from chronosaudit_stage2.public_acquisition.control_denominator_expansion_chunks import (
    build_control_denominator_expansion_chunks,
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
            "Partition the frozen Stage 2 historical-denominator deficit into "
            "bounded, disjoint, non-authorizing acquisition chunks."
        )
    )
    parser.add_argument("--expansion-requirements", type=Path, required=True)
    parser.add_argument("--pair-scope-manifest", type=Path, required=True)
    parser.add_argument("--authority-projection", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--max-cases-per-chunk", type=int, default=25)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()

    source_paths = {
        "expansion_requirements": args.expansion_requirements.expanduser().resolve(
            strict=True
        ),
        "pair_scope_manifest": args.pair_scope_manifest.expanduser().resolve(
            strict=True
        ),
        "authority_projection": args.authority_projection.expanduser().resolve(
            strict=True
        ),
        "policy": args.policy.expanduser().resolve(strict=True),
    }
    output_csv = args.output_csv.expanduser().resolve(strict=False)
    output_manifest = args.output_manifest.expanduser().resolve(strict=False)
    if output_csv == output_manifest:
        raise ValueError("chunk CSV and manifest outputs must be distinct")
    if {output_csv, output_manifest} & set(source_paths.values()):
        raise ValueError("chunk outputs must not overwrite source artifacts")

    requirements = pd.read_csv(
        source_paths["expansion_requirements"],
        dtype=str,
        keep_default_na=False,
        low_memory=False,
    )
    plan, manifest = build_control_denominator_expansion_chunks(
        requirements=requirements,
        expansion_ledger_sha256=_sha256_file(
            source_paths["expansion_requirements"]
        ),
        pair_scope_manifest_sha256=_sha256_file(
            source_paths["pair_scope_manifest"]
        ),
        authority_projection_sha256=_sha256_file(
            source_paths["authority_projection"]
        ),
        policy_sha256=_sha256_file(source_paths["policy"]),
        max_cases_per_chunk=args.max_cases_per_chunk,
    )
    _atomic_write_csv(output_csv, plan)
    manifest["source_paths"] = {
        label: str(path) for label, path in source_paths.items()
    }
    manifest["output"] = {
        "path": str(output_csv),
        "sha256": _sha256_file(output_csv),
    }
    _atomic_write_json(output_manifest, manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
