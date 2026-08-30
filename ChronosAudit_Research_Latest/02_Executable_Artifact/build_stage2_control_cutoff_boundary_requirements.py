from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_requirements import (
    build_cutoff_boundary_requirements,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze bounded cutoff-block search requirements from verified "
            "reserve pair scope and non-independent local-test block windows. "
            "This does not resolve final cutoff blocks or authorize RPC."
        )
    )
    parser.add_argument("--reserve-pair-scope", type=Path, required=True)
    parser.add_argument("--block-windows", type=Path, required=True)
    parser.add_argument("--block-windows-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = build_cutoff_boundary_requirements(
        reserve_pair_scope_path=args.reserve_pair_scope,
        block_windows_path=args.block_windows,
        block_windows_manifest_path=args.block_windows_manifest,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, payload)
    print(
        json.dumps(
            {
                "boundary_target_count": payload["boundary_target_count"],
                "case_count": payload["case_count"],
                "complete": payload["complete"],
                "pair_scope_record_count": payload["pair_scope_record_count"],
                "requirements_sha256": payload["requirements_sha256"],
                "rpc_authorized": False,
                "selection_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
