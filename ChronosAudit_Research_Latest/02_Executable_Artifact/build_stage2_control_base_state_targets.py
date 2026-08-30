from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_base_state_targets import (
    build_base_state_targets,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze fixed-address Stage 2 cutoff-state targets from a complete "
            "dual-provider boundary batch. This does not authorize RPC, "
            "derived-address reads, selection, or stage promotion."
        )
    )
    parser.add_argument("--reserve-pair-scope", type=Path, required=True)
    parser.add_argument("--boundary-results", type=Path, required=True)
    parser.add_argument(
        "--provider-registry",
        type=Path,
        help=(
            "Rebind Phase 1 calls to the exact two independently owned, "
            "verified providers per chain in this registry. The completed "
            "boundary packet remains the cutoff-block evidence."
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = build_base_state_targets(
        reserve_pair_scope_path=args.reserve_pair_scope,
        boundary_results_path=args.boundary_results,
        provider_registry_path=args.provider_registry,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, payload)
    print(
        json.dumps(
            {
                "call_count": payload["call_count"],
                "complete": payload["complete"],
                "derived_address_reads_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
                "target_count": payload["target_count"],
                "targets_sha256": payload["targets_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
