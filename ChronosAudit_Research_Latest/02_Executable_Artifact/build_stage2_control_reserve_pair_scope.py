from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_reserve_pair_scope import (
    build_reserve_pair_scope,
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
            "Bind verified reserve deployments to the frozen positive-specific "
            "cutoff-state acquisition scope. This does not add denominator, "
            "selection, qualification, or counter authority."
        )
    )
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--queue-manifest", type=Path, required=True)
    parser.add_argument("--queue-verification", type=Path, required=True)
    parser.add_argument("--expansion-requirements", type=Path, required=True)
    parser.add_argument("--pair-scope-manifest", type=Path, required=True)
    parser.add_argument("--reserve-deployment-projection", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = build_reserve_pair_scope(
        queue_path=args.queue,
        queue_manifest_path=args.queue_manifest,
        queue_verification_path=args.queue_verification,
        expansion_requirements_path=args.expansion_requirements,
        pair_scope_manifest_path=args.pair_scope_manifest,
        reserve_deployment_projection_path=args.reserve_deployment_projection,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, payload)
    print(
        json.dumps(
            {
                "complete": payload["complete"],
                "record_count": payload["record_count"],
                "pending_trace_count": payload["pending_trace_count"],
                "unprocessed_queue_count": payload["unprocessed_queue_count"],
                "projection_sha256": payload["projection_sha256"],
                "counter_authority": False,
                "selection_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
