from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_trace_targets import (
    build_effective_trace_target_identities,
)


def _source(value: str) -> tuple[Path, Path]:
    manifest, separator, complete = value.partition("::")
    if not separator or not manifest or not complete:
        raise argparse.ArgumentTypeError(
            "source must be RECONCILIATION_MANIFEST::COMPLETE_CSV"
        )
    return Path(manifest), Path(complete)


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
            "Freeze exact unresolved trace identities from terminal effective "
            "candidate reconciliations. This grants no RPC, admission, selection, "
            "qualification, counter, or stage authority."
        )
    )
    parser.add_argument(
        "--source",
        action="append",
        type=_source,
        required=True,
        help=(
            "Repeat as RECONCILIATION_MANIFEST::COMPLETE_CSV for each immutable "
            "effective source."
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = build_effective_trace_target_identities(sources=args.source)
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, payload)
    print(
        json.dumps(
            {
                "chain_target_counts": payload["chain_target_counts"],
                "rpc_authorized": False,
                "selection_authorized": False,
                "source_reconciliation_count": payload[
                    "source_reconciliation_count"
                ],
                "target_count": payload["target_count"],
                "target_identities_sha256": payload["target_identities_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
