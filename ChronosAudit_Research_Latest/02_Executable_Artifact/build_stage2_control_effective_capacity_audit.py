from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_capacity_audit import (
    build_effective_control_capacity_audit,
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
            "Audit exact post-reconciliation Stage 2 capacity while excluding "
            "unresolved trace-required candidates."
        )
    )
    parser.add_argument("--original-pair-scope", type=Path, required=True)
    parser.add_argument("--expansion-requirements", type=Path, required=True)
    parser.add_argument(
        "--source", action="append", type=_source, required=True,
        help="Repeat as RECONCILIATION_MANIFEST::COMPLETE_CSV.",
    )
    parser.add_argument("--trace-target-identities", type=Path, required=True)
    parser.add_argument("--trace-deployment-projection", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    audit = build_effective_control_capacity_audit(
        original_pair_scope_path=args.original_pair_scope,
        expansion_requirements_path=args.expansion_requirements,
        sources=args.source,
        trace_target_identities_path=args.trace_target_identities,
        trace_deployment_projection_path=args.trace_deployment_projection,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, audit)
    print(
        json.dumps(
            {
                "audit_sha256": audit["audit_sha256"],
                "denominator_qualifies": audit["denominator_qualifies"],
                "evidence_complete_candidate_count": audit[
                    "evidence_complete_candidate_count"
                ],
                "maximum_assignable_controls": audit[
                    "evidence_complete_capacity"
                ]["maximum_assignable_controls"],
                "target_control_rows": audit["target_control_rows"],
                "unresolved_trace_candidate_count": audit[
                    "unresolved_trace_candidate_count"
                ],
                "trace_closed_candidate_count": audit[
                    "trace_closed_candidate_count"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
