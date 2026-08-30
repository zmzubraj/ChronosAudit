from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_pair_feature_projection import (
    ControlPairFeatureProjectionError,
    build_pair_feature,
    project_pair_features,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _records(path: Path, label: str) -> list[dict[str, object]]:
    payload = json.loads(path.expanduser().resolve(strict=True).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ControlPairFeatureProjectionError(f"{label}_root_invalid")
    rows = payload.get("targets", payload.get("records"))
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ControlPairFeatureProjectionError(f"{label}_records_invalid")
    return rows


def _identity(row: dict[str, object]) -> tuple[str, str, str]:
    case = str(row.get("case_name", row.get("case_id", row.get("positive_case_id", ""))))
    chain = str(row.get("chain", "")).lower()
    address = str(row.get("control_address", "")).lower()
    if not address and row.get("chain_address"):
        address = str(row["chain_address"]).split(":", 1)[-1].lower()
    return case, chain, address


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build deterministic, non-authorizing cutoff-safe Stage 2 pair features."
    )
    parser.add_argument("--pair-scope", type=Path, required=True)
    parser.add_argument("--denominator", type=Path, required=True)
    parser.add_argument("--trace-results", type=Path, required=True)
    parser.add_argument("--trace-checkpoint", type=Path, required=True)
    parser.add_argument("--state-results", type=Path, required=True)
    parser.add_argument("--state-checkpoint", type=Path, required=True)
    parser.add_argument("--source-records", type=Path)
    parser.add_argument("--protocol-records", type=Path)
    parser.add_argument("--dynamic-horizon-spec", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    pair_scope = pd.read_csv(
        args.pair_scope.expanduser().resolve(strict=True), keep_default_na=False
    ).to_dict("records")
    denominator_rows = pd.read_csv(
        args.denominator.expanduser().resolve(strict=True), keep_default_na=False
    ).to_dict("records")
    traces = _records(args.trace_results, "trace_results")
    states = _records(args.state_results, "state_results")
    sources = _records(args.source_records, "source_records") if args.source_records else []
    protocols = _records(args.protocol_records, "protocol_records") if args.protocol_records else []
    denominator_by_hash = {
        str(row.get("denominator_record_sha256", "")).lower(): row
        for row in denominator_rows
    }
    trace_by_identity = {_identity(row): row for row in traces}
    state_by_identity = {_identity(row): row for row in states}
    source_by_identity = {_identity(row): row for row in sources}
    protocol_by_identity = {_identity(row): row for row in protocols}
    spec_sha = _sha(args.dynamic_horizon_spec.expanduser().resolve(strict=True))
    rows = []
    for scope in pair_scope:
        identity = _identity(scope)
        denominator_hash = str(scope.get("denominator_record_sha256", "")).lower()
        if denominator_hash not in denominator_by_hash:
            raise ControlPairFeatureProjectionError("denominator_record_missing")
        if identity not in trace_by_identity:
            raise ControlPairFeatureProjectionError("trace_result_missing")
        if identity not in state_by_identity:
            raise ControlPairFeatureProjectionError("state_result_missing")
        rows.append(build_pair_feature(
            pair_scope=scope,
            denominator=denominator_by_hash[denominator_hash],
            trace=trace_by_identity[identity],
            state=state_by_identity[identity],
            source=source_by_identity.get(identity),
            protocol=protocol_by_identity.get(identity),
            dynamic_horizon_spec_sha256=spec_sha,
        ))
    upstream_artifacts = {
        "pair_scope": args.pair_scope,
        "denominator": args.denominator,
        "trace_results": args.trace_results,
        "trace_checkpoint": args.trace_checkpoint,
        "state_results": args.state_results,
        "state_checkpoint": args.state_checkpoint,
        "dynamic_horizon_spec": args.dynamic_horizon_spec,
    }
    if args.source_records:
        upstream_artifacts["source_records"] = args.source_records
    if args.protocol_records:
        upstream_artifacts["protocol_records"] = args.protocol_records
    result = project_pair_features(
        rows=rows,
        output_root=args.output_root,
        upstream_artifacts=upstream_artifacts,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
