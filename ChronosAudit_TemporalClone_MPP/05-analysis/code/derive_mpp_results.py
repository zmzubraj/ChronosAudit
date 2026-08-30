#!/usr/bin/env python3
"""Deterministic derivation for the ChronosAudit TemporalClone MPP.

The script is intentionally standard-library only. It consumes the frozen
per-case JSON envelopes, validates the minimum evidentiary contract, and emits
machine-readable descriptive results. It does not perform RPC collection,
prediction, matched-control analysis, or causal inference.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ANALYSIS_VERSION = "temporalclone-mpp-v1"
REQUIRED_PROVIDERS = {"alchemy", "infura"}
LANDMARKS = (("eligible_1h", 1.0), ("eligible_24h", 24.0), ("eligible_7d", 168.0), ("eligible_30d", 720.0))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentile_linear(values: Iterable[float], quantile: float) -> float:
    """Return the R-7 / NumPy-default linearly interpolated percentile."""
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be in [0, 1]")
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Two-sided 95% Wilson score interval for a binomial proportion."""
    if total <= 0 or successes < 0 or successes > total:
        raise ValueError("Wilson interval requires 0 <= successes <= total and total > 0")
    proportion = successes / total
    denominator = 1.0 + z * z / total
    centre = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def landmark_eligibility(deployment_to_incident_hours: float) -> dict[str, bool]:
    """Whether the contract existed at each prespecified pre-incident landmark."""
    age_at_incident = float(deployment_to_incident_hours)
    return {name: age_at_incident >= threshold for name, threshold in LANDMARKS}


def _required(mapping: dict[str, Any], key: str, context: str) -> Any:
    if key not in mapping or mapping[key] is None:
        raise ValueError(f"{context}: missing required field {key}")
    return mapping[key]


def _normalize_optional_address(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text or text in {"0x", "0x0", "0x" + "0" * 40, "0x" + "0" * 64}:
        return None
    return text


def extract_case(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    case_id = str(_required(payload, "case_id", path.name))
    if payload.get("status") != "VERIFIED":
        raise ValueError(f"{case_id}: status must be VERIFIED")
    if payload.get("strict_snapshot_closed") is not True:
        raise ValueError(f"{case_id}: top-level strict_snapshot_closed must be true")

    snapshot_envelope = _required(payload, "strict_snapshot", case_id)
    if snapshot_envelope.get("strict_snapshot_closed") is not True:
        raise ValueError(f"{case_id}: strict_snapshot.strict_snapshot_closed must be true")
    if str(snapshot_envelope.get("case_id")) != case_id:
        raise ValueError(f"{case_id}: nested case_id mismatch")
    provider_families = {str(value).lower() for value in snapshot_envelope.get("provider_families", [])}
    if provider_families != REQUIRED_PROVIDERS:
        raise ValueError(f"{case_id}: provider_families must equal {sorted(REQUIRED_PROVIDERS)}")
    if snapshot_envelope.get("blockers") not in ([], None):
        raise ValueError(f"{case_id}: blockers must be empty")

    chain = str(_required(snapshot_envelope, "chain", case_id)).lower()
    address = str(_required(snapshot_envelope, "address", case_id)).lower()
    lead_hours = float(_required(snapshot_envelope, "cutoff_lead_hours", case_id))
    deployment = int(_required(snapshot_envelope, "deployment_timestamp", case_id))
    cutoff = int(_required(snapshot_envelope, "prediction_cutoff_timestamp", case_id))
    incident = int(_required(snapshot_envelope, "incident_timestamp", case_id))
    if not deployment < cutoff < incident:
        raise ValueError(f"{case_id}: timestamps must satisfy deployment < cutoff < incident")
    derived_lead = (incident - cutoff) / 3600.0
    if not math.isclose(lead_hours, derived_lead, rel_tol=0.0, abs_tol=0.02):
        raise ValueError(f"{case_id}: cutoff_lead_hours disagrees with timestamps")

    snapshot = _required(snapshot_envelope, "snapshot", case_id)
    runtime_hash = str(_required(snapshot, "runtime_bytecode_sha256", case_id)).lower()
    stripped_hash = str(_required(snapshot, "metadata_stripped_bytecode_sha256", case_id)).lower()
    implementation = _normalize_optional_address((snapshot.get("implementation") or {}).get("value"))
    admin = _normalize_optional_address((snapshot.get("admin") or {}).get("value"))
    beacon = _normalize_optional_address((snapshot.get("beacon") or {}).get("value"))
    beacon_implementation = _normalize_optional_address((snapshot.get("beacon_implementation") or {}).get("value"))
    eip1167_target = _normalize_optional_address(snapshot.get("eip1167_target"))
    any_proxy = any((implementation, beacon, eip1167_target))

    deployment_to_incident_hours = (incident - deployment) / 3600.0
    row = {
        "case_id": case_id,
        "source_file": path.name,
        "source_sha256": sha256_file(path),
        "chain": chain,
        "address": address,
        "chain_address": f"{chain}:{address}",
        "runtime_bytecode_sha256": runtime_hash,
        "metadata_stripped_bytecode_sha256": stripped_hash,
        "metadata_status": str(snapshot.get("metadata_status") or "unknown"),
        "deployment_timestamp": deployment,
        "prediction_cutoff_timestamp": cutoff,
        "incident_timestamp": incident,
        "cutoff_lead_hours": lead_hours,
        "deployment_to_incident_hours": deployment_to_incident_hours,
        "implementation_address": implementation or "",
        "admin_address": admin or "",
        "beacon_address": beacon or "",
        "beacon_implementation_address": beacon_implementation or "",
        "eip1167_target": eip1167_target or "",
        "has_implementation": implementation is not None,
        "has_admin": admin is not None,
        "has_beacon": beacon is not None,
        "has_eip1167_target": eip1167_target is not None,
        "has_any_proxy_indicator": any_proxy,
    }
    row.update(landmark_eligibility(deployment_to_incident_hours))
    return row


def _identity_groups(rows: list[dict[str, Any]], field: str, abstraction: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row[field])].append(row)
    output = []
    for key in sorted(grouped):
        members = grouped[key]
        chains = sorted({str(row["chain"]) for row in members})
        addresses = sorted({str(row["address"]) for row in members})
        output.append(
            {
                "abstraction": abstraction,
                "identity_key": key,
                "n_cases": len(members),
                "n_chains": len(chains),
                "n_addresses": len(addresses),
                "cross_chain": len(chains) > 1,
                "cross_address": len(addresses) > 1,
                "chains": "|".join(chains),
                "addresses": "|".join(addresses),
                "case_ids": "|".join(sorted(str(row["case_id"]) for row in members)),
            }
        )
    return output


def _identity_summary(groups: list[dict[str, Any]]) -> dict[str, int]:
    duplicates = [group for group in groups if int(group["n_cases"]) > 1]
    cross_address = [group for group in duplicates if group["cross_address"]]
    cross_chain = [group for group in duplicates if group["cross_chain"]]
    return {
        "unique_identities": len(groups),
        "duplicate_groups": len(duplicates),
        "duplicate_rows": sum(int(group["n_cases"]) for group in duplicates),
        "maximum_group_size": max(int(group["n_cases"]) for group in groups),
        "cross_address_duplicate_groups": len(cross_address),
        "cross_address_duplicate_rows": sum(int(group["n_cases"]) for group in cross_address),
        "cross_chain_duplicate_groups": len(cross_chain),
        "cross_chain_duplicate_rows": sum(int(group["n_cases"]) for group in cross_chain),
    }


def _proportion_record(successes: int, total: int) -> dict[str, float | int]:
    low, high = wilson_interval(successes, total)
    return {
        "n": successes,
        "denominator": total,
        "proportion": successes / total,
        "wilson_95_low": low,
        "wilson_95_high": high,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run_analysis(
    cases_dir: Path,
    output_dir: Path,
    *,
    expected_count: int = 417,
    provenance_manifest: Path | None = None,
) -> dict[str, Any]:
    paths = sorted(cases_dir.glob("*.json"))
    if len(paths) != expected_count:
        raise ValueError(f"expected {expected_count} JSON cases, found {len(paths)}")
    rows = sorted((extract_case(path) for path in paths), key=lambda row: str(row["case_id"]))
    case_ids = [str(row["case_id"]) for row in rows]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("case_id values must be unique")

    identity_specs = [
        ("chain_address", "chain_address"),
        ("address", "address_only"),
        ("runtime_bytecode_sha256", "runtime_bytecode"),
        ("metadata_stripped_bytecode_sha256", "metadata_stripped_bytecode"),
    ]
    all_groups: list[dict[str, Any]] = []
    identity_summaries: dict[str, dict[str, int]] = {}
    for field, abstraction in identity_specs:
        groups = _identity_groups(rows, field, abstraction)
        all_groups.extend(groups)
        identity_summaries[abstraction] = _identity_summary(groups)

    n_cases = len(rows)
    lead_values = [float(row["cutoff_lead_hours"]) for row in rows]
    deployment_values = [float(row["deployment_to_incident_hours"]) for row in rows]
    temporal = {
        name: _proportion_record(sum(bool(row[name]) for row in rows), n_cases)
        for name, _threshold in LANDMARKS
    }
    proxy = {
        "implementation_slot": _proportion_record(sum(bool(row["has_implementation"]) for row in rows), n_cases),
        "admin_slot": _proportion_record(sum(bool(row["has_admin"]) for row in rows), n_cases),
        "beacon_slot": _proportion_record(sum(bool(row["has_beacon"]) for row in rows), n_cases),
        "eip1167_target": _proportion_record(sum(bool(row["has_eip1167_target"]) for row in rows), n_cases),
        "any_proxy_indicator": _proportion_record(sum(bool(row["has_any_proxy_indicator"]) for row in rows), n_cases),
    }

    summary: dict[str, Any] = {
        "analysis_version": ANALYSIS_VERSION,
        "cohort": {
            "n_cases": n_cases,
            "status_verified": n_cases,
            "strict_snapshot_closed": n_cases,
            "provider_families": sorted(REQUIRED_PROVIDERS),
            "chains": dict(sorted(Counter(str(row["chain"]) for row in rows).items())),
        },
        "temporal_eligibility": temporal,
        "cutoff_lead_hours": {
            "minimum": min(lead_values),
            "p10": percentile_linear(lead_values, 0.10),
            "p25": percentile_linear(lead_values, 0.25),
            "median": percentile_linear(lead_values, 0.50),
            "p75": percentile_linear(lead_values, 0.75),
            "p90": percentile_linear(lead_values, 0.90),
            "maximum": max(lead_values),
        },
        "deployment_to_incident_hours": {
            "minimum": min(deployment_values),
            "median": percentile_linear(deployment_values, 0.50),
            "maximum": max(deployment_values),
        },
        "identity_abstractions": identity_summaries,
        "proxy_linkage": proxy,
        "interpretation_boundary": "Descriptive benchmark-validity audit; no prediction, causal risk, or matched-control inference.",
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows = [
        {
            "case_id": row["case_id"],
            "source_file": row["source_file"],
            "sha256": row["source_sha256"],
            "status": "VERIFIED",
            "strict_snapshot_closed": True,
            "provider_families": "alchemy|infura",
        }
        for row in rows
    ]
    manifest_fields = ["case_id", "source_file", "sha256", "status", "strict_snapshot_closed", "provider_families"]
    _write_csv(output_dir / "input-manifest.csv", manifest_rows, manifest_fields)
    if provenance_manifest is not None:
        _write_csv(provenance_manifest, manifest_rows, manifest_fields)

    analysis_fields = [
        "case_id", "source_file", "source_sha256", "chain", "address", "chain_address",
        "runtime_bytecode_sha256", "metadata_stripped_bytecode_sha256", "metadata_status",
        "deployment_timestamp", "prediction_cutoff_timestamp", "incident_timestamp",
        "cutoff_lead_hours", "deployment_to_incident_hours", "eligible_1h", "eligible_24h",
        "eligible_7d", "eligible_30d", "implementation_address", "admin_address", "beacon_address",
        "beacon_implementation_address", "eip1167_target", "has_implementation", "has_admin",
        "has_beacon", "has_eip1167_target", "has_any_proxy_indicator",
    ]
    _write_csv(output_dir / "analysis_cases.csv", rows, analysis_fields)
    group_fields = [
        "abstraction", "identity_key", "n_cases", "n_chains", "n_addresses", "cross_chain",
        "cross_address", "chains", "addresses", "case_ids",
    ]
    _write_csv(output_dir / "identity-groups.csv", all_groups, group_fields)
    proxy_rows = [
        {
            "case_id": row["case_id"],
            "chain": row["chain"],
            "address": row["address"],
            "implementation_address": row["implementation_address"],
            "admin_address": row["admin_address"],
            "beacon_address": row["beacon_address"],
            "beacon_implementation_address": row["beacon_implementation_address"],
            "eip1167_target": row["eip1167_target"],
            "has_any_proxy_indicator": row["has_any_proxy_indicator"],
        }
        for row in rows
        if row["has_any_proxy_indicator"] or row["has_admin"]
    ]
    _write_csv(
        output_dir / "proxy-linkage.csv",
        proxy_rows,
        ["case_id", "chain", "address", "implementation_address", "admin_address", "beacon_address", "beacon_implementation_address", "eip1167_target", "has_any_proxy_indicator"],
    )
    (output_dir / "results-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-count", type=int, default=417)
    parser.add_argument("--provenance-manifest", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = run_analysis(
        args.cases_dir,
        args.output_dir,
        expected_count=args.expected_count,
        provenance_manifest=args.provenance_manifest,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
