from __future__ import annotations

import hashlib
import json
from typing import Mapping

import pandas as pd


class ControlDenominatorExpansionChunkError(ValueError):
    """Raised when a denominator-expansion chunk plan is not authoritative."""


_REQUIRED_COLUMNS = {
    "case_name",
    "chain",
    "positive_deployment_time",
    "positive_prediction_cutoff_time",
    "positive_record_sha256",
    "admissible_deployment_start",
    "admissible_deployment_end",
    "existing_pair_count",
    "maximum_flow_allocated",
    "controls_required",
    "minimum_additional_distinct_slots",
    "require_new_chain_address_identity",
    "require_deployed_by_positive_cutoff",
    "require_pair_specific_cutoff_covariates",
    "expansion_status",
    "selection_authorized",
    "expansion_requirement_sha256",
}

_INTEGER_COLUMNS = {
    "existing_pair_count",
    "maximum_flow_allocated",
    "controls_required",
    "minimum_additional_distinct_slots",
}

_BOOLEAN_COLUMNS = {
    "require_new_chain_address_identity",
    "require_deployed_by_positive_cutoff",
    "require_pair_specific_cutoff_covariates",
    "selection_authorized",
}

_TIME_COLUMNS = {
    "positive_deployment_time",
    "positive_prediction_cutoff_time",
    "admissible_deployment_start",
    "admissible_deployment_end",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _integer(value: object, label: str) -> int:
    text = str(value).strip()
    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]
    try:
        number = int(text)
    except (TypeError, ValueError) as exc:
        raise ControlDenominatorExpansionChunkError(f"{label}_invalid") from exc
    if number < 0:
        raise ControlDenominatorExpansionChunkError(f"{label}_invalid")
    return number


def _boolean(value: object, label: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    raise ControlDenominatorExpansionChunkError(f"{label}_invalid")


def _time(value: object, label: str) -> str:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlDenominatorExpansionChunkError(f"{label}_invalid")
    return parsed.isoformat().replace("+00:00", "Z")


def _normalized_requirement(row: Mapping[str, object]) -> dict[str, object]:
    record: dict[str, object] = {}
    for field in _REQUIRED_COLUMNS - {"expansion_requirement_sha256"}:
        value = row.get(field)
        if field in _INTEGER_COLUMNS:
            record[field] = _integer(value, "deficit" if field == "minimum_additional_distinct_slots" else field)
        elif field in _BOOLEAN_COLUMNS:
            record[field] = _boolean(value, field)
        elif field in _TIME_COLUMNS:
            record[field] = _time(value, field)
        elif field in {"chain", "positive_record_sha256"}:
            record[field] = str(value or "").strip().lower()
        else:
            record[field] = str(value or "").strip()
        if record[field] == "":
            raise ControlDenominatorExpansionChunkError(f"{field}_empty")
    return record


def build_control_denominator_expansion_chunks(
    *,
    requirements: pd.DataFrame,
    expansion_ledger_sha256: str,
    pair_scope_manifest_sha256: str,
    authority_projection_sha256: str,
    policy_sha256: str,
    max_cases_per_chunk: int = 25,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Create a deterministic, disjoint, non-authorizing acquisition plan."""
    missing = sorted(_REQUIRED_COLUMNS - set(requirements.columns))
    if missing:
        raise ControlDenominatorExpansionChunkError(
            f"requirements_missing_columns:{','.join(missing)}"
        )
    if max_cases_per_chunk <= 0:
        raise ControlDenominatorExpansionChunkError("max_cases_per_chunk_invalid")
    governance_hashes = {
        "expansion_ledger_sha256": str(expansion_ledger_sha256).strip().lower(),
        "pair_scope_manifest_sha256": str(pair_scope_manifest_sha256).strip().lower(),
        "authority_projection_sha256": str(authority_projection_sha256).strip().lower(),
        "policy_sha256": str(policy_sha256).strip().lower(),
    }
    for label, value in governance_hashes.items():
        if not _is_sha256(value):
            raise ControlDenominatorExpansionChunkError(f"{label}_invalid")

    case_names = requirements["case_name"].astype(str).str.strip()
    if case_names.duplicated().any():
        raise ControlDenominatorExpansionChunkError("duplicate_case_name")
    requirement_hashes = (
        requirements["expansion_requirement_sha256"].astype(str).str.strip().str.lower()
    )
    if requirement_hashes.duplicated().any():
        raise ControlDenominatorExpansionChunkError("duplicate_requirement_hash")
    if not requirement_hashes.map(_is_sha256).all():
        raise ControlDenominatorExpansionChunkError("requirement_hash_invalid")

    normalized: list[dict[str, object]] = []
    for source in requirements.to_dict("records"):
        record = _normalized_requirement(source)
        expected_hash = str(source["expansion_requirement_sha256"]).strip().lower()
        deficit = int(record["minimum_additional_distinct_slots"])
        required = int(record["controls_required"])
        allocated = int(record["maximum_flow_allocated"])
        if deficit != max(0, required - allocated):
            raise ControlDenominatorExpansionChunkError("deficit_allocation_mismatch")
        if record["selection_authorized"] is not False:
            raise ControlDenominatorExpansionChunkError("selection_authorized_invalid")
        expected_status = (
            "HISTORICAL_DENOMINATOR_EXPANSION_REQUIRED"
            if deficit > 0
            else "NO_DEPLOYMENT_SCOPE_DEFICIT"
        )
        if record["expansion_status"] != expected_status:
            raise ControlDenominatorExpansionChunkError("expansion_status_invalid")
        if not all(
            record[field] is True
            for field in (
                "require_new_chain_address_identity",
                "require_deployed_by_positive_cutoff",
                "require_pair_specific_cutoff_covariates",
            )
        ):
            raise ControlDenominatorExpansionChunkError("requirement_guard_invalid")
        if not _is_sha256(record["positive_record_sha256"]):
            raise ControlDenominatorExpansionChunkError("positive_record_sha256_invalid")
        if _canonical_sha256(record) != expected_hash:
            raise ControlDenominatorExpansionChunkError("requirement_hash_mismatch")
        if deficit > 0:
            normalized.append({**record, "expansion_requirement_sha256": expected_hash})

    normalized.sort(key=lambda row: (str(row["chain"]), str(row["case_name"])))
    plan_no_repeat_sha256 = _canonical_sha256(
        [row["expansion_requirement_sha256"] for row in normalized]
    )
    output_records: list[dict[str, object]] = []
    chunk_summaries: list[dict[str, object]] = []
    for offset in range(0, len(normalized), max_cases_per_chunk):
        chunk_rows = normalized[offset : offset + max_cases_per_chunk]
        sequence = offset // max_cases_per_chunk + 1
        chunk_scope_sha256 = _canonical_sha256(
            [row["expansion_requirement_sha256"] for row in chunk_rows]
        )
        chunk_id = f"stage2-expansion-{sequence:04d}-{chunk_scope_sha256[:12]}"
        chunk_shortfall = sum(
            int(row["minimum_additional_distinct_slots"]) for row in chunk_rows
        )
        chunk_summaries.append(
            {
                "chunk_id": chunk_id,
                "chunk_sequence": sequence,
                "case_count": len(chunk_rows),
                "minimum_additional_distinct_slots": chunk_shortfall,
                "chunk_scope_sha256": chunk_scope_sha256,
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            }
        )
        for position, row in enumerate(chunk_rows, start=1):
            assignment: dict[str, object] = {
                "chunk_id": chunk_id,
                "chunk_sequence": sequence,
                "chunk_case_position": position,
                "case_name": row["case_name"],
                "chain": row["chain"],
                "admissible_deployment_start": row["admissible_deployment_start"],
                "admissible_deployment_end": row["admissible_deployment_end"],
                "positive_prediction_cutoff_time": row[
                    "positive_prediction_cutoff_time"
                ],
                "minimum_additional_distinct_slots": row[
                    "minimum_additional_distinct_slots"
                ],
                "expansion_requirement_sha256": row[
                    "expansion_requirement_sha256"
                ],
                **governance_hashes,
                "plan_no_repeat_sha256": plan_no_repeat_sha256,
                "chunk_scope_sha256": chunk_scope_sha256,
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            }
            assignment["chunk_assignment_sha256"] = _canonical_sha256(assignment)
            output_records.append(assignment)

    output = pd.DataFrame(output_records)
    if output.empty:
        output = pd.DataFrame(
            columns=[
                "chunk_id",
                "chunk_sequence",
                "chunk_case_position",
                "case_name",
                "chain",
                "admissible_deployment_start",
                "admissible_deployment_end",
                "positive_prediction_cutoff_time",
                "minimum_additional_distinct_slots",
                "expansion_requirement_sha256",
                *governance_hashes,
                "plan_no_repeat_sha256",
                "chunk_scope_sha256",
                "acquisition_authorized",
                "rpc_authorized",
                "selection_authorized",
                "chunk_assignment_sha256",
            ]
        )
    case_overlap_count = int(output["case_name"].duplicated().sum())
    requirement_overlap_count = int(
        output["expansion_requirement_sha256"].duplicated().sum()
    )
    if case_overlap_count or requirement_overlap_count:
        raise ControlDenominatorExpansionChunkError("chunk_scope_overlap")
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_denominator_expansion_chunk_plan.v1",
        "decision": (
            "BOUNDED_EXPANSION_PLAN_AWAITS_ACCOUNTABLE_ACQUISITION_APPROVAL"
            if len(output)
            else "NO_EXPANSION_REQUIRED"
        ),
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "max_cases_per_chunk": int(max_cases_per_chunk),
        "chunk_count": len(chunk_summaries),
        "cases_requiring_expansion": len(output),
        "minimum_additional_distinct_slots": int(
            output["minimum_additional_distinct_slots"].sum()
        ),
        "case_overlap_count": case_overlap_count,
        "requirement_overlap_count": requirement_overlap_count,
        "plan_no_repeat_sha256": plan_no_repeat_sha256,
        "inputs": governance_hashes,
        "chunks": chunk_summaries,
        "records_sha256": _canonical_sha256(output.to_dict("records")),
        "warning": (
            "This artifact partitions minimum acquisition requirements only. "
            "It authorizes neither RPC acquisition nor control selection, and "
            "covariate exclusions can increase the final acquisition volume."
        ),
    }
    return output, manifest
