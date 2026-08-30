from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import pandas as pd


class ControlReservePairScopeError(ValueError):
    """Raised when verified reserve evidence cannot enter pair acquisition scope."""


_QUEUE_REQUIRED = {
    "case_name",
    "chain",
    "control_address",
    "control_identity",
    "positive_prediction_cutoff_time",
    "source_object_key",
    "source_object_sha256",
    "source_record_sha256",
    "reserve_assignment_sha256",
    "queue_status",
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
}
_REQUIREMENTS_REQUIRED = {
    "case_name",
    "chain",
    "positive_deployment_time",
    "positive_prediction_cutoff_time",
    "positive_record_sha256",
    "admissible_deployment_start",
    "admissible_deployment_end",
    "minimum_additional_distinct_slots",
    "expansion_status",
    "selection_authorized",
    "expansion_requirement_sha256",
}


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlReservePairScopeError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlReservePairScopeError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlReservePairScopeError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlReservePairScopeError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlReservePairScopeError(f"{label}_root_invalid")
    return payload


def _require_self_hash(
    payload: Mapping[str, object], field: str, label: str
) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlReservePairScopeError(f"{label}_self_hash_invalid")


def _false(value: object) -> bool:
    if isinstance(value, bool):
        return value is False
    return str(value).strip().lower() in {"false", "0", "no", "n"}


def _require_false_authority(payload: Mapping[str, object], label: str) -> None:
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(field) is not False:
            raise ControlReservePairScopeError(f"{label}_{field}_invalid")


def _time(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlReservePairScopeError(f"{label}_invalid")
    return parsed


def _normalized_sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ControlReservePairScopeError(f"{label}_invalid")
    return text


def build_reserve_pair_scope(
    *,
    queue_path: Path,
    queue_manifest_path: Path,
    queue_verification_path: Path,
    expansion_requirements_path: Path,
    pair_scope_manifest_path: Path,
    reserve_deployment_projection_path: Path,
) -> dict[str, object]:
    """Bind verified reserve deployments to the frozen positive-specific scope.

    The output is an acquisition scope only. It never upgrades the expanded
    reserve into canonical denominator, selection, qualification, or counter
    authority.
    """
    queue_file = _ordinary(queue_path, "queue")
    queue_manifest_file = _ordinary(queue_manifest_path, "queue_manifest")
    queue_verification_file = _ordinary(
        queue_verification_path, "queue_verification"
    )
    requirements_file = _ordinary(
        expansion_requirements_path, "expansion_requirements"
    )
    pair_manifest_file = _ordinary(pair_scope_manifest_path, "pair_scope_manifest")
    deployment_file = _ordinary(
        reserve_deployment_projection_path, "reserve_deployment_projection"
    )

    queue_manifest = _load(queue_manifest_file, "queue_manifest")
    if queue_manifest.get("schema_version") != (
        "chronosaudit.control_historical_candidate_reserve_queue.v1"
    ):
        raise ControlReservePairScopeError("queue_manifest_schema_invalid")
    _require_false_authority(queue_manifest, "queue_manifest")
    if queue_manifest.get("rpc_authorized") is not False:
        raise ControlReservePairScopeError("queue_manifest_rpc_authorized_invalid")
    if (
        queue_manifest.get("global_no_reuse_verified") is not True
        or queue_manifest.get("queue_sha256") != _file_sha(queue_file)
    ):
        raise ControlReservePairScopeError("queue_hash_mismatch")

    queue_verification = _load(queue_verification_file, "queue_verification")
    if queue_verification.get("schema_version") != (
        "chronosaudit.control_historical_candidate_reserve_queue_verification.v1"
    ):
        raise ControlReservePairScopeError("queue_verification_schema_invalid")
    _require_false_authority(queue_verification, "queue_verification")
    if queue_verification.get("rpc_authorized") is not False:
        raise ControlReservePairScopeError(
            "queue_verification_rpc_authorized_invalid"
        )
    if (
        queue_verification.get("decision")
        != "RESERVE_QUEUE_VERIFIED_NON_AUTHORIZING"
        or queue_verification.get("global_no_reuse_verified") is not True
        or queue_verification.get("manifest_sha256")
        != _file_sha(queue_manifest_file)
        or queue_verification.get("queue_sha256") != _file_sha(queue_file)
    ):
        raise ControlReservePairScopeError("queue_verification_invalid")

    queue = pd.read_csv(queue_file, dtype=str, keep_default_na=False, low_memory=False)
    missing = sorted(_QUEUE_REQUIRED - set(queue.columns))
    if missing:
        raise ControlReservePairScopeError(
            "queue_missing_columns:" + ",".join(missing)
        )
    if len(queue) != int(queue_manifest.get("queue_row_count", -1)) or len(
        queue
    ) != int(queue_verification.get("queue_row_count", -1)):
        raise ControlReservePairScopeError("queue_row_count_mismatch")
    if queue["reserve_assignment_sha256"].duplicated().any():
        raise ControlReservePairScopeError("queue_assignment_duplicate")
    if queue.duplicated(["chain", "control_address"]).any():
        raise ControlReservePairScopeError("queue_chain_address_duplicate")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if not queue[field].map(_false).all():
            raise ControlReservePairScopeError(f"queue_{field}_invalid")

    pair_manifest = _load(pair_manifest_file, "pair_scope_manifest")
    if pair_manifest.get("schema_version") != (
        "chronosaudit.control_pair_acquisition_scope.v1"
    ):
        raise ControlReservePairScopeError("pair_scope_manifest_schema_invalid")
    if (
        pair_manifest.get("decision") != "PAIR_COVARIATE_EVIDENCE_REQUIRED"
        or pair_manifest.get("selection_authorized") is not False
    ):
        raise ControlReservePairScopeError("pair_scope_manifest_invalid")
    outputs = pair_manifest.get("outputs")
    expansion_output = (
        outputs.get("expansion_requirements")
        if isinstance(outputs, Mapping)
        else None
    )
    if (
        not isinstance(expansion_output, Mapping)
        or expansion_output.get("sha256") != _file_sha(requirements_file)
    ):
        raise ControlReservePairScopeError("expansion_requirements_hash_mismatch")
    requirements = pd.read_csv(
        requirements_file, dtype=str, keep_default_na=False, low_memory=False
    )
    missing = sorted(_REQUIREMENTS_REQUIRED - set(requirements.columns))
    if missing:
        raise ControlReservePairScopeError(
            "expansion_requirements_missing_columns:" + ",".join(missing)
        )
    if requirements["case_name"].duplicated().any():
        raise ControlReservePairScopeError("expansion_case_duplicate")
    if not requirements["selection_authorized"].map(_false).all():
        raise ControlReservePairScopeError(
            "expansion_selection_authorized_invalid"
        )
    expected_expansion = pair_manifest.get("expansion_requirements")
    if not isinstance(expected_expansion, Mapping) or len(requirements) != int(
        expected_expansion.get("case_count", -1)
    ):
        raise ControlReservePairScopeError("expansion_case_count_mismatch")

    deployment = _load(deployment_file, "reserve_deployment_projection")
    if deployment.get("schema_version") != (
        "stage2_control_reserve_deployment_projection.v1"
    ):
        raise ControlReservePairScopeError("deployment_projection_schema_invalid")
    _require_self_hash(deployment, "projection_sha256", "deployment_projection")
    _require_false_authority(deployment, "deployment_projection")
    if deployment.get("counter_authority") is not False:
        raise ControlReservePairScopeError(
            "deployment_projection_counter_authority_invalid"
        )
    deployment_rows = deployment.get("records")
    if (
        not isinstance(deployment_rows, list)
        or len(deployment_rows) != deployment.get("record_count")
        or not all(isinstance(row, Mapping) for row in deployment_rows)
    ):
        raise ControlReservePairScopeError("deployment_records_invalid")

    queue_by_assignment = {
        str(row["reserve_assignment_sha256"]): row
        for row in queue.to_dict("records")
    }
    requirements_by_case = {
        str(row["case_name"]): row for row in requirements.to_dict("records")
    }
    records: list[dict[str, object]] = []
    seen_assignments: set[str] = set()
    for deployment_row in deployment_rows:
        _require_self_hash(deployment_row, "record_sha256", "deployment_record")
        _require_false_authority(deployment_row, "deployment_record")
        assignment = _normalized_sha(
            deployment_row.get("reserve_assignment_sha256"),
            "reserve_assignment_sha256",
        )
        if assignment in seen_assignments or assignment not in queue_by_assignment:
            raise ControlReservePairScopeError("deployment_assignment_invalid")
        seen_assignments.add(assignment)
        queue_row = queue_by_assignment[assignment]
        case_name = str(queue_row["case_name"])
        if case_name not in requirements_by_case:
            raise ControlReservePairScopeError("expansion_case_missing")
        requirement = requirements_by_case[case_name]
        chain = str(queue_row["chain"]).strip().lower()
        address = str(queue_row["control_address"]).strip().lower()
        if (
            str(deployment_row.get("case_id", "")) != case_name
            or str(deployment_row.get("chain", "")).strip().lower() != chain
            or str(deployment_row.get("control_address", "")).strip().lower()
            != address
            or str(requirement["chain"]).strip().lower() != chain
            or str(queue_row["positive_prediction_cutoff_time"])
            != str(requirement["positive_prediction_cutoff_time"])
        ):
            raise ControlReservePairScopeError("pair_identity_mismatch")
        deployment_time = _time(
            deployment_row.get("control_deployment_time"),
            "control_deployment_time",
        )
        positive_deployment = _time(
            requirement["positive_deployment_time"], "positive_deployment_time"
        )
        cutoff = _time(
            requirement["positive_prediction_cutoff_time"],
            "positive_prediction_cutoff_time",
        )
        window_start = _time(
            requirement["admissible_deployment_start"],
            "admissible_deployment_start",
        )
        window_end = _time(
            requirement["admissible_deployment_end"],
            "admissible_deployment_end",
        )
        if (
            deployment_time < window_start
            or deployment_time > window_end
            or deployment_time > cutoff
            or deployment_row.get("temporal_pre_cutoff") is not True
        ):
            raise ControlReservePairScopeError("deployment_outside_window")
        distance = int(abs((deployment_time - positive_deployment).total_seconds()))
        pair: dict[str, object] = {
            "schema_version": "stage2_control_reserve_pair_scope_record.v1",
            "case_name": case_name,
            "chain": chain,
            "positive_deployment_time": str(requirement["positive_deployment_time"]),
            "positive_prediction_cutoff_time": str(
                requirement["positive_prediction_cutoff_time"]
            ),
            "positive_record_sha256": _normalized_sha(
                requirement["positive_record_sha256"], "positive_record_sha256"
            ),
            "deployment_id": f"reserve:{assignment}",
            "reserve_assignment_sha256": assignment,
            "control_address": address,
            "control_deployment_time": deployment_time.isoformat().replace(
                "+00:00", "Z"
            ),
            "deployment_distance_seconds": distance,
            "denominator_record_sha256": deployment_row["record_sha256"],
            "source_manifest_sha256": _file_sha(queue_manifest_file),
            "source_record_sha256": _normalized_sha(
                queue_row["source_record_sha256"], "source_record_sha256"
            ),
            "source_object_key": str(queue_row["source_object_key"]),
            "source_object_sha256": _normalized_sha(
                queue_row["source_object_sha256"], "source_object_sha256"
            ),
            "row_evidence_sha256": deployment_row["record_sha256"],
            "authority_projection_sha256": _file_sha(deployment_file),
            "required_covariate_cutoff_time": str(
                requirement["positive_prediction_cutoff_time"]
            ),
            "scope_status": "RESERVE_PAIR_CUTOFF_STATE_EVIDENCE_REQUIRED",
            "reserve_evidence_verified": True,
            "counter_authority": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        pair["pair_scope_record_sha256"] = _canonical_sha(pair)
        records.append(pair)

    records.sort(
        key=lambda row: (
            str(row["case_name"]),
            str(row["chain"]),
            str(row["control_address"]),
        )
    )
    queue_count = len(queue)
    completed_candidate_count = int(deployment.get("completed_candidate_count", -1))
    if completed_candidate_count < len(records) or completed_candidate_count > queue_count:
        raise ControlReservePairScopeError("deployment_candidate_count_invalid")
    pending_trace_count = int(deployment.get("pending_trace_count", -1))
    unprocessed_queue_count = queue_count - completed_candidate_count
    output: dict[str, object] = {
        "schema_version": "stage2_control_reserve_pair_scope.v1",
        "queue_file_sha256": _file_sha(queue_file),
        "queue_manifest_file_sha256": _file_sha(queue_manifest_file),
        "queue_verification_file_sha256": _file_sha(queue_verification_file),
        "expansion_requirements_file_sha256": _file_sha(requirements_file),
        "pair_scope_manifest_file_sha256": _file_sha(pair_manifest_file),
        "reserve_deployment_projection_file_sha256": _file_sha(deployment_file),
        "reserve_deployment_projection_sha256": deployment["projection_sha256"],
        "queue_row_count": queue_count,
        "completed_candidate_count": completed_candidate_count,
        "record_count": len(records),
        "pending_trace_count": pending_trace_count,
        "unprocessed_queue_count": unprocessed_queue_count,
        "complete": (
            deployment.get("complete") is True
            and len(records) == queue_count
            and pending_trace_count == 0
            and unprocessed_queue_count == 0
        ),
        "records": records,
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["projection_sha256"] = _canonical_sha(output)
    return output
