from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path


class ControlReserveDeploymentProjectionError(ValueError):
    """Raised when reserve deployment evidence cannot be projected exactly."""


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
        raise ControlReserveDeploymentProjectionError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlReserveDeploymentProjectionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlReserveDeploymentProjectionError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlReserveDeploymentProjectionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlReserveDeploymentProjectionError(f"{label}_root_invalid")
    return payload


def _require_self_hash(
    payload: Mapping[str, object], field: str, label: str
) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlReserveDeploymentProjectionError(f"{label}_self_hash_invalid")


def _require_false_authority(payload: Mapping[str, object], label: str) -> None:
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(field) is not False:
            raise ControlReserveDeploymentProjectionError(f"{label}_{field}_invalid")


def _completed_ledger(path: Path) -> dict[str, str]:
    previous = "0" * 64
    completed: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ControlReserveDeploymentProjectionError(
            "acquisition_ledger_invalid"
        ) from exc
    for index, line in enumerate(lines):
        try:
            stored = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlReserveDeploymentProjectionError(
                "acquisition_ledger_invalid"
            ) from exc
        if not isinstance(stored, dict):
            raise ControlReserveDeploymentProjectionError(
                "acquisition_ledger_invalid"
            )
        event = dict(stored)
        stored_sha = event.pop("event_sha256", None)
        if (
            event.get("previous_event_sha256") != previous
            or stored_sha != _canonical_sha(event)
        ):
            raise ControlReserveDeploymentProjectionError(
                f"acquisition_ledger_chain_invalid:{index}"
            )
        previous = str(stored_sha)
        if event.get("status") != "COMPLETE":
            continue
        assignment = str(event.get("reserve_assignment_sha256", ""))
        result_sha = str(event.get("result_sha256", ""))
        if (
            len(assignment) != 64
            or len(result_sha) != 64
            or assignment in completed
        ):
            raise ControlReserveDeploymentProjectionError(
                "acquisition_ledger_complete_invalid"
            )
        completed[assignment] = result_sha
    return completed


def _candidate_root(path: Path) -> Path:
    root = path.expanduser()
    if root.is_symlink():
        raise ControlReserveDeploymentProjectionError("candidate_root_symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ControlReserveDeploymentProjectionError(
            "candidate_root_not_directory"
        )
    return root


def _receipt_record(
    candidate: Mapping[str, object], candidate_file_sha256: str
) -> dict[str, object]:
    observations = candidate.get("provider_observations")
    if not isinstance(observations, list) or len(observations) != 2:
        raise ControlReserveDeploymentProjectionError(
            "receipt_provider_observations_invalid"
        )
    provider_ids = [str(item.get("provider_id", "")) for item in observations]
    families = [str(item.get("operator_family", "")) for item in observations]
    if (
        "" in provider_ids
        or len(set(provider_ids)) != 2
        or "" in families
        or len(set(families)) != 2
    ):
        raise ControlReserveDeploymentProjectionError(
            "receipt_provider_independence_invalid"
        )
    chain = str(candidate.get("chain", "")).strip().lower()
    address = str(candidate.get("control_address", "")).strip().lower()
    transaction_hash = str(candidate.get("creation_tx_hash", "")).strip().lower()
    creation = [
        transaction_hash,
        address,
        "top_level_create",
        "unknown",
        "[]",
    ]
    row: dict[str, object] = {
        "schema_version": "stage2_control_reserve_deployment_record.v1",
        "reserve_assignment_sha256": candidate["reserve_assignment_sha256"],
        "case_id": candidate["case_name"],
        "chain": chain,
        "chain_address": f"{chain}:{address}",
        "control_address": address,
        "transaction_hash": transaction_hash,
        "block_number": candidate["deployment_block"],
        "block_hash": candidate["deployment_block_hash"],
        "control_deployment_time": candidate["control_deployment_time"],
        "deployment_distance_seconds": candidate["deployment_distance_seconds"],
        "temporal_pre_cutoff": True,
        "creation_type": "top_level_create",
        "creator_address": "unknown",
        "canonical_trace_path": "[]",
        "creation_set_sha256": _canonical_sha((tuple(creation),)),
        "provider_ids": provider_ids,
        "operator_families": families,
        "source_candidate_record_sha256": candidate["result_sha256"],
        "source_candidate_file_sha256": candidate_file_sha256,
        "source_trace_deployment_record_sha256": None,
        "evidence_type": "receipt_create",
        "trace_proof": False,
        "provider_consensus": True,
        "rpc_classification_complete": True,
        "disposition": "complete",
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    row["record_sha256"] = _canonical_sha(row)
    return row


def _trace_record(
    candidate: Mapping[str, object], trace: Mapping[str, object]
) -> dict[str, object]:
    for field, trace_field in (
        ("case_name", "case_id"),
        ("chain", "chain"),
        ("control_address", "control_address"),
        ("creation_tx_hash", "creation_tx_hash"),
        ("deployment_block", "deployment_block"),
        ("deployment_block_hash", "deployment_block_hash"),
        ("control_deployment_time", "control_deployment_time"),
        ("deployment_distance_seconds", "deployment_distance_seconds"),
        ("reserve_assignment_sha256", "reserve_assignment_sha256"),
        ("result_sha256", "reserve_record_sha256"),
    ):
        left = candidate.get(field)
        right = trace.get(trace_field)
        if isinstance(left, str) and isinstance(right, str):
            left, right = left.lower(), right.lower()
        if left != right:
            raise ControlReserveDeploymentProjectionError(
                f"trace_candidate_{field}_mismatch"
            )
    if (
        trace.get("trace_proof") is not True
        or trace.get("provider_consensus") is not True
        or trace.get("rpc_classification_complete") is not True
        or trace.get("temporal_pre_cutoff") is not True
    ):
        raise ControlReserveDeploymentProjectionError("trace_record_incomplete")
    provider_ids = trace.get("provider_ids")
    families = trace.get("operator_families")
    if not isinstance(provider_ids, list) or not isinstance(families, list):
        raise ControlReserveDeploymentProjectionError("trace_provider_invalid")
    creation = [
        str(trace["creation_tx_hash"]).lower(),
        str(trace["control_address"]).lower(),
        str(trace["creation_type"]).lower(),
        str(trace["creator_address"]).lower(),
        str(trace["canonical_trace_path"]),
    ]
    row: dict[str, object] = {
        "schema_version": "stage2_control_reserve_deployment_record.v1",
        "reserve_assignment_sha256": candidate["reserve_assignment_sha256"],
        "case_id": candidate["case_name"],
        "chain": str(candidate["chain"]).lower(),
        "chain_address": trace["chain_address"],
        "control_address": str(candidate["control_address"]).lower(),
        "transaction_hash": str(candidate["creation_tx_hash"]).lower(),
        "block_number": candidate["deployment_block"],
        "block_hash": str(candidate["deployment_block_hash"]).lower(),
        "control_deployment_time": candidate["control_deployment_time"],
        "deployment_distance_seconds": candidate["deployment_distance_seconds"],
        "temporal_pre_cutoff": True,
        "creation_type": str(trace["creation_type"]).lower(),
        "creator_address": str(trace["creator_address"]).lower(),
        "canonical_trace_path": str(trace["canonical_trace_path"]),
        "creation_set_sha256": _canonical_sha((tuple(creation),)),
        "provider_ids": list(provider_ids),
        "operator_families": list(families),
        "source_candidate_record_sha256": candidate["result_sha256"],
        "source_candidate_file_sha256": trace["reserve_record_file_sha256"],
        "source_trace_deployment_record_sha256": trace["record_sha256"],
        "evidence_type": "dual_provider_trace_create",
        "trace_proof": True,
        "provider_consensus": True,
        "rpc_classification_complete": True,
        "disposition": "complete",
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    row["record_sha256"] = _canonical_sha(row)
    return row


def build_reserve_deployment_projection(
    *,
    acquisition_summary_path: Path,
    signature_verification_path: Path,
    acquisition_ledger_path: Path,
    candidate_root: Path,
    trace_deployment_projection_path: Path | None = None,
) -> dict[str, object]:
    """Aggregate receipt and trace deployment proof without adding authority."""
    summary_path = _ordinary(acquisition_summary_path, "acquisition_summary")
    summary = _load(summary_path, "acquisition_summary")
    if summary.get("schema_version") != (
        "chronosaudit.control_candidate_rpc_acquisition_summary.v1"
    ):
        raise ControlReserveDeploymentProjectionError("summary_schema_invalid")
    _require_self_hash(summary, "summary_sha256", "summary")
    _require_false_authority(summary, "summary")

    verification_path = _ordinary(
        signature_verification_path, "signature_verification"
    )
    verification = _load(verification_path, "signature_verification")
    if verification.get("decision") != (
        "LOCAL_TEST_CHECKPOINT_SIGNATURE_VERIFIED_NON_AUTHORIZING"
    ):
        raise ControlReserveDeploymentProjectionError(
            "signature_verification_decision_invalid"
        )
    if verification.get("summary_sha256") != _file_sha(summary_path):
        raise ControlReserveDeploymentProjectionError(
            "signature_verification_summary_mismatch"
        )
    _require_false_authority(verification, "signature_verification")
    if verification.get("counter_authority") is not False:
        raise ControlReserveDeploymentProjectionError(
            "signature_verification_counter_authority_invalid"
        )

    ledger_path = _ordinary(acquisition_ledger_path, "acquisition_ledger")
    completed = _completed_ledger(ledger_path)
    if len(completed) != int(summary.get("completed_count", -1)):
        raise ControlReserveDeploymentProjectionError(
            "acquisition_ledger_completed_count_mismatch"
        )
    root = _candidate_root(candidate_root)

    trace_by_assignment: dict[str, Mapping[str, object]] = {}
    trace_path: Path | None = None
    trace_projection_sha: str | None = None
    if trace_deployment_projection_path is not None:
        trace_path = _ordinary(
            trace_deployment_projection_path, "trace_deployment_projection"
        )
        trace_projection = _load(trace_path, "trace_deployment_projection")
        if trace_projection.get("schema_version") != (
            "stage2_control_trace_deployment_projection.v1"
        ):
            raise ControlReserveDeploymentProjectionError(
                "trace_projection_schema_invalid"
            )
        _require_self_hash(trace_projection, "projection_sha256", "trace_projection")
        _require_false_authority(trace_projection, "trace_projection")
        trace_rows = trace_projection.get("records")
        if (
            not isinstance(trace_rows, list)
            or len(trace_rows) != trace_projection.get("record_count")
            or not all(isinstance(row, Mapping) for row in trace_rows)
        ):
            raise ControlReserveDeploymentProjectionError(
                "trace_projection_records_invalid"
            )
        for trace in trace_rows:
            _require_self_hash(trace, "record_sha256", "trace_record")
            _require_false_authority(trace, "trace_record")
            assignment = str(trace.get("reserve_assignment_sha256", ""))
            if not assignment or assignment in trace_by_assignment:
                raise ControlReserveDeploymentProjectionError(
                    "trace_projection_identity_invalid"
                )
            trace_by_assignment[assignment] = trace
        trace_projection_sha = str(trace_projection["projection_sha256"])

    records: list[dict[str, object]] = []
    pending: list[str] = []
    receipt_count = 0
    trace_count = 0
    for assignment in sorted(completed):
        candidate_path = _ordinary(
            root / f"{assignment}.json", "candidate_record"
        )
        try:
            candidate_path.relative_to(root)
        except ValueError as exc:
            raise ControlReserveDeploymentProjectionError(
                "candidate_record_path_escape"
            ) from exc
        candidate = _load(candidate_path, "candidate_record")
        if candidate.get("schema_version") != (
            "chronosaudit.control_candidate_rpc_acquisition_result.v1"
        ):
            raise ControlReserveDeploymentProjectionError("candidate_schema_invalid")
        _require_self_hash(candidate, "result_sha256", "candidate")
        _require_false_authority(candidate, "candidate")
        if (
            candidate.get("result_sha256") != completed[assignment]
            or candidate.get("reserve_assignment_sha256") != assignment
            or candidate.get("run_binding_sha256")
            != summary.get("run_binding_sha256")
            or candidate.get("provider_consensus") is not True
            or candidate.get("temporal_pre_cutoff") is not True
        ):
            raise ControlReserveDeploymentProjectionError(
                "candidate_checkpoint_binding_invalid"
            )
        creation_type = candidate.get("creation_type")
        if creation_type == "TOP_LEVEL_CREATE_RECEIPT_PROVEN":
            if (
                candidate.get("rpc_classification_complete") is not True
                or candidate.get("trace_proof") is not False
            ):
                raise ControlReserveDeploymentProjectionError(
                    "receipt_candidate_classification_invalid"
                )
            records.append(_receipt_record(candidate, _file_sha(candidate_path)))
            receipt_count += 1
        elif creation_type == (
            "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED"
        ):
            if (
                candidate.get("rpc_classification_complete") is not False
                or candidate.get("trace_proof") is not False
            ):
                raise ControlReserveDeploymentProjectionError(
                    "trace_candidate_classification_invalid"
                )
            trace = trace_by_assignment.pop(assignment, None)
            if trace is None:
                pending.append(assignment)
            else:
                records.append(_trace_record(candidate, trace))
                trace_count += 1
        else:
            raise ControlReserveDeploymentProjectionError(
                "candidate_creation_type_invalid"
            )
    if trace_by_assignment:
        raise ControlReserveDeploymentProjectionError("trace_projection_scope_escape")
    if receipt_count != int(summary.get("rpc_classification_complete_count", -1)):
        raise ControlReserveDeploymentProjectionError(
            "receipt_classification_count_mismatch"
        )
    expected_trace = int(summary.get("trace_required_count", -1))
    if trace_count + len(pending) != expected_trace:
        raise ControlReserveDeploymentProjectionError("trace_scope_count_mismatch")

    records.sort(key=lambda row: str(row["reserve_assignment_sha256"]))
    output: dict[str, object] = {
        "schema_version": "stage2_control_reserve_deployment_projection.v1",
        "acquisition_summary_file_sha256": _file_sha(summary_path),
        "acquisition_summary_sha256": summary["summary_sha256"],
        "signature_verification_file_sha256": _file_sha(verification_path),
        "acquisition_ledger_file_sha256": _file_sha(ledger_path),
        "trace_deployment_projection_file_sha256": (
            _file_sha(trace_path) if trace_path is not None else None
        ),
        "trace_deployment_projection_sha256": trace_projection_sha,
        "completed_candidate_count": len(completed),
        "receipt_record_count": receipt_count,
        "trace_record_count": trace_count,
        "pending_trace_count": len(pending),
        "pending_trace_reserve_assignment_sha256s": pending,
        "record_count": len(records),
        "complete": len(pending) == 0 and len(records) == len(completed),
        "records": records,
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["projection_sha256"] = _canonical_sha(output)
    return output
