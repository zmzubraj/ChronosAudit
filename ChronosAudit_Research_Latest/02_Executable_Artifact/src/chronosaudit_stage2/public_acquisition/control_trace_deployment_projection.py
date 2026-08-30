from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path


class ControlTraceDeploymentProjectionError(ValueError):
    """Raised when completed trace evidence cannot close deployment identity."""


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
        raise ControlTraceDeploymentProjectionError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlTraceDeploymentProjectionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlTraceDeploymentProjectionError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlTraceDeploymentProjectionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlTraceDeploymentProjectionError(f"{label}_root_invalid")
    return payload


def _require_self_hash(
    payload: Mapping[str, object], field: str, label: str
) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlTraceDeploymentProjectionError(f"{label}_self_hash_invalid")


def _require_false_authority(payload: Mapping[str, object], label: str) -> None:
    for flag in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(flag) is not False:
            raise ControlTraceDeploymentProjectionError(f"{label}_{flag}_invalid")


def _resolved_child(root: Path, value: object, label: str) -> Path:
    relative = Path(str(value or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ControlTraceDeploymentProjectionError(f"{label}_path_escape")
    child = _ordinary(root / relative, label)
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise ControlTraceDeploymentProjectionError(f"{label}_path_escape") from exc
    return child


def build_trace_deployment_projection(
    *,
    trace_targets_path: Path,
    trace_results_path: Path | None = None,
    checkpoint_path: Path | None = None,
    checkpoint_verification_path: Path | None = None,
    trace_overlay_path: Path | None = None,
    trace_overlay_verification_path: Path | None = None,
    overlay_reconstruction_inputs: Mapping[str, object] | None = None,
    candidate_root: Path,
) -> dict[str, object]:
    """Project complete dual-provider traces into immutable deployment evidence.

    This bridge closes only RPC deployment classification. It does not admit a
    row to pair scope, select or qualify a control, or change a canonical count.
    """
    targets_path = _ordinary(trace_targets_path, "trace_targets")
    targets_payload = _load(targets_path, "trace_targets")
    if targets_payload.get("schema_version") != "stage2_control_trace_targets.v1":
        raise ControlTraceDeploymentProjectionError("trace_targets_schema_invalid")
    _require_self_hash(
        targets_payload, "trace_targets_sha256", "trace_targets"
    )
    _require_false_authority(targets_payload, "trace_targets")
    if targets_payload.get("rpc_authorized") is not False:
        raise ControlTraceDeploymentProjectionError(
            "trace_targets_rpc_authorized_invalid"
        )
    target_rows = targets_payload.get("targets")
    if (
        not isinstance(target_rows, list)
        or not target_rows
        or len(target_rows) != targets_payload.get("target_count")
        or not all(isinstance(row, Mapping) for row in target_rows)
    ):
        raise ControlTraceDeploymentProjectionError("trace_targets_invalid")
    targets_by_id = {str(row.get("target_id", "")): row for row in target_rows}
    if "" in targets_by_id or len(targets_by_id) != len(target_rows):
        raise ControlTraceDeploymentProjectionError("trace_target_identity_invalid")

    single_mode = all(value is not None for value in (
        trace_results_path, checkpoint_path, checkpoint_verification_path
    ))
    overlay_mode = all(value is not None for value in (
        trace_overlay_path, trace_overlay_verification_path,
        overlay_reconstruction_inputs,
    ))
    if single_mode == overlay_mode:
        raise ControlTraceDeploymentProjectionError("trace_evidence_mode_ambiguous")

    evidence_bindings: dict[str, object]
    if single_mode:
        assert trace_results_path is not None
        assert checkpoint_path is not None
        assert checkpoint_verification_path is not None
        results_path = _ordinary(trace_results_path, "trace_results")
        results = _load(results_path, "trace_results")
        if results.get("schema_version") != "stage2_control_trace_acquisition_results.v1":
            raise ControlTraceDeploymentProjectionError("trace_results_schema_invalid")
        _require_self_hash(results, "results_sha256", "trace_results")
        _require_false_authority(results, "trace_results")
        if (
            results.get("trace_targets_sha256") != _file_sha(targets_path)
            or results.get("target_count") != len(target_rows)
            or results.get("processed_target_count") != len(target_rows)
            or results.get("completed_target_count") != len(target_rows)
            or results.get("dispositions") != {"complete": len(target_rows)}
        ):
            raise ControlTraceDeploymentProjectionError("trace_results_not_complete")
        result_rows = results.get("targets")
        if not isinstance(result_rows, list) or len(result_rows) != len(target_rows):
            raise ControlTraceDeploymentProjectionError("trace_result_count_invalid")

        checkpoint_file = _ordinary(checkpoint_path, "checkpoint")
        checkpoint = _load(checkpoint_file, "checkpoint")
        if checkpoint.get("schema_version") != "stage2_control_trace_acquisition_checkpoint.v1":
            raise ControlTraceDeploymentProjectionError("checkpoint_schema_invalid")
        _require_self_hash(checkpoint, "checkpoint_sha256", "checkpoint")
        _require_false_authority(checkpoint, "checkpoint")
        if (
            checkpoint.get("status") != "COMPLETE"
            or checkpoint.get("target_count") != len(target_rows)
            or checkpoint.get("completed_target_count") != len(target_rows)
            or checkpoint.get("trace_targets_sha256") != _file_sha(targets_path)
        ):
            raise ControlTraceDeploymentProjectionError("checkpoint_not_complete")
        checkpoint_root = checkpoint_file.parent.resolve(strict=True)
        bound_results = _resolved_child(checkpoint_root, checkpoint.get("normalized_results_path"), "trace_results")
        if bound_results != results_path or checkpoint.get("normalized_results_sha256") != _file_sha(results_path):
            raise ControlTraceDeploymentProjectionError("checkpoint_results_mismatch")
        bound_ledger = _resolved_child(checkpoint_root, checkpoint.get("event_ledger_path"), "event_ledger")
        if checkpoint.get("event_ledger_sha256") != _file_sha(bound_ledger):
            raise ControlTraceDeploymentProjectionError("checkpoint_ledger_mismatch")
        verification_path = _ordinary(checkpoint_verification_path, "checkpoint_verification")
        verification = _load(verification_path, "checkpoint_verification")
        if verification.get("schema_version") != "stage2_control_trace_acquisition_checkpoint_verification.v1":
            raise ControlTraceDeploymentProjectionError("checkpoint_verification_schema_invalid")
        _require_self_hash(verification, "verification_sha256", "checkpoint_verification")
        _require_false_authority(verification, "checkpoint_verification")
        if (
            verification.get("complete") is not True
            or verification.get("status") != "COMPLETE"
            or verification.get("errors") != []
            or verification.get("checkpoint_sha256") != checkpoint.get("checkpoint_sha256")
            or verification.get("checkpoint_file_sha256") != _file_sha(checkpoint_file)
        ):
            raise ControlTraceDeploymentProjectionError("checkpoint_verification_invalid")
        evidence_bindings = {
            "trace_evidence_mode": "SINGLE_COMPLETE_ROOT_V1",
            "trace_results_file_sha256": _file_sha(results_path),
            "trace_results_sha256": results["results_sha256"],
            "checkpoint_file_sha256": _file_sha(checkpoint_file),
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "checkpoint_verification_file_sha256": _file_sha(verification_path),
            "checkpoint_verification_sha256": verification["verification_sha256"],
        }
    else:
        assert trace_overlay_path is not None
        assert trace_overlay_verification_path is not None
        assert overlay_reconstruction_inputs is not None
        overlay_path = _ordinary(trace_overlay_path, "trace_overlay")
        overlay_verification_path = _ordinary(trace_overlay_verification_path, "trace_overlay_verification")
        overlay = _load(overlay_path, "trace_overlay")
        stored_overlay_verification = _load(overlay_verification_path, "trace_overlay_verification")
        try:
            from .control_trace_retry_overlay import verify_trace_completion_overlay

            reverified = verify_trace_completion_overlay(
                overlay_path=overlay_path,
                **dict(overlay_reconstruction_inputs),
            )
        except Exception as exc:
            raise ControlTraceDeploymentProjectionError("trace_overlay_invalid") from exc
        if stored_overlay_verification != reverified or reverified.get("decision") != "COMPLETE_NON_AUTHORIZING":
            raise ControlTraceDeploymentProjectionError("trace_overlay_not_complete")
        result_rows = overlay.get("targets")
        if not isinstance(result_rows, list) or len(result_rows) != len(target_rows):
            raise ControlTraceDeploymentProjectionError("trace_overlay_not_complete")
        evidence_bindings = {
            "trace_evidence_mode": "TRACE_RETRY_OVERLAY_V1",
            "trace_overlay_file_sha256": _file_sha(overlay_path),
            "trace_overlay_sha256": overlay["overlay_sha256"],
            "trace_overlay_verification_file_sha256": _file_sha(overlay_verification_path),
            "trace_overlay_verification_sha256": reverified["verification_sha256"],
        }

    results_by_id = {str(row.get("target_id", "")): row for row in result_rows if isinstance(row, Mapping)}
    if "" in results_by_id or set(results_by_id) != set(targets_by_id):
        raise ControlTraceDeploymentProjectionError("trace_result_identity_mismatch")

    root = candidate_root.expanduser()
    if root.is_symlink():
        raise ControlTraceDeploymentProjectionError("candidate_root_symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ControlTraceDeploymentProjectionError("candidate_root_not_directory")

    projected: list[dict[str, object]] = []
    for target_id in sorted(targets_by_id):
        target = targets_by_id[target_id]
        trace_result = results_by_id[target_id]
        if not isinstance(trace_result, Mapping):
            raise ControlTraceDeploymentProjectionError("trace_result_invalid")
        if evidence_bindings["trace_evidence_mode"] == "TRACE_RETRY_OVERLAY_V1":
            trace_result = {
                key: value
                for key, value in trace_result.items()
                if key not in {
                    "evidence_origin",
                    "agreeing_source_provenance",
                    "overlay_record_sha256",
                }
            }
        _require_self_hash(trace_result, "record_sha256", "trace_result")
        if (
            trace_result.get("disposition") != "complete"
            or trace_result.get("target_sha256") != _canonical_sha(target)
        ):
            raise ControlTraceDeploymentProjectionError("trace_result_not_complete")
        for field in (
            "case_id",
            "chain",
            "chain_address",
            "transaction_hash",
            "block_number",
            "block_hash",
            "reserve_record_sha256",
        ):
            if trace_result.get(field) != target.get(field):
                raise ControlTraceDeploymentProjectionError(
                    f"trace_result_{field}_mismatch"
                )
        provider_ids = trace_result.get("provider_ids")
        families = trace_result.get("operator_families")
        if (
            not isinstance(provider_ids, list)
            or len(provider_ids) != 2
            or len(set(str(value) for value in provider_ids)) != 2
            or not isinstance(families, list)
            or len(families) != 2
            or len(set(str(value) for value in families)) != 2
        ):
            raise ControlTraceDeploymentProjectionError(
                "trace_provider_independence_invalid"
            )
        creation_set = trace_result.get("creation_set")
        if not isinstance(creation_set, list):
            raise ControlTraceDeploymentProjectionError("trace_creation_set_invalid")
        normalized_creation_set = tuple(tuple(row) for row in creation_set)
        if trace_result.get("creation_set_sha256") != _canonical_sha(
            normalized_creation_set
        ):
            raise ControlTraceDeploymentProjectionError(
                "trace_creation_set_hash_invalid"
            )
        expected_address = str(target["chain_address"]).split(":", 1)[-1].lower()
        expected_tx = str(target["transaction_hash"]).lower()
        matches = [
            row
            for row in creation_set
            if isinstance(row, list)
            and len(row) == 5
            and str(row[0]).lower() == expected_tx
            and str(row[1]).lower() == expected_address
        ]
        if len(matches) != 1:
            raise ControlTraceDeploymentProjectionError("candidate_creation_missing")
        creation = matches[0]
        creation_type = str(creation[2]).lower()
        if creation_type not in {"internal_create", "internal_create2"}:
            raise ControlTraceDeploymentProjectionError("creation_type_invalid")

        assignment = str(target.get("reserve_assignment_sha256", ""))
        candidate_path = _ordinary(root / f"{assignment}.json", "candidate_record")
        try:
            candidate_path.relative_to(root)
        except ValueError as exc:
            raise ControlTraceDeploymentProjectionError(
                "candidate_record_path_escape"
            ) from exc
        candidate = _load(candidate_path, "candidate_record")
        if candidate.get("schema_version") != (
            "chronosaudit.control_candidate_rpc_acquisition_result.v1"
        ):
            raise ControlTraceDeploymentProjectionError("candidate_schema_invalid")
        _require_self_hash(candidate, "result_sha256", "candidate_record")
        _require_false_authority(candidate, "candidate_record")
        if (
            candidate.get("reserve_assignment_sha256") != assignment
            or candidate.get("result_sha256") != target.get("reserve_record_sha256")
            or _file_sha(candidate_path) != target.get("reserve_record_file_sha256")
            or candidate.get("case_name") != target.get("case_id")
            or candidate.get("chain") != target.get("chain")
            or candidate.get("control_address") != expected_address
            or candidate.get("creation_tx_hash") != expected_tx
            or candidate.get("deployment_block") != target.get("block_number")
            or candidate.get("deployment_block_hash") != target.get("block_hash")
            or candidate.get("temporal_pre_cutoff") is not True
            or candidate.get("creation_type") != (
                "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED"
            )
            or candidate.get("trace_proof") is not False
            or candidate.get("rpc_classification_complete") is not False
        ):
            raise ControlTraceDeploymentProjectionError(
                "candidate_record_binding_invalid"
            )

        row: dict[str, object] = {
            "schema_version": "stage2_control_trace_deployment_record.v1",
            "target_id": target_id,
            "case_id": target["case_id"],
            "chain": target["chain"],
            "chain_address": target["chain_address"],
            "control_address": expected_address,
            "creation_tx_hash": expected_tx,
            "deployment_block": target["block_number"],
            "deployment_block_hash": target["block_hash"],
            "control_deployment_time": candidate["control_deployment_time"],
            "deployment_distance_seconds": candidate["deployment_distance_seconds"],
            "temporal_pre_cutoff": True,
            "creation_type": creation_type,
            "creator_address": str(creation[3]).lower(),
            "canonical_trace_path": str(creation[4]),
            "reserve_assignment_sha256": assignment,
            "reserve_record_sha256": candidate["result_sha256"],
            "reserve_record_file_sha256": _file_sha(candidate_path),
            "trace_result_record_sha256": trace_result["record_sha256"],
            "provider_ids": list(provider_ids),
            "operator_families": list(families),
            "trace_proof": True,
            "provider_consensus": True,
            "rpc_classification_complete": True,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        row["record_sha256"] = _canonical_sha(row)
        projected.append(row)

    output: dict[str, object] = {
        "schema_version": "stage2_control_trace_deployment_projection.v1",
        "trace_targets_file_sha256": _file_sha(targets_path),
        "trace_targets_sha256": targets_payload["trace_targets_sha256"],
        **evidence_bindings,
        "record_count": len(projected),
        "records": projected,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["projection_sha256"] = _canonical_sha(output)
    return output
