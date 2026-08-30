from __future__ import annotations

import csv
from datetime import datetime
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path


class ControlDenominatorExpansionAdmissionError(ValueError):
    """Raised when expansion evidence cannot enter an admission projection."""


_FALSE_AUTHORITY = (
    "selection_authorized",
    "qualification_authorized",
    "counter_authority",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_QUEUE_BINDINGS = (
    "case_name",
    "chain",
    "chain_id",
    "positive_prediction_cutoff_time",
    "reserve_target",
    "control_address",
    "control_identity",
    "source_object_key",
    "source_object_sha256",
    "source_record_sha256",
    "edge_rank_sha256",
    "reserve_assignment_sha256",
    "queue_status",
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_PROHIBITED_OUTCOME_FRAGMENTS = (
    "control_outcome",
    "incident_after",
    "post_cutoff",
    "exploit_outcome",
    "maturity_outcome",
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlDenominatorExpansionAdmissionError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlDenominatorExpansionAdmissionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlDenominatorExpansionAdmissionError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlDenominatorExpansionAdmissionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlDenominatorExpansionAdmissionError(f"{label}_root_invalid")
    return payload


def _self_hash(payload: Mapping[str, object], field: str, label: str) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _sha(material):
        raise ControlDenominatorExpansionAdmissionError(f"{label}_self_hash_invalid")


def _false_authority(payload: Mapping[str, object], label: str) -> None:
    for field in _FALSE_AUTHORITY:
        if payload.get(field) is not False:
            raise ControlDenominatorExpansionAdmissionError(
                f"{label}_{field}_invalid"
            )


def _is_sha(value: object) -> bool:
    text = str(value or "").lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _canonical_time(value: object, label: str) -> datetime:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlDenominatorExpansionAdmissionError(f"{label}_invalid") from exc
    if parsed.tzinfo is None or parsed.isoformat().replace("+00:00", "Z") != text:
        raise ControlDenominatorExpansionAdmissionError(f"{label}_invalid")
    return parsed


def _validate_implementation_approval(
    approval: Mapping[str, object], specification_file: Path
) -> None:
    if (
        approval.get("schema_version")
        != "chronosaudit.denominator_expansion_admission_user_approval.v1"
        or approval.get("decision") != "APPROVE_DENOMINATOR_EXPANSION_ADMISSION_V1"
        or approval.get("approval_text") != "APPROVE_DENOMINATOR_EXPANSION_ADMISSION_V1"
        or approval.get("scope")
        != "DENOMINATOR_EXPANSION_ADMISSION_PATH_IMPLEMENTATION_ONLY"
    ):
        raise ControlDenominatorExpansionAdmissionError("implementation_approval_invalid")
    _self_hash(approval, "record_sha256", "implementation_approval")
    if approval.get("specification_preapproval_sha256") != _file_sha(specification_file):
        raise ControlDenominatorExpansionAdmissionError("approved_specification_mismatch")
    for field in (
        "row_admission_authorized",
        "rpc_authorized",
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
        "independent_adjudication_authorized",
        "r5_authorized",
        "release_authorized",
        "publication_claims_authorized",
    ):
        if approval.get(field) is not False:
            raise ControlDenominatorExpansionAdmissionError(
                f"implementation_approval_{field}_invalid"
            )


def _validate_bridge(bridge: Mapping[str, object]) -> None:
    if (
        bridge.get("schema_version")
        != "chronosaudit.control_denominator_authority_bridge.v1"
        or bridge.get("decision") != "AUTHORITY_BRIDGE_VERIFIED"
        or int(bridge.get("row_count", 0)) != 20000
        or bridge.get("selection_authorized") is not False
        or not _is_sha(bridge.get("bridged_records_sha256"))
        or not _is_sha(bridge.get("sealed_manifest_rows_sha256"))
    ):
        raise ControlDenominatorExpansionAdmissionError("authority_bridge_invalid")


def _queue_rows(
    queue_file: Path,
    queue_manifest: Mapping[str, object],
    source_verification: Mapping[str, object],
) -> tuple[list[dict[str, str]], dict[str, tuple[int, dict[str, str]]]]:
    if (
        queue_manifest.get("schema_version")
        != "chronosaudit.control_historical_candidate_reserve_queue.v1"
        or queue_manifest.get("queue_sha256") != _file_sha(queue_file)
        or queue_manifest.get("global_no_reuse_verified") is not True
        or queue_manifest.get("selection_authorized") is not False
        or queue_manifest.get("stage_promotion_authorized") is not False
        or queue_manifest.get("recovery3_mutation_authorized") is not False
    ):
        raise ControlDenominatorExpansionAdmissionError("reserve_queue_manifest_invalid")
    if (
        source_verification.get("schema_version")
        != "chronosaudit.control_historical_source_import_verification.v1"
        or source_verification.get("decision") != "SOURCE_BATCH_VERIFIED_FOR_LOCAL_TRANSFORM"
        or queue_manifest.get("source_import_manifest_sha256")
        != source_verification.get("import_manifest_sha256")
        or source_verification.get("selection_authorized") is not False
        or source_verification.get("stage_promotion_authorized") is not False
        or source_verification.get("recovery3_mutation_authorized") is not False
    ):
        raise ControlDenominatorExpansionAdmissionError("source_import_verification_invalid")
    with queue_file.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not set(_QUEUE_BINDINGS).issubset(reader.fieldnames):
            raise ControlDenominatorExpansionAdmissionError("reserve_queue_columns_invalid")
        rows = list(reader)
    if len(rows) != int(queue_manifest.get("queue_row_count", -1)):
        raise ControlDenominatorExpansionAdmissionError("reserve_queue_count_mismatch")
    by_assignment: dict[str, tuple[int, dict[str, str]]] = {}
    for rank, row in enumerate(rows, start=1):
        assignment = str(row.get("reserve_assignment_sha256", ""))
        if not _is_sha(assignment) or assignment in by_assignment:
            raise ControlDenominatorExpansionAdmissionError("reserve_assignment_invalid")
        if any(str(row.get(field, "")).lower() != "false" for field in (
            "rpc_authorized", "selection_authorized", "stage_promotion_authorized",
            "recovery3_mutation_authorized",
        )):
            raise ControlDenominatorExpansionAdmissionError("reserve_queue_authority_invalid")
        for field in ("source_object_sha256", "source_record_sha256", "edge_rank_sha256"):
            if not _is_sha(row.get(field)):
                raise ControlDenominatorExpansionAdmissionError("source_lineage_invalid")
        by_assignment[assignment] = (rank, row)
    return rows, by_assignment


def _validate_attestation(attestation: Mapping[str, object]) -> None:
    if (
        attestation.get("schema_version")
        != "chronosaudit.control_denominator_expansion_outcome_blind_attestation.v1"
        or attestation.get("decision")
        != "NO_CONTROL_OUTCOMES_INSPECTED_BEFORE_ADMISSION_FREEZE"
    ):
        raise ControlDenominatorExpansionAdmissionError("outcome_blindness_invalid")
    _self_hash(attestation, "attestation_sha256", "outcome_blind_attestation")
    if (
        attestation.get("control_outcomes_inspected") is not False
        or attestation.get("outcome_or_post_cutoff_fields_used") != []
        or attestation.get("admission_ordering_rule")
        != "FROZEN_RESERVE_QUEUE_ROW_ORDER_V1"
    ):
        raise ControlDenominatorExpansionAdmissionError("outcome_blindness_invalid")
    _false_authority(attestation, "outcome_blind_attestation")


def _validate_capacity(
    capacity: Mapping[str, object],
    *,
    sources: Sequence[tuple[Path, Path]],
    trace_projection: Mapping[str, object] | None,
    expected_case_count: int,
    controls_per_positive: int,
) -> int:
    if capacity.get("schema_version") != "chronosaudit.control_effective_capacity_audit.v1":
        raise ControlDenominatorExpansionAdmissionError("capacity_schema_invalid")
    _self_hash(capacity, "audit_sha256", "capacity_audit")
    target = expected_case_count * controls_per_positive
    try:
        maximum = int(
            (capacity.get("evidence_complete_capacity") or {}).get(
                "maximum_assignable_controls", -1
            )
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ControlDenominatorExpansionAdmissionError("capacity_invalid") from exc
    if (
        capacity.get("decision") != "EVIDENCE_COMPLETE_DENOMINATOR_CAPACITY_VERIFIED"
        or capacity.get("denominator_qualifies") is not True
        or int(capacity.get("case_count", -1)) != expected_case_count
        or int(capacity.get("controls_per_positive", -1)) != controls_per_positive
        or int(capacity.get("target_control_rows", -1)) != target
        or maximum < target
    ):
        raise ControlDenominatorExpansionAdmissionError("capacity_not_qualifying")
    for field in (
        "denominator_admission_authorized", "selection_authorized",
        "qualification_authorized", "counter_authority", "stage_promotion_authorized",
        "recovery3_mutation_authorized", "independent_review_established",
        "release_authorized",
    ):
        if capacity.get(field) is not False:
            raise ControlDenominatorExpansionAdmissionError(f"capacity_{field}_invalid")
    reconciliations = capacity.get("source_reconciliations")
    if not isinstance(reconciliations, list) or len(reconciliations) != len(sources):
        raise ControlDenominatorExpansionAdmissionError("capacity_sources_invalid")
    for index, ((manifest, complete), binding) in enumerate(zip(sources, reconciliations)):
        if not isinstance(binding, Mapping) or (
            binding.get("source_index") != index
            or binding.get("manifest_file_sha256") != _file_sha(manifest)
            or binding.get("complete_file_sha256") != _file_sha(complete)
        ):
            raise ControlDenominatorExpansionAdmissionError("capacity_sources_invalid")
    expected_trace = (
        trace_projection.get("projection_sha256") if trace_projection is not None else None
    )
    if capacity.get("trace_deployment_projection_sha256") != expected_trace:
        raise ControlDenominatorExpansionAdmissionError("capacity_trace_binding_invalid")
    return maximum


def _raw_evidence(observations: object) -> tuple[list[str], list[str]]:
    if not isinstance(observations, list) or len(observations) != 2:
        raise ControlDenominatorExpansionAdmissionError("provider_independence_invalid")
    provider_ids: list[str] = []
    families: list[str] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            raise ControlDenominatorExpansionAdmissionError("provider_independence_invalid")
        provider_ids.append(str(observation.get("provider_id", "")))
        families.append(str(observation.get("operator_family", "")))
        for path_field, hash_field in (
            ("rpc_envelope_path", "rpc_envelope_sha256"),
            ("block_rpc_envelope_path", "block_rpc_envelope_sha256"),
        ):
            raw_file = _ordinary(Path(str(observation.get(path_field, ""))), "raw_evidence")
            if observation.get(hash_field) != _file_sha(raw_file):
                raise ControlDenominatorExpansionAdmissionError(
                    "raw_evidence_hash_mismatch"
                )
    if (
        any(not value for value in provider_ids + families)
        or len(set(provider_ids)) != 2
        or len(set(families)) != 2
    ):
        raise ControlDenominatorExpansionAdmissionError("provider_independence_invalid")
    return provider_ids, families


def _trace_records(path: Path | None) -> tuple[Path | None, dict[str, Mapping[str, object]]]:
    if path is None:
        return None, {}
    trace_file = _ordinary(path, "trace_deployment_projection")
    payload = _load(trace_file, "trace_deployment_projection")
    if payload.get("schema_version") != "stage2_control_trace_deployment_projection.v1":
        raise ControlDenominatorExpansionAdmissionError("trace_projection_schema_invalid")
    _self_hash(payload, "projection_sha256", "trace_projection")
    for field in ("selection_authorized", "stage_promotion_authorized", "recovery3_mutation_authorized"):
        if payload.get(field) is not False:
            raise ControlDenominatorExpansionAdmissionError("trace_projection_authority_invalid")
    records = payload.get("records")
    if not isinstance(records, list) or len(records) != int(payload.get("record_count", -1)):
        raise ControlDenominatorExpansionAdmissionError("trace_projection_records_invalid")
    by_assignment: dict[str, Mapping[str, object]] = {}
    for row in records:
        if not isinstance(row, Mapping):
            raise ControlDenominatorExpansionAdmissionError("trace_projection_records_invalid")
        _self_hash(row, "record_sha256", "trace_record")
        assignment = str(row.get("reserve_assignment_sha256", ""))
        if not assignment or assignment in by_assignment:
            raise ControlDenominatorExpansionAdmissionError("trace_projection_scope_invalid")
        by_assignment[assignment] = row
    return trace_file, by_assignment


def build_denominator_expansion_admission_projection(
    *,
    specification_path: Path,
    implementation_approval_path: Path,
    authority_bridge_manifest_path: Path,
    reserve_queue_path: Path,
    reserve_queue_manifest_path: Path,
    source_import_verification_path: Path,
    effective_sources: Sequence[tuple[Path, Path]],
    capacity_audit_path: Path,
    outcome_blind_attestation_path: Path,
    expected_case_count: int = 417,
    controls_per_positive: int = 10,
    trace_deployment_projection_path: Path | None = None,
) -> dict[str, object]:
    """Build an all-checks-passing projection without granting authority."""
    if expected_case_count <= 0 or controls_per_positive <= 0 or not effective_sources:
        raise ControlDenominatorExpansionAdmissionError("projection_scope_invalid")
    specification_file = _ordinary(specification_path, "specification")
    approval_file = _ordinary(implementation_approval_path, "implementation_approval")
    bridge_file = _ordinary(authority_bridge_manifest_path, "authority_bridge")
    queue_file = _ordinary(reserve_queue_path, "reserve_queue")
    queue_manifest_file = _ordinary(reserve_queue_manifest_path, "reserve_queue_manifest")
    source_verification_file = _ordinary(
        source_import_verification_path, "source_import_verification"
    )
    capacity_file = _ordinary(capacity_audit_path, "capacity_audit")
    attestation_file = _ordinary(outcome_blind_attestation_path, "outcome_blind_attestation")
    sources = [
        (_ordinary(manifest, f"effective_manifest_{index}"),
         _ordinary(complete, f"effective_complete_{index}"))
        for index, (manifest, complete) in enumerate(effective_sources)
    ]

    approval = _load(approval_file, "implementation_approval")
    _validate_implementation_approval(approval, specification_file)
    bridge = _load(bridge_file, "authority_bridge")
    _validate_bridge(bridge)
    queue_manifest = _load(queue_manifest_file, "reserve_queue_manifest")
    source_verification = _load(source_verification_file, "source_import_verification")
    _, queue_by_assignment = _queue_rows(
        queue_file, queue_manifest, source_verification
    )
    attestation = _load(attestation_file, "outcome_blind_attestation")
    _validate_attestation(attestation)
    trace_file, trace_by_assignment = _trace_records(trace_deployment_projection_path)
    capacity = _load(capacity_file, "capacity_audit")
    maximum = _validate_capacity(
        capacity,
        sources=sources,
        trace_projection=(
            _load(trace_file, "trace_deployment_projection") if trace_file else None
        ),
        expected_case_count=expected_case_count,
        controls_per_positive=controls_per_positive,
    )

    candidate_rows: list[dict[str, object]] = []
    source_bindings: list[dict[str, object]] = []
    seen_assignments: set[str] = set()
    for source_index, (manifest_file, complete_file) in enumerate(sources):
        with complete_file.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or any(
                fragment in field.lower()
                for field in reader.fieldnames
                for fragment in _PROHIBITED_OUTCOME_FRAGMENTS
            ):
                raise ControlDenominatorExpansionAdmissionError("outcome_field_leakage")
            complete_rows = list(reader)
        source_bindings.append({
            "source_index": source_index,
            "manifest_file_sha256": _file_sha(manifest_file),
            "complete_file_sha256": _file_sha(complete_file),
            "complete_count": len(complete_rows),
        })
        for effective in complete_rows:
            assignment = str(effective.get("reserve_assignment_sha256", ""))
            if assignment in seen_assignments or assignment not in queue_by_assignment:
                raise ControlDenominatorExpansionAdmissionError("queue_membership_invalid")
            seen_assignments.add(assignment)
            queue_rank, queue = queue_by_assignment[assignment]
            if any(str(effective.get(field, "")) != str(queue.get(field, "")) for field in _QUEUE_BINDINGS):
                raise ControlDenominatorExpansionAdmissionError("queue_membership_invalid")
            result_file = _ordinary(Path(str(effective.get("result_path", ""))), "candidate_result")
            if effective.get("result_file_sha256") != _file_sha(result_file):
                raise ControlDenominatorExpansionAdmissionError("source_lineage_invalid")
            result = _load(result_file, "candidate_result")
            _self_hash(result, "result_sha256", "candidate_result")
            if effective.get("result_sha256") != result.get("result_sha256"):
                raise ControlDenominatorExpansionAdmissionError("source_lineage_invalid")
            for field in ("selection_authorized", "stage_promotion_authorized", "recovery3_mutation_authorized"):
                if result.get(field) is not False:
                    raise ControlDenominatorExpansionAdmissionError("candidate_authority_invalid")
            expected_identity = f"{str(queue['chain']).lower()}:{str(queue['control_address']).lower()}"
            if (
                result.get("case_name") != queue["case_name"]
                or str(result.get("chain", "")).lower() != str(queue["chain"]).lower()
                or str(result.get("control_address", "")).lower() != str(queue["control_address"]).lower()
                or result.get("reserve_assignment_sha256") != assignment
                or result.get("provider_consensus") is not True
                or result.get("temporal_pre_cutoff") is not True
            ):
                raise ControlDenominatorExpansionAdmissionError("deployment_identity_invalid")
            cutoff = _canonical_time(queue["positive_prediction_cutoff_time"], "positive_cutoff")
            deployed = _canonical_time(result.get("control_deployment_time"), "deployment_time")
            if deployed >= cutoff:
                raise ControlDenominatorExpansionAdmissionError("temporal_pre_cutoff_invalid")

            trace = trace_by_assignment.get(assignment)
            if result.get("rpc_classification_complete") is True:
                if (
                    result.get("creation_type") != "TOP_LEVEL_CREATE_RECEIPT_PROVEN"
                    or result.get("trace_proof") is not False
                ):
                    raise ControlDenominatorExpansionAdmissionError("evidence_completeness_invalid")
                provider_ids, families = _raw_evidence(result.get("provider_observations"))
                creation_type = result["creation_type"]
                trace_record_sha = None
            else:
                if trace is None:
                    raise ControlDenominatorExpansionAdmissionError("evidence_completeness_invalid")
                provider_ids = [str(value) for value in trace.get("provider_ids", [])]
                families = [str(value) for value in trace.get("operator_families", [])]
                if (
                    len(provider_ids) != 2 or len(set(provider_ids)) != 2
                    or len(families) != 2 or len(set(families)) != 2
                    or trace.get("case_id") != queue["case_name"]
                    or str(trace.get("chain_address", "")).lower() != expected_identity
                    or trace.get("reserve_record_sha256") != result.get("result_sha256")
                    or trace.get("deployment_block") != result.get("deployment_block")
                    or trace.get("deployment_block_hash") != result.get("deployment_block_hash")
                    or trace.get("creation_tx_hash") != result.get("creation_tx_hash")
                    or trace.get("temporal_pre_cutoff") is not True
                    or trace.get("trace_proof") is not True
                    or trace.get("provider_consensus") is not True
                    or trace.get("rpc_classification_complete") is not True
                ):
                    raise ControlDenominatorExpansionAdmissionError("trace_record_binding_invalid")
                creation_type = trace.get("creation_type")
                trace_record_sha = trace.get("record_sha256")
            if not all(_is_sha(result.get(field)) for field in ("result_sha256",)):
                raise ControlDenominatorExpansionAdmissionError("source_lineage_invalid")
            row: dict[str, object] = {
                "schema_version": "chronosaudit.denominator_expansion_admitted_row.v1",
                "queue_rank": queue_rank,
                "case_id": queue["case_name"],
                "chain": str(queue["chain"]).lower(),
                "chain_id": queue["chain_id"],
                "chain_address": expected_identity,
                "control_address": str(queue["control_address"]).lower(),
                "positive_prediction_cutoff_time": queue["positive_prediction_cutoff_time"],
                "control_deployment_time": result["control_deployment_time"],
                "creation_tx_hash": result["creation_tx_hash"],
                "creation_type": creation_type,
                "deployment_block": result["deployment_block"],
                "deployment_block_hash": result["deployment_block_hash"],
                "reserve_assignment_sha256": assignment,
                "edge_rank_sha256": queue["edge_rank_sha256"],
                "source_object_key": queue["source_object_key"],
                "source_object_sha256": queue["source_object_sha256"],
                "source_record_sha256": queue["source_record_sha256"],
                "deployment_result_sha256": result["result_sha256"],
                "deployment_result_file_sha256": _file_sha(result_file),
                "trace_record_sha256": trace_record_sha,
                "provider_ids": provider_ids,
                "operator_families": families,
                "checks": {
                    "queue_membership": True,
                    "source_lineage": True,
                    "provider_independence": True,
                    "deployment_identity": True,
                    "temporal_pre_cutoff": True,
                    "global_no_reuse": True,
                    "outcome_blindness": True,
                    "evidence_completeness": True,
                },
                "selection_authorized": False,
                "qualification_authorized": False,
                "counter_authority": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            }
            row["row_sha256"] = _sha(row)
            candidate_rows.append(row)

    # The earliest frozen queue rank wins; assignment is the deterministic tie-break.
    candidate_rows.sort(key=lambda row: (int(row["queue_rank"]), str(row["reserve_assignment_sha256"])))
    admitted: list[dict[str, object]] = []
    identities: set[str] = set()
    for row in candidate_rows:
        identity = str(row["chain_address"])
        if identity in identities:
            continue
        identities.add(identity)
        admitted.append(row)
    target = expected_case_count * controls_per_positive
    combined_denominator_sha = _sha({
        "authority_bridge_file_sha256": _file_sha(bridge_file),
        "authority_bridge_records_sha256": bridge["bridged_records_sha256"],
        "admitted_row_sha256": [row["row_sha256"] for row in admitted],
    })
    projection: dict[str, object] = {
        "schema_version": "chronosaudit.denominator_expansion_admission_projection.v1",
        "decision": "DENOMINATOR_EXPANSION_PROJECTED_NON_AUTHORIZING",
        "expected_case_count": expected_case_count,
        "controls_per_positive": controls_per_positive,
        "target_control_rows": target,
        "maximum_assignable_controls": maximum,
        "denominator_qualifies": True,
        "input_candidate_row_count": len(candidate_rows),
        "admitted_row_count": len(admitted),
        "duplicate_identity_rows_excluded": len(candidate_rows) - len(admitted),
        "deduplication_rule": "EARLIEST_FROZEN_QUEUE_RANK_THEN_ASSIGNMENT_SHA256_V1",
        "admission_ordering_rule": "FROZEN_RESERVE_QUEUE_ROW_ORDER_V1",
        "admitted_rows": admitted,
        "admitted_rows_sha256": _sha(admitted),
        "combined_denominator_sha256": combined_denominator_sha,
        "source_reconciliations": source_bindings,
        "input_sha256": {
            "specification": _file_sha(specification_file),
            "implementation_approval": _file_sha(approval_file),
            "authority_bridge_manifest": _file_sha(bridge_file),
            "reserve_queue": _file_sha(queue_file),
            "reserve_queue_manifest": _file_sha(queue_manifest_file),
            "source_import_verification": _file_sha(source_verification_file),
            "capacity_audit": _file_sha(capacity_file),
            "outcome_blind_attestation": _file_sha(attestation_file),
            "trace_deployment_projection": _file_sha(trace_file) if trace_file else None,
        },
        "row_admission_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "independent_review_established": False,
        "r5_authorized": False,
        "release_authorized": False,
        "publication_authorized": False,
    }
    projection["projection_sha256"] = _sha(projection)
    return projection


def verify_denominator_expansion_admission_projection(
    *, projection: Mapping[str, object], **build_inputs: object
) -> dict[str, object]:
    """Reconstruct a projection exactly; verification remains non-authorizing."""
    rebuilt = build_denominator_expansion_admission_projection(**build_inputs)
    if dict(projection) != rebuilt:
        raise ControlDenominatorExpansionAdmissionError("projection_rebuild_mismatch")
    verification: dict[str, object] = {
        "schema_version": "chronosaudit.denominator_expansion_admission_projection_verification.v1",
        "decision": "DENOMINATOR_EXPANSION_PROJECTION_VERIFIED_NON_AUTHORIZING",
        "projection_sha256": rebuilt["projection_sha256"],
        "combined_denominator_sha256": rebuilt["combined_denominator_sha256"],
        "admitted_row_count": rebuilt["admitted_row_count"],
        "maximum_assignable_controls": rebuilt["maximum_assignable_controls"],
        "denominator_qualifies": True,
        "row_admission_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "independent_review_established": False,
        "r5_authorized": False,
        "release_authorized": False,
        "publication_authorized": False,
    }
    verification["verification_sha256"] = _sha(verification)
    return verification
