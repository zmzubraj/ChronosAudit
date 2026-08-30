from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pandas as pd

from .control_pair_scope import maximum_no_reuse_allocation
from .control_trace_targets import build_effective_trace_target_identities


class ControlCapacityAuditError(ValueError):
    """Raised when the current control-capacity evidence cannot be audited."""


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
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
        raise ControlCapacityAuditError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCapacityAuditError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCapacityAuditError(f"{label}_not_ordinary_file")
    return resolved


def _json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCapacityAuditError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCapacityAuditError(f"{label}_root_invalid")
    return payload


def _verified_summary(path: Path) -> dict[str, object]:
    payload = _json(path, "acquisition_summary")
    if payload.get("schema_version") != "chronosaudit.control_candidate_rpc_acquisition_summary.v1":
        raise ControlCapacityAuditError("acquisition_summary_schema_invalid")
    material = {key: value for key, value in payload.items() if key != "summary_sha256"}
    if payload.get("summary_sha256") != _sha(material):
        raise ControlCapacityAuditError("acquisition_summary_self_hash_invalid")
    if any(payload.get(field) is not False for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    )):
        raise ControlCapacityAuditError("acquisition_summary_authority_invalid")
    return payload


def _complete_assignments(events_path: Path) -> set[str]:
    previous = "0" * 64
    complete: set[str] = set()
    for index, line in enumerate(events_path.read_text(encoding="utf-8").splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlCapacityAuditError(f"event_json_invalid:{index}") from exc
        if not isinstance(event, dict):
            raise ControlCapacityAuditError(f"event_root_invalid:{index}")
        stored = event.pop("event_sha256", None)
        if event.get("previous_event_sha256") != previous or stored != _sha(event):
            raise ControlCapacityAuditError(f"event_chain_invalid:{index}")
        previous = str(stored)
        if event.get("status") == "COMPLETE":
            assignment = str(event.get("reserve_assignment_sha256") or "")
            if not assignment or assignment in complete:
                raise ControlCapacityAuditError("complete_assignment_duplicate_or_missing")
            complete.add(assignment)
    return complete


def _candidate_rows(root: Path, assignments: set[str], run_binding: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for assignment in sorted(assignments):
        payload = _json(
            _ordinary(root / "candidates" / f"{assignment}.json", "candidate_result"),
            "candidate_result",
        )
        material = {key: value for key, value in payload.items() if key != "result_sha256"}
        if payload.get("result_sha256") != _sha(material):
            raise ControlCapacityAuditError(f"candidate_result_self_hash_invalid:{assignment}")
        if payload.get("reserve_assignment_sha256") != assignment:
            raise ControlCapacityAuditError(f"candidate_assignment_mismatch:{assignment}")
        if payload.get("run_binding_sha256") != run_binding:
            raise ControlCapacityAuditError(f"candidate_run_binding_mismatch:{assignment}")
        rows.append(payload)
    identities = [
        f"{str(row.get('chain')).lower()}:{str(row.get('control_address')).lower()}"
        for row in rows
    ]
    if len(identities) != len(set(identities)):
        raise ControlCapacityAuditError("observed_chain_address_duplicate")
    return rows


def _staged_identities(path: Path) -> tuple[dict[str, object], set[tuple[str, str]]]:
    payload = _json(path, "staged_state_results")
    if payload.get("schema_version") != "stage2_control_staged_cutoff_state_results.v1":
        raise ControlCapacityAuditError("staged_state_schema_invalid")
    material = {key: value for key, value in payload.items() if key != "projection_sha256"}
    if payload.get("projection_sha256") != _sha(material):
        raise ControlCapacityAuditError("staged_state_self_hash_invalid")
    targets = payload.get("targets")
    count = payload.get("target_count")
    if (
        not isinstance(targets, list)
        or len(targets) != count
        or payload.get("complete") is not True
        or payload.get("decision") != "STAGED_CUTOFF_STATE_PROJECTED_NON_AUTHORIZING"
    ):
        raise ControlCapacityAuditError("staged_state_incomplete")
    if any(payload.get(field) is not False for field in (
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    )):
        raise ControlCapacityAuditError("staged_state_authority_invalid")
    identities = {
        (str(row.get("case_id") or ""), str(row.get("chain_address") or "").lower())
        for row in targets
        if isinstance(row, dict)
    }
    if any(not all(identity) for identity in identities) or len(identities) != len(targets):
        raise ControlCapacityAuditError("staged_state_identity_membership_invalid")
    return payload, identities


def _edges(frame: pd.DataFrame) -> pd.DataFrame:
    required = {"case_name", "chain", "control_address"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ControlCapacityAuditError(f"scope_missing_columns:{','.join(missing)}")
    return frame[["case_name", "chain", "control_address"]].copy()


def build_control_capacity_audit(
    *,
    original_pair_scope_path: Path,
    expansion_requirements_path: Path,
    acquisition_summary_path: Path,
    acquisition_root: Path,
    staged_state_results_path: Path,
) -> dict[str, object]:
    scope_file = _ordinary(original_pair_scope_path, "original_pair_scope")
    requirements_file = _ordinary(expansion_requirements_path, "expansion_requirements")
    summary_file = _ordinary(acquisition_summary_path, "acquisition_summary")
    staged_file = _ordinary(staged_state_results_path, "staged_state_results")
    root = acquisition_root.expanduser().resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ControlCapacityAuditError("acquisition_root_invalid")
    events_file = _ordinary(root / "events.jsonl", "acquisition_events")

    scope = _edges(pd.read_csv(scope_file, dtype=str, keep_default_na=False))
    requirements = pd.read_csv(requirements_file, dtype=str, keep_default_na=False)
    if "case_name" not in requirements or "controls_required" not in requirements:
        raise ControlCapacityAuditError("expansion_requirements_columns_invalid")
    if requirements["case_name"].duplicated().any():
        raise ControlCapacityAuditError("expansion_requirements_duplicate_case")
    controls_required = {int(value) for value in requirements["controls_required"]}
    if len(controls_required) != 1 or next(iter(controls_required)) <= 0:
        raise ControlCapacityAuditError("controls_required_inconsistent")
    controls_per_positive = next(iter(controls_required))
    case_names = requirements["case_name"].astype(str).tolist()

    summary = _verified_summary(summary_file)
    complete = _complete_assignments(events_file)
    if len(complete) != int(summary.get("completed_count", -1)):
        raise ControlCapacityAuditError("completed_count_mismatch")
    candidates = _candidate_rows(root, complete, str(summary.get("run_binding_sha256") or ""))
    staged_payload, staged_identities = _staged_identities(staged_file)
    by_identity = {
        (
            str(row["case_name"]),
            f"{str(row['chain']).lower()}:{str(row['control_address']).lower()}",
        ): row
        for row in candidates
    }
    if not staged_identities.issubset(by_identity):
        raise ControlCapacityAuditError("staged_state_unknown_candidate_identity")
    staged_candidates = [by_identity[value] for value in sorted(staged_identities)]
    if any(row.get("rpc_classification_complete") is not True for row in staged_candidates):
        raise ControlCapacityAuditError("staged_state_deployment_not_classification_complete")

    observed_edges = pd.DataFrame(
        [
            {
                "case_name": row["case_name"],
                "chain": row["chain"],
                "control_address": row["control_address"],
            }
            for row in candidates
        ]
    )
    staged_edges = pd.DataFrame(
        [
            {
                "case_name": row["case_name"],
                "chain": row["chain"],
                "control_address": row["control_address"],
            }
            for row in staged_candidates
        ]
    )
    original = maximum_no_reuse_allocation(
        scope, controls_per_positive=controls_per_positive, case_names=case_names
    )
    all_observed = maximum_no_reuse_allocation(
        pd.concat([scope, observed_edges], ignore_index=True),
        controls_per_positive=controls_per_positive,
        case_names=case_names,
    )
    staged_ready = maximum_no_reuse_allocation(
        pd.concat([scope, staged_edges], ignore_index=True),
        controls_per_positive=controls_per_positive,
        case_names=case_names,
    )
    target = len(case_names) * controls_per_positive
    audit: dict[str, object] = {
        "schema_version": "chronosaudit.control_capacity_audit.v1",
        "decision": "INSUFFICIENT_CAPACITY_AND_DENOMINATOR_EXPANSION_AUTHORITY_REQUIRED",
        "case_count": len(case_names),
        "controls_per_positive": controls_per_positive,
        "target_control_rows": target,
        "observed_complete_count": len(candidates),
        "staged_state_ready_observation_count": len(staged_candidates),
        "queue_row_count": int(summary.get("queue_row_count", -1)),
        "queue_remaining_count": int(summary.get("remaining_count", -1)),
        "original_denominator": original,
        "all_observed_deployments": all_observed,
        "staged_state_ready": staged_ready,
        "minimum_additional_unique_allocatable_edges_even_if_every_new_edge_qualifies": int(
            all_observed["total_shortfall"]
        ),
        "denominator_expansion_admission_required": True,
        "pair_feature_projection_required": True,
        "dynamic_horizon_freeze_required": True,
        "eight_check_qualification_required": True,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "input_sha256": {
            "original_pair_scope": _file_sha(scope_file),
            "expansion_requirements": _file_sha(requirements_file),
            "acquisition_summary": _file_sha(summary_file),
            "acquisition_events": _file_sha(events_file),
            "staged_state_results": _file_sha(staged_file),
        },
        "source_bindings": {
            "acquisition_summary_sha256": summary.get("summary_sha256"),
            "staged_state_results_sha256": staged_payload.get("projection_sha256"),
            "acquisition_run_binding_sha256": summary.get("run_binding_sha256"),
        },
        "interpretation": (
            "These are exact deployment-graph ceilings under chain-address capacity one. "
            "They do not admit reserve rows into the counter-authorized denominator and do "
            "not imply maturity or any of the eight qualification checks."
        ),
    }
    audit["audit_sha256"] = _sha(audit)
    return audit


def build_effective_control_capacity_audit(
    *,
    original_pair_scope_path: Path,
    expansion_requirements_path: Path,
    sources: Sequence[tuple[Path, Path]],
    trace_target_identities_path: Path,
    trace_deployment_projection_path: Path | None = None,
) -> dict[str, object]:
    """Audit post-reconciliation capacity under strict evidence completeness."""
    scope_file = _ordinary(original_pair_scope_path, "original_pair_scope")
    requirements_file = _ordinary(expansion_requirements_path, "expansion_requirements")
    trace_file = _ordinary(trace_target_identities_path, "trace_target_identities")
    if not sources:
        raise ControlCapacityAuditError("effective_sources_empty")

    scope = _edges(pd.read_csv(scope_file, dtype=str, keep_default_na=False))
    requirements = pd.read_csv(requirements_file, dtype=str, keep_default_na=False)
    if "case_name" not in requirements or "controls_required" not in requirements:
        raise ControlCapacityAuditError("expansion_requirements_columns_invalid")
    if requirements["case_name"].duplicated().any():
        raise ControlCapacityAuditError("expansion_requirements_duplicate_case")
    controls_required = {int(value) for value in requirements["controls_required"]}
    if len(controls_required) != 1 or next(iter(controls_required)) <= 0:
        raise ControlCapacityAuditError("controls_required_inconsistent")
    controls_per_positive = next(iter(controls_required))
    case_names = requirements["case_name"].astype(str).tolist()

    rebuilt_trace = build_effective_trace_target_identities(sources=sources)
    trace_payload = _json(trace_file, "trace_target_identities")
    if trace_payload != rebuilt_trace:
        raise ControlCapacityAuditError("trace_target_identities_rebuild_mismatch")
    trace_assignments = {
        str(row["reserve_assignment_sha256"])
        for row in rebuilt_trace["targets"]
    }

    complete_count = 0
    evidence_complete_rows: list[dict[str, object]] = []
    trace_candidate_rows: dict[str, dict[str, object]] = {}
    source_bindings: list[dict[str, object]] = []
    for source_index, (manifest_input, complete_input) in enumerate(sources):
        manifest_file = _ordinary(manifest_input, f"effective_manifest_{source_index}")
        complete_file = _ordinary(complete_input, f"effective_complete_{source_index}")
        with complete_file.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        complete_count += len(rows)
        for row in rows:
            result_file = _ordinary(
                Path(str(row.get("result_path", ""))), "effective_candidate_result"
            )
            result = _json(result_file, "effective_candidate_result")
            assignment = str(result.get("reserve_assignment_sha256", ""))
            if assignment in trace_assignments:
                if result.get("rpc_classification_complete") is not False:
                    raise ControlCapacityAuditError("trace_assignment_classification_invalid")
                if assignment in trace_candidate_rows:
                    raise ControlCapacityAuditError("trace_assignment_duplicate")
                trace_candidate_rows[assignment] = result
                continue
            if (
                result.get("creation_type") != "TOP_LEVEL_CREATE_RECEIPT_PROVEN"
                or result.get("rpc_classification_complete") is not True
                or result.get("provider_consensus") is not True
                or result.get("temporal_pre_cutoff") is not True
            ):
                raise ControlCapacityAuditError("evidence_complete_candidate_invalid")
            evidence_complete_rows.append(result)
        source_bindings.append(
            {
                "source_index": source_index,
                "manifest_file_sha256": _file_sha(manifest_file),
                "complete_file_sha256": _file_sha(complete_file),
                "complete_count": len(rows),
            }
        )

    if complete_count != len(evidence_complete_rows) + len(trace_assignments):
        raise ControlCapacityAuditError("effective_candidate_partition_mismatch")
    if set(trace_candidate_rows) != trace_assignments:
        raise ControlCapacityAuditError("trace_candidate_membership_mismatch")

    trace_projection_file: Path | None = None
    trace_projection_sha: str | None = None
    trace_closed_rows: list[dict[str, object]] = []
    if trace_deployment_projection_path is not None:
        trace_projection_file = _ordinary(
            trace_deployment_projection_path, "trace_deployment_projection"
        )
        trace_projection = _json(
            trace_projection_file, "trace_deployment_projection"
        )
        if trace_projection.get("schema_version") != (
            "stage2_control_trace_deployment_projection.v1"
        ):
            raise ControlCapacityAuditError("trace_projection_schema_invalid")
        material = {
            key: value
            for key, value in trace_projection.items()
            if key != "projection_sha256"
        }
        if trace_projection.get("projection_sha256") != _sha(material):
            raise ControlCapacityAuditError("trace_projection_self_hash_invalid")
        if any(
            trace_projection.get(field) is not False
            for field in (
                "selection_authorized",
                "stage_promotion_authorized",
                "recovery3_mutation_authorized",
            )
        ):
            raise ControlCapacityAuditError("trace_projection_authority_invalid")
        records = trace_projection.get("records")
        if (
            not isinstance(records, list)
            or len(records) != trace_projection.get("record_count")
            or not all(isinstance(row, dict) for row in records)
        ):
            raise ControlCapacityAuditError("trace_projection_records_invalid")
        closed_assignments: set[str] = set()
        for row in records:
            record_material = {
                key: value for key, value in row.items() if key != "record_sha256"
            }
            if row.get("record_sha256") != _sha(record_material):
                raise ControlCapacityAuditError("trace_record_self_hash_invalid")
            if any(
                row.get(field) is not False
                for field in (
                    "selection_authorized",
                    "stage_promotion_authorized",
                    "recovery3_mutation_authorized",
                )
            ):
                raise ControlCapacityAuditError("trace_record_authority_invalid")
            assignment = str(row.get("reserve_assignment_sha256", ""))
            if assignment in closed_assignments or assignment not in trace_candidate_rows:
                raise ControlCapacityAuditError("trace_projection_scope_invalid")
            candidate = trace_candidate_rows[assignment]
            expected_chain_address = (
                f"{str(candidate.get('chain', '')).lower()}:"
                f"{str(candidate.get('control_address', '')).lower()}"
            )
            if (
                row.get("case_id") != candidate.get("case_name")
                or str(row.get("chain", "")).lower()
                != str(candidate.get("chain", "")).lower()
                or str(row.get("control_address", "")).lower()
                != str(candidate.get("control_address", "")).lower()
                or str(row.get("chain_address", "")).lower()
                != expected_chain_address
                or row.get("reserve_record_sha256") != candidate.get("result_sha256")
                or row.get("temporal_pre_cutoff") is not True
                or row.get("trace_proof") is not True
                or row.get("provider_consensus") is not True
                or row.get("rpc_classification_complete") is not True
            ):
                raise ControlCapacityAuditError("trace_record_binding_invalid")
            closed_assignments.add(assignment)
            trace_closed_rows.append(candidate)
        if closed_assignments != trace_assignments:
            raise ControlCapacityAuditError("trace_projection_incomplete")
        trace_projection_sha = str(trace_projection["projection_sha256"])

    unresolved_trace_assignments = trace_assignments - {
        str(row["reserve_assignment_sha256"]) for row in trace_closed_rows
    }
    evidence_complete_rows.extend(trace_closed_rows)
    candidate_edges = pd.DataFrame(
        [
            {
                "case_name": row["case_name"],
                "chain": row["chain"],
                "control_address": row["control_address"],
            }
            for row in evidence_complete_rows
        ],
        columns=["case_name", "chain", "control_address"],
    )
    original = maximum_no_reuse_allocation(
        scope, controls_per_positive=controls_per_positive, case_names=case_names
    )
    evidence_complete_capacity = maximum_no_reuse_allocation(
        pd.concat([scope, candidate_edges], ignore_index=True),
        controls_per_positive=controls_per_positive,
        case_names=case_names,
    )
    target = len(case_names) * controls_per_positive
    qualifies = int(evidence_complete_capacity["maximum_assignable_controls"]) == target
    audit: dict[str, object] = {
        "schema_version": "chronosaudit.control_effective_capacity_audit.v1",
        "decision": (
            "EVIDENCE_COMPLETE_DENOMINATOR_CAPACITY_VERIFIED"
            if qualifies
            else "EVIDENCE_COMPLETE_DENOMINATOR_CAPACITY_INSUFFICIENT"
        ),
        "case_count": len(case_names),
        "controls_per_positive": controls_per_positive,
        "target_control_rows": target,
        "effective_complete_count": complete_count,
        "evidence_complete_candidate_count": len(evidence_complete_rows),
        "receipt_evidence_complete_candidate_count": (
            len(evidence_complete_rows) - len(trace_closed_rows)
        ),
        "trace_closed_candidate_count": len(trace_closed_rows),
        "unresolved_trace_candidate_count": len(unresolved_trace_assignments),
        "original_denominator": original,
        "evidence_complete_capacity": evidence_complete_capacity,
        "minimum_trace_or_additional_unique_allocatable_edges_required": int(
            evidence_complete_capacity["total_shortfall"]
        ),
        "denominator_qualifies": qualifies,
        "source_reconciliations": source_bindings,
        "input_sha256": {
            "original_pair_scope": _file_sha(scope_file),
            "expansion_requirements": _file_sha(requirements_file),
            "trace_target_identities": _file_sha(trace_file),
            "trace_deployment_projection": (
                _file_sha(trace_projection_file)
                if trace_projection_file is not None
                else None
            ),
        },
        "trace_target_identities_sha256": rebuilt_trace[
            "target_identities_sha256"
        ],
        "trace_deployment_projection_sha256": trace_projection_sha,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "independent_review_established": False,
        "release_authorized": False,
        "interpretation": (
            "Only fully classified, provider-consensus, pre-cutoff deployment rows "
            "enter this capacity graph. Trace-required rows enter only through an "
            "exact complete self-hash-valid trace deployment projection; unresolved "
            "trace rows are excluded. "
            "Capacity is necessary but does not itself admit, select, qualify, or count rows."
        ),
    }
    audit["audit_sha256"] = _sha(audit)
    return audit
