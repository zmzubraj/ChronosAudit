from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

import pandas as pd

from .control_candidate_rpc_acquisition import _round_robin_by_case
from .control_candidate_next_batch import (
    _observed_edges,
    _terminal_statuses,
    _verified_run_manifest,
    _verified_summary,
)
from .control_pair_scope import maximum_no_reuse_allocation


class ControlCandidateAttritionExtensionError(ValueError):
    """A deterministic attrition-replacement prefix could not be frozen."""


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCandidateAttritionExtensionError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateAttritionExtensionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCandidateAttritionExtensionError(f"{label}_not_ordinary_file")
    return resolved


def _json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCandidateAttritionExtensionError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise ControlCandidateAttritionExtensionError(f"{label}_root_invalid")
    return value


def _csv(path: Path, label: str) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = [dict(row) for row in reader]
    needed = {"case_name", "chain", "control_address", "reserve_assignment_sha256"}
    if not needed.issubset(fields) or not rows:
        raise ControlCandidateAttritionExtensionError(f"{label}_columns_or_rows_invalid")
    assignments = [row["reserve_assignment_sha256"] for row in rows]
    identities = [f"{row['chain'].lower()}:{row['control_address'].lower()}" for row in rows]
    if len(assignments) != len(set(assignments)) or len(identities) != len(set(identities)):
        raise ControlCandidateAttritionExtensionError(f"{label}_identity_duplicate")
    return fields, rows


def _atomic_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCandidateAttritionExtensionError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_control_candidate_attrition_extension(
    *,
    original_pair_scope_path: Path,
    expansion_requirements_path: Path,
    full_queue_path: Path,
    attempted_queue_path: Path,
    reconciliation_manifest_path: Path,
    effective_complete_path: Path,
    effective_rejected_path: Path,
    prior_acquisition_summary_path: Path,
    prior_acquisition_root: Path,
    output_queue_path: Path,
) -> dict[str, object]:
    """Freeze the smallest remaining optimistic prefix after observed attrition."""
    scope_file = _ordinary(original_pair_scope_path, "original_pair_scope")
    requirements_file = _ordinary(expansion_requirements_path, "expansion_requirements")
    full_file = _ordinary(full_queue_path, "full_queue")
    attempted_file = _ordinary(attempted_queue_path, "attempted_queue")
    reconciliation_file = _ordinary(reconciliation_manifest_path, "reconciliation")
    complete_file = _ordinary(effective_complete_path, "effective_complete")
    rejected_file = _ordinary(effective_rejected_path, "effective_rejected")
    prior_summary_file = _ordinary(prior_acquisition_summary_path, "prior_summary")

    reconciliation = _json(reconciliation_file, "reconciliation")
    material = {
        key: value for key, value in reconciliation.items() if key != "manifest_sha256"
    }
    if (
        reconciliation.get("schema_version")
        != "chronosaudit.control_candidate_effective_reconciliation.v1"
        or reconciliation.get("decision")
        != "EFFECTIVE_ACQUISITION_TERMINAL_RECONCILIATION_VERIFIED"
        or reconciliation.get("manifest_sha256") != _sha(material)
        or reconciliation.get("initial_queue_sha256") != _file_sha(attempted_file)
        or reconciliation.get("complete_output_sha256") != _file_sha(complete_file)
        or reconciliation.get("rejected_output_sha256") != _file_sha(rejected_file)
        or reconciliation.get("effective_unresolved_count") != 0
    ):
        raise ControlCandidateAttritionExtensionError("reconciliation_binding_invalid")
    for field in (
        "denominator_admission_authorized",
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if reconciliation.get(field) is not False:
            raise ControlCandidateAttritionExtensionError(
                f"reconciliation_{field}_invalid"
            )

    scope = pd.read_csv(scope_file, dtype=str, keep_default_na=False)
    if not {"case_name", "chain", "control_address"}.issubset(scope.columns):
        raise ControlCandidateAttritionExtensionError("original_pair_scope_columns_invalid")
    requirements = pd.read_csv(requirements_file, dtype=str, keep_default_na=False)
    if (
        not {"case_name", "controls_required"}.issubset(requirements.columns)
        or requirements["case_name"].duplicated().any()
    ):
        raise ControlCandidateAttritionExtensionError("expansion_requirements_invalid")
    required_values = {int(value) for value in requirements["controls_required"]}
    if len(required_values) != 1:
        raise ControlCandidateAttritionExtensionError("controls_required_inconsistent")
    controls_per_positive = next(iter(required_values))
    case_names = requirements["case_name"].astype(str).tolist()
    target = len(case_names) * controls_per_positive

    full_fields, full_rows = _csv(full_file, "full_queue")
    _, attempted_rows = _csv(attempted_file, "attempted_queue")
    _, complete_rows = _csv(complete_file, "effective_complete")
    _, rejected_rows = _csv(rejected_file, "effective_rejected")
    full_by_assignment = {row["reserve_assignment_sha256"]: row for row in full_rows}
    attempted_by_assignment = {
        row["reserve_assignment_sha256"]: row for row in attempted_rows
    }
    if not set(attempted_by_assignment).issubset(full_by_assignment):
        raise ControlCandidateAttritionExtensionError("attempted_outside_full_queue")
    for assignment, row in attempted_by_assignment.items():
        full_row = full_by_assignment[assignment]
        if any(
            str(row[field]).lower() != str(full_row[field]).lower()
            for field in ("case_name", "chain", "control_address")
        ):
            raise ControlCandidateAttritionExtensionError(
                f"attempted_row_mismatch:{assignment}"
            )
    complete_ids = {row["reserve_assignment_sha256"] for row in complete_rows}
    rejected_ids = {row["reserve_assignment_sha256"] for row in rejected_rows}
    if (
        complete_ids & rejected_ids
        or complete_ids | rejected_ids != set(attempted_by_assignment)
        or len(complete_rows) != int(reconciliation.get("effective_complete_count") or -1)
        or len(rejected_rows) != int(reconciliation.get("effective_rejected_count") or -1)
        or any(row.get("effective_status") != "COMPLETE" for row in complete_rows)
        or any(row.get("effective_status") != "TERMINAL_REJECTED" for row in rejected_rows)
    ):
        raise ControlCandidateAttritionExtensionError("effective_membership_invalid")

    prior_root_candidate = prior_acquisition_root.expanduser()
    if prior_root_candidate.is_symlink():
        raise ControlCandidateAttritionExtensionError("prior_acquisition_root_invalid")
    try:
        prior_root = prior_root_candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateAttritionExtensionError("prior_acquisition_root_missing") from exc
    if not prior_root.is_dir():
        raise ControlCandidateAttritionExtensionError("prior_acquisition_root_invalid")
    prior_run = _verified_run_manifest(prior_root, full_file)
    prior_summary = _verified_summary(
        prior_summary_file, str(prior_run["run_binding_sha256"]), len(full_rows)
    )
    prior_complete, prior_rejected, prior_terminal = _terminal_statuses(
        _ordinary(prior_root / "events.jsonl", "prior_acquisition_events")
    )
    if (
        len(prior_complete) != int(prior_summary.get("completed_count", -1))
        or len(prior_rejected) != int(prior_summary.get("terminal_rejected_count", -1))
        or prior_rejected
    ):
        raise ControlCandidateAttritionExtensionError("prior_acquisition_counts_invalid")
    prior_observed = _observed_edges(
        prior_root, prior_complete, str(prior_run["run_binding_sha256"])
    )

    base = pd.concat(
        [
            scope[["case_name", "chain", "control_address"]],
            prior_observed[["case_name", "chain", "control_address"]],
            pd.DataFrame(complete_rows)[["case_name", "chain", "control_address"]],
        ],
        ignore_index=True,
    )
    pending = _round_robin_by_case(
        [
            row
            for row in full_rows
            if row["reserve_assignment_sha256"] not in attempted_by_assignment
        ]
    )

    def allocation(prefix_count: int) -> dict[str, object]:
        added = pd.DataFrame(
            [
                {
                    "case_name": row["case_name"],
                    "chain": row["chain"],
                    "control_address": row["control_address"],
                }
                for row in pending[:prefix_count]
            ],
            columns=["case_name", "chain", "control_address"],
        )
        return maximum_no_reuse_allocation(
            pd.concat([base, added], ignore_index=True),
            controls_per_positive=controls_per_positive,
            case_names=case_names,
        )

    current = allocation(0)
    if int(current["maximum_assignable_controls"]) >= target:
        prefix_count = 0
    else:
        if int(allocation(len(pending))["maximum_assignable_controls"]) < target:
            raise ControlCandidateAttritionExtensionError(
                "full_remaining_queue_cannot_reach_target"
            )
        low, high = 1, len(pending)
        while low < high:
            middle = (low + high) // 2
            if int(allocation(middle)["maximum_assignable_controls"]) >= target:
                high = middle
            else:
                low = middle + 1
        prefix_count = low
    selected = pending[:prefix_count]
    projected = allocation(prefix_count)
    previous = allocation(max(0, prefix_count - 1))
    output = output_queue_path.expanduser().resolve(strict=False)
    _atomic_csv(output, full_fields, selected)
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_attrition_extension.v1",
        "decision": "MINIMUM_FROZEN_REMAINING_PREFIX_AFTER_VERIFIED_ATTRITION_IF_ALL_ROWS_VALID",
        "case_count": len(case_names),
        "controls_per_positive": controls_per_positive,
        "target_control_rows": target,
        "attempted_row_count": len(attempted_rows),
        "effective_complete_count": len(complete_rows),
        "effective_rejected_count": len(rejected_rows),
        "prior_observed_deployment_count": len(prior_complete),
        "current_maximum_assignable_controls": int(current["maximum_assignable_controls"]),
        "current_total_shortfall": int(current["total_shortfall"]),
        "remaining_queue_row_count": len(pending),
        "minimum_extension_prefix_row_count": prefix_count,
        "projected_maximum_assignable_controls_if_all_valid": int(
            projected["maximum_assignable_controls"]
        ),
        "previous_prefix_maximum_assignable_controls": int(
            previous["maximum_assignable_controls"]
        ),
        "assumption": "EVERY_EXTENSION_ROW_RETURNS_VALID_DISTINCT_DEPLOYMENT_EVIDENCE",
        "warning": "Receipt, trace, admission, covariate, and qualification attrition can require another extension.",
        "output_queue_path": str(output),
        "output_queue_sha256": _file_sha(output),
        "output_records_sha256": _sha(selected),
        "input_sha256": {
            "original_pair_scope": _file_sha(scope_file),
            "expansion_requirements": _file_sha(requirements_file),
            "full_queue": _file_sha(full_file),
            "attempted_queue": _file_sha(attempted_file),
            "reconciliation_manifest": _file_sha(reconciliation_file),
            "effective_complete": _file_sha(complete_file),
            "effective_rejected": _file_sha(rejected_file),
            "prior_acquisition_summary": _file_sha(prior_summary_file),
            "prior_acquisition_events": _file_sha(prior_root / "events.jsonl"),
        },
        "source_bindings": {
            "reconciliation_manifest_sha256": reconciliation["manifest_sha256"],
            "prior_acquisition_run_binding_sha256": prior_run["run_binding_sha256"],
            "prior_acquisition_summary_sha256": prior_summary["summary_sha256"],
            "prior_acquisition_event_terminal_hash": prior_terminal,
        },
        "rpc_authorized": False,
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
    manifest["manifest_sha256"] = _sha(manifest)
    return manifest
