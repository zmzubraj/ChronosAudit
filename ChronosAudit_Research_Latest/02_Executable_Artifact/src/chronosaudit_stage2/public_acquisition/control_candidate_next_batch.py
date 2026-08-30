from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pandas as pd

from .control_candidate_rpc_acquisition import _round_robin_by_case
from .control_pair_scope import maximum_no_reuse_allocation


class ControlCandidateNextBatchError(ValueError):
    """Raised when a deterministic capacity-closing batch cannot be frozen."""


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
        raise ControlCandidateNextBatchError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateNextBatchError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCandidateNextBatchError(f"{label}_not_ordinary_file")
    return resolved


def _json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCandidateNextBatchError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCandidateNextBatchError(f"{label}_root_invalid")
    return payload


def _verified_run_manifest(root: Path, queue_file: Path) -> dict[str, object]:
    manifest = _json(_ordinary(root / "run_manifest.json", "run_manifest"), "run_manifest")
    material = {key: value for key, value in manifest.items() if key != "run_binding_sha256"}
    if manifest.get("run_binding_sha256") != _sha(material):
        raise ControlCandidateNextBatchError("run_manifest_self_hash_invalid")
    if manifest.get("queue_sha256") != _file_sha(queue_file):
        raise ControlCandidateNextBatchError("run_manifest_queue_hash_mismatch")
    return manifest


def _verified_summary(path: Path, run_binding: str, queue_count: int) -> dict[str, object]:
    summary = _json(path, "acquisition_summary")
    material = {key: value for key, value in summary.items() if key != "summary_sha256"}
    if (
        summary.get("schema_version") != "chronosaudit.control_candidate_rpc_acquisition_summary.v1"
        or summary.get("summary_sha256") != _sha(material)
        or summary.get("run_binding_sha256") != run_binding
        or summary.get("queue_row_count") != queue_count
    ):
        raise ControlCandidateNextBatchError("acquisition_summary_binding_invalid")
    if any(summary.get(field) is not False for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    )):
        raise ControlCandidateNextBatchError("acquisition_summary_authority_invalid")
    return summary


def _terminal_statuses(events_file: Path) -> tuple[set[str], set[str], str]:
    previous = "0" * 64
    statuses: dict[str, str] = {}
    for index, line in enumerate(events_file.read_text(encoding="utf-8").splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlCandidateNextBatchError(f"event_json_invalid:{index}") from exc
        stored = event.pop("event_sha256", None)
        if event.get("previous_event_sha256") != previous or stored != _sha(event):
            raise ControlCandidateNextBatchError(f"event_chain_invalid:{index}")
        previous = str(stored)
        assignment = str(event.get("reserve_assignment_sha256") or "")
        status = str(event.get("status") or "")
        if not assignment or status not in {"COMPLETE", "TERMINAL_REJECTED", "PARTIAL"}:
            raise ControlCandidateNextBatchError(f"event_identity_or_status_invalid:{index}")
        prior = statuses.get(assignment)
        if prior in {"COMPLETE", "TERMINAL_REJECTED"}:
            raise ControlCandidateNextBatchError(f"event_after_terminal_status:{index}")
        statuses[assignment] = status
    return (
        {assignment for assignment, status in statuses.items() if status == "COMPLETE"},
        {assignment for assignment, status in statuses.items() if status == "TERMINAL_REJECTED"},
        previous,
    )


def _observed_edges(root: Path, assignments: set[str], run_binding: str) -> pd.DataFrame:
    records: list[dict[str, str]] = []
    for assignment in sorted(assignments):
        result = _json(
            _ordinary(root / "candidates" / f"{assignment}.json", "candidate_result"),
            "candidate_result",
        )
        material = {key: value for key, value in result.items() if key != "result_sha256"}
        if (
            result.get("result_sha256") != _sha(material)
            or result.get("reserve_assignment_sha256") != assignment
            or result.get("run_binding_sha256") != run_binding
        ):
            raise ControlCandidateNextBatchError(f"candidate_result_binding_invalid:{assignment}")
        records.append(
            {
                "case_name": str(result["case_name"]),
                "chain": str(result["chain"]).lower(),
                "control_address": str(result["control_address"]).lower(),
            }
        )
    return pd.DataFrame(records, columns=["case_name", "chain", "control_address"])


def _atomic_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def build_control_candidate_next_batch(
    *,
    original_pair_scope_path: Path,
    expansion_requirements_path: Path,
    full_queue_path: Path,
    acquisition_summary_path: Path,
    acquisition_root: Path,
    output_queue_path: Path,
) -> dict[str, object]:
    scope_file = _ordinary(original_pair_scope_path, "original_pair_scope")
    requirements_file = _ordinary(expansion_requirements_path, "expansion_requirements")
    queue_file = _ordinary(full_queue_path, "full_queue")
    summary_file = _ordinary(acquisition_summary_path, "acquisition_summary")
    root = acquisition_root.expanduser().resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ControlCandidateNextBatchError("acquisition_root_invalid")
    events_file = _ordinary(root / "events.jsonl", "acquisition_events")

    scope = pd.read_csv(scope_file, dtype=str, keep_default_na=False)
    needed_scope = {"case_name", "chain", "control_address"}
    if not needed_scope.issubset(scope.columns):
        raise ControlCandidateNextBatchError("original_pair_scope_columns_invalid")
    requirements = pd.read_csv(requirements_file, dtype=str, keep_default_na=False)
    if not {"case_name", "controls_required"}.issubset(requirements.columns):
        raise ControlCandidateNextBatchError("expansion_requirements_columns_invalid")
    if requirements["case_name"].duplicated().any():
        raise ControlCandidateNextBatchError("expansion_requirements_duplicate_case")
    required_values = {int(value) for value in requirements["controls_required"]}
    if len(required_values) != 1:
        raise ControlCandidateNextBatchError("controls_required_inconsistent")
    controls_per_positive = next(iter(required_values))
    case_names = requirements["case_name"].astype(str).tolist()

    with queue_file.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        queue = list(reader)
    needed_queue = {"case_name", "chain", "control_address", "reserve_assignment_sha256"}
    if not needed_queue.issubset(fieldnames) or not queue:
        raise ControlCandidateNextBatchError("full_queue_columns_or_rows_invalid")
    assignments = [row["reserve_assignment_sha256"] for row in queue]
    identities = [f"{row['chain'].lower()}:{row['control_address'].lower()}" for row in queue]
    if len(assignments) != len(set(assignments)) or len(identities) != len(set(identities)):
        raise ControlCandidateNextBatchError("full_queue_identity_duplicate")

    run_manifest = _verified_run_manifest(root, queue_file)
    summary = _verified_summary(
        summary_file, str(run_manifest["run_binding_sha256"]), len(queue)
    )
    complete, rejected, event_terminal = _terminal_statuses(events_file)
    if len(complete) != int(summary.get("completed_count", -1)):
        raise ControlCandidateNextBatchError("completed_count_mismatch")
    if len(rejected) != int(summary.get("terminal_rejected_count", -1)):
        raise ControlCandidateNextBatchError("rejected_count_mismatch")
    known = set(assignments)
    if not (complete | rejected).issubset(known):
        raise ControlCandidateNextBatchError("event_assignment_outside_queue")

    observed = _observed_edges(root, complete, str(run_manifest["run_binding_sha256"]))
    base = pd.concat(
        [scope[["case_name", "chain", "control_address"]], observed],
        ignore_index=True,
    )
    pending = _round_robin_by_case(
        [row for row in queue if row["reserve_assignment_sha256"] not in complete | rejected]
    )
    target = len(case_names) * controls_per_positive

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
    if int(allocation(len(pending))["maximum_assignable_controls"]) < target:
        raise ControlCandidateNextBatchError("full_pending_queue_cannot_reach_target")
    low, high = 0, len(pending)
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
    _atomic_csv(output, fieldnames, selected)
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_next_batch.v1",
        "decision": "MINIMUM_FROZEN_PENDING_PREFIX_IF_ALL_ROWS_ARE_VALID",
        "case_count": len(case_names),
        "controls_per_positive": controls_per_positive,
        "target_control_rows": target,
        "current_maximum_assignable_controls": int(current["maximum_assignable_controls"]),
        "current_total_shortfall": int(current["total_shortfall"]),
        "pending_row_count": len(pending),
        "minimum_pending_prefix_row_count": prefix_count,
        "projected_maximum_assignable_controls_if_all_valid": int(
            projected["maximum_assignable_controls"]
        ),
        "previous_prefix_maximum_assignable_controls": int(
            previous["maximum_assignable_controls"]
        ),
        "assumption": "EVERY_PREFIX_ROW_RETURNS_VALID_DISTINCT_DEPLOYMENT_EVIDENCE",
        "warning": "Qualification attrition can require a larger acquisition batch.",
        "output_queue_path": str(output),
        "output_queue_sha256": _file_sha(output),
        "output_records_sha256": _sha(selected),
        "input_sha256": {
            "original_pair_scope": _file_sha(scope_file),
            "expansion_requirements": _file_sha(requirements_file),
            "full_queue": _file_sha(queue_file),
            "acquisition_summary": _file_sha(summary_file),
            "acquisition_events": _file_sha(events_file),
        },
        "source_bindings": {
            "acquisition_run_binding_sha256": run_manifest["run_binding_sha256"],
            "acquisition_summary_sha256": summary["summary_sha256"],
            "acquisition_event_terminal_hash": event_terminal,
        },
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["manifest_sha256"] = _sha(manifest)
    return manifest
