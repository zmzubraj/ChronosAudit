from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path


class ControlCandidateRpcRetryResolutionError(ValueError):
    """A retry result set could not be verified into the resolution index."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCandidateRpcRetryResolutionError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateRpcRetryResolutionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCandidateRpcRetryResolutionError(f"{label}_not_ordinary_file")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCandidateRpcRetryResolutionError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise ControlCandidateRpcRetryResolutionError(f"{label}_root_invalid")
    return value


def _authority_false(payload: Mapping[str, object], label: str) -> None:
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(field) is not False:
            raise ControlCandidateRpcRetryResolutionError(f"{label}_{field}_invalid")


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCandidateRpcRetryResolutionError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_canonical_json(dict(payload)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _verify_index(path: Path) -> tuple[Path, dict[str, object]]:
    index_file = _ordinary(path, "prior_index")
    index = _load(index_file, "prior_index")
    material = {key: value for key, value in index.items() if key != "index_sha256"}
    if (
        index.get("schema_version")
        != "chronosaudit.control_candidate_rpc_retry_resolution_index.v1"
        or index.get("index_sha256") != _canonical_sha(material)
    ):
        raise ControlCandidateRpcRetryResolutionError("prior_index_binding_invalid")
    _authority_false(index, "prior_index")
    if index.get("counter_authority") is not False:
        raise ControlCandidateRpcRetryResolutionError("prior_index_counter_authority_invalid")
    entries = index.get("resolved_assignments")
    if not isinstance(entries, list) or len(entries) != int(index.get("resolved_count") or -1):
        raise ControlCandidateRpcRetryResolutionError("prior_index_entries_invalid")
    return index_file, index


def build_control_candidate_rpc_retry_resolution_index(
    *,
    retry_queue_path: Path,
    retry_targets_manifest_path: Path,
    retry_run_manifest_path: Path,
    retry_summary_path: Path,
    retry_event_ledger_path: Path,
    output_path: Path,
    prior_index_path: Path | None = None,
    allow_partial_run: bool = False,
) -> dict[str, object]:
    """Verify successful retry results and append them to a non-authorizing index."""
    queue_file = _ordinary(retry_queue_path, "retry_queue")
    targets_file = _ordinary(retry_targets_manifest_path, "retry_targets")
    run_file = _ordinary(retry_run_manifest_path, "retry_run_manifest")
    summary_file = _ordinary(retry_summary_path, "retry_summary")
    events_file = _ordinary(retry_event_ledger_path, "retry_event_ledger")
    targets = _load(targets_file, "retry_targets")
    target_material = {
        key: value for key, value in targets.items() if key != "manifest_sha256"
    }
    if (
        targets.get("schema_version")
        != "chronosaudit.control_candidate_rpc_retry_targets.v1"
        or targets.get("manifest_sha256") != _canonical_sha(target_material)
        or targets.get("retry_queue_sha256") != _file_sha(queue_file)
    ):
        raise ControlCandidateRpcRetryResolutionError("retry_targets_binding_invalid")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if targets.get(field) is not False:
            raise ControlCandidateRpcRetryResolutionError(
                f"retry_targets_{field}_invalid"
            )

    with queue_file.open(encoding="utf-8", newline="") as handle:
        queue_rows = list(csv.DictReader(handle))
    queue_ids = [str(row.get("reserve_assignment_sha256") or "") for row in queue_rows]
    if (
        not queue_ids
        or len(queue_ids) != int(targets.get("retry_row_count") or -1)
        or len(set(queue_ids)) != len(queue_ids)
    ):
        raise ControlCandidateRpcRetryResolutionError("retry_queue_invalid")
    target_scopes = targets.get("retry_scopes")
    if not isinstance(target_scopes, list) or {
        str(scope.get("reserve_assignment_sha256") or "")
        for scope in target_scopes
        if isinstance(scope, Mapping)
    } != set(queue_ids):
        raise ControlCandidateRpcRetryResolutionError("retry_scope_queue_mismatch")

    run = _load(run_file, "retry_run_manifest")
    run_material = {key: value for key, value in run.items() if key != "run_binding_sha256"}
    if (
        run.get("schema_version")
        != "chronosaudit.control_candidate_rpc_acquisition_run.v2"
        or run.get("run_binding_sha256") != _canonical_sha(run_material)
        or run.get("queue_sha256") != _file_sha(queue_file)
        or int(run.get("queue_row_count") or -1) != len(queue_ids)
    ):
        raise ControlCandidateRpcRetryResolutionError("retry_run_binding_invalid")
    _authority_false(run, "retry_run")

    summary = _load(summary_file, "retry_summary")
    summary_material = {
        key: value for key, value in summary.items() if key != "summary_sha256"
    }
    if (
        summary.get("schema_version")
        != "chronosaudit.control_candidate_rpc_acquisition_summary.v1"
        or summary.get("summary_sha256") != _canonical_sha(summary_material)
        or summary.get("run_binding_sha256") != run.get("run_binding_sha256")
        or int(summary.get("queue_row_count") or -1) != len(queue_ids)
    ):
        raise ControlCandidateRpcRetryResolutionError("retry_summary_binding_invalid")
    _authority_false(summary, "retry_summary")

    previous = "0" * 64
    events: list[dict[str, object]] = []
    status_counts: Counter[str] = Counter()
    for index, line in enumerate(events_file.read_text(encoding="utf-8").splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlCandidateRpcRetryResolutionError(
                f"retry_event_json_invalid:{index}"
            ) from exc
        if not isinstance(event, dict):
            raise ControlCandidateRpcRetryResolutionError(
                f"retry_event_row_invalid:{index}"
            )
        material = dict(event)
        stored = material.pop("event_sha256", None)
        if (
            material.get("schema_version")
            != "chronosaudit.control_candidate_rpc_acquisition_event.v1"
            or material.get("previous_event_sha256") != previous
            or stored != _canonical_sha(material)
        ):
            raise ControlCandidateRpcRetryResolutionError(
                f"retry_event_chain_invalid:{index}"
            )
        previous = str(stored)
        status_counts[str(event.get("status") or "")] += 1
        events.append(event)
    if dict(sorted(status_counts.items())) != dict(
        sorted((summary.get("ledger_status_counts") or {}).items())
    ):
        raise ControlCandidateRpcRetryResolutionError("retry_summary_status_mismatch")
    complete_count = status_counts.get("COMPLETE", 0)
    unresolved_count = len(events) - complete_count
    summary_complete_count = int(
        summary.get("completed_count")
        if summary.get("completed_count") is not None
        else -1
    )
    summary_retry_count = int(
        summary.get("retry_required_count")
        if summary.get("retry_required_count") is not None
        else -1
    )
    strict_complete = (
        summary_complete_count == len(queue_ids)
        and summary_retry_count == 0
        and set(status_counts) == {"COMPLETE"}
        and len(events) == len(queue_ids)
    )
    partial_complete = (
        allow_partial_run
        and len(events) == len(queue_ids)
        and set(status_counts).issubset({"COMPLETE", "PARTIAL"})
        and complete_count > 0
        and unresolved_count > 0
        and summary_complete_count == complete_count
        and summary_retry_count == status_counts.get("PARTIAL", 0)
    )
    if not (strict_complete or partial_complete):
        raise ControlCandidateRpcRetryResolutionError("retry_not_fully_complete")

    new_entries: list[dict[str, object]] = []
    event_ids: set[str] = set()
    for event in events:
        assignment = str(event.get("reserve_assignment_sha256") or "")
        if assignment not in queue_ids or assignment in event_ids:
            raise ControlCandidateRpcRetryResolutionError("retry_event_assignment_invalid")
        event_ids.add(assignment)
        if event.get("status") != "COMPLETE":
            continue
        result_file = _ordinary(Path(str(event.get("result_path") or "")), "retry_result")
        result = _load(result_file, "retry_result")
        result_material = {
            key: value for key, value in result.items() if key != "result_sha256"
        }
        if (
            result.get("result_sha256") != _canonical_sha(result_material)
            or result.get("result_sha256") != event.get("result_sha256")
            or result.get("run_binding_sha256") != run.get("run_binding_sha256")
            or result.get("reserve_assignment_sha256") != assignment
        ):
            raise ControlCandidateRpcRetryResolutionError("retry_result_binding_invalid")
        _authority_false(result, "retry_result")
        new_entries.append(
            {
                "reserve_assignment_sha256": assignment,
                "retry_targets_manifest_sha256": targets["manifest_sha256"],
                "retry_run_binding_sha256": run["run_binding_sha256"],
                "retry_complete_event_sha256": event["event_sha256"],
                "result_sha256": result["result_sha256"],
                "result_file_sha256": _file_sha(result_file),
                "result_path": str(result_file),
            }
        )

    prior_entries: list[dict[str, object]] = []
    prior_file_sha: str | None = None
    prior_index_sha: str | None = None
    if prior_index_path is not None:
        prior_file, prior = _verify_index(prior_index_path)
        prior_file_sha = _file_sha(prior_file)
        prior_index_sha = str(prior["index_sha256"])
        prior_entries = [dict(entry) for entry in prior["resolved_assignments"]]
    by_assignment = {
        str(entry.get("reserve_assignment_sha256") or ""): entry
        for entry in prior_entries
    }
    for entry in new_entries:
        assignment = str(entry["reserve_assignment_sha256"])
        if assignment in by_assignment:
            raise ControlCandidateRpcRetryResolutionError("retry_resolution_duplicate")
        by_assignment[assignment] = entry
    resolved = [by_assignment[key] for key in sorted(by_assignment)]
    payload: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_retry_resolution_index.v1",
        "decision": "RETRY_RESOLUTION_INDEX_VERIFIED_NON_AUTHORIZING",
        "prior_index_file_sha256": prior_file_sha,
        "prior_index_sha256": prior_index_sha,
        "appended_retry_targets_manifest_sha256": targets["manifest_sha256"],
        "appended_retry_run_binding_sha256": run["run_binding_sha256"],
        "appended_retry_summary_sha256": summary["summary_sha256"],
        "appended_retry_event_ledger_sha256": _file_sha(events_file),
        "source_run_complete_count": complete_count,
        "source_run_unresolved_count": unresolved_count,
        "resolved_count": len(resolved),
        "resolved_assignments": resolved,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    payload["index_sha256"] = _canonical_sha(payload)
    _atomic_json(output_path.expanduser(), payload)
    return payload
