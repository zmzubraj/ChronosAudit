from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path


class ControlCandidateRpcRetryTargetsError(ValueError):
    """A retry queue could not be derived from immutable candidate-RPC evidence."""


_RUN_SCHEMA = "chronosaudit.control_candidate_rpc_acquisition_run.v2"
_SUMMARY_SCHEMA = "chronosaudit.control_candidate_rpc_acquisition_summary.v1"
_EVENT_SCHEMA = "chronosaudit.control_candidate_rpc_acquisition_event.v1"
_REQUEST_EVENT_SCHEMA = "chronosaudit.control_candidate_rpc_request_event.v1"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
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
        raise ControlCandidateRpcRetryTargetsError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateRpcRetryTargetsError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCandidateRpcRetryTargetsError(f"{label}_not_ordinary_file")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCandidateRpcRetryTargetsError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCandidateRpcRetryTargetsError(f"{label}_root_invalid")
    return payload


def _read_jsonl(path: Path, label: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ControlCandidateRpcRetryTargetsError(f"{label}_encoding_invalid") from exc
    for index, line in enumerate(lines):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlCandidateRpcRetryTargetsError(
                f"{label}_json_invalid:{index}"
            ) from exc
        if not isinstance(row, dict):
            raise ControlCandidateRpcRetryTargetsError(
                f"{label}_row_invalid:{index}"
            )
        rows.append(row)
    return rows


def _validate_hash_chain(
    rows: list[dict[str, object]], *, label: str, schema: str, sequenced: bool
) -> str:
    previous = "0" * 64
    for index, original in enumerate(rows):
        row = dict(original)
        stored = row.pop("event_sha256", None)
        if (
            row.get("schema_version") != schema
            or row.get("previous_event_sha256") != previous
            or stored != _canonical_sha(row)
        ):
            raise ControlCandidateRpcRetryTargetsError(
                f"{label}_chain_invalid:{index}"
            )
        if sequenced and row.get("request_sequence") != index + 1:
            raise ControlCandidateRpcRetryTargetsError(
                f"{label}_sequence_invalid:{index}"
            )
        previous = str(stored)
    return previous


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCandidateRpcRetryTargetsError("output_manifest_symlink")
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


def _atomic_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCandidateRpcRetryTargetsError("output_queue_symlink")
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


def build_control_candidate_rpc_retry_targets(
    *,
    original_queue_path: Path,
    run_manifest_path: Path,
    summary_path: Path,
    event_ledger_path: Path,
    request_ledger_path: Path,
    output_queue_path: Path,
    output_manifest_path: Path,
    resolved_retry_index_path: Path | None = None,
    required_chains: list[str] | None = None,
) -> dict[str, object]:
    """Freeze only terminal PARTIAL scopes for a fresh, separately activated run."""
    queue_file = _ordinary(original_queue_path, "original_queue")
    run_file = _ordinary(run_manifest_path, "run_manifest")
    summary_file = _ordinary(summary_path, "summary")
    event_file = _ordinary(event_ledger_path, "event_ledger")
    request_file = _ordinary(request_ledger_path, "request_ledger")

    run = _load_json(run_file, "run_manifest")
    if run.get("schema_version") != _RUN_SCHEMA:
        raise ControlCandidateRpcRetryTargetsError("run_manifest_schema_invalid")
    run_material = {key: value for key, value in run.items() if key != "run_binding_sha256"}
    if run.get("run_binding_sha256") != _canonical_sha(run_material):
        raise ControlCandidateRpcRetryTargetsError("run_manifest_binding_invalid")
    if run.get("queue_sha256") != _file_sha(queue_file):
        raise ControlCandidateRpcRetryTargetsError("run_manifest_queue_hash_mismatch")
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if run.get(field) is not False:
            raise ControlCandidateRpcRetryTargetsError(f"run_manifest_{field}_invalid")

    summary = _load_json(summary_file, "summary")
    summary_material = {
        key: value for key, value in summary.items() if key != "summary_sha256"
    }
    if (
        summary.get("schema_version") != _SUMMARY_SCHEMA
        or summary.get("summary_sha256") != _canonical_sha(summary_material)
    ):
        raise ControlCandidateRpcRetryTargetsError("summary_binding_invalid")
    if summary.get("run_binding_sha256") != run.get("run_binding_sha256"):
        raise ControlCandidateRpcRetryTargetsError("summary_run_binding_mismatch")
    if summary.get("request_ledger_sha256") != _file_sha(request_file):
        raise ControlCandidateRpcRetryTargetsError("request_ledger_hash_mismatch")
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if summary.get(field) is not False:
            raise ControlCandidateRpcRetryTargetsError(f"summary_{field}_invalid")

    with queue_file.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        queue_rows = list(reader)
    if not fieldnames or not {"chain", "reserve_assignment_sha256"}.issubset(fieldnames):
        raise ControlCandidateRpcRetryTargetsError("original_queue_schema_invalid")
    if len(queue_rows) != int(run.get("queue_row_count") or -1):
        raise ControlCandidateRpcRetryTargetsError("original_queue_row_count_mismatch")
    by_assignment: dict[str, dict[str, str]] = {}
    for row in queue_rows:
        assignment = str(row.get("reserve_assignment_sha256") or "")
        if not assignment or assignment in by_assignment:
            raise ControlCandidateRpcRetryTargetsError("original_queue_assignment_duplicate")
        by_assignment[assignment] = row

    events = _read_jsonl(event_file, "event_ledger")
    _validate_hash_chain(
        events, label="event_ledger", schema=_EVENT_SCHEMA, sequenced=False
    )
    terminal_by_assignment: dict[str, dict[str, object]] = {}
    status_counts: Counter[str] = Counter()
    for event in events:
        assignment = str(event.get("reserve_assignment_sha256") or "")
        status = str(event.get("status") or "")
        if not assignment or assignment in terminal_by_assignment:
            raise ControlCandidateRpcRetryTargetsError("event_assignment_duplicate")
        if assignment not in by_assignment:
            raise ControlCandidateRpcRetryTargetsError("event_assignment_not_in_queue")
        terminal_by_assignment[assignment] = event
        status_counts[status] += 1
    if dict(sorted(status_counts.items())) != dict(
        sorted((summary.get("ledger_status_counts") or {}).items())
    ):
        raise ControlCandidateRpcRetryTargetsError("summary_status_counts_mismatch")
    partial_ids = {
        assignment
        for assignment, event in terminal_by_assignment.items()
        if event.get("status") == "PARTIAL"
    }
    if len(partial_ids) != int(summary.get("retry_required_count") or -1):
        raise ControlCandidateRpcRetryTargetsError("summary_retry_count_mismatch")
    if not partial_ids:
        raise ControlCandidateRpcRetryTargetsError("no_partial_retry_targets")

    resolved_ids: set[str] = set()
    resolved_index_file_sha: str | None = None
    resolved_index_sha: str | None = None
    if resolved_retry_index_path is not None:
        resolved_file = _ordinary(resolved_retry_index_path, "resolved_retry_index")
        resolved = _load_json(resolved_file, "resolved_retry_index")
        resolved_material = {
            key: value for key, value in resolved.items() if key != "index_sha256"
        }
        if (
            resolved.get("schema_version")
            != "chronosaudit.control_candidate_rpc_retry_resolution_index.v1"
            or resolved.get("decision")
            != "RETRY_RESOLUTION_INDEX_VERIFIED_NON_AUTHORIZING"
            or resolved.get("index_sha256") != _canonical_sha(resolved_material)
        ):
            raise ControlCandidateRpcRetryTargetsError(
                "resolved_retry_index_binding_invalid"
            )
        for field in (
            "denominator_admission_authorized",
            "selection_authorized",
            "qualification_authorized",
            "counter_authority",
            "stage_promotion_authorized",
            "recovery3_mutation_authorized",
        ):
            if resolved.get(field) is not False:
                raise ControlCandidateRpcRetryTargetsError(
                    f"resolved_retry_index_{field}_invalid"
                )
        entries = resolved.get("resolved_assignments")
        if not isinstance(entries, list) or len(entries) != int(
            resolved.get("resolved_count") or -1
        ):
            raise ControlCandidateRpcRetryTargetsError(
                "resolved_retry_index_entries_invalid"
            )
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ControlCandidateRpcRetryTargetsError(
                    "resolved_retry_index_entry_invalid"
                )
            assignment = str(entry.get("reserve_assignment_sha256") or "")
            if not assignment or assignment in resolved_ids:
                raise ControlCandidateRpcRetryTargetsError(
                    "resolved_retry_index_assignment_duplicate"
                )
            resolved_ids.add(assignment)
        if not resolved_ids.issubset(partial_ids):
            raise ControlCandidateRpcRetryTargetsError(
                "resolved_retry_index_not_primary_partial_subset"
            )
        resolved_index_file_sha = _file_sha(resolved_file)
        resolved_index_sha = str(resolved["index_sha256"])
    retry_ids = partial_ids - resolved_ids
    if required_chains is not None:
        chain_scope = sorted(
            {str(chain).strip().lower() for chain in required_chains if str(chain).strip()}
        )
        if not chain_scope:
            raise ControlCandidateRpcRetryTargetsError("required_chain_scope_invalid")
        retry_ids = {
            assignment
            for assignment in retry_ids
            if str(by_assignment[assignment].get("chain") or "").strip().lower()
            in chain_scope
        }
    else:
        chain_scope = sorted(
            {
                str(by_assignment[assignment].get("chain") or "").strip().lower()
                for assignment in retry_ids
            }
        )
    if not retry_ids:
        raise ControlCandidateRpcRetryTargetsError("no_unresolved_partial_retry_targets")

    requests = _read_jsonl(request_file, "request_ledger")
    request_terminal_hash = _validate_hash_chain(
        requests,
        label="request_ledger",
        schema=_REQUEST_EVENT_SCHEMA,
        sequenced=True,
    )
    if len(requests) != int(summary.get("request_count") or -1):
        raise ControlCandidateRpcRetryTargetsError("summary_request_count_mismatch")
    if request_terminal_hash != summary.get("request_ledger_terminal_hash"):
        raise ControlCandidateRpcRetryTargetsError("summary_request_terminal_hash_mismatch")

    retry_scopes: list[dict[str, object]] = []
    for assignment in sorted(retry_ids):
        attempted = [
            request
            for request in requests
            if request.get("scope_kind") == "candidate"
            and request.get("scope_id") == assignment
        ]
        if not attempted:
            raise ControlCandidateRpcRetryTargetsError("partial_scope_without_request")
        failed = [
            request
            for request in attempted
            if request.get("disposition") in {"TRANSPORT_ERROR", "RPC_ERROR"}
        ]
        if not failed:
            raise ControlCandidateRpcRetryTargetsError(
                "partial_scope_without_failed_request"
            )
        retry_scopes.append(
            {
                "reserve_assignment_sha256": assignment,
                "source_partial_event_sha256": terminal_by_assignment[assignment][
                    "event_sha256"
                ],
                "source_partial_error_code": terminal_by_assignment[assignment].get(
                    "error_code"
                ),
                "attempted_request_sequences": [
                    int(request["request_sequence"]) for request in attempted
                ],
                "attempted_request_event_sha256s": [
                    str(request["event_sha256"]) for request in attempted
                ],
                "attempted_request_dispositions": [
                    str(request["disposition"]) for request in attempted
                ],
            }
        )

    retry_rows = [
        dict(row)
        for row in queue_rows
        if row["reserve_assignment_sha256"] in retry_ids
    ]
    chain_retry_counts = dict(
        sorted(Counter(str(row["chain"]).strip().lower() for row in retry_rows).items())
    )
    retry_queue = output_queue_path.expanduser()
    retry_manifest = output_manifest_path.expanduser()
    _atomic_csv(retry_queue, fieldnames, retry_rows)
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_retry_targets.v1",
        "decision": "RETRY_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION",
        "retry_reason": "TERMINAL_PARTIAL_SCOPE_ONLY",
        "original_queue_sha256": _file_sha(queue_file),
        "source_run_manifest_sha256": _file_sha(run_file),
        "source_run_binding_sha256": run["run_binding_sha256"],
        "source_summary_file_sha256": _file_sha(summary_file),
        "source_summary_sha256": summary["summary_sha256"],
        "source_event_ledger_sha256": _file_sha(event_file),
        "source_request_ledger_sha256": _file_sha(request_file),
        "source_request_ledger_terminal_hash": request_terminal_hash,
        "resolved_retry_index_file_sha256": resolved_index_file_sha,
        "resolved_retry_index_sha256": resolved_index_sha,
        "resolved_retry_count": len(resolved_ids),
        "required_chains": chain_scope,
        "chain_retry_counts": chain_retry_counts,
        "original_queue_row_count": len(queue_rows),
        "retry_queue_sha256": _file_sha(retry_queue),
        "retry_row_count": len(retry_rows),
        "retry_scopes": retry_scopes,
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    _atomic_json(retry_manifest, manifest)
    return manifest


def build_control_candidate_rpc_unattempted_targets(
    *,
    original_queue_path: Path,
    run_manifest_path: Path,
    summary_path: Path,
    event_ledger_path: Path,
    request_ledger_path: Path,
    output_queue_path: Path,
    output_manifest_path: Path,
    required_chains: list[str] | None = None,
) -> dict[str, object]:
    """Freeze queue scopes absent from the source run's terminal event ledger."""
    queue_file = _ordinary(original_queue_path, "original_queue")
    run_file = _ordinary(run_manifest_path, "run_manifest")
    summary_file = _ordinary(summary_path, "summary")
    event_file = _ordinary(event_ledger_path, "event_ledger")
    request_file = _ordinary(request_ledger_path, "request_ledger")

    run = _load_json(run_file, "run_manifest")
    run_material = {key: value for key, value in run.items() if key != "run_binding_sha256"}
    if (
        run.get("schema_version") != _RUN_SCHEMA
        or run.get("run_binding_sha256") != _canonical_sha(run_material)
        or run.get("queue_sha256") != _file_sha(queue_file)
    ):
        raise ControlCandidateRpcRetryTargetsError("run_manifest_binding_invalid")
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if run.get(field) is not False:
            raise ControlCandidateRpcRetryTargetsError(f"run_manifest_{field}_invalid")

    summary = _load_json(summary_file, "summary")
    summary_material = {
        key: value for key, value in summary.items() if key != "summary_sha256"
    }
    if (
        summary.get("schema_version") != _SUMMARY_SCHEMA
        or summary.get("summary_sha256") != _canonical_sha(summary_material)
        or summary.get("run_binding_sha256") != run.get("run_binding_sha256")
        or summary.get("request_ledger_sha256") != _file_sha(request_file)
    ):
        raise ControlCandidateRpcRetryTargetsError("summary_binding_invalid")
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if summary.get(field) is not False:
            raise ControlCandidateRpcRetryTargetsError(f"summary_{field}_invalid")

    with queue_file.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        queue_rows = list(reader)
    if not fieldnames or not {"chain", "reserve_assignment_sha256"}.issubset(fieldnames):
        raise ControlCandidateRpcRetryTargetsError("original_queue_schema_invalid")
    if len(queue_rows) != int(run.get("queue_row_count") or -1):
        raise ControlCandidateRpcRetryTargetsError("original_queue_row_count_mismatch")
    by_assignment: dict[str, dict[str, str]] = {}
    for row in queue_rows:
        assignment = str(row.get("reserve_assignment_sha256") or "")
        if not assignment or assignment in by_assignment:
            raise ControlCandidateRpcRetryTargetsError("original_queue_assignment_duplicate")
        by_assignment[assignment] = row

    events = _read_jsonl(event_file, "event_ledger")
    event_terminal_hash = _validate_hash_chain(
        events, label="event_ledger", schema=_EVENT_SCHEMA, sequenced=False
    )
    terminal_ids: set[str] = set()
    status_counts: Counter[str] = Counter()
    for event in events:
        assignment = str(event.get("reserve_assignment_sha256") or "")
        if not assignment or assignment in terminal_ids:
            raise ControlCandidateRpcRetryTargetsError("event_assignment_duplicate")
        if assignment not in by_assignment:
            raise ControlCandidateRpcRetryTargetsError("event_assignment_not_in_queue")
        terminal_ids.add(assignment)
        status_counts[str(event.get("status") or "")] += 1
    if dict(sorted(status_counts.items())) != dict(
        sorted((summary.get("ledger_status_counts") or {}).items())
    ):
        raise ControlCandidateRpcRetryTargetsError("summary_status_counts_mismatch")

    requests = _read_jsonl(request_file, "request_ledger")
    request_terminal_hash = _validate_hash_chain(
        requests,
        label="request_ledger",
        schema=_REQUEST_EVENT_SCHEMA,
        sequenced=True,
    )
    if (
        len(requests) != int(summary.get("request_count") or -1)
        or request_terminal_hash != summary.get("request_ledger_terminal_hash")
    ):
        raise ControlCandidateRpcRetryTargetsError("summary_request_binding_mismatch")

    unattempted_ids = set(by_assignment) - terminal_ids
    requested_candidate_ids = {
        str(request.get("scope_id") or "")
        for request in requests
        if request.get("scope_kind") == "candidate"
    }
    if unattempted_ids & requested_candidate_ids:
        raise ControlCandidateRpcRetryTargetsError("unattempted_scope_has_request")
    if required_chains is not None:
        chain_scope = sorted(
            {str(chain).strip().lower() for chain in required_chains if str(chain).strip()}
        )
        if not chain_scope:
            raise ControlCandidateRpcRetryTargetsError("required_chain_scope_invalid")
        unattempted_ids = {
            assignment
            for assignment in unattempted_ids
            if str(by_assignment[assignment].get("chain") or "").strip().lower()
            in chain_scope
        }
    else:
        chain_scope = sorted(
            {
                str(by_assignment[assignment].get("chain") or "").strip().lower()
                for assignment in unattempted_ids
            }
        )
    if not unattempted_ids:
        raise ControlCandidateRpcRetryTargetsError("no_unattempted_targets")

    unattempted_rows = [
        dict(row)
        for row in queue_rows
        if row["reserve_assignment_sha256"] in unattempted_ids
    ]
    chain_counts = dict(
        sorted(
            Counter(
                str(row["chain"]).strip().lower() for row in unattempted_rows
            ).items()
        )
    )
    output_queue = output_queue_path.expanduser()
    output_manifest = output_manifest_path.expanduser()
    _atomic_csv(output_queue, fieldnames, unattempted_rows)
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_unattempted_targets.v1",
        "decision": "UNATTEMPTED_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION",
        "original_queue_sha256": _file_sha(queue_file),
        "source_run_manifest_sha256": _file_sha(run_file),
        "source_run_binding_sha256": run["run_binding_sha256"],
        "source_summary_file_sha256": _file_sha(summary_file),
        "source_summary_sha256": summary["summary_sha256"],
        "source_event_ledger_sha256": _file_sha(event_file),
        "source_event_ledger_terminal_hash": event_terminal_hash,
        "source_terminal_event_count": len(events),
        "source_request_ledger_sha256": _file_sha(request_file),
        "source_request_ledger_terminal_hash": request_terminal_hash,
        "required_chains": chain_scope,
        "chain_unattempted_counts": chain_counts,
        "original_queue_row_count": len(queue_rows),
        "unattempted_queue_sha256": _file_sha(output_queue),
        "unattempted_row_count": len(unattempted_rows),
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    _atomic_json(output_manifest, manifest)
    return manifest
