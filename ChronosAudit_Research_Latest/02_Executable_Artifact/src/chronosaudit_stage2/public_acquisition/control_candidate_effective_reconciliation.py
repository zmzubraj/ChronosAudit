from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path


class ControlCandidateEffectiveReconciliationError(ValueError):
    """Acquisition ledgers could not be reconciled without replay or ambiguity."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCandidateEffectiveReconciliationError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateEffectiveReconciliationError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCandidateEffectiveReconciliationError(f"{label}_not_ordinary_file")
    return resolved


def _directory(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCandidateEffectiveReconciliationError(f"{label}_not_directory")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateEffectiveReconciliationError(f"{label}_missing") from exc
    if not resolved.is_dir():
        raise ControlCandidateEffectiveReconciliationError(f"{label}_not_directory")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCandidateEffectiveReconciliationError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCandidateEffectiveReconciliationError(f"{label}_root_invalid")
    return payload


def _authority_false(payload: Mapping[str, object], label: str) -> None:
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(field) is not False:
            raise ControlCandidateEffectiveReconciliationError(f"{label}_{field}_invalid")


def _read_queue(path: Path, label: str) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = [dict(row) for row in reader]
    required = {"case_name", "chain", "control_address", "reserve_assignment_sha256"}
    if not required.issubset(fieldnames) or not rows:
        raise ControlCandidateEffectiveReconciliationError(f"{label}_columns_or_rows_invalid")
    assignments = [str(row["reserve_assignment_sha256"]) for row in rows]
    identities = [
        f"{str(row['chain']).lower()}:{str(row['control_address']).lower()}" for row in rows
    ]
    if (
        any(len(value) != 64 for value in assignments)
        or len(assignments) != len(set(assignments))
        or len(identities) != len(set(identities))
    ):
        raise ControlCandidateEffectiveReconciliationError(f"{label}_identity_invalid")
    return fieldnames, rows


def _atomic_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCandidateEffectiveReconciliationError("output_symlink")
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


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCandidateEffectiveReconciliationError("output_symlink")
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


def build_control_candidate_effective_reconciliation(
    *,
    initial_queue_path: Path,
    source_runs: Sequence[tuple[Path, Path]],
    output_complete_path: Path,
    output_rejected_path: Path,
    output_manifest_path: Path,
) -> dict[str, object]:
    """Reconcile immutable primary and overlay ledgers into one terminal state."""
    initial_file = _ordinary(initial_queue_path, "initial_queue")
    initial_fields, initial_rows = _read_queue(initial_file, "initial_queue")
    initial_by_assignment = {
        row["reserve_assignment_sha256"]: row for row in initial_rows
    }
    initial_assignments = set(initial_by_assignment)
    if not source_runs:
        raise ControlCandidateEffectiveReconciliationError("source_runs_empty")

    effective: dict[str, dict[str, object]] = {}
    source_bindings: list[dict[str, object]] = []
    for source_index, (queue_path, root_path) in enumerate(source_runs):
        queue_file = _ordinary(queue_path, f"source_queue_{source_index}")
        _, queue_rows = _read_queue(queue_file, f"source_queue_{source_index}")
        queue_by_assignment = {
            row["reserve_assignment_sha256"]: row for row in queue_rows
        }
        if not set(queue_by_assignment).issubset(initial_assignments):
            raise ControlCandidateEffectiveReconciliationError(
                f"source_queue_outside_initial:{source_index}"
            )
        for assignment, row in queue_by_assignment.items():
            initial = initial_by_assignment[assignment]
            if any(
                str(row[field]).lower() != str(initial[field]).lower()
                for field in ("case_name", "chain", "control_address")
            ):
                raise ControlCandidateEffectiveReconciliationError(
                    f"source_queue_row_mismatch:{assignment}"
                )

        root = _directory(root_path, f"source_root_{source_index}")
        run_file = _ordinary(root / "run_manifest.json", f"source_run_{source_index}")
        summary_file = _ordinary(root / "summary.json", f"source_summary_{source_index}")
        events_file = _ordinary(root / "events.jsonl", f"source_events_{source_index}")
        run = _load(run_file, f"source_run_{source_index}")
        run_material = {key: value for key, value in run.items() if key != "run_binding_sha256"}
        if (
            run.get("schema_version")
            != "chronosaudit.control_candidate_rpc_acquisition_run.v2"
            or run.get("run_binding_sha256") != _sha(run_material)
            or run.get("queue_sha256") != _file_sha(queue_file)
            or int(run.get("queue_row_count") or -1) != len(queue_rows)
        ):
            raise ControlCandidateEffectiveReconciliationError(
                f"source_run_binding_invalid:{source_index}"
            )
        _authority_false(run, f"source_run_{source_index}")
        summary = _load(summary_file, f"source_summary_{source_index}")
        summary_material = {
            key: value for key, value in summary.items() if key != "summary_sha256"
        }
        if (
            summary.get("schema_version")
            != "chronosaudit.control_candidate_rpc_acquisition_summary.v1"
            or summary.get("summary_sha256") != _sha(summary_material)
            or summary.get("run_binding_sha256") != run.get("run_binding_sha256")
            or int(summary.get("queue_row_count") or -1) != len(queue_rows)
        ):
            raise ControlCandidateEffectiveReconciliationError(
                f"source_summary_binding_invalid:{source_index}"
            )
        _authority_false(summary, f"source_summary_{source_index}")

        previous = "0" * 64
        statuses: Counter[str] = Counter()
        seen_in_run: set[str] = set()
        for event_index, line in enumerate(events_file.read_text(encoding="utf-8").splitlines()):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ControlCandidateEffectiveReconciliationError(
                    f"source_event_json_invalid:{source_index}:{event_index}"
                ) from exc
            if not isinstance(event, dict):
                raise ControlCandidateEffectiveReconciliationError(
                    f"source_event_row_invalid:{source_index}:{event_index}"
                )
            material = dict(event)
            stored = material.pop("event_sha256", None)
            assignment = str(material.get("reserve_assignment_sha256") or "")
            status = str(material.get("status") or "")
            if (
                material.get("schema_version")
                != "chronosaudit.control_candidate_rpc_acquisition_event.v1"
                or material.get("previous_event_sha256") != previous
                or stored != _sha(material)
                or assignment not in queue_by_assignment
                or assignment in seen_in_run
                or status not in {"COMPLETE", "PARTIAL", "TERMINAL_REJECTED"}
            ):
                raise ControlCandidateEffectiveReconciliationError(
                    f"source_event_binding_invalid:{source_index}:{event_index}"
                )
            previous = str(stored)
            seen_in_run.add(assignment)
            statuses[status] += 1
            prior = effective.get(assignment)
            if prior and prior["status"] in {"COMPLETE", "TERMINAL_REJECTED"}:
                raise ControlCandidateEffectiveReconciliationError(
                    f"overlay_after_terminal:{assignment}"
                )
            evidence: dict[str, object] = {
                "status": status,
                "source_index": source_index,
                "source_run_binding_sha256": run["run_binding_sha256"],
                "source_event_sha256": stored,
            }
            if status != "PARTIAL":
                result_file = _ordinary(
                    Path(str(material.get("result_path") or "")),
                    f"source_result_{source_index}_{event_index}",
                )
                result = _load(result_file, f"source_result_{source_index}_{event_index}")
                result_material = {
                    key: value for key, value in result.items() if key != "result_sha256"
                }
                queue_row = queue_by_assignment[assignment]
                if (
                    result.get("result_sha256") != _sha(result_material)
                    or result.get("result_sha256") != material.get("result_sha256")
                    or result.get("run_binding_sha256") != run.get("run_binding_sha256")
                    or result.get("reserve_assignment_sha256") != assignment
                    or any(
                        str(result.get(field) or "").lower()
                        != str(queue_row[field]).lower()
                        for field in ("case_name", "chain", "control_address")
                    )
                ):
                    raise ControlCandidateEffectiveReconciliationError(
                        f"source_result_binding_invalid:{assignment}"
                    )
                _authority_false(result, f"source_result_{source_index}_{event_index}")
                evidence.update(
                    {
                        "result_path": str(result_file),
                        "result_file_sha256": _file_sha(result_file),
                        "result_sha256": result["result_sha256"],
                        "rejection_reason": result.get("rejection_reason"),
                    }
                )
            effective[assignment] = evidence

        declared_counts = summary.get("ledger_status_counts")
        if isinstance(declared_counts, Mapping) and dict(sorted(statuses.items())) != dict(
            sorted((str(key), int(value)) for key, value in declared_counts.items())
        ):
            raise ControlCandidateEffectiveReconciliationError(
                f"source_summary_status_mismatch:{source_index}"
            )
        for field, status in (
            ("completed_count", "COMPLETE"),
            ("terminal_rejected_count", "TERMINAL_REJECTED"),
            ("retry_required_count", "PARTIAL"),
        ):
            if summary.get(field) is not None and int(summary[field]) != statuses.get(status, 0):
                raise ControlCandidateEffectiveReconciliationError(
                    f"source_summary_count_mismatch:{source_index}:{field}"
                )
        source_bindings.append(
            {
                "source_index": source_index,
                "queue_path": str(queue_file),
                "queue_sha256": _file_sha(queue_file),
                "queue_row_count": len(queue_rows),
                "root_path": str(root),
                "run_manifest_file_sha256": _file_sha(run_file),
                "run_binding_sha256": run["run_binding_sha256"],
                "summary_file_sha256": _file_sha(summary_file),
                "summary_sha256": summary["summary_sha256"],
                "events_file_sha256": _file_sha(events_file),
                "event_terminal_sha256": previous,
                "ledger_status_counts": dict(sorted(statuses.items())),
            }
        )

    complete_assignments = sorted(
        assignment for assignment, state in effective.items() if state["status"] == "COMPLETE"
    )
    rejected_assignments = sorted(
        assignment
        for assignment, state in effective.items()
        if state["status"] == "TERMINAL_REJECTED"
    )
    unresolved_assignments = sorted(initial_assignments - set(complete_assignments) - set(rejected_assignments))
    if unresolved_assignments:
        raise ControlCandidateEffectiveReconciliationError(
            f"effective_state_not_terminal:{len(unresolved_assignments)}"
        )
    evidence_fields = [
        "effective_status",
        "source_index",
        "source_run_binding_sha256",
        "source_event_sha256",
        "result_sha256",
        "result_file_sha256",
        "result_path",
        "rejection_reason",
    ]

    def materialize(assignments: list[str]) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for assignment in assignments:
            row = dict(initial_by_assignment[assignment])
            state = effective[assignment]
            row.update(
                {
                    "effective_status": str(state["status"]),
                    "source_index": str(state["source_index"]),
                    "source_run_binding_sha256": str(state["source_run_binding_sha256"]),
                    "source_event_sha256": str(state["source_event_sha256"]),
                    "result_sha256": str(state.get("result_sha256") or ""),
                    "result_file_sha256": str(state.get("result_file_sha256") or ""),
                    "result_path": str(state.get("result_path") or ""),
                    "rejection_reason": str(state.get("rejection_reason") or ""),
                }
            )
            rows.append(row)
        return rows

    complete_rows = materialize(complete_assignments)
    rejected_rows = materialize(rejected_assignments)
    complete_output = output_complete_path.expanduser().resolve(strict=False)
    rejected_output = output_rejected_path.expanduser().resolve(strict=False)
    manifest_output = output_manifest_path.expanduser().resolve(strict=False)
    _atomic_csv(complete_output, initial_fields + evidence_fields, complete_rows)
    _atomic_csv(rejected_output, initial_fields + evidence_fields, rejected_rows)
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_effective_reconciliation.v1",
        "decision": "EFFECTIVE_ACQUISITION_TERMINAL_RECONCILIATION_VERIFIED",
        "initial_queue_path": str(initial_file),
        "initial_queue_sha256": _file_sha(initial_file),
        "initial_row_count": len(initial_rows),
        "source_run_count": len(source_bindings),
        "source_bindings": source_bindings,
        "effective_complete_count": len(complete_rows),
        "effective_rejected_count": len(rejected_rows),
        "effective_unresolved_count": 0,
        "complete_output_path": str(complete_output),
        "complete_output_sha256": _file_sha(complete_output),
        "complete_records_sha256": _sha(complete_rows),
        "rejected_output_path": str(rejected_output),
        "rejected_output_sha256": _file_sha(rejected_output),
        "rejected_records_sha256": _sha(rejected_rows),
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
    _atomic_json(manifest_output, manifest)
    return manifest
