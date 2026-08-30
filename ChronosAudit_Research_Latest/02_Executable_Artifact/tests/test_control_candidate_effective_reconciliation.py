from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from chronosaudit_stage2.public_acquisition.control_candidate_effective_reconciliation import (
    ControlCandidateEffectiveReconciliationError,
    build_control_candidate_effective_reconciliation,
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _queue(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_name", "chain", "control_address", "reserve_assignment_sha256"],
        )
        writer.writeheader()
        writer.writerows(rows)


def _run(
    root: Path,
    queue: Path,
    rows: list[dict[str, str]],
    statuses: list[str],
) -> None:
    root.mkdir()
    (root / "candidates").mkdir()
    run: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_run.v2",
        "queue_sha256": _file_sha(queue),
        "queue_row_count": len(rows),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    run["run_binding_sha256"] = _sha(run)
    (root / "run_manifest.json").write_text(json.dumps(run), encoding="utf-8")
    previous = "0" * 64
    events = []
    counts: dict[str, int] = {}
    for row, status in zip(rows, statuses, strict=True):
        result = {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
            "run_binding_sha256": run["run_binding_sha256"],
            "reserve_assignment_sha256": row["reserve_assignment_sha256"],
            "case_name": row["case_name"],
            "chain": row["chain"],
            "control_address": row["control_address"],
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        if status == "TERMINAL_REJECTED":
            result["rejection_reason"] = "top_level_contract_address_mismatch"
        result["result_sha256"] = _sha(result)
        result_path = root / "candidates" / f"{row['reserve_assignment_sha256']}.json"
        result_path.write_text(json.dumps(result), encoding="utf-8")
        event: dict[str, object] = {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_event.v1",
            "previous_event_sha256": previous,
            "reserve_assignment_sha256": row["reserve_assignment_sha256"],
            "status": status,
        }
        if status != "PARTIAL":
            event["result_path"] = str(result_path)
            event["result_sha256"] = result["result_sha256"]
        else:
            event["error_code"] = "http_408"
        event["event_sha256"] = _sha(event)
        previous = str(event["event_sha256"])
        events.append(event)
        counts[status] = counts.get(status, 0) + 1
    (root / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )
    summary: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": run["run_binding_sha256"],
        "queue_row_count": len(rows),
        "completed_count": counts.get("COMPLETE", 0),
        "terminal_rejected_count": counts.get("TERMINAL_REJECTED", 0),
        "retry_required_count": counts.get("PARTIAL", 0),
        "ledger_status_counts": counts,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _sha(summary)
    (root / "summary.json").write_text(json.dumps(summary), encoding="utf-8")


def test_reconciliation_applies_only_terminal_immutable_overlays(tmp_path: Path) -> None:
    rows = [
        {
            "case_name": "case-1",
            "chain": "ethereum",
            "control_address": "0x" + "11" * 20,
            "reserve_assignment_sha256": "1" * 64,
        },
        {
            "case_name": "case-2",
            "chain": "ethereum",
            "control_address": "0x" + "22" * 20,
            "reserve_assignment_sha256": "2" * 64,
        },
        {
            "case_name": "case-3",
            "chain": "ethereum",
            "control_address": "0x" + "33" * 20,
            "reserve_assignment_sha256": "3" * 64,
        },
    ]
    initial = tmp_path / "initial.csv"
    _queue(initial, rows)
    primary_queue = tmp_path / "primary.csv"
    _queue(primary_queue, rows)
    primary = tmp_path / "primary"
    _run(primary, primary_queue, rows, ["COMPLETE", "PARTIAL", "TERMINAL_REJECTED"])
    retry_queue = tmp_path / "retry.csv"
    _queue(retry_queue, [rows[1]])
    retry = tmp_path / "retry"
    _run(retry, retry_queue, [rows[1]], ["COMPLETE"])

    manifest = build_control_candidate_effective_reconciliation(
        initial_queue_path=initial,
        source_runs=[(primary_queue, primary), (retry_queue, retry)],
        output_complete_path=tmp_path / "complete.csv",
        output_rejected_path=tmp_path / "rejected.csv",
        output_manifest_path=tmp_path / "manifest.json",
    )

    assert manifest["initial_row_count"] == 3
    assert manifest["effective_complete_count"] == 2
    assert manifest["effective_rejected_count"] == 1
    assert manifest["effective_unresolved_count"] == 0
    assert manifest["decision"] == "EFFECTIVE_ACQUISITION_TERMINAL_RECONCILIATION_VERIFIED"
    assert manifest["denominator_admission_authorized"] is False
    assert manifest["counter_authority"] is False
    assert [
        row["reserve_assignment_sha256"]
        for row in csv.DictReader((tmp_path / "complete.csv").open(encoding="utf-8"))
    ] == ["1" * 64, "2" * 64]


def test_reconciliation_rejects_overlay_over_terminal_result(tmp_path: Path) -> None:
    row = {
        "case_name": "case-1",
        "chain": "ethereum",
        "control_address": "0x" + "11" * 20,
        "reserve_assignment_sha256": "1" * 64,
    }
    initial = tmp_path / "initial.csv"
    _queue(initial, [row])
    first_queue = tmp_path / "first.csv"
    _queue(first_queue, [row])
    first = tmp_path / "first"
    _run(first, first_queue, [row], ["COMPLETE"])
    second_queue = tmp_path / "second.csv"
    _queue(second_queue, [row])
    second = tmp_path / "second"
    _run(second, second_queue, [row], ["COMPLETE"])

    try:
        build_control_candidate_effective_reconciliation(
            initial_queue_path=initial,
            source_runs=[(first_queue, first), (second_queue, second)],
            output_complete_path=tmp_path / "complete.csv",
            output_rejected_path=tmp_path / "rejected.csv",
            output_manifest_path=tmp_path / "manifest.json",
        )
    except ControlCandidateEffectiveReconciliationError as exc:
        assert str(exc) == "overlay_after_terminal:1111111111111111111111111111111111111111111111111111111111111111"
    else:
        raise AssertionError("expected overlay replay rejection")
