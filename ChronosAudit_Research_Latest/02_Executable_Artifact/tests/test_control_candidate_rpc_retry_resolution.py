from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_retry_resolution import (
    build_control_candidate_rpc_retry_resolution_index,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retry_resolution_index_binds_complete_result_and_remains_non_authorizing(
    tmp_path: Path,
) -> None:
    assignment = "1" * 64
    queue = tmp_path / "retry.csv"
    with queue.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["case_name", "chain", "reserve_assignment_sha256"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "case_name": "case-a",
                "chain": "bsc",
                "reserve_assignment_sha256": assignment,
            }
        )
    target_manifest = {
        "schema_version": "chronosaudit.control_candidate_rpc_retry_targets.v1",
        "decision": "RETRY_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION",
        "retry_queue_sha256": _file_sha(queue),
        "retry_row_count": 1,
        "retry_scopes": [{"reserve_assignment_sha256": assignment}],
        "rpc_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    target_manifest["manifest_sha256"] = _canonical_sha(target_manifest)
    target_path = tmp_path / "retry-manifest.json"
    target_path.write_text(json.dumps(target_manifest), encoding="utf-8")
    run = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_run.v2",
        "queue_sha256": _file_sha(queue),
        "queue_row_count": 1,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    run["run_binding_sha256"] = _canonical_sha(run)
    run_path = tmp_path / "run_manifest.json"
    run_path.write_text(json.dumps(run), encoding="utf-8")
    result = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
        "run_binding_sha256": run["run_binding_sha256"],
        "reserve_assignment_sha256": assignment,
        "rpc_classification_complete": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["result_sha256"] = _canonical_sha(result)
    result_path = tmp_path / "candidate.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    event = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_event.v1",
        "previous_event_sha256": "0" * 64,
        "reserve_assignment_sha256": assignment,
        "status": "COMPLETE",
        "result_sha256": result["result_sha256"],
        "result_path": str(result_path),
    }
    event["event_sha256"] = _canonical_sha(event)
    event_path = tmp_path / "events.jsonl"
    event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    summary = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": run["run_binding_sha256"],
        "queue_row_count": 1,
        "completed_count": 1,
        "ledger_status_counts": {"COMPLETE": 1},
        "retry_required_count": 0,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _canonical_sha(summary)
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    output = tmp_path / "resolution-index.json"

    index = build_control_candidate_rpc_retry_resolution_index(
        retry_queue_path=queue,
        retry_targets_manifest_path=target_path,
        retry_run_manifest_path=run_path,
        retry_summary_path=summary_path,
        retry_event_ledger_path=event_path,
        output_path=output,
    )

    assert index["resolved_count"] == 1
    assert index["resolved_assignments"][0]["reserve_assignment_sha256"] == assignment
    assert index["resolved_assignments"][0]["result_sha256"] == result["result_sha256"]
    assert index["resolved_assignments"][0]["result_file_sha256"] == _file_sha(result_path)
    assert index["selection_authorized"] is False
    assert index["counter_authority"] is False
    assert index["index_sha256"] == _canonical_sha(
        {key: value for key, value in index.items() if key != "index_sha256"}
    )


def test_retry_resolution_index_can_preserve_complete_events_from_mixed_run(
    tmp_path: Path,
) -> None:
    complete_assignment = "1" * 64
    partial_assignment = "2" * 64
    queue = tmp_path / "retry.csv"
    with queue.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["case_name", "chain", "reserve_assignment_sha256"]
        )
        writer.writeheader()
        writer.writerows(
            [
                {
                    "case_name": "case-complete",
                    "chain": "ethereum",
                    "reserve_assignment_sha256": complete_assignment,
                },
                {
                    "case_name": "case-partial",
                    "chain": "ethereum",
                    "reserve_assignment_sha256": partial_assignment,
                },
            ]
        )
    target_manifest = {
        "schema_version": "chronosaudit.control_candidate_rpc_retry_targets.v1",
        "decision": "RETRY_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION",
        "retry_queue_sha256": _file_sha(queue),
        "retry_row_count": 2,
        "retry_scopes": [
            {"reserve_assignment_sha256": complete_assignment},
            {"reserve_assignment_sha256": partial_assignment},
        ],
        "rpc_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    target_manifest["manifest_sha256"] = _canonical_sha(target_manifest)
    target_path = tmp_path / "retry-manifest.json"
    target_path.write_text(json.dumps(target_manifest), encoding="utf-8")
    run = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_run.v2",
        "queue_sha256": _file_sha(queue),
        "queue_row_count": 2,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    run["run_binding_sha256"] = _canonical_sha(run)
    run_path = tmp_path / "run_manifest.json"
    run_path.write_text(json.dumps(run), encoding="utf-8")
    result = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
        "run_binding_sha256": run["run_binding_sha256"],
        "reserve_assignment_sha256": complete_assignment,
        "rpc_classification_complete": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["result_sha256"] = _canonical_sha(result)
    result_path = tmp_path / "candidate.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    complete_event = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_event.v1",
        "previous_event_sha256": "0" * 64,
        "reserve_assignment_sha256": complete_assignment,
        "status": "COMPLETE",
        "result_sha256": result["result_sha256"],
        "result_path": str(result_path),
    }
    complete_event["event_sha256"] = _canonical_sha(complete_event)
    partial_event = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_event.v1",
        "previous_event_sha256": complete_event["event_sha256"],
        "reserve_assignment_sha256": partial_assignment,
        "status": "PARTIAL",
        "error_code": "rpc_result_invalid:provider:eth_getTransactionReceipt",
    }
    partial_event["event_sha256"] = _canonical_sha(partial_event)
    event_path = tmp_path / "events.jsonl"
    event_path.write_text(
        json.dumps(complete_event) + "\n" + json.dumps(partial_event) + "\n",
        encoding="utf-8",
    )
    summary = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": run["run_binding_sha256"],
        "queue_row_count": 2,
        "completed_count": 1,
        "ledger_status_counts": {"COMPLETE": 1, "PARTIAL": 1},
        "retry_required_count": 1,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _canonical_sha(summary)
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    index = build_control_candidate_rpc_retry_resolution_index(
        retry_queue_path=queue,
        retry_targets_manifest_path=target_path,
        retry_run_manifest_path=run_path,
        retry_summary_path=summary_path,
        retry_event_ledger_path=event_path,
        output_path=tmp_path / "resolution-index.json",
        allow_partial_run=True,
    )

    assert index["resolved_count"] == 1
    assert index["source_run_complete_count"] == 1
    assert index["source_run_unresolved_count"] == 1
    assert [
        entry["reserve_assignment_sha256"] for entry in index["resolved_assignments"]
    ] == [complete_assignment]
    assert index["selection_authorized"] is False
    assert index["counter_authority"] is False
