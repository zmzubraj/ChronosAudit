from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition import (
    control_candidate_rpc_retry_targets as retry_targets_module,
)
from chronosaudit_stage2.public_acquisition.control_candidate_rpc_retry_targets import (
    ControlCandidateRpcRetryTargetsError,
    build_control_candidate_rpc_retry_targets,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _append_event(path: Path, payloads: list[dict[str, object]], *, request: bool) -> None:
    previous = "0" * 64
    rows = []
    for index, payload in enumerate(payloads, start=1):
        event = {
            "schema_version": (
                "chronosaudit.control_candidate_rpc_request_event.v1"
                if request
                else "chronosaudit.control_candidate_rpc_acquisition_event.v1"
            ),
            "previous_event_sha256": previous,
            **({"request_sequence": index} if request else {}),
            **payload,
        }
        event["event_sha256"] = _canonical_sha(event)
        previous = str(event["event_sha256"])
        rows.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _inputs(tmp_path: Path) -> dict[str, Path]:
    queue = tmp_path / "queue.csv"
    fields = [
        "case_name",
        "chain",
        "control_address",
        "creation_tx_hash",
        "reserve_assignment_sha256",
        "selection_authorized",
    ]
    assignments = ["1" * 64, "2" * 64, "3" * 64]
    with queue.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index, assignment in enumerate(assignments, start=1):
            writer.writerow(
                {
                    "case_name": f"case-{index}",
                    "chain": "bsc",
                    "control_address": "0x" + str(index) * 40,
                    "creation_tx_hash": "0x" + str(index) * 64,
                    "reserve_assignment_sha256": assignment,
                    "selection_authorized": "false",
                }
            )
    run_manifest = tmp_path / "run_manifest.json"
    run_body = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_run.v2",
        "queue_sha256": _file_sha(queue),
        "queue_row_count": 3,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    run_body["run_binding_sha256"] = _canonical_sha(run_body)
    run_manifest.write_text(json.dumps(run_body), encoding="utf-8")
    events = tmp_path / "events.jsonl"
    _append_event(
        events,
        [
            {"reserve_assignment_sha256": assignments[0], "status": "COMPLETE"},
            {
                "reserve_assignment_sha256": assignments[1],
                "status": "PARTIAL",
                "error_code": "TimeoutError",
            },
            {
                "reserve_assignment_sha256": assignments[2],
                "status": "TERMINAL_REJECTED",
                "error_code": "candidate_input_invalid",
            },
        ],
        request=False,
    )
    requests = tmp_path / "request-events.jsonl"
    _append_event(
        requests,
        [
            {
                "scope_kind": "candidate",
                "scope_id": assignments[0],
                "provider_id": "p1",
                "method": "eth_getTransactionReceipt",
                "params_sha256": "b" * 64,
                "disposition": "SUCCESS",
                "rpc_envelope_sha256": "c" * 64,
                "rpc_envelope_path": "/tmp/one.json",
            },
            {
                "scope_kind": "candidate",
                "scope_id": assignments[1],
                "provider_id": "p1",
                "method": "eth_getTransactionReceipt",
                "params_sha256": "d" * 64,
                "disposition": "TRANSPORT_ERROR",
                "error_code": "TimeoutError",
            },
        ],
        request=True,
    )
    summary = tmp_path / "summary.json"
    summary_body = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "queue_row_count": 3,
        "run_binding_sha256": run_body["run_binding_sha256"],
        "ledger_status_counts": {"COMPLETE": 1, "PARTIAL": 1, "TERMINAL_REJECTED": 1},
        "retry_required_count": 1,
        "request_count": 2,
        "request_ledger_sha256": _file_sha(requests),
        "request_ledger_terminal_hash": json.loads(requests.read_text().splitlines()[-1])[
            "event_sha256"
        ],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary_body["summary_sha256"] = _canonical_sha(summary_body)
    summary.write_text(json.dumps(summary_body), encoding="utf-8")
    return {
        "queue": queue,
        "run_manifest": run_manifest,
        "summary": summary,
        "events": events,
        "requests": requests,
        "retry_queue": tmp_path / "retry.csv",
        "retry_manifest": tmp_path / "retry-manifest.json",
    }


def _build(
    paths: dict[str, Path],
    *,
    resolved_retry_index_path: Path | None = None,
    required_chains: list[str] | None = None,
) -> dict[str, object]:
    return build_control_candidate_rpc_retry_targets(
        original_queue_path=paths["queue"],
        run_manifest_path=paths["run_manifest"],
        summary_path=paths["summary"],
        event_ledger_path=paths["events"],
        request_ledger_path=paths["requests"],
        output_queue_path=paths["retry_queue"],
        output_manifest_path=paths["retry_manifest"],
        resolved_retry_index_path=resolved_retry_index_path,
        required_chains=required_chains,
    )


def test_retry_targets_freeze_only_partial_scope_and_bind_attempts(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)

    result = _build(paths)

    rows = list(csv.DictReader(paths["retry_queue"].open(encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["reserve_assignment_sha256"] == "2" * 64
    assert result["decision"] == (
        "RETRY_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION"
    )
    assert result["retry_queue_sha256"] == _file_sha(paths["retry_queue"])
    assert result["retry_row_count"] == 1
    assert result["source_request_ledger_sha256"] == _file_sha(paths["requests"])
    assert result["retry_scopes"][0]["attempted_request_sequences"] == [2]
    assert result["retry_scopes"][0]["attempted_request_dispositions"] == [
        "TRANSPORT_ERROR"
    ]
    assert result["rpc_authorized"] is False
    assert result["selection_authorized"] is False
    assert result["counter_authority"] is False
    assert result["manifest_sha256"] == _canonical_sha(
        {key: value for key, value in result.items() if key != "manifest_sha256"}
    )


def test_retry_targets_bind_exact_required_chain_subset(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)

    result = _build(paths, required_chains=["bsc"])

    assert result["required_chains"] == ["bsc"]
    assert result["chain_retry_counts"] == {"bsc": 1}


def test_retry_targets_reject_tampered_request_ledger(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    requests = paths["requests"].read_text(encoding="utf-8")
    paths["requests"].write_text(requests.replace("TimeoutError", "OtherError"), encoding="utf-8")

    with pytest.raises(ControlCandidateRpcRetryTargetsError, match="request_ledger_hash_mismatch"):
        _build(paths)


def test_retry_targets_reject_partial_without_failed_request(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request_rows = [json.loads(line) for line in paths["requests"].read_text().splitlines()]
    request_rows[1]["disposition"] = "SUCCESS"
    request_rows[1].pop("error_code")
    request_rows[1].pop("event_sha256")
    request_rows[1]["event_sha256"] = _canonical_sha(request_rows[1])
    paths["requests"].write_text(
        "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in request_rows)
        + "\n",
        encoding="utf-8",
    )
    summary = json.loads(paths["summary"].read_text())
    summary["request_ledger_sha256"] = _file_sha(paths["requests"])
    summary["request_ledger_terminal_hash"] = request_rows[-1]["event_sha256"]
    summary.pop("summary_sha256")
    summary["summary_sha256"] = _canonical_sha(summary)
    paths["summary"].write_text(json.dumps(summary), encoding="utf-8")

    with pytest.raises(
        ControlCandidateRpcRetryTargetsError,
        match="partial_scope_without_failed_request",
    ):
        _build(paths)


def test_retry_targets_exclude_assignments_in_verified_resolution_index(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    events = [json.loads(line) for line in paths["events"].read_text().splitlines()]
    events[0]["status"] = "PARTIAL"
    events[0]["error_code"] = "prior-timeout"
    previous = "0" * 64
    for event in events:
        event["previous_event_sha256"] = previous
        event.pop("event_sha256")
        event["event_sha256"] = _canonical_sha(event)
        previous = event["event_sha256"]
    paths["events"].write_text(
        "\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8"
    )
    summary = json.loads(paths["summary"].read_text())
    summary["ledger_status_counts"] = {"PARTIAL": 2, "TERMINAL_REJECTED": 1}
    summary["retry_required_count"] = 2
    summary.pop("summary_sha256")
    summary["summary_sha256"] = _canonical_sha(summary)
    paths["summary"].write_text(json.dumps(summary), encoding="utf-8")
    index = {
        "schema_version": "chronosaudit.control_candidate_rpc_retry_resolution_index.v1",
        "decision": "RETRY_RESOLUTION_INDEX_VERIFIED_NON_AUTHORIZING",
        "resolved_count": 1,
        "resolved_assignments": [
            {"reserve_assignment_sha256": "1" * 64, "result_sha256": "f" * 64}
        ],
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    index["index_sha256"] = _canonical_sha(index)
    index_path = tmp_path / "resolved-index.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")

    result = _build(paths, resolved_retry_index_path=index_path)

    assert result["retry_row_count"] == 1
    assert result["resolved_retry_count"] == 1
    assert result["resolved_retry_index_sha256"] == index["index_sha256"]
    rows = list(csv.DictReader(paths["retry_queue"].open(encoding="utf-8")))
    assert [row["reserve_assignment_sha256"] for row in rows] == ["2" * 64]


def test_unattempted_targets_freeze_only_queue_rows_without_terminal_events(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    event_rows = paths["events"].read_text(encoding="utf-8").splitlines()[:2]
    paths["events"].write_text("\n".join(event_rows) + "\n", encoding="utf-8")
    summary = json.loads(paths["summary"].read_text(encoding="utf-8"))
    summary["ledger_status_counts"] = {"COMPLETE": 1, "PARTIAL": 1}
    summary.pop("summary_sha256")
    summary["summary_sha256"] = _canonical_sha(summary)
    paths["summary"].write_text(json.dumps(summary), encoding="utf-8")

    manifest = retry_targets_module.build_control_candidate_rpc_unattempted_targets(
        original_queue_path=paths["queue"],
        run_manifest_path=paths["run_manifest"],
        summary_path=paths["summary"],
        event_ledger_path=paths["events"],
        request_ledger_path=paths["requests"],
        output_queue_path=paths["retry_queue"],
        output_manifest_path=paths["retry_manifest"],
        required_chains=["bsc"],
    )

    rows = list(csv.DictReader(paths["retry_queue"].open(encoding="utf-8")))
    assert [row["reserve_assignment_sha256"] for row in rows] == ["3" * 64]
    assert manifest["decision"] == (
        "UNATTEMPTED_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION"
    )
    assert manifest["unattempted_row_count"] == 1
    assert manifest["required_chains"] == ["bsc"]
    assert manifest["chain_unattempted_counts"] == {"bsc": 1}
    assert manifest["source_terminal_event_count"] == 2
    assert manifest["rpc_authorized"] is False
    assert manifest["selection_authorized"] is False
    assert manifest["counter_authority"] is False
    assert manifest["manifest_sha256"] == _canonical_sha(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
