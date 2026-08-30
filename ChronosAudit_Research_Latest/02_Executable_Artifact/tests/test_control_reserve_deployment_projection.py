from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.control_reserve_deployment_projection import (
    ControlReserveDeploymentProjectionError,
    build_reserve_deployment_projection,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    run_binding = "a" * 64
    candidate_root = tmp_path / "candidates"
    candidate_root.mkdir()
    rows = [
        {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
            "run_binding_sha256": run_binding,
            "reserve_assignment_sha256": "1" * 64,
            "case_name": "case-1",
            "chain": "ethereum",
            "control_address": "0x" + "11" * 20,
            "creation_tx_hash": "0x" + "21" * 32,
            "deployment_block": 10,
            "deployment_block_hash": "0x" + "31" * 32,
            "control_deployment_time": "2020-01-01T00:00:00Z",
            "deployment_distance_seconds": -100,
            "temporal_pre_cutoff": True,
            "creation_type": "TOP_LEVEL_CREATE_RECEIPT_PROVEN",
            "trace_proof": False,
            "provider_consensus": True,
            "provider_observations": [
                {"provider_id": "p1", "operator_family": "f1"},
                {"provider_id": "p2", "operator_family": "f2"},
            ],
            "rpc_classification_complete": True,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
            "run_binding_sha256": run_binding,
            "reserve_assignment_sha256": "2" * 64,
            "case_name": "case-1",
            "chain": "ethereum",
            "control_address": "0x" + "12" * 20,
            "creation_tx_hash": "0x" + "22" * 32,
            "deployment_block": 11,
            "deployment_block_hash": "0x" + "32" * 32,
            "control_deployment_time": "2020-01-01T00:01:00Z",
            "deployment_distance_seconds": -40,
            "temporal_pre_cutoff": True,
            "creation_type": "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED",
            "trace_proof": False,
            "provider_consensus": True,
            "provider_observations": [],
            "rpc_classification_complete": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
    ]
    for row in rows:
        row["result_sha256"] = _canonical_sha(row)
        (candidate_root / f'{row["reserve_assignment_sha256"]}.json').write_text(
            json.dumps(row), encoding="utf-8"
        )

    summary = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": run_binding,
        "completed_count": 2,
        "rpc_classification_complete_count": 1,
        "trace_required_count": 1,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _canonical_sha(summary)
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    verification = {
        "decision": "LOCAL_TEST_CHECKPOINT_SIGNATURE_VERIFIED_NON_AUTHORIZING",
        "summary_sha256": _file_sha(summary_path),
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    verification_path = tmp_path / "verification.json"
    verification_path.write_text(json.dumps(verification), encoding="utf-8")

    previous = "0" * 64
    events = []
    for row in rows:
        event = {
            "schema_version": "chronosaudit.control_candidate_rpc_acquisition_event.v1",
            "previous_event_sha256": previous,
            "reserve_assignment_sha256": row["reserve_assignment_sha256"],
            "status": "COMPLETE",
            "result_sha256": row["result_sha256"],
            "result_path": str(
                candidate_root / f'{row["reserve_assignment_sha256"]}.json'
            ),
        }
        event["event_sha256"] = _canonical_sha(event)
        previous = event["event_sha256"]
        events.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
    ledger_path = tmp_path / "events.jsonl"
    ledger_path.write_text("\n".join(events) + "\n", encoding="utf-8")

    trace_record = {
        "schema_version": "stage2_control_trace_deployment_record.v1",
        "target_id": "trace-" + "2" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": "ethereum:0x" + "12" * 20,
        "control_address": "0x" + "12" * 20,
        "creation_tx_hash": "0x" + "22" * 32,
        "deployment_block": 11,
        "deployment_block_hash": "0x" + "32" * 32,
        "control_deployment_time": "2020-01-01T00:01:00Z",
        "deployment_distance_seconds": -40,
        "temporal_pre_cutoff": True,
        "creation_type": "internal_create2",
        "creator_address": "0x" + "41" * 20,
        "canonical_trace_path": "[0]",
        "reserve_assignment_sha256": "2" * 64,
        "reserve_record_sha256": rows[1]["result_sha256"],
        "reserve_record_file_sha256": _file_sha(
            candidate_root / f'{"2" * 64}.json'
        ),
        "trace_result_record_sha256": "5" * 64,
        "provider_ids": ["p1", "p2"],
        "operator_families": ["f1", "f2"],
        "trace_proof": True,
        "provider_consensus": True,
        "rpc_classification_complete": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    trace_record["record_sha256"] = _canonical_sha(trace_record)
    trace_projection = {
        "schema_version": "stage2_control_trace_deployment_projection.v1",
        "record_count": 1,
        "records": [trace_record],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    trace_projection["projection_sha256"] = _canonical_sha(trace_projection)
    trace_path = tmp_path / "trace-projection.json"
    trace_path.write_text(json.dumps(trace_projection), encoding="utf-8")
    return summary_path, verification_path, ledger_path, candidate_root, trace_path


def test_projects_receipt_rows_and_preserves_unresolved_trace_as_pending(tmp_path: Path):
    summary, verification, ledger, candidate_root, _ = _inputs(tmp_path)
    projection = build_reserve_deployment_projection(
        acquisition_summary_path=summary,
        signature_verification_path=verification,
        acquisition_ledger_path=ledger,
        candidate_root=candidate_root,
    )

    assert projection["complete"] is False
    assert projection["record_count"] == 1
    assert projection["pending_trace_count"] == 1
    assert projection["records"][0]["evidence_type"] == "receipt_create"
    assert projection["counter_authority"] is False


def test_trace_projection_closes_exact_pending_set(tmp_path: Path):
    summary, verification, ledger, candidate_root, trace = _inputs(tmp_path)
    projection = build_reserve_deployment_projection(
        acquisition_summary_path=summary,
        signature_verification_path=verification,
        acquisition_ledger_path=ledger,
        candidate_root=candidate_root,
        trace_deployment_projection_path=trace,
    )

    assert projection["complete"] is True
    assert projection["record_count"] == 2
    assert projection["pending_trace_count"] == 0
    assert {row["evidence_type"] for row in projection["records"]} == {
        "receipt_create",
        "dual_provider_trace_create",
    }
    assert projection["projection_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in projection.items()
            if key != "projection_sha256"
        }
    )


def test_rejects_tampered_acquisition_ledger(tmp_path: Path):
    summary, verification, ledger, candidate_root, _ = _inputs(tmp_path)
    lines = ledger.read_text().splitlines()
    event = json.loads(lines[0])
    event["result_sha256"] = "0" * 64
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(
        ControlReserveDeploymentProjectionError,
        match="acquisition_ledger_chain_invalid",
    ):
        build_reserve_deployment_projection(
            acquisition_summary_path=summary,
            signature_verification_path=verification,
            acquisition_ledger_path=ledger,
            candidate_root=candidate_root,
        )
