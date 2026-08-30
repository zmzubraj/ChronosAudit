from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.control_trace_deployment_projection import (
    ControlTraceDeploymentProjectionError,
    build_trace_deployment_projection,
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
    assignment = "1" * 64
    address = "0x" + "22" * 20
    transaction_hash = "0x" + "33" * 32
    block_hash = "0x" + "44" * 32
    candidate_root = tmp_path / "candidates"
    candidate_root.mkdir()
    candidate = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
        "run_binding_sha256": "a" * 64,
        "reserve_assignment_sha256": assignment,
        "case_name": "case-1",
        "chain": "ethereum",
        "control_address": address,
        "creation_tx_hash": transaction_hash,
        "deployment_block": 10,
        "deployment_block_hash": block_hash,
        "control_deployment_time": "2020-01-01T00:00:00Z",
        "deployment_distance_seconds": -86400,
        "temporal_pre_cutoff": True,
        "creation_type": "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED",
        "trace_proof": False,
        "provider_consensus": True,
        "provider_observations": [],
        "rpc_classification_complete": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    candidate["result_sha256"] = _canonical_sha(candidate)
    candidate_path = candidate_root / f"{assignment}.json"
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")

    target = {
        "target_id": f"trace-{assignment}",
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": f"ethereum:{address}",
        "transaction_hash": transaction_hash,
        "block_number": 10,
        "block_hash": block_hash,
        "reserve_assignment_sha256": assignment,
        "reserve_record_sha256": candidate["result_sha256"],
        "reserve_record_file_sha256": _file_sha(candidate_path),
        "calls": [
            {
                "provider_id": "provider-a",
                "operator_family": "family-a",
                "method": "trace_transaction",
                "params": [transaction_hash],
            },
            {
                "provider_id": "provider-b",
                "operator_family": "family-b",
                "method": "trace_transaction",
                "params": [transaction_hash],
            },
        ],
    }
    targets = {
        "schema_version": "stage2_control_trace_targets.v1",
        "target_count": 1,
        "rpc_call_count": 2,
        "targets": [target],
        "provider_registry_verified": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    targets["trace_targets_sha256"] = _canonical_sha(targets)
    targets_path = tmp_path / "trace-targets.json"
    targets_path.write_text(json.dumps(targets), encoding="utf-8")

    creation = [
        transaction_hash,
        address,
        "internal_create2",
        "0x" + "55" * 20,
        "[0,1]",
    ]
    result_row = {
        "target_id": target["target_id"],
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": target["chain_address"],
        "transaction_hash": transaction_hash,
        "block_number": 10,
        "block_hash": block_hash,
        "reserve_record_sha256": candidate["result_sha256"],
        "target_sha256": _canonical_sha(target),
        "provider_ids": ["provider-a", "provider-b"],
        "operator_families": ["family-a", "family-b"],
        "creation_set": [creation],
        "creation_set_sha256": _canonical_sha((tuple(creation),)),
        "disposition": "complete",
    }
    result_row["record_sha256"] = _canonical_sha(result_row)
    results = {
        "schema_version": "stage2_control_trace_acquisition_results.v1",
        "activation_verification_sha256": "b" * 64,
        "trace_targets_sha256": _file_sha(targets_path),
        "target_count": 1,
        "processed_target_count": 1,
        "completed_target_count": 1,
        "dispositions": {"complete": 1},
        "targets": [result_row],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    results["results_sha256"] = _canonical_sha(results)
    results_path = tmp_path / "normalized-trace-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")

    ledger_path = tmp_path / "trace-events.jsonl"
    ledger_path.write_text("{}\n", encoding="utf-8")
    checkpoint = {
        "schema_version": "stage2_control_trace_acquisition_checkpoint.v1",
        "status": "COMPLETE",
        "activation_verification_sha256": "b" * 64,
        "trace_targets_sha256": _file_sha(targets_path),
        "target_count": 1,
        "processed_target_count": 1,
        "completed_target_count": 1,
        "processed_target_ids": [target["target_id"]],
        "completed_target_ids": [target["target_id"]],
        "request_count": 2,
        "used_sequences": [1, 2],
        "event_tip_sha256": "c" * 64,
        "event_ledger_path": ledger_path.name,
        "event_ledger_sha256": _file_sha(ledger_path),
        "normalized_results_path": results_path.name,
        "normalized_results_sha256": _file_sha(results_path),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    checkpoint["checkpoint_sha256"] = _canonical_sha(checkpoint)
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")

    verification = {
        "schema_version": "stage2_control_trace_acquisition_checkpoint_verification.v1",
        "complete": True,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "checkpoint_file_sha256": _file_sha(checkpoint_path),
        "status": "COMPLETE",
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
        "errors": [],
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    verification_path = tmp_path / "checkpoint-verification.json"
    verification_path.write_text(json.dumps(verification), encoding="utf-8")
    return (
        targets_path,
        results_path,
        checkpoint_path,
        verification_path,
        candidate_root,
    )


def test_projects_complete_trace_into_deployment_evidence(tmp_path: Path):
    targets, results, checkpoint, verification, candidate_root = _inputs(tmp_path)
    projection = build_trace_deployment_projection(
        trace_targets_path=targets,
        trace_results_path=results,
        checkpoint_path=checkpoint,
        checkpoint_verification_path=verification,
        candidate_root=candidate_root,
    )

    assert projection["record_count"] == 1
    assert projection["selection_authorized"] is False
    row = projection["records"][0]
    assert row["creation_type"] == "internal_create2"
    assert row["creator_address"] == "0x" + "55" * 20
    assert row["canonical_trace_path"] == "[0,1]"
    assert row["trace_proof"] is True
    assert row["rpc_classification_complete"] is True
    assert projection["projection_sha256"] == _canonical_sha({
        key: value for key, value in projection.items()
        if key != "projection_sha256"
    })


def test_projection_rejects_ambiguous_single_root_and_overlay(tmp_path: Path):
    targets, results, checkpoint, verification, candidate_root = _inputs(tmp_path)
    with pytest.raises(
        ControlTraceDeploymentProjectionError, match="trace_evidence_mode_ambiguous"
    ):
        build_trace_deployment_projection(
            trace_targets_path=targets,
            trace_results_path=results,
            checkpoint_path=checkpoint,
            checkpoint_verification_path=verification,
            trace_overlay_path=results,
            trace_overlay_verification_path=verification,
            overlay_reconstruction_inputs={},
            candidate_root=candidate_root,
        )


def test_projection_accepts_reconstruction_verified_complete_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    targets, results, _, _, candidate_root = _inputs(tmp_path)
    result_row = json.loads(results.read_text(encoding="utf-8"))["targets"][0]
    overlay_row = {
        **result_row,
        "evidence_origin": "FRESH_RETRY_ROOT",
        "agreeing_source_provenance": [{"source_key": "retry"}],
    }
    overlay_row["overlay_record_sha256"] = _canonical_sha(overlay_row)
    overlay_payload = {
        "schema_version": "stage2_control_trace_completion_overlay.v1",
        "decision": "COMPLETE_NON_AUTHORIZING",
        "targets": [overlay_row],
        "overlay_sha256": "a" * 64,
    }
    overlay = tmp_path / "overlay.json"
    overlay.write_text(json.dumps(overlay_payload), encoding="utf-8")
    report = {
        "decision": "COMPLETE_NON_AUTHORIZING",
        "verification_sha256": "b" * 64,
    }
    overlay_verification = tmp_path / "overlay-verification.json"
    overlay_verification.write_text(json.dumps(report), encoding="utf-8")
    import chronosaudit_stage2.public_acquisition.control_trace_retry_overlay as retry_module

    monkeypatch.setattr(
        retry_module,
        "verify_trace_completion_overlay",
        lambda **_: report,
    )
    projection = build_trace_deployment_projection(
        trace_targets_path=targets,
        trace_overlay_path=overlay,
        trace_overlay_verification_path=overlay_verification,
        overlay_reconstruction_inputs={"fixture": True},
        candidate_root=candidate_root,
    )
    assert projection["trace_evidence_mode"] == "TRACE_RETRY_OVERLAY_V1"
    assert projection["record_count"] == 1


def test_projection_rejects_missing_candidate_creation(tmp_path: Path):
    targets, results, checkpoint, verification, candidate_root = _inputs(tmp_path)
    payload = json.loads(results.read_text())
    payload["targets"][0]["creation_set"][0][1] = "0x" + "99" * 20
    row = payload["targets"][0]
    row["creation_set_sha256"] = _canonical_sha(
        tuple(tuple(item) for item in row["creation_set"])
    )
    row["record_sha256"] = _canonical_sha({
        key: value for key, value in row.items() if key != "record_sha256"
    })
    payload["results_sha256"] = _canonical_sha({
        key: value for key, value in payload.items() if key != "results_sha256"
    })
    results.write_text(json.dumps(payload), encoding="utf-8")
    checkpoint_payload = json.loads(checkpoint.read_text())
    checkpoint_payload["normalized_results_sha256"] = _file_sha(results)
    checkpoint_payload["checkpoint_sha256"] = _canonical_sha({
        key: value for key, value in checkpoint_payload.items()
        if key != "checkpoint_sha256"
    })
    checkpoint.write_text(json.dumps(checkpoint_payload), encoding="utf-8")
    verification_payload = json.loads(verification.read_text())
    verification_payload["checkpoint_sha256"] = checkpoint_payload["checkpoint_sha256"]
    verification_payload["checkpoint_file_sha256"] = _file_sha(checkpoint)
    verification_payload["verification_sha256"] = _canonical_sha({
        key: value for key, value in verification_payload.items()
        if key != "verification_sha256"
    })
    verification.write_text(json.dumps(verification_payload), encoding="utf-8")

    with pytest.raises(
        ControlTraceDeploymentProjectionError, match="candidate_creation_missing"
    ):
        build_trace_deployment_projection(
            trace_targets_path=targets,
            trace_results_path=results,
            checkpoint_path=checkpoint,
            checkpoint_verification_path=verification,
            candidate_root=candidate_root,
        )


def test_projection_rejects_partial_checkpoint(tmp_path: Path):
    targets, results, checkpoint, verification, candidate_root = _inputs(tmp_path)
    payload = json.loads(checkpoint.read_text())
    payload["status"] = "PARTIAL_NON_AUTHORIZING"
    payload["checkpoint_sha256"] = _canonical_sha({
        key: value for key, value in payload.items() if key != "checkpoint_sha256"
    })
    checkpoint.write_text(json.dumps(payload), encoding="utf-8")
    verified = json.loads(verification.read_text())
    verified["checkpoint_sha256"] = payload["checkpoint_sha256"]
    verified["checkpoint_file_sha256"] = _file_sha(checkpoint)
    verified["status"] = "PARTIAL_NON_AUTHORIZING"
    verified["verification_sha256"] = _canonical_sha({
        key: value for key, value in verified.items()
        if key != "verification_sha256"
    })
    verification.write_text(json.dumps(verified), encoding="utf-8")

    with pytest.raises(
        ControlTraceDeploymentProjectionError, match="checkpoint_not_complete"
    ):
        build_trace_deployment_projection(
            trace_targets_path=targets,
            trace_results_path=results,
            checkpoint_path=checkpoint,
            checkpoint_verification_path=verification,
            candidate_root=candidate_root,
        )
