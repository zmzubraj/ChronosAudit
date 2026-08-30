from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.control_denominator_expansion_admission import (
    ControlDenominatorExpansionAdmissionError,
    build_denominator_expansion_admission_projection,
    verify_denominator_expansion_admission_projection,
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _self_hashed(payload: dict[str, object], field: str) -> dict[str, object]:
    payload[field] = _sha(payload)
    return payload


def _fixture(tmp_path: Path) -> dict[str, object]:
    assignment = "1" * 64
    address = "0x" + "22" * 20
    tx_hash = "0x" + "33" * 32
    block_hash = "0x" + "44" * 32

    spec = tmp_path / "spec.md"
    spec.write_text("frozen admission specification\n", encoding="utf-8")
    approval = _self_hashed(
        {
            "schema_version": "chronosaudit.denominator_expansion_admission_user_approval.v1",
            "decision": "APPROVE_DENOMINATOR_EXPANSION_ADMISSION_V1",
            "approval_text": "APPROVE_DENOMINATOR_EXPANSION_ADMISSION_V1",
            "approved_by_principal": "human-author",
            "specification_preapproval_sha256": _file_sha(spec),
            "scope": "DENOMINATOR_EXPANSION_ADMISSION_PATH_IMPLEMENTATION_ONLY",
            "row_admission_authorized": False,
            "rpc_authorized": False,
            "selection_authorized": False,
            "qualification_authorized": False,
            "counter_authority": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
            "independent_adjudication_authorized": False,
            "r5_authorized": False,
            "release_authorized": False,
            "publication_claims_authorized": False,
        },
        "record_sha256",
    )
    approval_path = _write_json(tmp_path / "implementation-approval.json", approval)

    bridge = {
        "schema_version": "chronosaudit.control_denominator_authority_bridge.v1",
        "decision": "AUTHORITY_BRIDGE_VERIFIED",
        "row_count": 20000,
        "bridged_records_sha256": "a" * 64,
        "sealed_manifest_rows_sha256": "b" * 64,
        "selection_authorized": False,
    }
    bridge_path = _write_json(tmp_path / "authority-bridge.json", bridge)

    source_verification = {
        "schema_version": "chronosaudit.control_historical_source_import_verification.v1",
        "decision": "SOURCE_BATCH_VERIFIED_FOR_LOCAL_TRANSFORM",
        "import_manifest_sha256": "c" * 64,
        "verified_object_count": 1,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    source_verification_path = _write_json(
        tmp_path / "source-import-verification.json", source_verification
    )

    queue_fields = [
        "case_name", "chain", "chain_id", "positive_prediction_cutoff_time",
        "reserve_target", "control_address", "control_identity",
        "source_object_key", "source_object_sha256", "source_record_sha256",
        "edge_rank_sha256", "reserve_assignment_sha256", "queue_status",
        "rpc_authorized", "selection_authorized", "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ]
    queue_row = {
        "case_name": "case-1", "chain": "ethereum", "chain_id": "1",
        "positive_prediction_cutoff_time": "2020-01-03T00:00:00Z",
        "reserve_target": "1", "control_address": address,
        "control_identity": f"1:{address}", "source_object_key": "object.parquet",
        "source_object_sha256": "d" * 64, "source_record_sha256": "e" * 64,
        "edge_rank_sha256": "f" * 64, "reserve_assignment_sha256": assignment,
        "queue_status": "RESERVE_CANDIDATE_REQUIRES_RPC_AND_PAIR_EVIDENCE",
        "rpc_authorized": "False", "selection_authorized": "False",
        "stage_promotion_authorized": "False", "recovery3_mutation_authorized": "False",
    }
    queue_path = tmp_path / "reserve-queue.csv"
    with queue_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=queue_fields)
        writer.writeheader(); writer.writerow(queue_row)
    queue_manifest = {
        "schema_version": "chronosaudit.control_historical_candidate_reserve_queue.v1",
        "decision": "RESERVE_QUEUE_FROZEN_NON_AUTHORIZING",
        "queue_path": str(queue_path), "queue_row_count": 1,
        "queue_sha256": _file_sha(queue_path), "reserve_allocated": 1,
        "reserve_target": 1, "reserve_shortfall": 0,
        "global_no_reuse_verified": True,
        "source_import_manifest_sha256": source_verification["import_manifest_sha256"],
        "rpc_authorized": False, "selection_authorized": False,
        "stage_promotion_authorized": False, "recovery3_mutation_authorized": False,
    }
    queue_manifest_path = _write_json(tmp_path / "queue-manifest.json", queue_manifest)

    raw = []
    for index in range(4):
        path = tmp_path / f"rpc-{index}.json"
        path.write_text(json.dumps({"jsonrpc": "2.0", "id": index}), encoding="utf-8")
        raw.append(path)
    result = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_result.v1",
        "case_name": "case-1", "chain": "ethereum", "control_address": address,
        "control_deployment_time": "2020-01-01T00:00:00Z",
        "creation_tx_hash": tx_hash, "creation_type": "TOP_LEVEL_CREATE_RECEIPT_PROVEN",
        "deployment_block": 10, "deployment_block_hash": block_hash,
        "deployment_distance_seconds": -172800, "provider_consensus": True,
        "provider_observations": [
            {
                "provider_id": "provider-a", "operator_family": "family-a",
                "rpc_envelope_path": str(raw[0]), "rpc_envelope_sha256": _file_sha(raw[0]),
                "block_rpc_envelope_path": str(raw[1]),
                "block_rpc_envelope_sha256": _file_sha(raw[1]),
            },
            {
                "provider_id": "provider-b", "operator_family": "family-b",
                "rpc_envelope_path": str(raw[2]), "rpc_envelope_sha256": _file_sha(raw[2]),
                "block_rpc_envelope_path": str(raw[3]),
                "block_rpc_envelope_sha256": _file_sha(raw[3]),
            },
        ],
        "reserve_assignment_sha256": assignment, "rpc_classification_complete": True,
        "temporal_pre_cutoff": True, "trace_proof": False,
        "selection_authorized": False, "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["result_sha256"] = _sha(result)
    result_path = _write_json(tmp_path / "candidate.json", result)

    complete_fields = queue_fields + [
        "effective_status", "result_sha256", "result_file_sha256", "result_path",
        "rejection_reason",
    ]
    complete_path = tmp_path / "effective-complete.csv"
    with complete_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=complete_fields)
        writer.writeheader()
        writer.writerow({
            **queue_row, "effective_status": "COMPLETE",
            "result_sha256": result["result_sha256"],
            "result_file_sha256": _file_sha(result_path), "result_path": str(result_path),
            "rejection_reason": "",
        })
    effective_manifest = tmp_path / "effective-manifest.json"
    effective_manifest.write_text("{}\n", encoding="utf-8")

    capacity = _self_hashed(
        {
            "schema_version": "chronosaudit.control_effective_capacity_audit.v1",
            "decision": "EVIDENCE_COMPLETE_DENOMINATOR_CAPACITY_VERIFIED",
            "case_count": 1, "controls_per_positive": 1, "target_control_rows": 1,
            "evidence_complete_capacity": {"maximum_assignable_controls": 1},
            "denominator_qualifies": True,
            "source_reconciliations": [{
                "source_index": 0,
                "manifest_file_sha256": _file_sha(effective_manifest),
                "complete_file_sha256": _file_sha(complete_path), "complete_count": 1,
            }],
            "trace_deployment_projection_sha256": None,
            "denominator_admission_authorized": False, "selection_authorized": False,
            "qualification_authorized": False, "counter_authority": False,
            "stage_promotion_authorized": False, "recovery3_mutation_authorized": False,
            "independent_review_established": False, "release_authorized": False,
        },
        "audit_sha256",
    )
    capacity_path = _write_json(tmp_path / "capacity.json", capacity)

    attestation = _self_hashed(
        {
            "schema_version": "chronosaudit.control_denominator_expansion_outcome_blind_attestation.v1",
            "decision": "NO_CONTROL_OUTCOMES_INSPECTED_BEFORE_ADMISSION_FREEZE",
            "attested_by_principal": "human-author",
            "control_outcomes_inspected": False,
            "outcome_or_post_cutoff_fields_used": [],
            "admission_ordering_rule": "FROZEN_RESERVE_QUEUE_ROW_ORDER_V1",
            "selection_authorized": False, "qualification_authorized": False,
            "counter_authority": False, "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        "attestation_sha256",
    )
    attestation_path = _write_json(tmp_path / "attestation.json", attestation)
    return {
        "specification_path": spec,
        "implementation_approval_path": approval_path,
        "authority_bridge_manifest_path": bridge_path,
        "reserve_queue_path": queue_path,
        "reserve_queue_manifest_path": queue_manifest_path,
        "source_import_verification_path": source_verification_path,
        "effective_sources": [(effective_manifest, complete_path)],
        "capacity_audit_path": capacity_path,
        "outcome_blind_attestation_path": attestation_path,
        "expected_case_count": 1,
        "controls_per_positive": 1,
    }


def test_builds_non_authorizing_all_checks_pass_projection(tmp_path: Path):
    inputs = _fixture(tmp_path)
    projection = build_denominator_expansion_admission_projection(**inputs)

    assert projection["decision"] == "DENOMINATOR_EXPANSION_PROJECTED_NON_AUTHORIZING"
    assert projection["admitted_row_count"] == 1
    assert projection["counter_authority"] is False
    assert projection["denominator_qualifies"] is True
    assert set(projection["admitted_rows"][0]["checks"]) == {
        "queue_membership", "source_lineage", "provider_independence",
        "deployment_identity", "temporal_pre_cutoff", "global_no_reuse",
        "outcome_blindness", "evidence_completeness",
    }
    assert all(projection["admitted_rows"][0]["checks"].values())
    assert verify_denominator_expansion_admission_projection(
        projection=projection, **inputs
    )["decision"] == "DENOMINATOR_EXPANSION_PROJECTION_VERIFIED_NON_AUTHORIZING"


def test_rejects_tampered_raw_evidence(tmp_path: Path):
    inputs = _fixture(tmp_path)
    complete = Path(inputs["effective_sources"][0][1])
    row = next(csv.DictReader(complete.open(encoding="utf-8")))
    result = json.loads(Path(row["result_path"]).read_text())
    Path(result["provider_observations"][0]["rpc_envelope_path"]).write_text("tampered")
    with pytest.raises(ControlDenominatorExpansionAdmissionError, match="raw_evidence_hash_mismatch"):
        build_denominator_expansion_admission_projection(**inputs)


def test_rejects_nonqualifying_capacity(tmp_path: Path):
    inputs = _fixture(tmp_path)
    path = Path(inputs["capacity_audit_path"])
    capacity = json.loads(path.read_text())
    capacity["decision"] = "EVIDENCE_COMPLETE_DENOMINATOR_CAPACITY_INSUFFICIENT"
    capacity["denominator_qualifies"] = False
    capacity["evidence_complete_capacity"]["maximum_assignable_controls"] = 0
    capacity["audit_sha256"] = _sha({k: v for k, v in capacity.items() if k != "audit_sha256"})
    _write_json(path, capacity)
    with pytest.raises(ControlDenominatorExpansionAdmissionError, match="capacity_not_qualifying"):
        build_denominator_expansion_admission_projection(**inputs)


def test_rejects_outcome_inspection(tmp_path: Path):
    inputs = _fixture(tmp_path)
    path = Path(inputs["outcome_blind_attestation_path"])
    attestation = json.loads(path.read_text())
    attestation["control_outcomes_inspected"] = True
    attestation["attestation_sha256"] = _sha(
        {k: v for k, v in attestation.items() if k != "attestation_sha256"}
    )
    _write_json(path, attestation)
    with pytest.raises(ControlDenominatorExpansionAdmissionError, match="outcome_blindness_invalid"):
        build_denominator_expansion_admission_projection(**inputs)
