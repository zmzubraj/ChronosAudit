from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_reserve_pair_scope import (
    ControlReservePairScopeError,
    build_reserve_pair_scope,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> dict[str, Path]:
    assignment = "1" * 64
    queue = pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "chain_id": "1",
                "positive_prediction_cutoff_time": "2020-01-10T00:00:00Z",
                "control_address": "0x" + "22" * 20,
                "control_identity": "1:0x" + "22" * 20,
                "source_object_key": "object.parquet",
                "source_object_sha256": "2" * 64,
                "source_record_sha256": "3" * 64,
                "reserve_assignment_sha256": assignment,
                "queue_status": "RESERVE_CANDIDATE_REQUIRES_RPC_AND_PAIR_EVIDENCE",
                "rpc_authorized": False,
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            }
        ]
    )
    queue_path = tmp_path / "queue.csv"
    queue.to_csv(queue_path, index=False)
    queue_manifest = {
        "schema_version": "chronosaudit.control_historical_candidate_reserve_queue.v1",
        "decision": "RESERVE_QUEUE_FROZEN_REQUIRES_HASH_BOUND_RPC_ACTIVATION",
        "queue_row_count": 1,
        "queue_sha256": _file_sha(queue_path),
        "global_no_reuse_verified": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    queue_manifest_path = tmp_path / "queue-manifest.json"
    queue_manifest_path.write_text(json.dumps(queue_manifest), encoding="utf-8")
    queue_verification = {
        "schema_version": "chronosaudit.control_historical_candidate_reserve_queue_verification.v1",
        "decision": "RESERVE_QUEUE_VERIFIED_NON_AUTHORIZING",
        "manifest_sha256": _file_sha(queue_manifest_path),
        "queue_sha256": _file_sha(queue_path),
        "queue_row_count": 1,
        "global_no_reuse_verified": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    queue_verification_path = tmp_path / "queue-verification.json"
    queue_verification_path.write_text(
        json.dumps(queue_verification), encoding="utf-8"
    )

    requirements = pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "positive_deployment_time": "2020-01-01T00:00:00Z",
                "positive_prediction_cutoff_time": "2020-01-10T00:00:00Z",
                "positive_record_sha256": "4" * 64,
                "admissible_deployment_start": "2019-12-01T00:00:00Z",
                "admissible_deployment_end": "2020-01-10T00:00:00Z",
                "minimum_additional_distinct_slots": 1,
                "expansion_status": "HISTORICAL_DENOMINATOR_EXPANSION_REQUIRED",
                "selection_authorized": False,
                "expansion_requirement_sha256": "5" * 64,
            }
        ]
    )
    requirements_path = tmp_path / "requirements.csv"
    requirements.to_csv(requirements_path, index=False)
    pair_manifest = {
        "schema_version": "chronosaudit.control_pair_acquisition_scope.v1",
        "decision": "PAIR_COVARIATE_EVIDENCE_REQUIRED",
        "selection_authorized": False,
        "outputs": {
            "expansion_requirements": {
                "sha256": _file_sha(requirements_path),
            }
        },
        "expansion_requirements": {
            "case_count": 1,
            "cases_requiring_expansion": 1,
            "minimum_additional_distinct_slots": 1,
        },
    }
    pair_manifest_path = tmp_path / "pair-manifest.json"
    pair_manifest_path.write_text(json.dumps(pair_manifest), encoding="utf-8")

    deployment_row = {
        "schema_version": "stage2_control_reserve_deployment_record.v1",
        "reserve_assignment_sha256": assignment,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": "ethereum:0x" + "22" * 20,
        "control_address": "0x" + "22" * 20,
        "transaction_hash": "0x" + "33" * 32,
        "block_number": 10,
        "block_hash": "0x" + "44" * 32,
        "control_deployment_time": "2020-01-05T00:00:00Z",
        "deployment_distance_seconds": 345600,
        "temporal_pre_cutoff": True,
        "creation_type": "top_level_create",
        "creator_address": "unknown",
        "canonical_trace_path": "[]",
        "creation_set_sha256": "6" * 64,
        "provider_ids": ["p1", "p2"],
        "operator_families": ["f1", "f2"],
        "source_candidate_record_sha256": "7" * 64,
        "source_candidate_file_sha256": "8" * 64,
        "source_trace_deployment_record_sha256": None,
        "evidence_type": "receipt_create",
        "trace_proof": False,
        "provider_consensus": True,
        "rpc_classification_complete": True,
        "disposition": "complete",
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    deployment_row["record_sha256"] = _canonical_sha(deployment_row)
    deployment = {
        "schema_version": "stage2_control_reserve_deployment_projection.v1",
        "completed_candidate_count": 1,
        "receipt_record_count": 1,
        "trace_record_count": 0,
        "pending_trace_count": 0,
        "pending_trace_reserve_assignment_sha256s": [],
        "record_count": 1,
        "complete": True,
        "records": [deployment_row],
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    deployment["projection_sha256"] = _canonical_sha(deployment)
    deployment_path = tmp_path / "deployment.json"
    deployment_path.write_text(json.dumps(deployment), encoding="utf-8")
    return {
        "queue": queue_path,
        "queue_manifest": queue_manifest_path,
        "queue_verification": queue_verification_path,
        "requirements": requirements_path,
        "pair_manifest": pair_manifest_path,
        "deployment": deployment_path,
    }


def test_builds_non_authorizing_reserve_pair_scope(tmp_path: Path):
    paths = _inputs(tmp_path)
    projection = build_reserve_pair_scope(
        queue_path=paths["queue"],
        queue_manifest_path=paths["queue_manifest"],
        queue_verification_path=paths["queue_verification"],
        expansion_requirements_path=paths["requirements"],
        pair_scope_manifest_path=paths["pair_manifest"],
        reserve_deployment_projection_path=paths["deployment"],
    )

    assert projection["record_count"] == 1
    assert projection["complete"] is True
    assert projection["counter_authority"] is False
    row = projection["records"][0]
    assert row["case_name"] == "case-1"
    assert row["control_deployment_time"] == "2020-01-05T00:00:00Z"
    assert row["deployment_distance_seconds"] == 345600
    assert row["reserve_evidence_verified"] is True
    assert row["counter_authority"] is False
    assert row["selection_authorized"] is False


def test_rejects_deployment_outside_frozen_window(tmp_path: Path):
    paths = _inputs(tmp_path)
    payload = json.loads(paths["deployment"].read_text())
    row = payload["records"][0]
    row["control_deployment_time"] = "2020-01-11T00:00:00Z"
    row["record_sha256"] = _canonical_sha(
        {key: value for key, value in row.items() if key != "record_sha256"}
    )
    payload["projection_sha256"] = _canonical_sha(
        {
            key: value
            for key, value in payload.items()
            if key != "projection_sha256"
        }
    )
    paths["deployment"].write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ControlReservePairScopeError, match="deployment_outside_window"):
        build_reserve_pair_scope(
            queue_path=paths["queue"],
            queue_manifest_path=paths["queue_manifest"],
            queue_verification_path=paths["queue_verification"],
            expansion_requirements_path=paths["requirements"],
            pair_scope_manifest_path=paths["pair_manifest"],
            reserve_deployment_projection_path=paths["deployment"],
        )


def test_rejects_queue_hash_mismatch(tmp_path: Path):
    paths = _inputs(tmp_path)
    paths["queue"].write_text(paths["queue"].read_text() + "\n", encoding="utf-8")
    with pytest.raises(ControlReservePairScopeError, match="queue_hash_mismatch"):
        build_reserve_pair_scope(
            queue_path=paths["queue"],
            queue_manifest_path=paths["queue_manifest"],
            queue_verification_path=paths["queue_verification"],
            expansion_requirements_path=paths["requirements"],
            pair_scope_manifest_path=paths["pair_manifest"],
            reserve_deployment_projection_path=paths["deployment"],
        )
