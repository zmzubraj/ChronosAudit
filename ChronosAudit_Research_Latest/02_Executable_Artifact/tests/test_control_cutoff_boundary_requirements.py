from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_requirements import (
    ControlCutoffBoundaryRequirementsError,
    build_cutoff_boundary_requirements,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pair_record(*, address_byte: str, pair_sha_seed: str) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": "stage2_control_reserve_pair_scope_record.v1",
        "case_name": "case-1",
        "chain": "ethereum",
        "positive_deployment_time": "2020-01-01T00:00:00Z",
        "positive_prediction_cutoff_time": "2020-01-10T00:00:00Z",
        "positive_record_sha256": "1" * 64,
        "deployment_id": f"reserve:{pair_sha_seed * 64}",
        "reserve_assignment_sha256": pair_sha_seed * 64,
        "control_address": "0x" + address_byte * 40,
        "control_deployment_time": "2020-01-05T00:00:00Z",
        "deployment_distance_seconds": 345600,
        "denominator_record_sha256": "2" * 64,
        "source_manifest_sha256": "3" * 64,
        "source_record_sha256": "4" * 64,
        "source_object_key": "object.parquet",
        "source_object_sha256": "5" * 64,
        "row_evidence_sha256": "2" * 64,
        "authority_projection_sha256": "6" * 64,
        "required_covariate_cutoff_time": "2020-01-10T00:00:00Z",
        "scope_status": "RESERVE_PAIR_CUTOFF_STATE_EVIDENCE_REQUIRED",
        "reserve_evidence_verified": True,
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    row["pair_scope_record_sha256"] = _canonical_sha(row)
    return row


def _inputs(tmp_path: Path) -> dict[str, Path]:
    records = [
        _pair_record(address_byte="a", pair_sha_seed="7"),
        _pair_record(address_byte="b", pair_sha_seed="8"),
    ]
    pair_scope: dict[str, object] = {
        "schema_version": "stage2_control_reserve_pair_scope.v1",
        "queue_file_sha256": "9" * 64,
        "queue_manifest_file_sha256": "a" * 64,
        "queue_verification_file_sha256": "b" * 64,
        "expansion_requirements_file_sha256": "c" * 64,
        "pair_scope_manifest_file_sha256": "d" * 64,
        "reserve_deployment_projection_file_sha256": "e" * 64,
        "reserve_deployment_projection_sha256": "f" * 64,
        "queue_row_count": 10,
        "completed_candidate_count": 2,
        "record_count": 2,
        "pending_trace_count": 8,
        "unprocessed_queue_count": 0,
        "complete": False,
        "records": records,
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    pair_scope["projection_sha256"] = _canonical_sha(pair_scope)
    pair_scope_path = tmp_path / "pair-scope.json"
    pair_scope_path.write_text(json.dumps(pair_scope), encoding="utf-8")

    window = {
                "case_name": "case-1",
                "chain": "ethereum",
                "chain_id": 1,
                "admissible_deployment_start": "2019-12-01T00:00:00Z",
                "admissible_deployment_end": "2020-01-10T00:00:00Z",
                "start_block": 900,
                "end_block": 1000,
                "start_boundary_sha256": "1" * 64,
                "end_boundary_sha256": "2" * 64,
                "expansion_requirement_sha256": "3" * 64,
                "boundary_status": "LOCAL_TEST_SINGLE_PROVIDER_EXACT_BLOCK_BRACKET",
    }
    window["block_window_sha256"] = _canonical_sha(window)
    windows = pd.DataFrame([window])
    windows_path = tmp_path / "windows.csv"
    windows.to_csv(windows_path, index=False)
    manifest = {
        "schema_version": "chronosaudit.control_block_window_resolution.local_test.v1",
        "decision": "LOCAL_TEST_BLOCK_WINDOWS_RESOLVED_NON_AUTHORIZING",
        "local_test_only": True,
        "single_provider_non_independent": True,
        "boundary_target_count": 1,
        "case_count": 1,
        "output_csv_sha256": _file_sha(windows_path),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest_path = tmp_path / "windows-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return {
        "pair_scope": pair_scope_path,
        "windows": windows_path,
        "manifest": manifest_path,
    }


def _build(paths: dict[str, Path]) -> dict[str, object]:
    return build_cutoff_boundary_requirements(
        reserve_pair_scope_path=paths["pair_scope"],
        block_windows_path=paths["windows"],
        block_windows_manifest_path=paths["manifest"],
    )


def test_collapses_pair_rows_to_one_non_authorizing_cutoff_requirement(
    tmp_path: Path,
):
    paths = _inputs(tmp_path)
    projection = _build(paths)

    assert projection["pair_scope_record_count"] == 2
    assert projection["boundary_target_count"] == 1
    assert projection["complete"] is True
    assert projection["rpc_authorized"] is False
    assert projection["selection_authorized"] is False
    target = projection["targets"][0]
    assert target["case_id"] == "case-1"
    assert target["cutoff_timestamp"] == "2020-01-10T00:00:00Z"
    assert target["lower_bound_block"] == 900
    assert target["source_upper_bound_block"] == 1000
    assert target["upper_bound_expansion_blocks"] == 64
    assert target["upper_bound_block"] == 1064
    assert target["required_result"] == (
        "LAST_CANONICAL_BLOCK_NOT_AFTER_CUTOFF_AND_ADJACENT_NEXT_BLOCK_AFTER_CUTOFF"
    )
    assert target["pair_scope_record_count"] == 2
    assert target["pair_scope_record_sha256s"] == sorted(
        row["pair_scope_record_sha256"]
        for row in json.loads(paths["pair_scope"].read_text())["records"]
    )
    assert projection["requirements_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in projection.items()
            if key != "requirements_sha256"
        }
    )


def test_rejects_cutoff_that_does_not_match_frozen_window_end(tmp_path: Path):
    paths = _inputs(tmp_path)
    windows = pd.read_csv(paths["windows"], dtype=str, keep_default_na=False)
    windows.loc[0, "admissible_deployment_end"] = "2020-01-11T00:00:00Z"
    window = windows.iloc[0].to_dict()
    window["chain_id"] = int(window["chain_id"])
    window["start_block"] = int(window["start_block"])
    window["end_block"] = int(window["end_block"])
    window.pop("block_window_sha256")
    windows.loc[0, "block_window_sha256"] = _canonical_sha(window)
    windows.to_csv(paths["windows"], index=False)
    manifest = json.loads(paths["manifest"].read_text())
    manifest["output_csv_sha256"] = _file_sha(paths["windows"])
    paths["manifest"].write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(
        ControlCutoffBoundaryRequirementsError, match="cutoff_window_mismatch"
    ):
        _build(paths)


def test_rejects_tampered_pair_scope_record(tmp_path: Path):
    paths = _inputs(tmp_path)
    pair_scope = json.loads(paths["pair_scope"].read_text())
    pair_scope["records"][0]["control_address"] = "0x" + "c" * 40
    pair_scope["projection_sha256"] = _canonical_sha(
        {
            key: value
            for key, value in pair_scope.items()
            if key != "projection_sha256"
        }
    )
    paths["pair_scope"].write_text(json.dumps(pair_scope), encoding="utf-8")

    with pytest.raises(
        ControlCutoffBoundaryRequirementsError, match="pair_record_self_hash_invalid"
    ):
        _build(paths)


def test_rejects_block_window_file_hash_mismatch(tmp_path: Path):
    paths = _inputs(tmp_path)
    paths["windows"].write_text(paths["windows"].read_text() + "\n", encoding="utf-8")

    with pytest.raises(
        ControlCutoffBoundaryRequirementsError, match="block_windows_hash_mismatch"
    ):
        _build(paths)
