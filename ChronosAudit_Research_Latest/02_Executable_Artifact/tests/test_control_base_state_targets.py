from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from chronosaudit_stage2.onchain import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
)
from chronosaudit_stage2.public_acquisition.control_base_state_targets import (
    ControlBaseStateTargetsError,
    build_base_state_targets,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _pair(address: str, seed: str) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": "stage2_control_reserve_pair_scope_record.v1",
        "case_name": "case-1",
        "chain": "ethereum",
        "positive_deployment_time": "2020-01-01T00:00:00Z",
        "positive_prediction_cutoff_time": "2020-01-10T00:00:00Z",
        "positive_record_sha256": "1" * 64,
        "deployment_id": "reserve:" + seed * 64,
        "reserve_assignment_sha256": seed * 64,
        "control_address": address,
        "control_deployment_time": "2020-01-05T00:00:00Z",
        "deployment_distance_seconds": 1,
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


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    pairs = [
        _pair("0x" + "aa" * 20, "7"),
        _pair("0x" + "bb" * 20, "8"),
    ]
    pair_scope: dict[str, object] = {
        "schema_version": "stage2_control_reserve_pair_scope.v1",
        "record_count": 2,
        "records": pairs,
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    pair_scope["projection_sha256"] = _canonical_sha(pair_scope)
    pair_path = tmp_path / "pairs.json"
    pair_path.write_text(json.dumps(pair_scope), encoding="utf-8")

    boundary_target_id = "cutoff-boundary:" + "9" * 64
    raw_evidence: list[dict[str, object]] = []
    for sequence, provider_id in enumerate(("provider-a", "provider-b"), start=1):
        raw_path = tmp_path / f"raw-{provider_id}.json"
        raw_path.write_text(
            json.dumps(
                {
                    "target_id": boundary_target_id,
                    "provider_id": provider_id,
                    "sequence_number": sequence,
                }
            ),
            encoding="utf-8",
        )
        raw_evidence.append(
            {
                "sequence_number": sequence,
                "target_id": boundary_target_id,
                "provider_id": provider_id,
                "block_number": 900,
                "path": str(raw_path),
                "sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                "succeeded": True,
            }
        )

    boundary: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_result.v1",
        "target_id": boundary_target_id,
        "target_sha256": "a" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "cutoff_timestamp": "2020-01-10T00:00:00Z",
        "evidence_block_number": 900,
        "evidence_block_hash": "0x" + "11" * 32,
        "evidence_block_timestamp": 1_578_614_390,
        "next_block_number": 901,
        "next_block_hash": "0x" + "22" * 32,
        "next_block_timestamp": 1_578_614_410,
        "pair_scope_record_count": 2,
        "pair_scope_record_sha256s": sorted(
            str(row["pair_scope_record_sha256"]) for row in pairs
        ),
        "provider_results": [
            {"provider_id": "provider-a", "operator_family": "family-a"},
            {"provider_id": "provider-b", "operator_family": "family-b"},
        ],
        "raw_evidence": raw_evidence,
        "raw_evidence_count": len(raw_evidence),
        "provider_agreement": True,
        "disposition": "complete",
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    boundary["result_sha256"] = _canonical_sha(boundary)
    results: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_results.v1",
        "requirements_sha256": "b" * 64,
        "activation_verification_sha256": "c" * 64,
        "target_count": 1,
        "completed_target_count": 1,
        "complete": True,
        "targets": [boundary],
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    results["results_sha256"] = _canonical_sha(results)
    results_path = tmp_path / "boundary-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    return pair_path, results_path


def _provider_registry(tmp_path: Path) -> Path:
    registry = {
        "version": "test",
        "providers": [
            {
                "provider_id": "state-a",
                "chain": "ethereum",
                "endpoint": "https://state-a.example/rpc",
                "operator_family": "state-family-a",
                "operator_verified": True,
                "tracking_enabled": True,
                "discovery_source": "https://state-a.example/docs",
                "operator_evidence_url": "https://state-a.example/about",
                "operator_evidence_sha256": "a" * 64,
            },
            {
                "provider_id": "state-b",
                "chain": "ethereum",
                "endpoint": "https://state-b.example/rpc",
                "operator_family": "state-family-b",
                "operator_verified": True,
                "tracking_enabled": True,
                "discovery_source": "https://state-b.example/docs",
                "operator_evidence_url": "https://state-b.example/about",
                "operator_evidence_sha256": "b" * 64,
            },
        ],
    }
    path = tmp_path / "provider-registry.yaml"
    path.write_text(yaml.safe_dump(registry), encoding="utf-8")
    return path


def test_materializes_only_fixed_address_base_state_calls(tmp_path: Path):
    pair_path, results_path = _inputs(tmp_path)
    output = build_base_state_targets(
        reserve_pair_scope_path=pair_path,
        boundary_results_path=results_path,
    )

    assert output["target_count"] == 2
    assert output["call_count"] == 24
    assert output["complete"] is True
    assert output["rpc_authorized"] is False
    expected_slots = {
        EIP1967_IMPLEMENTATION_SLOT,
        EIP1967_BEACON_SLOT,
        EIP1967_ADMIN_SLOT,
    }
    for target in output["targets"]:
        assert len(target["calls"]) == 12
        assert {call["method"] for call in target["calls"]} == {
            "eth_getBlockByNumber",
            "eth_getCode",
            "eth_getStorageAt",
        }
        assert not any(call["method"] == "eth_call" for call in target["calls"])
        storage_calls = [
            call for call in target["calls"] if call["method"] == "eth_getStorageAt"
        ]
        assert {call["params"][1] for call in storage_calls} == expected_slots
        for call in target["calls"]:
            if call["method"] in {"eth_getCode", "eth_getStorageAt"}:
                assert call["params"][0] == target["control_address"]
        assert target["derived_address_reads_authorized"] is False
        assert target["selection_authorized"] is False


def test_rebinds_state_calls_to_exact_verified_registry_pair(tmp_path: Path):
    pair_path, results_path = _inputs(tmp_path)
    registry_path = _provider_registry(tmp_path)

    output = build_base_state_targets(
        reserve_pair_scope_path=pair_path,
        boundary_results_path=results_path,
        provider_registry_path=registry_path,
    )

    assert output["provider_registry_file_sha256"] == hashlib.sha256(
        registry_path.read_bytes()
    ).hexdigest()
    for target in output["targets"]:
        assert {
            (call["provider_id"], call["operator_family"])
            for call in target["calls"]
        } == {
            ("state-a", "state-family-a"),
            ("state-b", "state-family-b"),
        }


def test_rejects_registry_without_two_independent_chain_providers(tmp_path: Path):
    pair_path, results_path = _inputs(tmp_path)
    registry_path = _provider_registry(tmp_path)
    registry = yaml.safe_load(registry_path.read_text())
    registry["providers"] = registry["providers"][:1]
    registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")

    with pytest.raises(ControlBaseStateTargetsError, match="state_provider_pair_invalid"):
        build_base_state_targets(
            reserve_pair_scope_path=pair_path,
            boundary_results_path=results_path,
            provider_registry_path=registry_path,
        )


def test_rejects_boundary_pair_membership_gap(tmp_path: Path):
    pair_path, results_path = _inputs(tmp_path)
    results = json.loads(results_path.read_text())
    boundary = results["targets"][0]
    boundary["pair_scope_record_sha256s"] = boundary[
        "pair_scope_record_sha256s"
    ][:1]
    boundary["pair_scope_record_count"] = 1
    boundary["result_sha256"] = _canonical_sha(
        {key: value for key, value in boundary.items() if key != "result_sha256"}
    )
    results["results_sha256"] = _canonical_sha(
        {key: value for key, value in results.items() if key != "results_sha256"}
    )
    results_path.write_text(json.dumps(results), encoding="utf-8")

    with pytest.raises(ControlBaseStateTargetsError, match="pair_membership_incomplete"):
        build_base_state_targets(
            reserve_pair_scope_path=pair_path,
            boundary_results_path=results_path,
        )


def test_rejects_nonadjacent_boundary(tmp_path: Path):
    pair_path, results_path = _inputs(tmp_path)
    results = json.loads(results_path.read_text())
    boundary = results["targets"][0]
    boundary["next_block_number"] = 902
    boundary["result_sha256"] = _canonical_sha(
        {key: value for key, value in boundary.items() if key != "result_sha256"}
    )
    results["results_sha256"] = _canonical_sha(
        {key: value for key, value in results.items() if key != "results_sha256"}
    )
    results_path.write_text(json.dumps(results), encoding="utf-8")

    with pytest.raises(ControlBaseStateTargetsError, match="boundary_not_adjacent"):
        build_base_state_targets(
            reserve_pair_scope_path=pair_path,
            boundary_results_path=results_path,
        )


def test_rejects_tampered_boundary_raw_evidence(tmp_path: Path):
    pair_path, results_path = _inputs(tmp_path)
    results = json.loads(results_path.read_text())
    raw_path = Path(results["targets"][0]["raw_evidence"][0]["path"])
    raw_path.write_text("tampered", encoding="utf-8")

    with pytest.raises(ControlBaseStateTargetsError, match="boundary_raw_evidence_invalid"):
        build_base_state_targets(
            reserve_pair_scope_path=pair_path,
            boundary_results_path=results_path,
        )


def test_cli_writes_deterministic_non_authorizing_base_targets(tmp_path: Path):
    pair_path, results_path = _inputs(tmp_path)
    output_path = tmp_path / "base-state-targets.json"
    script = (
        Path(__file__).resolve().parents[1]
        / "build_stage2_control_base_state_targets.py"
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--reserve-pair-scope",
            str(pair_path),
            "--boundary-results",
            str(results_path),
            "--output",
            str(output_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output_path.read_text())
    summary = json.loads(completed.stdout)
    assert payload["target_count"] == 2
    assert payload["call_count"] == 24
    assert payload["complete"] is True
    assert payload["rpc_authorized"] is False
    assert payload["selection_authorized"] is False
    assert summary == {
        "call_count": 24,
        "complete": True,
        "derived_address_reads_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "target_count": 2,
        "targets_sha256": payload["targets_sha256"],
    }

    first_bytes = output_path.read_bytes()
    repeated = subprocess.run(
        [
            sys.executable,
            str(script),
            "--reserve-pair-scope",
            str(pair_path),
            "--boundary-results",
            str(results_path),
            "--output",
            str(output_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert repeated.returncode == 0, repeated.stderr
    assert output_path.read_bytes() == first_bytes
