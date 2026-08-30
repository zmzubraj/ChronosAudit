from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_derived_state_targets import (
    ControlDerivedStateTargetsError,
    build_derived_state_targets,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _result(*, implementation: str | None, beacon: str | None, clone: str | None) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": "stage2_control_base_state_result.v1",
        "status": "complete",
        "phase": "FIXED_ADDRESS_BASE_STATE_DISCOVERY_ONLY",
        "target_id": "base-state:" + "1" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": "ethereum:0x" + "11" * 20,
        "identity_group": "ethereum:0x" + "11" * 20,
        "cutoff_timestamp": 1_600_000_000,
        "evidence_block_number": 100,
        "evidence_block_hash": "0x" + "aa" * 32,
        "next_block_number": 101,
        "next_block_hash": "0x" + "bb" * 32,
        "provider_agreement": True,
        "provider_families": ["family-a", "family-b"],
        "eip1898_pinned": True,
        "direct_implementation_address": implementation,
        "beacon_address": beacon,
        "admin_address": None,
        "eip1167_target": clone,
        "pair_scope_record_sha256": "2" * 64,
        "denominator_record_sha256": "3" * 64,
        "deployment_result_sha256": "4" * 64,
        "raw_evidence_hashes": ["5" * 64],
        "raw_evidence": [{"path": "raw/one.json", "sha256": "5" * 64}],
        "derived_address_reads_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    row["result_sha256"] = _canonical_sha(row)
    return row


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    row = _result(
        implementation="0x" + "22" * 20,
        beacon="0x" + "33" * 20,
        clone="0x" + "44" * 20,
    )
    row_with_disposition = {**row, "disposition": "complete"}
    results: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_state_results.v1",
        "activation_verification_sha256": "6" * 64,
        "state_targets_sha256": "7" * 64,
        "target_count": 1,
        "processed_target_count": 1,
        "completed_target_count": 1,
        "dispositions": {"complete": 1},
        "targets": [row_with_disposition],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    results["results_sha256"] = _canonical_sha(results)
    results_path = tmp_path / "base-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")

    registry = {
        "version": "test",
        "providers": [
            {
                "provider_id": provider_id,
                "chain": "ethereum",
                "endpoint": f"https://{provider_id}.example/rpc",
                "operator_family": family,
                "operator_verified": True,
                "tracking_enabled": True,
                "discovery_source": f"https://{provider_id}.example/docs",
                "operator_evidence_url": f"https://{provider_id}.example/about",
                "operator_evidence_sha256": suffix * 64,
            }
            for provider_id, family, suffix in (
                ("provider-a", "family-a", "a"),
                ("provider-b", "family-b", "b"),
            )
        ],
    }
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")
    return results_path, registry_path


def test_freezes_only_result_bound_derived_reads(tmp_path: Path) -> None:
    results_path, registry_path = _inputs(tmp_path)

    output = build_derived_state_targets(
        base_state_results_path=results_path,
        provider_registry_path=registry_path,
    )

    assert output["decision"] == "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION"
    assert output["target_count"] == 3
    assert output["call_count"] == 6
    assert output["complete"] is True
    assert output["rpc_authorized"] is False
    assert output["selection_authorized"] is False
    targets = {target["derived_role"]: target for target in output["targets"]}
    assert set(targets) == {
        "direct_implementation_runtime_code",
        "eip1167_target_runtime_code",
        "beacon_implementation_call",
    }
    assert {call["method"] for call in targets["direct_implementation_runtime_code"]["calls"]} == {"eth_getCode"}
    assert {call["method"] for call in targets["eip1167_target_runtime_code"]["calls"]} == {"eth_getCode"}
    beacon_calls = targets["beacon_implementation_call"]["calls"]
    assert {call["method"] for call in beacon_calls} == {"eth_call"}
    assert all(call["params"][0]["data"] == "0x5c60da1b" for call in beacon_calls)
    assert all(target["base_state_result_sha256"] for target in output["targets"])


def test_rejects_incomplete_phase1_results(tmp_path: Path) -> None:
    results_path, registry_path = _inputs(tmp_path)
    payload = json.loads(results_path.read_text())
    payload["completed_target_count"] = 0
    payload["results_sha256"] = _canonical_sha(
        {key: value for key, value in payload.items() if key != "results_sha256"}
    )
    results_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ControlDerivedStateTargetsError, match="base_state_results_incomplete"):
        build_derived_state_targets(
            base_state_results_path=results_path,
            provider_registry_path=registry_path,
        )


def test_rejects_tampered_phase1_row(tmp_path: Path) -> None:
    results_path, registry_path = _inputs(tmp_path)
    payload = json.loads(results_path.read_text())
    payload["targets"][0]["beacon_address"] = "0x" + "55" * 20
    payload["results_sha256"] = _canonical_sha(
        {key: value for key, value in payload.items() if key != "results_sha256"}
    )
    results_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ControlDerivedStateTargetsError, match="base_state_result_self_hash_invalid"):
        build_derived_state_targets(
            base_state_results_path=results_path,
            provider_registry_path=registry_path,
        )
