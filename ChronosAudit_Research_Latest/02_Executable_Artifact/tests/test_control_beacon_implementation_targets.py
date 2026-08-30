from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_beacon_implementation_targets import (
    ControlBeaconImplementationTargetsError,
    build_beacon_implementation_targets,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    beacon: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_result.v1",
        "status": "complete",
        "phase": "RESULT_BOUND_DERIVED_STATE_READS_ONLY",
        "target_id": "derived-state:" + "1" * 64,
        "target_sha256": "2" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": "ethereum:0x" + "11" * 20,
        "source_base_state_target_id": "base-state:" + "3" * 64,
        "base_state_result_sha256": "4" * 64,
        "derived_role": "beacon_implementation_call",
        "derived_address": "0x" + "22" * 20,
        "evidence_block_number": 100,
        "evidence_block_hash": "0x" + "aa" * 32,
        "provider_agreement": True,
        "provider_families": ["family-a", "family-b"],
        "eip1898_pinned": True,
        "beacon_implementation_address": "0x" + "33" * 20,
        "raw_evidence_hashes": ["5" * 64],
        "raw_evidence": [{"path": "raw/a.json", "sha256": "5" * 64}],
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    beacon["result_sha256"] = _canonical_sha(beacon)
    code = {**beacon, "target_id": "derived-state:" + "6" * 64, "derived_role": "direct_implementation_runtime_code"}
    code.pop("beacon_implementation_address")
    code["runtime_code_hash"] = "7" * 64
    code["result_sha256"] = _canonical_sha({key: value for key, value in code.items() if key != "result_sha256"})
    results: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_state_results.v1",
        "activation_verification_sha256": "8" * 64,
        "state_targets_sha256": "9" * 64,
        "target_count": 2,
        "processed_target_count": 2,
        "completed_target_count": 2,
        "dispositions": {"complete": 2},
        "targets": [{**beacon, "disposition": "complete"}, {**code, "disposition": "complete"}],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    for row in results["targets"]:
        row["result_sha256"] = _canonical_sha(
            {
                key: value
                for key, value in row.items()
                if key not in {"result_sha256", "disposition"}
            }
        )
    results["results_sha256"] = _canonical_sha(results)
    results_path = tmp_path / "phase2-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    registry = {
        "version": "test",
        "providers": [
            {
                "provider_id": provider,
                "chain": "ethereum",
                "endpoint": f"https://{provider}.example/rpc",
                "operator_family": family,
                "operator_verified": True,
                "tracking_enabled": True,
                "discovery_source": f"https://{provider}.example/docs",
                "operator_evidence_url": f"https://{provider}.example/about",
                "operator_evidence_sha256": suffix * 64,
            }
            for provider, family, suffix in (("eth-a", "family-a", "a"), ("eth-b", "family-b", "b"))
        ],
    }
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")
    return results_path, registry_path


def test_freezes_only_beacon_returned_implementation_code(tmp_path: Path) -> None:
    results, registry = _inputs(tmp_path)
    output = build_beacon_implementation_targets(
        derived_state_results_path=results,
        provider_registry_path=registry,
    )
    assert output["decision"] == "BEACON_IMPLEMENTATION_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION"
    assert output["target_count"] == 1
    assert output["call_count"] == 2
    target = output["targets"][0]
    assert target["beacon_implementation_address"] == "0x" + "33" * 20
    assert {call["method"] for call in target["calls"]} == {"eth_getCode"}
    assert all(call["params"][0] == target["beacon_implementation_address"] for call in target["calls"])
    assert target["derived_state_result_sha256"]


def test_rejects_tampered_phase2_result(tmp_path: Path) -> None:
    results, registry = _inputs(tmp_path)
    payload = json.loads(results.read_text())
    payload["targets"][0]["beacon_implementation_address"] = "0x" + "44" * 20
    payload["results_sha256"] = _canonical_sha({key: value for key, value in payload.items() if key != "results_sha256"})
    results.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ControlBeaconImplementationTargetsError, match="derived_state_result_self_hash_invalid"):
        build_beacon_implementation_targets(derived_state_results_path=results, provider_registry_path=registry)


def test_no_beacon_results_require_no_phase3_rpc(tmp_path: Path) -> None:
    results, registry = _inputs(tmp_path)
    payload = json.loads(results.read_text())
    payload["targets"] = [
        row
        for row in payload["targets"]
        if row["derived_role"] != "beacon_implementation_call"
    ]
    payload["target_count"] = 1
    payload["processed_target_count"] = 1
    payload["completed_target_count"] = 1
    payload["dispositions"] = {"complete": 1}
    payload["results_sha256"] = _canonical_sha(
        {key: value for key, value in payload.items() if key != "results_sha256"}
    )
    results.write_text(json.dumps(payload), encoding="utf-8")

    output = build_beacon_implementation_targets(
        derived_state_results_path=results,
        provider_registry_path=registry,
    )

    assert output["decision"] == "NO_BEACON_IMPLEMENTATION_TARGETS_REQUIRED"
    assert output["target_count"] == 0
    assert output["call_count"] == 0
    assert output["complete"] is True
    assert output["rpc_authorized"] is False
