from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_derived_state_activation import (
    ControlDerivedStateActivationError,
    authorize_derived_state_rpc_call,
    build_derived_state_activation_approval,
    build_derived_state_activation_request,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    address = "0x" + "22" * 20
    selector = {"blockHash": "0x" + "aa" * 32, "requireCanonical": True}
    calls = [
        {
            "provider_id": provider_id,
            "operator_family": family,
            "method": "eth_getCode",
            "params": [address, selector],
        }
        for provider_id, family in (
            ("provider-a", "family-a"),
            ("provider-b", "family-b"),
        )
    ]
    target: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_target.v1",
        "target_id": "derived-state:" + "1" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": "ethereum:0x" + "11" * 20,
        "source_base_state_target_id": "base-state:" + "2" * 64,
        "base_state_result_sha256": "3" * 64,
        "derived_role": "direct_implementation_runtime_code",
        "derived_address": address,
        "evidence_block_number": 100,
        "evidence_block_hash": selector["blockHash"],
        "calls": calls,
        "call_count": 2,
        "phase": "RESULT_BOUND_DERIVED_STATE_READS_ONLY",
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    target["target_sha256"] = _canonical_sha(target)
    targets: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_targets.v1",
        "decision": "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION",
        "base_state_results_file_sha256": "4" * 64,
        "base_state_results_sha256": "5" * 64,
        "provider_registry_file_sha256": "6" * 64,
        "source_base_state_target_count": 1,
        "target_count": 1,
        "call_count": 2,
        "complete": True,
        "targets": [target],
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    targets["targets_sha256"] = _canonical_sha(targets)
    targets_path = tmp_path / "targets.json"
    targets_path.write_text(json.dumps(targets), encoding="utf-8")

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

    capability: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_capability_verification.v1",
        "decision": "DERIVED_STATE_CAPABILITY_VERIFIED_NON_AUTHORIZING",
        "complete": True,
        "derived_state_targets_file_sha256": hashlib.sha256(targets_path.read_bytes()).hexdigest(),
        "derived_state_targets_sha256": targets["targets_sha256"],
        "provider_registry_sha256": hashlib.sha256(registry_path.read_bytes()).hexdigest(),
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["verification_sha256"] = _canonical_sha(capability)
    capability_path = tmp_path / "capability.json"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")
    return targets_path, registry_path, capability_path


def test_activation_binds_only_exact_phase2_calls(tmp_path: Path) -> None:
    targets, registry, capability = _inputs(tmp_path)
    request = build_derived_state_activation_request(
        capability_verification_path=capability,
        provider_registry_path=registry,
        derived_state_targets_path=targets,
        activation_start_utc="2026-08-23T00:00:00Z",
        activation_expires_utc="2026-08-24T00:00:00Z",
        retry_limit=2,
    )

    assert request["rpc_call_scope_count"] == 2
    assert request["maximum_request_count"] == 6
    assert request["rpc_authorized"] is False
    approval = build_derived_state_activation_approval(
        request=request, signer_principal="local-test"
    )
    assert approval["rpc_authorized"] is True
    assert approval["selection_authorized"] is False

    activation = {
        **approval,
        "schema_version": "stage2_control_derived_state_activation_verification.v1",
        "decision": "DERIVED_STATE_RPC_ACTIVATION_VERIFIED",
    }
    scope = activation["rpc_call_scopes"][0]
    authorize_derived_state_rpc_call(
        activation,
        target_id=scope["target_id"],
        chain=scope["chain"],
        provider_id=scope["provider_id"],
        method=scope["method"],
        params=scope["params"],
        sequence_number=1,
        used_sequences=set(),
        requests_used=0,
        now_utc="2026-08-23T01:00:00Z",
    )


def test_activation_rejects_unfrozen_address(tmp_path: Path) -> None:
    targets, registry, capability = _inputs(tmp_path)
    request = build_derived_state_activation_request(
        capability_verification_path=capability,
        provider_registry_path=registry,
        derived_state_targets_path=targets,
        activation_start_utc="2026-08-23T00:00:00Z",
        activation_expires_utc="2026-08-24T00:00:00Z",
        retry_limit=0,
    )
    approval = build_derived_state_activation_approval(
        request=request, signer_principal="local-test"
    )
    activation = {
        **approval,
        "schema_version": "stage2_control_derived_state_activation_verification.v1",
        "decision": "DERIVED_STATE_RPC_ACTIVATION_VERIFIED",
    }
    scope = activation["rpc_call_scopes"][0]
    escaped = ["0x" + "99" * 20, scope["params"][1]]
    with pytest.raises(ControlDerivedStateActivationError, match="rpc_scope_not_activated"):
        authorize_derived_state_rpc_call(
            activation,
            target_id=scope["target_id"],
            chain=scope["chain"],
            provider_id=scope["provider_id"],
            method=scope["method"],
            params=escaped,
            sequence_number=1,
            used_sequences=set(),
            requests_used=0,
            now_utc="2026-08-23T01:00:00Z",
        )
