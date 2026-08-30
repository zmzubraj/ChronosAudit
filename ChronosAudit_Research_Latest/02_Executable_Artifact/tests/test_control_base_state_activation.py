from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_base_state_activation import (
    ControlBaseStateActivationError,
    authorize_base_state_rpc_call,
    build_base_state_activation_approval,
    build_base_state_activation_request,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    address = "0x" + "11" * 20
    block_hash = "0x" + "aa" * 32
    selector = {"blockHash": block_hash, "requireCanonical": True}
    calls = []
    for provider_id, family in (("provider-a", "family-a"), ("provider-b", "family-b")):
        for method, params in (
            ("eth_getBlockByNumber", ["0x9", False]),
            ("eth_getBlockByNumber", ["0xa", False]),
            ("eth_getCode", [address, selector]),
            ("eth_getStorageAt", [address, "0x" + "01" * 32, selector]),
            ("eth_getStorageAt", [address, "0x" + "02" * 32, selector]),
            ("eth_getStorageAt", [address, "0x" + "03" * 32, selector]),
        ):
            calls.append(
                {
                    "provider_id": provider_id,
                    "operator_family": family,
                    "method": method,
                    "params": params,
                }
            )
    target = {
        "schema_version": "stage2_control_base_state_target.v1",
        "target_id": "base-state:" + "1" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": f"ethereum:{address}",
        "control_address": address,
        "calls": calls,
        "call_count": len(calls),
        "derived_address_reads_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    target["target_sha256"] = _canonical_sha(target)
    targets = {
        "schema_version": "stage2_control_base_state_targets.v1",
        "decision": "BASE_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION",
        "target_count": 1,
        "call_count": len(calls),
        "targets": [target],
        "complete": True,
        "derived_address_reads_authorized": False,
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

    capability = {
        "schema_version": "stage2_control_base_state_capability_verification.v1",
        "decision": "BASE_STATE_CAPABILITY_VERIFIED_NON_AUTHORIZING",
        "complete": True,
        "base_state_targets_file_sha256": hashlib.sha256(
            targets_path.read_bytes()
        ).hexdigest(),
        "base_state_targets_sha256": targets["targets_sha256"],
        "provider_registry_sha256": hashlib.sha256(
            registry_path.read_bytes()
        ).hexdigest(),
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["verification_sha256"] = _canonical_sha(capability)
    capability_path = tmp_path / "capability-verification.json"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")
    return targets_path, registry_path, capability_path


def test_builds_only_exact_phase1_call_scopes(tmp_path: Path) -> None:
    targets, registry, capability = _inputs(tmp_path)
    request = build_base_state_activation_request(
        capability_verification_path=capability,
        provider_registry_path=registry,
        base_state_targets_path=targets,
        activation_start_utc="2026-08-23T00:00:00Z",
        activation_expires_utc="2026-08-24T00:00:00Z",
        retry_limit=2,
    )

    assert request["rpc_call_scope_count"] == 12
    assert request["maximum_request_count"] == 36
    assert request["rpc_authorized"] is False
    assert request["derived_address_reads_authorized"] is False
    assert not any(
        scope["method"] == "eth_call" for scope in request["rpc_call_scopes"]
    )
    approval = build_base_state_activation_approval(
        request=request, signer_principal="local-test"
    )
    assert approval["rpc_authorized"] is True
    assert approval["selection_authorized"] is False


def test_rejects_tampered_capability_verification(tmp_path: Path) -> None:
    targets, registry, capability = _inputs(tmp_path)
    payload = json.loads(capability.read_text())
    payload["complete"] = False
    capability.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ControlBaseStateActivationError, match="capability_self_hash_invalid"):
        build_base_state_activation_request(
            capability_verification_path=capability,
            provider_registry_path=registry,
            base_state_targets_path=targets,
            activation_start_utc="2026-08-23T00:00:00Z",
            activation_expires_utc="2026-08-24T00:00:00Z",
            retry_limit=0,
        )


def test_exact_authorization_rejects_derived_address_escape(tmp_path: Path) -> None:
    targets, registry, capability = _inputs(tmp_path)
    request = build_base_state_activation_request(
        capability_verification_path=capability,
        provider_registry_path=registry,
        base_state_targets_path=targets,
        activation_start_utc="2026-08-23T00:00:00Z",
        activation_expires_utc="2026-08-24T00:00:00Z",
        retry_limit=0,
    )
    approval = build_base_state_activation_approval(
        request=request, signer_principal="local-test"
    )
    activation = {
        **approval,
        "schema_version": "stage2_control_base_state_activation_verification.v1",
        "decision": "BASE_STATE_RPC_ACTIVATION_VERIFIED",
    }
    scope = activation["rpc_call_scopes"][2]
    authorize_base_state_rpc_call(
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
    escaped = ["0x" + "22" * 20, scope["params"][-1]]
    with pytest.raises(ControlBaseStateActivationError, match="rpc_scope_not_activated"):
        authorize_base_state_rpc_call(
            activation,
            target_id=scope["target_id"],
            chain=scope["chain"],
            provider_id=scope["provider_id"],
            method="eth_getCode",
            params=escaped,
            sequence_number=2,
            used_sequences=set(),
            requests_used=1,
            now_utc="2026-08-23T01:00:00Z",
        )
