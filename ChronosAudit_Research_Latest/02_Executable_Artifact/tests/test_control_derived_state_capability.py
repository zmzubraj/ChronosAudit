from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_derived_state_capability import (
    ControlDerivedStateCapabilityError,
    assess_derived_state_capability,
    verify_derived_state_capability,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    selector = {"blockHash": "0x" + "aa" * 32, "requireCanonical": True}
    targets = []
    for index, (role, method, params) in enumerate(
        (
            ("direct_implementation_runtime_code", "eth_getCode", ["0x" + "22" * 20, selector]),
            ("beacon_implementation_call", "eth_call", [{"to": "0x" + "33" * 20, "data": "0x5c60da1b"}, selector]),
        ),
        start=1,
    ):
        target: dict[str, object] = {
            "schema_version": "stage2_control_derived_state_target.v1",
            "target_id": "derived-state:" + str(index) * 64,
            "case_id": "case-1",
            "chain": "ethereum",
            "chain_address": "ethereum:0x" + "11" * 20,
            "source_base_state_target_id": "base-state:" + "4" * 64,
            "base_state_result_sha256": "5" * 64,
            "derived_role": role,
            "derived_address": params[0]["to"] if method == "eth_call" else params[0],
            "evidence_block_number": 100,
            "evidence_block_hash": selector["blockHash"],
            "calls": [
                {"provider_id": provider, "operator_family": family, "method": method, "params": params}
                for provider, family in (("eth-a", "family-a"), ("eth-b", "family-b"))
            ],
            "call_count": 2,
            "phase": "RESULT_BOUND_DERIVED_STATE_READS_ONLY",
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        target["target_sha256"] = _canonical_sha(target)
        targets.append(target)
    payload: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_targets.v1",
        "decision": "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION",
        "target_count": 2,
        "call_count": 4,
        "complete": True,
        "targets": targets,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    payload["targets_sha256"] = _canonical_sha(payload)
    targets_path = tmp_path / "targets.json"
    targets_path.write_text(json.dumps(payload), encoding="utf-8")
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
    return targets_path, registry_path


class Provider:
    def __init__(self, provider_id: str, family: str, *, mismatch: bool = False):
        self.provider_id = provider_id
        self.provider_family = family
        self.chain = "ethereum"
        self.mismatch = mismatch

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        if method == "eth_chainId":
            result: object = "0x1"
        elif method == "eth_getCode":
            result = "0x6001" if not self.mismatch else "0x6002"
        else:
            result = "0x" + "00" * 12 + "44" * 20
        return ProviderObservation(
            provider_id=self.provider_id,
            method=method,
            params=params,
            result=result,
            observed_at_unix=1,
            error=None,
            response_sha256="f" * 64,
            provider_family=self.provider_family,
            request_sha256="e" * 64,
            observed_at_utc="2026-08-23T00:00:00Z",
        )


def _providers(*, mismatch: bool = False) -> list[Provider]:
    return [Provider("eth-a", "family-a"), Provider("eth-b", "family-b", mismatch=mismatch)]


def test_derived_capability_is_target_bound_and_verifiable(tmp_path: Path) -> None:
    targets, registry = _inputs(tmp_path)
    raw = tmp_path / "raw"
    report = assess_derived_state_capability(
        derived_state_targets_path=targets,
        provider_registry_path=registry,
        providers=_providers(),
        raw_root=raw,
    )
    assert report["decision"] == "DUAL_PROVIDER_DERIVED_STATE_CAPABILITY_VERIFIED"
    assert report["complete"] is True
    assert report["probe_target_count"] == 2
    assert report["rpc_authorized"] is False
    report_path = tmp_path / "capability.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    verification = verify_derived_state_capability(
        capability_path=report_path,
        derived_state_targets_path=targets,
        provider_registry_path=registry,
        raw_root=raw,
    )
    assert verification["decision"] == "DERIVED_STATE_CAPABILITY_VERIFIED_NON_AUTHORIZING"


def test_derived_capability_fails_on_provider_disagreement(tmp_path: Path) -> None:
    targets, registry = _inputs(tmp_path)
    report = assess_derived_state_capability(
        derived_state_targets_path=targets,
        provider_registry_path=registry,
        providers=_providers(mismatch=True),
        raw_root=tmp_path / "raw",
    )
    assert report["complete"] is False
    assert any("provider_semantic_disagreement" in error for error in report["errors"])


def test_verifier_rejects_tampered_raw_evidence(tmp_path: Path) -> None:
    targets, registry = _inputs(tmp_path)
    raw = tmp_path / "raw"
    report = assess_derived_state_capability(
        derived_state_targets_path=targets,
        provider_registry_path=registry,
        providers=_providers(),
        raw_root=raw,
    )
    report_path = tmp_path / "capability.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    (raw / report["raw_evidence"][0]["path"]).write_text("{}\n", encoding="utf-8")
    with pytest.raises(ControlDerivedStateCapabilityError, match="raw_evidence_hash_mismatch"):
        verify_derived_state_capability(
            capability_path=report_path,
            derived_state_targets_path=targets,
            provider_registry_path=registry,
            raw_root=raw,
        )
