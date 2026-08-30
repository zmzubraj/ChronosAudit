from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_base_state_capability import (
    ControlBaseStateCapabilityError,
    assess_base_state_capability,
    verify_base_state_capability,
)


ADDRESS_A = "0x" + "11" * 20
ADDRESS_B = "0x" + "22" * 20
BLOCK_HASH_A = "0x" + "aa" * 32
BLOCK_HASH_A_NEXT = "0x" + "ab" * 32
BLOCK_HASH_B = "0x" + "bb" * 32
BLOCK_HASH_B_NEXT = "0x" + "bc" * 32
IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
BEACON_SLOT = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)
ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _target(
    *, target_id: str, address: str, block: int, block_hash: str, next_hash: str
) -> dict[str, object]:
    selector = {"blockHash": block_hash, "requireCanonical": True}
    calls = []
    for provider_id, family in (("eth-a", "family-a"), ("eth-b", "family-b")):
        calls.extend(
            [
                {
                    "provider_id": provider_id,
                    "operator_family": family,
                    "method": "eth_getBlockByNumber",
                    "params": [hex(block), False],
                },
                {
                    "provider_id": provider_id,
                    "operator_family": family,
                    "method": "eth_getBlockByNumber",
                    "params": [hex(block + 1), False],
                },
                {
                    "provider_id": provider_id,
                    "operator_family": family,
                    "method": "eth_getCode",
                    "params": [address, selector],
                },
                *[
                    {
                        "provider_id": provider_id,
                        "operator_family": family,
                        "method": "eth_getStorageAt",
                        "params": [address, slot, selector],
                    }
                    for slot in (IMPLEMENTATION_SLOT, BEACON_SLOT, ADMIN_SLOT)
                ],
            ]
        )
    target = {
        "schema_version": "stage2_control_base_state_target.v1",
        "target_id": target_id,
        "case_id": target_id,
        "chain": "ethereum",
        "chain_address": f"ethereum:{address}",
        "cutoff_timestamp": block * 10 + 5,
        "evidence_block_number": block,
        "evidence_block_hash": block_hash,
        "evidence_block_timestamp": block * 10,
        "next_block_number": block + 1,
        "next_block_hash": next_hash,
        "next_block_timestamp": block * 10 + 10,
        "pair_scope_record_sha256": "1" * 64,
        "denominator_record_sha256": "2" * 64,
        "deployment_result_sha256": "3" * 64,
        "calls": calls,
        "derived_address_reads_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    target["target_sha256"] = _canonical_sha(target)
    return target


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    targets = [
        _target(
            target_id="a",
            address=ADDRESS_A,
            block=10,
            block_hash=BLOCK_HASH_A,
            next_hash=BLOCK_HASH_A_NEXT,
        ),
        _target(
            target_id="b",
            address=ADDRESS_B,
            block=20,
            block_hash=BLOCK_HASH_B,
            next_hash=BLOCK_HASH_B_NEXT,
        ),
    ]
    payload = {
        "schema_version": "stage2_control_base_state_targets.v1",
        "decision": "BASE_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION",
        "complete": True,
        "target_count": len(targets),
        "call_count": sum(len(row["calls"]) for row in targets),
        "targets": targets,
        "derived_address_reads_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
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
                ("eth-a", "family-a", "a"),
                ("eth-b", "family-b", "b"),
            )
        ],
    }
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")
    return targets_path, registry_path


class StateProvider:
    def __init__(self, provider_id: str, family: str, *, mismatch_code: bool = False):
        self.provider_id = provider_id
        self.provider_family = family
        self.chain = "ethereum"
        self.mismatch_code = mismatch_code

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        if method == "eth_chainId":
            result: object = "0x1"
        elif method == "eth_getBlockByNumber":
            block = int(str(params[0]), 16)
            hashes = {
                10: BLOCK_HASH_A,
                11: BLOCK_HASH_A_NEXT,
                20: BLOCK_HASH_B,
                21: BLOCK_HASH_B_NEXT,
            }
            result = {
                "number": hex(block),
                "hash": hashes[block],
                "timestamp": hex(block * 10),
            }
        elif method == "eth_getCode":
            result = "0x6001" if not self.mismatch_code else "0x6002"
        else:
            result = "0x" + "00" * 32
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
            observed_at_utc="2026-08-22T00:00:00Z",
        )


def _providers(*, mismatch: bool = False) -> list[StateProvider]:
    return [
        StateProvider("eth-a", "family-a"),
        StateProvider("eth-b", "family-b", mismatch_code=mismatch),
    ]


def test_target_bound_base_state_capability_is_complete_and_verifiable(
    tmp_path: Path,
) -> None:
    targets_path, registry_path = _inputs(tmp_path)
    raw_root = tmp_path / "raw"
    report = assess_base_state_capability(
        base_state_targets_path=targets_path,
        provider_registry_path=registry_path,
        providers=_providers(),
        raw_root=raw_root,
    )

    assert report["decision"] == "DUAL_PROVIDER_BASE_STATE_CAPABILITY_VERIFIED"
    assert report["complete"] is True
    assert report["probe_target_count"] == 2
    assert report["raw_evidence_count"] == 52
    assert report["rpc_authorized"] is False
    assert report["selection_authorized"] is False

    report_path = tmp_path / "capability.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    verification = verify_base_state_capability(
        capability_path=report_path,
        base_state_targets_path=targets_path,
        provider_registry_path=registry_path,
        raw_root=raw_root,
    )
    assert verification["decision"] == "BASE_STATE_CAPABILITY_VERIFIED_NON_AUTHORIZING"
    assert verification["base_state_targets_file_sha256"] == _file_sha(targets_path)


def test_cross_provider_code_disagreement_fails_closed(tmp_path: Path) -> None:
    targets_path, registry_path = _inputs(tmp_path)
    report = assess_base_state_capability(
        base_state_targets_path=targets_path,
        provider_registry_path=registry_path,
        providers=_providers(mismatch=True),
        raw_root=tmp_path / "raw",
    )

    assert report["complete"] is False
    assert report["decision"] == "BASE_STATE_CAPABILITY_INCOMPLETE"
    assert any("provider_semantic_disagreement" in row for row in report["errors"])


def test_verifier_rejects_tampered_raw_evidence(tmp_path: Path) -> None:
    targets_path, registry_path = _inputs(tmp_path)
    raw_root = tmp_path / "raw"
    report = assess_base_state_capability(
        base_state_targets_path=targets_path,
        provider_registry_path=registry_path,
        providers=_providers(),
        raw_root=raw_root,
    )
    report_path = tmp_path / "capability.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    raw_path = raw_root / report["raw_evidence"][0]["path"]
    raw_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(
        ControlBaseStateCapabilityError, match="raw_evidence_hash_mismatch"
    ):
        verify_base_state_capability(
            capability_path=report_path,
            base_state_targets_path=targets_path,
            provider_registry_path=registry_path,
            raw_root=raw_root,
        )


def test_cli_help_exposes_only_non_authorizing_capability_inputs() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "preflight_stage2_control_base_state_capability.py"
    )
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--base-state-targets" in result.stdout
    assert "--provider-registry" in result.stdout
    assert "--raw-root" in result.stdout
    assert "--output-capability" in result.stdout
    assert "--output-verification" in result.stdout
    assert "--selection" not in result.stdout
