from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import pandas as pd

import chronosaudit_stage2.public_acquisition.strict_snapshot as strict_snapshot_module
from chronosaudit_stage2.public_acquisition.strict_snapshot import (
    acquire_strict_historical_snapshot,
    snapshot_counter_projection,
    validate_strict_historical_snapshot,
    verify_snapshot_receipt_bindings,
)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _write_receipt(
    receipt_root: Path,
    *,
    method: str,
    params: list[object],
    result: object,
    provider_id: str,
    provider_family: str,
    provider_identity: str,
    observed_at_utc: str = "2026-08-08T12:00:00Z",
) -> dict[str, object]:
    response_payload = {"jsonrpc": "2.0", "id": 1, "result": result}
    raw = json.dumps(response_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    response_sha = hashlib.sha256(raw).hexdigest()
    path = receipt_root / response_sha[:2] / f"{response_sha}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    request_payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    request_sha = hashlib.sha256(json.dumps(request_payload, separators=(",", ":")).encode("utf-8")).hexdigest()
    block_selector = params[0] if method == "eth_getBlockByNumber" and params else (params[-1] if params else None)
    return {
        "provider_id": provider_id,
        "provider_family": provider_family,
        "provider_identity": provider_identity,
        "method": method,
        "params": params,
        "block_selector": block_selector,
        "result": result,
        "error": None,
        "request_sha256": request_sha,
        "response_sha256": response_sha,
        "raw_response_path": str(path),
        "observed_at_utc": observed_at_utc,
    }


def _block_header(number: int, block_hash: str, timestamp: int) -> dict[str, str]:
    return {
        "hash": block_hash,
        "number": hex(number),
        "timestamp": hex(timestamp),
    }


def _identity_artifact() -> dict[str, object]:
    return {
        "complete": True,
        "checked_at_utc": "2026-08-08T12:10:00Z",
        "families": [
            {
                "family_id": "family-one",
                "operator_verified": True,
                "complete": True,
                "endpoint_template_sha256": "3" * 64,
                "evidence": [
                    {
                        "captured_path": "provider/family-one.html",
                        "sha256": "1" * 64,
                        "actual_sha256": "1" * 64,
                        "valid": True,
                        "provider_id": "provider-a",
                        "provider_identity": "identity-a",
                        "endpoint_template_sha256": "3" * 64,
                    }
                ],
            },
            {
                "family_id": "family-two",
                "operator_verified": True,
                "complete": True,
                "endpoint_template_sha256": "4" * 64,
                "evidence": [
                    {
                        "captured_path": "provider/family-two.html",
                        "sha256": "2" * 64,
                        "actual_sha256": "2" * 64,
                        "valid": True,
                        "provider_id": "provider-b",
                        "provider_identity": "identity-b",
                        "endpoint_template_sha256": "4" * 64,
                    }
                ],
            },
        ],
    }


def _case() -> dict[str, object]:
    return {
        "case_id": "ca2-testcase0000000001",
        "case_name": "strict-case",
        "chain": "ethereum",
        "address": "0x" + "11" * 20,
        "deployment_block": 100,
        "incident_block": 250,
        "prediction_cutoff_block": 110,
    }


def _policy() -> dict[str, object]:
    return {
        "cutoff_policy": {
            "rule": "deployment_timestamp_plus_24h",
            "primary_landmark_hours": 24,
            "minimum_incident_lead_hours": 1.0,
        }
    }


def test_optional_prediction_cutoff_treats_csv_nan_as_missing() -> None:
    assert strict_snapshot_module._optional_block_number(float("nan")) is None
    assert strict_snapshot_module._optional_block_number(pd.NA) is None
    assert strict_snapshot_module._optional_block_number(110.0) == 110


def test_cutoff_search_observations_receive_selector_and_provider_identity() -> None:
    class Provider:
        provider_id = "provider-a"
        public_endpoint_id = "identity-a"

    annotated = strict_snapshot_module._annotate_cutoff_search(
        {
            "binary_search_observations": [
                {
                    "provider_id": "provider-a",
                    "method": "eth_getBlockByNumber",
                    "params": ["0x64", False],
                }
            ]
        },
        [Provider()],
    )

    observation = annotated["binary_search_observations"][0]
    assert observation["block_selector"] == "0x64"
    assert observation["provider_identity"] == "identity-a"


def test_cutoff_search_falls_back_to_another_provider_when_preferred_header_is_unavailable() -> None:
    class Provider:
        def __init__(self, provider_id: str, *, unavailable: bool) -> None:
            self.provider_id = provider_id
            self.unavailable = unavailable

        def call(self, method: str, params: list[object]) -> SimpleNamespace:
            block_number = int(str(params[0]), 16)
            if self.unavailable:
                return SimpleNamespace(
                    provider_id=self.provider_id,
                    method=method,
                    params=params,
                    result=None,
                    error='{"code": -32603, "message": "precondition failure"}',
                )
            return SimpleNamespace(
                provider_id=self.provider_id,
                method=method,
                params=params,
                result=_block_header(block_number, "0x" + f"{block_number:064x}", block_number * 10),
                error=None,
            )

    search = strict_snapshot_module._first_block_at_or_after_timestamp_from_providers(
        [Provider("fallback", unavailable=False), Provider("preferred", unavailable=True)],
        target_timestamp=155,
        lower_block=10,
        upper_block=20,
    )

    assert search["previous_block"]["number"] == 15
    assert search["cutoff_block"]["number"] == 16
    assert {row["provider_id"] for row in search["binary_search_observations"]} == {"fallback"}
    assert search["attempted_provider_ids"] == ["preferred", "fallback"]
    assert search["failed_provider_ids"] == ["preferred"]
    assert search["fallback_used"] is True
    assert search["provider_selection_basis"] == "provider_list_secondary_then_primary"
    assert search["provider_failures"] == [
        {
            "provider_id": "preferred",
            "error_type": "header_unavailable",
        }
    ]


def _rehash_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    updated = dict(snapshot)
    updated["policy_sha256"] = _sha256_json(updated["policy_input"])
    artifact_without_self = dict(updated)
    artifact_without_self.pop("strict_snapshot_validation", None)
    artifact_without_self.pop("artifact_sha256_without_self_hash", None)
    artifact_without_self.pop("artifact_sha256", None)
    updated["artifact_sha256_without_self_hash"] = _sha256_json(artifact_without_self)
    artifact_with_inner = dict(artifact_without_self)
    artifact_with_inner["artifact_sha256_without_self_hash"] = updated["artifact_sha256_without_self_hash"]
    updated["artifact_sha256"] = _sha256_json(artifact_with_inner)
    return updated


def _assert_runtime_hashes_sealed(snapshot: dict[str, object]) -> None:
    artifact_without_self = dict(snapshot)
    artifact_without_self.pop("strict_snapshot_validation", None)
    artifact_without_self.pop("artifact_sha256_without_self_hash", None)
    artifact_without_self.pop("artifact_sha256", None)
    artifact_without_self.pop("cached_artifact_reused", None)
    artifact_without_self.pop("status", None)
    artifact_without_self.pop("blocked_reason", None)
    assert snapshot["artifact_sha256_without_self_hash"] == _sha256_json(artifact_without_self)
    artifact_with_inner = dict(artifact_without_self)
    artifact_with_inner["artifact_sha256_without_self_hash"] = snapshot["artifact_sha256_without_self_hash"]
    assert snapshot["artifact_sha256"] == _sha256_json(artifact_with_inner)


def _strict_snapshot(receipt_root: Path) -> dict[str, object]:
    selector = {"blockHash": "0x" + "ab" * 32, "requireCanonical": True}
    zero_word = "0x" + "00" * 32
    impl_address = "0x" + "22" * 20
    impl_word = "0x" + "00" * 12 + impl_address[2:]
    previous_header = _block_header(99, "0x" + "cd" * 32, 999_990)
    deployment_header = _block_header(100, "0x" + "ef" * 32, 1_000_000)
    cutoff_previous_header = _block_header(109, "0x" + "aa" * 32, 1_086_399)
    cutoff_header = _block_header(110, "0x" + "ab" * 32, 1_086_410)
    incident_header = _block_header(250, "0x" + "34" * 32, 1_090_010)
    deployment_header_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x63", False],
            result=previous_header,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x63", False],
            result=previous_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    deployment_block_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x64", False],
            result=deployment_header,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x64", False],
            result=deployment_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    deployment_code_previous_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getCode",
            params=["0x" + "11" * 20, {"blockHash": previous_header["hash"], "requireCanonical": True}],
            result="0x",
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getCode",
            params=["0x" + "11" * 20, {"blockHash": previous_header["hash"], "requireCanonical": True}],
            result="0x",
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    deployment_code_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getCode",
            params=["0x" + "11" * 20, {"blockHash": deployment_header["hash"], "requireCanonical": True}],
            result="0x6000",
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getCode",
            params=["0x" + "11" * 20, {"blockHash": deployment_header["hash"], "requireCanonical": True}],
            result="0x6000",
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    cutoff_search_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x64", False],
            result=deployment_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0xfa", False],
            result=incident_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6d", False],
            result=cutoff_previous_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6e", False],
            result=cutoff_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    cutoff_previous_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6d", False],
            result=cutoff_previous_header,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6d", False],
            result=cutoff_previous_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    cutoff_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6e", False],
            result=cutoff_header,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6e", False],
            result=cutoff_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    incident_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0xfa", False],
            result=incident_header,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0xfa", False],
            result=incident_header,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    block_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6e", False],
            result={"hash": "0x" + "ab" * 32, "number": "0x6e"},
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getBlockByNumber",
            params=["0x6e", False],
            result={"hash": "0x" + "ab" * 32, "number": "0x6e"},
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    observations = [
        _write_receipt(
            receipt_root,
            method="eth_getCode",
            params=["0x" + "11" * 20, selector],
            result="0x6000",
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getCode",
            params=["0x" + "11" * 20, selector],
            result="0x6000",
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    snapshot_impl_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getStorageAt",
            params=["0x" + "11" * 20, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", selector],
            result=impl_word,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getStorageAt",
            params=["0x" + "11" * 20, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", selector],
            result=impl_word,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    snapshot_beacon_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getStorageAt",
            params=["0x" + "11" * 20, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", selector],
            result=zero_word,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getStorageAt",
            params=["0x" + "11" * 20, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", selector],
            result=zero_word,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    snapshot_admin_observations = [
        _write_receipt(
            receipt_root,
            method="eth_getStorageAt",
            params=["0x" + "11" * 20, "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", selector],
            result=zero_word,
            provider_id="provider-a",
            provider_family="family-one",
            provider_identity="identity-a",
        ),
        _write_receipt(
            receipt_root,
            method="eth_getStorageAt",
            params=["0x" + "11" * 20, "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", selector],
            result=zero_word,
            provider_id="provider-b",
            provider_family="family-two",
            provider_identity="identity-b",
        ),
    ]
    receipt_bindings = {
        "complete": True,
        "cells": {
            cell: {
                "status": "consensus" if cell != "beacon_implementation_call" else "not_applicable",
                "complete": True,
                "provider_families": ["family-one", "family-two"] if cell != "beacon_implementation_call" else [],
                "receipt_sha256": [obs["response_sha256"] for obs in observations] if cell != "beacon_implementation_call" else [],
                "errors": [],
            }
            for cell in (
                "block_capability",
                "runtime_code",
                "eip1967_implementation_slot",
                "eip1967_beacon_slot",
                "eip1967_admin_slot",
                "beacon_implementation_call",
                "implementation_runtime_code",
            )
        },
    }
    snapshot = {
        "schema_version": "chronosaudit-strict-historical-snapshot-v1",
        "case_id": "ca2-testcase0000000001",
        "case_name": "strict-case",
        "chain": "ethereum",
        "address": "0x" + "11" * 20,
        "case_input": _case(),
        "case_input_sha256": _sha256_json(_case()),
        "policy_input": _policy(),
        "policy_sha256": _sha256_json(_policy()),
        "provider_identity": _identity_artifact(),
        "provider_identity_sha256": _sha256_json(_identity_artifact()),
        "provider_families": ["family-one", "family-two"],
        "deployment_block": 100,
        "deployment_timestamp": 1_000_000,
        "prediction_cutoff_policy": "deployment_timestamp_plus_24h",
        "prediction_cutoff_target_timestamp": 1_086_400,
        "prediction_cutoff_block": 110,
        "prediction_cutoff_timestamp": 1_086_410,
        "prediction_cutoff_block_hash": "0x" + "ab" * 32,
        "incident_block": 250,
        "incident_timestamp": 1_090_010,
        "cutoff_lead_hours": 1.0,
        "deployment_transition": {
            "status": "VERIFIED",
            "blockers": [],
            "headers": {
                "previous": {
                    "status": "consensus",
                    "value": {"hash": "0x" + "cd" * 32, "number": 99, "timestamp": 999_990},
                    "observations": deployment_header_observations,
                },
                "deployment": {
                    "status": "consensus",
                    "value": {"hash": "0x" + "ef" * 32, "number": 100, "timestamp": 1_000_000},
                    "observations": deployment_block_observations,
                },
            },
            "code": {
                "previous": {"status": "consensus", "value": "0x", "observations": deployment_code_previous_observations},
                "deployment": {"status": "consensus", "value": "0x6000", "observations": deployment_code_observations},
            },
        },
        "cutoff_search": {
            "target_timestamp": 1_086_400,
            "previous_block": {"number": 109, "hash": "0x" + "aa" * 32, "timestamp": 1_086_399},
            "cutoff_block": {"number": 110, "hash": "0x" + "ab" * 32, "timestamp": 1_086_410},
            "binary_search_observations": cutoff_search_observations,
            "reused_from_case_input": False,
        },
        "cutoff_bracket": {
            "status": "VERIFIED",
            "blockers": [],
            "previous": {
                "status": "consensus",
                "value": {"number": 109, "hash": "0x" + "aa" * 32, "timestamp": 1_086_399},
                "observations": cutoff_previous_observations,
            },
            "cutoff": {
                "status": "consensus",
                "agreement_provider_families": ["family-one", "family-two"],
                "value": {"number": 110, "hash": "0x" + "ab" * 32, "timestamp": 1_086_410},
                "observations": cutoff_observations,
            },
        },
        "incident_block_consensus": {
            "status": "consensus",
            "value": {"number": 250, "hash": "0x" + "34" * 32, "timestamp": 1_090_010},
            "observations": incident_observations,
        },
        "snapshot": {
            "status": "complete",
            "address": "0x" + "11" * 20,
            "block_number": 110,
            "canonical_block_hash": "0x" + "ab" * 32,
            "eip1898_pinned": True,
            "block": {
                "status": "consensus",
                "value": {"hash": "0x" + "ab" * 32, "number": "0x6e"},
                "observations": block_observations,
            },
            "code": {"status": "consensus", "value": "0x6000", "observations": observations},
            "implementation": {"status": "consensus", "value": impl_address, "observations": [
                _write_receipt(
                    receipt_root,
                    method="eth_getStorageAt",
                    params=["0x" + "11" * 20, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", selector],
                    result=impl_word,
                    provider_id="provider-a",
                    provider_family="family-one",
                    provider_identity="identity-a",
                ),
                _write_receipt(
                    receipt_root,
                    method="eth_getStorageAt",
                    params=["0x" + "11" * 20, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", selector],
                    result=impl_word,
                    provider_id="provider-b",
                    provider_family="family-two",
                    provider_identity="identity-b",
                ),
            ]},
            "beacon": {"status": "consensus", "value": None, "observations": [
                _write_receipt(
                    receipt_root,
                    method="eth_getStorageAt",
                    params=["0x" + "11" * 20, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", selector],
                    result=zero_word,
                    provider_id="provider-a",
                    provider_family="family-one",
                    provider_identity="identity-a",
                ),
                _write_receipt(
                    receipt_root,
                    method="eth_getStorageAt",
                    params=["0x" + "11" * 20, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", selector],
                    result=zero_word,
                    provider_id="provider-b",
                    provider_family="family-two",
                    provider_identity="identity-b",
                ),
            ]},
            "admin": {"status": "consensus", "value": None, "observations": [
                _write_receipt(
                    receipt_root,
                    method="eth_getStorageAt",
                    params=["0x" + "11" * 20, "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", selector],
                    result=zero_word,
                    provider_id="provider-a",
                    provider_family="family-one",
                    provider_identity="identity-a",
                ),
                _write_receipt(
                    receipt_root,
                    method="eth_getStorageAt",
                    params=["0x" + "11" * 20, "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", selector],
                    result=zero_word,
                    provider_id="provider-b",
                    provider_family="family-two",
                    provider_identity="identity-b",
                ),
            ]},
            "beacon_implementation": {"status": "not_applicable", "value": None, "observations": []},
            "runtime_bytecode_sha256": hashlib.sha256(bytes.fromhex("6000")).hexdigest(),
            "metadata_stripped_bytecode_sha256": hashlib.sha256(bytes.fromhex("6000")).hexdigest(),
            "metadata_status": "metadata_not_recognized",
            "eip1167_target": None,
            "diamond_resolution_status": "requires_loupe_or_historical_event_resolver",
        },
        "state_cells": {
            "block_capability": {
                "status": "consensus",
                "value": {"hash": "0x" + "ab" * 32, "number": "0x6e"},
                "observations": block_observations,
            },
            "runtime_code": {"status": "consensus", "value": "0x6000", "observations": observations},
            "eip1967_implementation_slot": {
                "status": "consensus",
                "value": impl_address,
                "observations": snapshot_impl_observations,
            },
            "eip1967_beacon_slot": {
                "status": "consensus",
                "value": None,
                "observations": snapshot_beacon_observations,
            },
            "eip1967_admin_slot": {
                "status": "consensus",
                "value": None,
                "observations": snapshot_admin_observations,
            },
            "beacon_implementation_call": {"status": "not_applicable", "value": None, "observations": []},
            "implementation_runtime_code": {
                "status": "consensus",
                "value": "0x6000",
                "observations": [
                    _write_receipt(
                        receipt_root,
                        method="eth_getCode",
                        params=[impl_address, selector],
                        result="0x6000",
                        provider_id="provider-a",
                        provider_family="family-one",
                        provider_identity="identity-a",
                    ),
                    _write_receipt(
                        receipt_root,
                        method="eth_getCode",
                        params=[impl_address, selector],
                        result="0x6000",
                        provider_id="provider-b",
                        provider_family="family-two",
                        provider_identity="identity-b",
                    ),
                ],
            },
        },
        "receipt_bindings": receipt_bindings,
        "required_state_cells": [
            "block_capability",
            "runtime_code",
            "eip1967_implementation_slot",
            "eip1967_beacon_slot",
            "eip1967_admin_slot",
            "beacon_implementation_call",
            "implementation_runtime_code",
        ],
        "strict_snapshot_closed": True,
        "blockers": [],
        "completed_at_utc": "2026-08-08T12:30:00Z",
    }
    snapshot["artifact_sha256_without_self_hash"] = _sha256_json(snapshot)
    snapshot["artifact_sha256"] = _sha256_json(snapshot)
    return snapshot


def _schema() -> dict[str, object]:
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "strict_historical_snapshot.schema.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def test_complete_snapshot_validates_and_counter_projection_is_hash_bound(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    snapshot = _strict_snapshot(receipt_root)

    validation = validate_strict_historical_snapshot(
        snapshot,
        schema=_schema(),
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert validation.ok is True
    snapshot["strict_snapshot_validation"] = validation.to_dict()
    projection = snapshot_counter_projection(snapshot, "cases/strict-case.json", "a" * 64)
    assert projection["historical_snapshot_status"] == "HISTORICAL_SNAPSHOT_VERIFIED"
    assert projection["historical_snapshot_schema_valid"] is True
    assert projection["historical_snapshot_hash_bound"] is True


@pytest.mark.parametrize(
    ("mutator", "expected_error"),
    [
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].pop("method"), "missing_method"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].pop("provider_id"), "provider_identity_incomplete"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].update(provider_id="provider-z"), "provider_identity_observation_mismatch"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].update(provider_family="family-two"), "provider_identity_observation_mismatch"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].update(provider_identity="identity-z"), "provider_identity_observation_mismatch"),
    ],
)
def test_verify_snapshot_receipt_bindings_rejects_unbound_state_cell_observations(
    tmp_path: Path,
    mutator,
    expected_error: str,
) -> None:
    receipt_root = tmp_path / "receipts"
    snapshot = _strict_snapshot(receipt_root)
    mutator(snapshot)

    bindings = verify_snapshot_receipt_bindings(
        snapshot["state_cells"],
        required_cells=tuple(snapshot["required_state_cells"]),
        allowed_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert bindings["complete"] is False
    assert expected_error in bindings["cells"]["runtime_code"]["errors"]


def test_projection_fails_closed_for_schema_valid_but_blocked_snapshot(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    snapshot = _strict_snapshot(receipt_root)
    validation = validate_strict_historical_snapshot(
        snapshot,
        schema=_schema(),
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )
    assert validation.ok is True

    snapshot["strict_snapshot_validation"] = validation.to_dict()
    snapshot["strict_snapshot_closed"] = False
    snapshot["blockers"] = ["receipt_binding_incomplete"]
    snapshot["receipt_bindings"]["complete"] = False

    projection = snapshot_counter_projection(snapshot, "cases/strict-case.json", "a" * 64)
    assert projection["historical_snapshot_status"] == ""
    assert projection["historical_snapshot_schema_valid"] is False
    assert projection["historical_snapshot_hash_bound"] is False


@pytest.mark.parametrize(
    ("mutator", "expected_error"),
    [
        (lambda snapshot: snapshot.update(provider_families=["family-one", "family-one"]), "same_provider_family"),
        (lambda snapshot: snapshot.update(chain="base"), "case_input_mismatch"),
        (lambda snapshot: snapshot.update(prediction_cutoff_target_timestamp=snapshot["deployment_timestamp"] + 1), "invalid_target_timestamp"),
        (lambda snapshot: snapshot["cutoff_bracket"]["previous"]["value"].update(number=108), "non_adjacent_cutoff_bracket"),
        (lambda snapshot: snapshot.update(cutoff_lead_hours=0.5), "insufficient_incident_lead_time"),
        (lambda snapshot: snapshot["snapshot"].update(eip1898_pinned=False), "snapshot_not_eip1898_pinned"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].update(block_selector="0x6e"), "non_eip1898_block_selector"),
        (lambda snapshot: snapshot["state_cells"].pop("runtime_code"), "missing_required_state_cell"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].pop("request_sha256"), "missing_request_sha256"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].update(raw_response_path=str(Path(snapshot["state_cells"]["runtime_code"]["observations"][0]["raw_response_path"]).parents[3] / "escape.json")), "receipt_path_escapes_root"),
        (lambda snapshot: Path(snapshot["state_cells"]["runtime_code"]["observations"][0]["raw_response_path"]).write_text("tampered", encoding="utf-8"), "response_hash_mismatch"),
        (lambda snapshot: snapshot["deployment_transition"]["headers"]["deployment"]["observations"][0].pop("request_sha256"), "missing_request_sha256"),
        (lambda snapshot: Path(snapshot["deployment_transition"]["code"]["deployment"]["observations"][0]["raw_response_path"]).write_text("tampered", encoding="utf-8"), "response_hash_mismatch"),
        (lambda snapshot: snapshot["cutoff_search"]["binary_search_observations"][0].update(raw_response_path=str(Path(snapshot["cutoff_search"]["binary_search_observations"][0]["raw_response_path"]).parents[3] / "escape.json")), "receipt_path_escapes_root"),
        (lambda snapshot: snapshot["incident_block_consensus"]["observations"][1].update(provider_family="family-one"), "same_provider_family"),
        (lambda snapshot: snapshot["state_cells"]["runtime_code"]["observations"][0].update(provider_id="provider-z"), "provider_identity_observation_mismatch"),
        (lambda snapshot: snapshot.update(schema_version="drifted"), "schema_validation_failed"),
        (lambda snapshot: snapshot.update(provider_identity_sha256="0" * 64), "provider_identity_hash_mismatch"),
        (lambda snapshot: snapshot["case_input"].update(chain="arbitrum"), "case_input_mismatch"),
        (lambda snapshot: snapshot["policy_input"]["cutoff_policy"].update(primary_landmark_hours=12), "policy_input_mismatch"),
        (lambda snapshot: snapshot.update(artifact_sha256="0" * 64), "artifact_sha256_mismatch"),
    ],
)
def test_validation_rejects_strict_contract_drift(
    tmp_path: Path,
    mutator,
    expected_error: str,
) -> None:
    receipt_root = tmp_path / "receipts"
    snapshot = _strict_snapshot(receipt_root)
    mutator(snapshot)

    validation = validate_strict_historical_snapshot(
        snapshot,
        schema=_schema(),
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert validation.ok is False
    assert expected_error in validation.errors
    projection = snapshot_counter_projection(snapshot, "cases/strict-case.json", "a" * 64)
    assert projection["historical_snapshot_status"] == ""
    assert projection["historical_snapshot_schema_valid"] is False
    assert projection["historical_snapshot_hash_bound"] is False


def test_acquire_blocks_without_complete_provider_identity(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    expected = _strict_snapshot(receipt_root)

    class Provider:
        provider_id = "provider-a"
        provider_family = "family-one"
        public_endpoint_id = "identity-a"

    def fake_build(case, *, providers, policy, receipt_root, provider_identity):
        assert provider_identity["complete"] is False
        return expected

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "chronosaudit_stage2.public_acquisition.strict_snapshot._build_strict_historical_snapshot",
        fake_build,
    )
    try:
        acquired = acquire_strict_historical_snapshot(
            _case(),
            providers=[Provider()],
            policy=_policy(),
            receipt_root=receipt_root,
        )
    finally:
        monkeypatch.undo()

    assert acquired["strict_snapshot_closed"] is False
    assert "provider_identity_incomplete" in acquired["blockers"]


def test_acquire_rejects_invalid_cached_artifact_before_reuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipt_root = tmp_path / "receipts"
    cached = _strict_snapshot(receipt_root)
    cached["artifact_sha256"] = "0" * 64
    expected = _strict_snapshot(receipt_root)
    calls: list[str] = []

    def fake_build(case, *, providers, policy, receipt_root, provider_identity):
        calls.append("built")
        return expected

    monkeypatch.setattr(
        "chronosaudit_stage2.public_acquisition.strict_snapshot._build_strict_historical_snapshot",
        fake_build,
    )

    acquired = acquire_strict_historical_snapshot(
        _case(),
        providers=[],
        policy={**_policy(), "provider_identity": _identity_artifact()},
        receipt_root=receipt_root,
        cached_artifact=cached,
    )

    assert calls == ["built"]
    assert acquired["artifact_sha256"] == expected["artifact_sha256"]


def test_acquire_reuses_valid_cached_artifact_without_rebuilding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipt_root = tmp_path / "receipts"
    cached = _strict_snapshot(receipt_root)

    def fail_build(*args, **kwargs):
        raise AssertionError("builder should not run when cache is valid")

    monkeypatch.setattr(
        "chronosaudit_stage2.public_acquisition.strict_snapshot._build_strict_historical_snapshot",
        fail_build,
    )

    acquired = acquire_strict_historical_snapshot(
        _case(),
        providers=[],
        policy={**_policy(), "provider_identity": _identity_artifact()},
        receipt_root=receipt_root,
        cached_artifact=cached,
    )

    assert acquired["cached_artifact_reused"] is True
    assert acquired["strict_snapshot_closed"] is True
    assert acquired["strict_snapshot_validation"]["ok"] is True


def test_acquire_fails_closed_when_rebuilt_snapshot_is_invalid_after_cache_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_root = tmp_path / "receipts"
    cached = _strict_snapshot(receipt_root)
    cached["artifact_sha256"] = "0" * 64
    rebuilt = _strict_snapshot(receipt_root)
    rebuilt["artifact_sha256"] = "0" * 64

    monkeypatch.setattr(
        "chronosaudit_stage2.public_acquisition.strict_snapshot._build_strict_historical_snapshot",
        lambda *args, **kwargs: rebuilt,
    )

    acquired = acquire_strict_historical_snapshot(
        _case(),
        providers=[],
        policy={**_policy(), "provider_identity": _identity_artifact()},
        receipt_root=receipt_root,
        cached_artifact=cached,
    )

    assert acquired.get("cached_artifact_reused") is not True
    assert acquired["strict_snapshot_closed"] is False
    assert "artifact_sha256_mismatch" in acquired["blockers"]


def test_validation_accepts_non_default_hash_bound_cutoff_policy(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    snapshot = _strict_snapshot(receipt_root)
    snapshot["policy_input"]["cutoff_policy"]["primary_landmark_hours"] = 12
    snapshot["policy_input"]["cutoff_policy"]["minimum_incident_lead_hours"] = 0.5
    snapshot["prediction_cutoff_target_timestamp"] = snapshot["deployment_timestamp"] + 12 * 3600
    snapshot = _rehash_snapshot(snapshot)

    validation = validate_strict_historical_snapshot(
        snapshot,
        schema=_schema(),
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert validation.ok is True


def test_validation_rejects_policy_bound_target_timestamp_drift(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    snapshot = _strict_snapshot(receipt_root)
    snapshot["policy_input"]["cutoff_policy"]["primary_landmark_hours"] = 12
    snapshot = _rehash_snapshot(snapshot)

    validation = validate_strict_historical_snapshot(
        snapshot,
        schema=_schema(),
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert validation.ok is False
    assert "invalid_target_timestamp" in validation.errors


def test_validation_rejects_policy_bound_incident_lead_drift(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    snapshot = _strict_snapshot(receipt_root)
    snapshot["policy_input"]["cutoff_policy"]["minimum_incident_lead_hours"] = 2.0
    snapshot = _rehash_snapshot(snapshot)

    validation = validate_strict_historical_snapshot(
        snapshot,
        schema=_schema(),
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert validation.ok is False
    assert "insufficient_incident_lead_time" in validation.errors


def test_build_strict_snapshot_blocks_missing_deployment_block_without_throwing(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    case = {**_case(), "deployment_block": None}

    built = strict_snapshot_module._build_strict_historical_snapshot(
        case,
        providers=[],
        policy={**_policy(), "provider_identity": _identity_artifact()},
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert built["strict_snapshot_closed"] is False
    assert "missing_deployment_block" in built["blockers"]


def test_acquire_missing_deployment_block_returns_sealed_final_hashes(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    acquired = acquire_strict_historical_snapshot(
        {**_case(), "deployment_block": None},
        providers=[],
        policy={**_policy(), "provider_identity": _identity_artifact()},
        receipt_root=receipt_root,
    )

    assert acquired["strict_snapshot_closed"] is False
    assert "missing_deployment_block" in acquired["blockers"]
    assert acquired["strict_snapshot_validation"]["ok"] is False
    _assert_runtime_hashes_sealed(acquired)


def test_build_strict_snapshot_blocks_missing_deployment_header_consensus_without_throwing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_root = tmp_path / "receipts"
    monkeypatch.setattr(
        strict_snapshot_module,
        "_verify_code_transition",
        lambda *args, **kwargs: {
            "status": "PARTIAL",
            "blockers": ["deployment_header_no_independent_consensus"],
            "headers": {
                "previous": {"status": "consensus", "value": {"hash": "0x" + "11" * 32, "number": 99, "timestamp": 999_990}, "observations": []},
                "deployment": {"status": "blocked_no_canonical_block_consensus", "value": None, "observations": []},
            },
            "code": {
                "previous": {"status": "consensus", "value": "0x", "observations": []},
                "deployment": {"status": "blocked_no_canonical_block_consensus", "value": None, "observations": []},
            },
        },
    )
    monkeypatch.setattr(strict_snapshot_module, "first_block_at_or_after_timestamp", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not search cutoff without deployment consensus")))

    built = strict_snapshot_module._build_strict_historical_snapshot(
        _case(),
        providers=[],
        policy={**_policy(), "provider_identity": _identity_artifact()},
        receipt_root=receipt_root,
        provider_identity=_identity_artifact(),
    )

    assert built["strict_snapshot_closed"] is False
    assert "deployment_header_no_independent_consensus" in built["blockers"]
