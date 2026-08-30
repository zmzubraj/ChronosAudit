from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.onchain import ProviderObservation, provider_consensus, provider_urls_from_env
from chronosaudit_stage2.public_acquisition.ledger import AppendOnlyLedger
from chronosaudit_stage2.public_acquisition.model import AcquisitionEvent, AcquisitionStatus
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry
from chronosaudit_stage2.public_acquisition.rpc import acquire_case_snapshot, acquire_queue, public_provider_objects

ROOT = Path(__file__).resolve().parents[1]


class FakeProvider:
    def __init__(self, provider_id: str, provider_family: str):
        self.provider_id = provider_id
        self.provider_family = provider_family

    def call(self, method, params):
        if method == "eth_getBlockByNumber":
            result = {"hash": "0x" + "ab" * 32, "number": "0x10"}
        elif method == "eth_getCode":
            result = "0x6000"
        elif method == "eth_getStorageAt":
            result = "0x" + "00" * 32
        else:
            result = None
        return ProviderObservation(
            self.provider_id,
            method,
            params,
            result,
            1,
            provider_family=self.provider_family,
        )


def test_public_provider_fallback_constructs_provider_objects():
    registry = ProviderRegistry.from_path(ROOT / "config" / "public_provider_registry.yaml")
    providers = public_provider_objects("ethereum", registry)

    assert len(providers) >= 2
    assert all(hasattr(provider, "call") for provider in providers)


def test_same_family_responses_cannot_close_snapshot():
    case = {
        "case_id": "ca2-testcase0000000001",
        "case_name": "same-family",
        "chain": "ethereum",
        "address": "0x" + "11" * 20,
        "incident_block": 16,
        "cutoff_status": "VERIFIED",
        "prediction_cutoff_block": 20,
        "deployment_verification_status": "VERIFIED",
        "prediction_cutoff_block_verification_status": "VERIFIED",
        "source_availability_verification_status": "VERIFIED",
        "incident_eligibility": True,
        "cutoff_lead_hours": 2.0,
    }

    result = acquire_case_snapshot(
        case,
        providers=[FakeProvider("a", "operator-a"), FakeProvider("b", "operator-a")],
    )

    assert result["status"] != "VERIFIED"
    assert result["blocked_reason"] == "insufficient_independent_provider_families"


def test_provider_consensus_strict_fails_closed_without_two_verified_families():
    result = provider_consensus(
        [FakeProvider("a", "unverified:operator-a"), FakeProvider("b", "unverified:operator-b")],
        "eth_getCode",
        ["0x" + "11" * 20, "0x10"],
        require_distinct_provider_families=True,
    )

    assert result["status"] == "insufficient_independent_provider_families"
    assert result["value"] is None


def test_acquire_case_snapshot_injects_frozen_default_cutoff_policy(monkeypatch: pytest.MonkeyPatch):
    case = {
        "case_id": "ca2-default-policy",
        "case_name": "default-policy",
        "chain": "ethereum",
        "address": "0x" + "55" * 20,
        "incident_block": 250,
        "deployment_block": 100,
        "cutoff_status": "VERIFIED",
        "prediction_cutoff_block": 110,
        "deployment_verification_status": "VERIFIED",
        "prediction_cutoff_block_verification_status": "VERIFIED",
        "source_availability_verification_status": "VERIFIED",
        "incident_eligibility": True,
        "cutoff_lead_hours": 2.0,
    }
    seen_policy: dict[str, object] = {}

    def fake_acquire(case, *, providers, policy, receipt_root, cached_artifact=None):
        seen_policy.update(policy)
        return {
            "strict_snapshot_closed": True,
            "blocked_reason": None,
            "snapshot": {
                "status": "complete",
                "code": {"status": "consensus"},
                "implementation": {"status": "consensus"},
                "beacon": {"status": "consensus"},
                "admin": {"status": "consensus"},
                "beacon_implementation": {"status": "not_applicable"},
            },
            "state_cells": {
                "implementation_runtime_code": {"status": "consensus"},
            },
            "prediction_cutoff_target_timestamp": 1_086_400,
            "prediction_cutoff_block": 110,
            "prediction_cutoff_block_hash": "0x" + "ab" * 32,
            "blockers": [],
        }

    monkeypatch.setattr(
        "chronosaudit_stage2.public_acquisition.rpc.acquire_strict_historical_snapshot",
        fake_acquire,
    )

    result = acquire_case_snapshot(
        case,
        providers=[FakeProvider("a", "operator-a"), FakeProvider("b", "operator-b")],
    )

    assert seen_policy["cutoff_policy"] == {
        "rule": "deployment_timestamp_plus_24h",
        "primary_landmark_hours": 24,
        "minimum_incident_lead_hours": 1.0,
    }
    assert result["status"] == "VERIFIED"
    assert result["prediction_cutoff_target_timestamp"] == 1_086_400


def test_env_provider_requires_exact_verified_endpoint_identity():
    registry = ProviderRegistry.from_mapping(
        {
            "providers": [
                {
                    "provider_id": "verified-a",
                    "chain": "ethereum",
                    "endpoint": "https://rpc.example/verified",
                    "operator_family": "operator-a",
                    "operator_evidence_url": "https://operator-a.example/about",
                    "operator_evidence_sha256": "a" * 64,
                    "operator_verified": True,
                    "discovery_source": "seed",
                    "tracking_enabled": True,
                },
                {
                    "provider_id": "verified-b",
                    "chain": "ethereum",
                    "endpoint": "https://rpc.example/verified-b",
                    "operator_family": "operator-b",
                    "operator_evidence_url": "https://operator-b.example/about",
                    "operator_evidence_sha256": "b" * 64,
                    "operator_verified": True,
                    "discovery_source": "seed",
                    "tracking_enabled": True,
                },
            ]
        }
    )

    providers = provider_urls_from_env(
        "ethereum",
        registry=registry,
        env={
            "CHRONOS_ETHEREUM_ARCHIVE_RPC_URLS": (
                "https://rpc.example/verified,https://rpc.example/verified-b"
            ),
            "CHRONOS_ETHEREUM_ARCHIVE_RPC_PROVIDER_FAMILIES": "operator-a,operator-b",
        },
    )
    assert [provider.provider_family for provider in providers] == ["operator-a", "operator-b"]

    with pytest.raises(ValueError, match="exact verified endpoint identity"):
        provider_urls_from_env(
            "ethereum",
            registry=registry,
            env={
                "CHRONOS_ETHEREUM_ARCHIVE_RPC_URLS": (
                    "https://rpc.example/spoofed,https://rpc.example/verified-b"
                ),
                "CHRONOS_ETHEREUM_ARCHIVE_RPC_PROVIDER_FAMILIES": "operator-a,operator-b",
            },
        )


def test_acquire_queue_resumes_per_cell_not_per_case(tmp_path: Path):
    registry = ProviderRegistry.from_mapping({"providers": []})
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    case = {
        "case_id": "ca2-testcase0000000002",
        "case_name": "resume-case",
        "chain": "ethereum",
        "address": "0x" + "22" * 20,
        "incident_block": 32,
        "cutoff_status": "PARTIAL",
        "prediction_cutoff_block": pd.NA,
        "pilot_member": True,
    }

    queued = AcquisitionEvent.queued(case["case_id"], case["chain"], None, "runtime_code", "incident:32")
    waiting = queued.transition(AcquisitionStatus.WAITING_EXTERNAL)
    ledger.append(queued)
    ledger.append(waiting)

    def provider_factory(_case):
        return [FakeProvider("a", "operator-a"), FakeProvider("b", "operator-b")]

    def snapshot_acquirer(_case, *, providers, policy):
        return {
            "status": "PARTIAL",
            "blocked_reason": "missing_prediction_cutoff_block",
            "cell_results": {
                "runtime_code": {"status": "VERIFIED", "block_selector": "incident:32"},
                "source_locator": {"status": "WAITING_EXTERNAL", "block_selector": "source"},
                "creation_locator": {"status": "WAITING_EXTERNAL", "block_selector": "creation"},
            },
        }

    result = acquire_queue(
        pd.DataFrame([case]),
        {"global_concurrency": 1, "per_provider_concurrency": 1},
        registry=registry,
        ledger=ledger,
        execute=True,
        provider_factory=provider_factory,
        snapshot_acquirer=snapshot_acquirer,
    )

    assert result["results"][0]["status"] == "PARTIAL"
    methods = [(event.method, event.status.value) for event in ledger.events()]
    assert methods.count(("runtime_code", "WAITING_EXTERNAL")) == 1
    assert methods.count(("source_locator", "WAITING_EXTERNAL")) == 1
    assert methods.count(("creation_locator", "WAITING_EXTERNAL")) == 1


def test_acquire_queue_records_managed_provider_configuration_block_per_case(tmp_path: Path):
    registry = ProviderRegistry.from_mapping({"providers": []})
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    case = {
        "case_id": "ca2-managed-provider-block",
        "case_name": "managed-provider-block",
        "chain": "ethereum",
        "address": "0x" + "33" * 20,
        "incident_block": 64,
        "cutoff_status": "VERIFIED",
        "prediction_cutoff_block": 48,
        "deployment_verification_status": "VERIFIED",
        "prediction_cutoff_block_verification_status": "VERIFIED",
        "source_availability_verification_status": "VERIFIED",
        "incident_eligibility": True,
        "cutoff_lead_hours": 2.0,
    }
    second_case = {
        **case,
        "case_id": "ca2-managed-provider-block-second",
        "case_name": "managed-provider-block-second",
        "address": "0x" + "44" * 20,
        "incident_block": 96,
        "prediction_cutoff_block": 80,
    }

    result = acquire_queue(
        pd.DataFrame([case, second_case]),
        {"global_concurrency": 1, "per_provider_concurrency": 1},
        registry=registry,
        ledger=ledger,
        execute=True,
        env={"CHRONOS_ALCHEMY_API_KEY": "test-only-key"},
        artifact_root=tmp_path / "receipts",
    )

    assert result["status"] == "completed"
    assert len(result["results"]) == 2
    assert all(item["status"] == "WAITING_EXTERNAL" for item in result["results"])
    assert all(item["strict_snapshot_closed"] is False for item in result["results"])
    assert "test-only-key" not in repr(result)
    blocked = result["results"][0]
    assert blocked["status"] == "WAITING_EXTERNAL"
    assert blocked["strict_snapshot_closed"] is False
    assert blocked["blocked_reason"] == "missing_api_key"
    assert blocked["provider_configuration_error"] == {"code": "missing_api_key"}
    assert set(blocked["cell_results"]) == {
        "block_capability",
        "runtime_code",
        "eip1967_implementation_slot",
        "eip1967_beacon_slot",
        "eip1967_admin_slot",
        "beacon_implementation_call",
        "implementation_runtime_code",
        "source_locator",
        "creation_locator",
    }
    assert all(cell["status"] == "WAITING_EXTERNAL" for cell in blocked["cell_results"].values())
    assert all(cell["error_detail"] == "missing_api_key" for cell in blocked["cell_results"].values())

    events = ledger.events()
    assert len(events) == 36
    assert sum(event.status == AcquisitionStatus.VERIFIED for event in events) == 0
    assert sum(event.status == AcquisitionStatus.WAITING_EXTERNAL for event in events) == 18
    assert {event.error_detail for event in events if event.status == AcquisitionStatus.WAITING_EXTERNAL} == {
        "missing_api_key"
    }


def test_acquire_queue_continues_when_strict_snapshot_returns_blocked_partial(tmp_path: Path):
    registry = ProviderRegistry.from_mapping({"providers": []})
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    case = {
        "case_id": "ca2-blocked-strict-one",
        "case_name": "blocked-strict-one",
        "chain": "ethereum",
        "address": "0x" + "55" * 20,
        "incident_block": 64,
        "deployment_block": 40,
        "cutoff_status": "VERIFIED",
        "prediction_cutoff_block": 48,
        "deployment_verification_status": "VERIFIED",
        "prediction_cutoff_block_verification_status": "VERIFIED",
        "source_availability_verification_status": "VERIFIED",
        "incident_eligibility": True,
        "cutoff_lead_hours": 2.0,
    }
    second_case = {
        **case,
        "case_id": "ca2-blocked-strict-two",
        "case_name": "blocked-strict-two",
        "address": "0x" + "66" * 20,
    }

    def provider_factory(_case):
        return [FakeProvider("a", "operator-a"), FakeProvider("b", "operator-b")]

    def snapshot_acquirer(_case, *, providers, policy):
        return {
            "status": "PARTIAL",
            "strict_snapshot_closed": False,
            "blocked_reason": "deployment_header_no_independent_consensus",
            "cell_results": {
                "block_capability": {"status": "PARTIAL", "block_selector": f"incident:{_case['incident_block']}", "error_detail": "deployment_header_no_independent_consensus"},
                "runtime_code": {"status": "WAITING_EXTERNAL", "block_selector": f"prediction:{_case['prediction_cutoff_block']}", "error_detail": "deployment_header_no_independent_consensus"},
                "eip1967_implementation_slot": {"status": "WAITING_EXTERNAL", "block_selector": f"prediction:{_case['prediction_cutoff_block']}", "error_detail": "deployment_header_no_independent_consensus"},
            },
        }

    result = acquire_queue(
        pd.DataFrame([case, second_case]),
        {"global_concurrency": 1, "per_provider_concurrency": 1},
        registry=registry,
        ledger=ledger,
        execute=True,
        provider_factory=provider_factory,
        snapshot_acquirer=snapshot_acquirer,
    )

    assert result["status"] == "completed"
    assert len(result["results"]) == 2
    assert all(item["status"] == "PARTIAL" for item in result["results"])
    assert all(item["strict_snapshot_closed"] is False for item in result["results"])
    events = ledger.events()
    assert sum(event.status == AcquisitionStatus.VERIFIED for event in events) == 0
