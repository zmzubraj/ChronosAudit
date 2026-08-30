import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from chronosaudit_stage2.public_acquisition.ledger import AppendOnlyLedger
from chronosaudit_stage2.public_acquisition.model import (
    AcquisitionEvent,
    AcquisitionStatus,
    canonical_json_sha256,
)
from chronosaudit_stage2.public_acquisition.providers import (
    ProviderRegistry,
    endpoint_id,
    redact_endpoint,
)

ROOT = Path(__file__).resolve().parents[1]


def test_secret_bearing_endpoint_is_redacted_and_stably_identified():
    raw = "https://rpc.example/v3/SECRET?apikey=TOPSECRET&x=1"
    assert redact_endpoint(raw) == "https://rpc.example/v3/<redacted>?apikey=<redacted>&x=1"
    assert endpoint_id(raw) == endpoint_id(raw)
    assert "SECRET" not in endpoint_id(raw)


def test_documented_nodereal_public_starter_key_is_not_redacted():
    endpoint = (
        "https://bsc-mainnet.nodereal.io/v1/"
        "64a9df0874fb4a93b9d0a3849de012d3"
    )

    assert redact_endpoint(endpoint) == endpoint


def test_registry_requires_distinct_verified_operator_families(tmp_path: Path):
    registry = ProviderRegistry.from_mapping(
        {
            "providers": [
                {
                    "provider_id": "a1",
                    "chain": "ethereum",
                    "operator_family": "operator-a",
                    "endpoint": "https://a/1",
                    "operator_evidence_url": "https://a/about",
                    "operator_evidence_sha256": "a" * 64,
                    "operator_verified": True,
                },
                {
                    "provider_id": "a2",
                    "chain": "ethereum",
                    "operator_family": "operator-a",
                    "endpoint": "https://a/2",
                    "operator_evidence_url": "https://a/about",
                    "operator_evidence_sha256": "a" * 64,
                    "operator_verified": True,
                },
            ]
        }
    )
    assert registry.independent_family_count("ethereum") == 1


def test_ledger_is_append_only_and_resumes_per_cell(tmp_path: Path):
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    event = AcquisitionEvent.queued("case-1", "ethereum", "provider-a", "eth_getCode", "0x10")
    ledger.append(event)
    ledger.append(event.transition(AcquisitionStatus.ATTEMPTED))
    assert ledger.resume_index()[event.cell_id] == AcquisitionStatus.ATTEMPTED
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) == 2


def test_attempted_and_partial_states_cannot_be_promoted_to_verified():
    queued = AcquisitionEvent.queued("case-1", "ethereum", "provider-a", "eth_getCode", "0x10")
    attempted = queued.transition(AcquisitionStatus.ATTEMPTED)
    partial = queued.transition(AcquisitionStatus.PARTIAL)
    with pytest.raises(ValueError):
        attempted.transition(AcquisitionStatus.VERIFIED)
    with pytest.raises(ValueError):
        partial.transition(AcquisitionStatus.VERIFIED)


def test_ledger_rejects_truncated_or_malformed_history(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text("{\"event_id\":", encoding="utf-8")
    with pytest.raises(ValueError):
        AppendOnlyLedger(path).resume_index()


def test_policy_file_matches_required_constants():
    policy = yaml.safe_load((ROOT / "config" / "public_acquisition_policy.yaml").read_text(encoding="utf-8"))
    assert policy == {
        "version": "1.0.0",
        "seed": "chronosaudit-public-pilot-v1-20260808",
        "pilot_allocation": {"ethereum": 3, "bsc": 3, "base": 2, "arbitrum": 2},
        "denominator_per_chain": 5000,
        "full_case_target": 417,
        "timeout_seconds": 20,
        "max_retries": 3,
        "max_response_bytes": 10485760,
        "global_concurrency": 4,
        "per_provider_concurrency": 1,
        "backoff_base_seconds": 0.5,
        "backoff_max_seconds": 30,
        "require_eip1898_for_strict_snapshot": True,
        "cutoff_policy": {
            "rule": "deployment_timestamp_plus_24h",
            "primary_landmark_hours": 24,
            "minimum_incident_lead_hours": 1.0,
        },
    }


def test_seed_registry_is_public_candidate_only_and_unverified():
    registry = ProviderRegistry.from_path(ROOT / "config" / "public_provider_registry.yaml")
    assert {provider.operator_family for provider in registry.providers_for_chain("ethereum")} == {"publicnode", "1rpc"}
    assert {provider.chain for provider in registry.providers} == {"ethereum", "bsc", "base", "arbitrum"}
    assert all(provider.operator_verified is False for provider in registry.providers)
    assert registry.providers_for_chain("ethereum", verified_only=True) == []
    assert registry.independent_family_count("ethereum") == 0


def test_written_events_are_schema_valid_and_hash_chained(tmp_path: Path):
    schema = json.loads((ROOT / "schemas" / "public_acquisition_event.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    queued = AcquisitionEvent.queued("case-1", "ethereum", "provider-a", "eth_getCode", "0x10")
    attempted = queued.transition(AcquisitionStatus.ATTEMPTED)

    ledger.append(queued)
    ledger.append(attempted)

    rows = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["previous_event_sha256"] == "0" * 64
    assert rows[1]["previous_event_sha256"] == rows[0]["event_sha256"]
    assert rows[0]["event_sha256"] == canonical_json_sha256({k: v for k, v in rows[0].items() if k != "event_sha256"})
    assert rows[1]["event_sha256"] == canonical_json_sha256({k: v for k, v in rows[1].items() if k != "event_sha256"})
    assert list(validator.iter_errors(rows[0])) == []
    assert list(validator.iter_errors(rows[1])) == []


def test_ledger_rejects_direct_illegal_persisted_transition_for_existing_cell(tmp_path: Path):
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    illegal_verified = AcquisitionEvent.create(
        case_id="case-1",
        chain="ethereum",
        provider_id="provider-a",
        method="eth_getCode",
        block_selector="0x10",
        status=AcquisitionStatus.VERIFIED,
    )

    with pytest.raises(ValueError, match="illegal acquisition status transition"):
        ledger.append(illegal_verified)


def test_ledger_rejects_direct_verified_shortcut_for_existing_cell(tmp_path: Path):
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    queued = AcquisitionEvent.queued("case-1", "ethereum", "provider-a", "eth_getCode", "0x10")
    illegal_verified = AcquisitionEvent.create(
        case_id="case-1",
        chain="ethereum",
        provider_id="provider-a",
        method="eth_getCode",
        block_selector="0x10",
        status=AcquisitionStatus.VERIFIED,
    )

    ledger.append(queued)
    with pytest.raises(ValueError, match="illegal acquisition status transition"):
        ledger.append(illegal_verified)


def test_ledger_read_rejects_hash_chained_but_per_cell_illegal_history(tmp_path: Path):
    ledger = AppendOnlyLedger(tmp_path / "events.jsonl")
    path = tmp_path / "events.jsonl"
    queued = AcquisitionEvent.queued("case-1", "ethereum", "provider-a", "eth_getCode", "0x10")
    illegal_verified = AcquisitionEvent.create(
        case_id="case-1",
        chain="ethereum",
        provider_id="provider-a",
        method="eth_getCode",
        block_selector="0x10",
        status=AcquisitionStatus.VERIFIED,
        previous_event_sha256=queued.event_sha256,
    )

    path.write_text(
        "\n".join(
            [
                json.dumps(queued.to_dict(), sort_keys=True, separators=(",", ":")),
                json.dumps(illegal_verified.to_dict(), sort_keys=True, separators=(",", ":")),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="illegal acquisition status transition"):
        ledger.events()
