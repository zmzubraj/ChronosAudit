from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.pilot import (
    apply_prespecified_pilot_replacement,
    build_postfreeze_pilot_amendment,
    first_block_at_or_after_timestamp,
    snapshot_state_cells,
    verify_cutoff_block_bracket,
    verify_snapshot_receipt_bindings,
)


def _load_pilot_runner():
    runner_path = Path(__file__).resolve().parents[1] / "run_evidence_grade_pilot.py"
    spec = importlib.util.spec_from_file_location("chronosaudit_evidence_grade_pilot_runner", runner_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256_json(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).hexdigest()


def _assert_runtime_hashes_sealed(snapshot: dict[str, object]) -> None:
    artifact_without_self = dict(snapshot)
    artifact_without_self.pop("strict_snapshot_validation", None)
    artifact_without_self.pop("artifact_sha256_without_self_hash", None)
    artifact_without_self.pop("artifact_sha256", None)
    assert snapshot["artifact_sha256_without_self_hash"] == _sha256_json(artifact_without_self)
    artifact_with_inner = dict(artifact_without_self)
    artifact_with_inner["artifact_sha256_without_self_hash"] = snapshot["artifact_sha256_without_self_hash"]
    assert snapshot["artifact_sha256"] == _sha256_json(artifact_with_inner)


def test_postfreeze_amendment_preserves_base_and_adds_one_arbitrum_case() -> None:
    base = pd.DataFrame(
        [
            {"case_id": f"base-{index}", "case_name": f"case-{index}", "chain": chain, "pilot_member": True}
            for index, chain in enumerate(
                ["ethereum", "ethereum", "ethereum", "bsc", "bsc", "bsc", "base", "base", "arbitrum"]
            )
        ]
    )
    candidates = pd.DataFrame(
        [
            {
                "case_id": "supp-treasure",
                "case_name": "treasuredao",
                "chain": "arbitrum",
                "address": "0x" + "11" * 20,
                "incident_block": 7_322_695,
                "prediction_cutoff_block": 5_300_000,
                "exploit_tx_hash": "0x" + "22" * 32,
                "candidate_source_sha256": "a" * 64,
                "eligibility_status": "VERIFIED",
            },
            {
                "case_id": "supp-ineligible",
                "case_name": "ineligible",
                "chain": "arbitrum",
                "address": "0x" + "33" * 20,
                "incident_block": 8_000_000,
                "prediction_cutoff_block": pd.NA,
                "exploit_tx_hash": "",
                "candidate_source_sha256": "b" * 64,
                "eligibility_status": "PARTIAL",
            },
        ]
    )

    amended, audit = build_postfreeze_pilot_amendment(
        base,
        candidates,
        seed="frozen-seed",
        base_manifest_sha256="c" * 64,
        amendment_id="pilot-amendment-a1",
    )

    assert len(amended) == 10
    assert amended["chain"].value_counts().to_dict() == {"ethereum": 3, "bsc": 3, "base": 2, "arbitrum": 2}
    assert amended.loc[amended["case_id"].eq("supp-treasure"), "program_case"].eq(False).all()
    assert amended.loc[amended["case_id"].str.startswith("base-"), "program_case"].eq(True).all()
    assert audit["selection_observed_provider_results"] is False
    assert audit["original_shortfall_preserved"] is True
    assert audit["selected_case_id"] == "supp-treasure"


def test_postfreeze_amendment_refuses_non_arbitrum_or_unverified_candidate() -> None:
    base = pd.DataFrame(
        [{"case_id": f"base-{index}", "case_name": f"case-{index}", "chain": "ethereum", "pilot_member": True} for index in range(9)]
    )
    candidates = pd.DataFrame(
        [
            {
                "case_id": "bad",
                "case_name": "bad",
                "chain": "base",
                "address": "0x" + "11" * 20,
                "incident_block": 1,
                "prediction_cutoff_block": 1,
                "exploit_tx_hash": "0x" + "22" * 32,
                "candidate_source_sha256": "a" * 64,
                "eligibility_status": "VERIFIED",
            }
        ]
    )

    with pytest.raises(ValueError, match="eligible Arbitrum supplement"):
        build_postfreeze_pilot_amendment(
            base,
            candidates,
            seed="frozen-seed",
            base_manifest_sha256="c" * 64,
            amendment_id="pilot-amendment-a1",
        )


def test_prespecified_replacement_removes_only_failed_case_and_records_outcome_blind_selection() -> None:
    pilot = pd.DataFrame(
        [
            {
                "case_id": f"case-{index}",
                "case_name": name,
                "chain": chain,
                "program_case": name != "treasuredao",
                "pilot_member": True,
            }
            for index, (name, chain) in enumerate(
                [
                    ("eth-one", "ethereum"),
                    ("eth-two", "ethereum"),
                    ("eth-three", "ethereum"),
                    ("bsc-one", "bsc"),
                    ("bsc-two", "bsc"),
                    ("bsc-three", "bsc"),
                    ("base-one", "base"),
                    ("leetswap", "base"),
                    ("arb-one", "arbitrum"),
                    ("treasuredao", "arbitrum"),
                ]
            )
        ]
    )
    replacement = {
        "case_id": "replacement-paribus-2025",
        "case_name": "paribus",
        "chain": "arbitrum",
        "address": "0x" + "11" * 20,
        "incident_block": 296_699_666,
        "prediction_cutoff_block": 96_328_740,
        "exploit_tx_hash": "0x" + "22" * 32,
        "candidate_source_sha256": "a" * 64,
        "eligibility_status": "VERIFIED",
    }

    amended, audit = apply_prespecified_pilot_replacement(
        pilot,
        replacement,
        failed_case_name="leetswap",
        failure_reason="insufficient_incident_lead_time",
        seed="replacement-seed",
        amendment_id="pilot-amendment-a2",
        parent_manifest_sha256="b" * 64,
    )

    assert len(amended) == 10
    assert "leetswap" not in set(amended["case_name"])
    assert "paribus" in set(amended["case_name"])
    assert amended["chain"].value_counts().to_dict() == {
        "ethereum": 3,
        "bsc": 3,
        "arbitrum": 3,
        "base": 1,
    }
    selected = amended.loc[amended["case_name"].eq("paribus")].iloc[0]
    assert selected["program_case"] is False or not bool(selected["program_case"])
    assert selected["pilot_selection_origin"] == "prespecified_protocol_replacement"
    assert audit["selection_observed_replacement_provider_results"] is False
    assert audit["replacement_trigger"] == "insufficient_incident_lead_time"
    assert audit["replaced_case_name"] == "leetswap"
    assert audit["selected_case_id"] == "replacement-paribus-2025"


def test_arbitrum_infura_override_is_secret_safe_and_keeps_independent_second_family(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _load_pilot_runner()
    secret_endpoint = "https://arbitrum-mainnet.infura.io/v3/test-secret"
    monkeypatch.setenv("CHRONOS_INFURA_ARBITRUM_URL", secret_endpoint)
    config = {
        "providers": {
            "arbitrum": {
                "sentio": "https://arbitrum-one.rpc.sentio.xyz",
                "alchemy-blast": "https://arbitrum-one.public.blastapi.io",
            }
        }
    }

    providers = runner._providers(config, "arbitrum", tmp_path)

    assert [(provider.provider_id, provider.provider_family) for provider in providers] == [
        ("infura-arbitrum", "infura"),
        ("blast-arbitrum", "alchemy-blast"),
    ]
    assert providers[0].url == secret_endpoint
    assert all("test-secret" not in provider.provider_id for provider in providers)


def test_infura_override_rejects_wrong_endpoint_without_disclosing_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _load_pilot_runner()
    monkeypatch.setenv("CHRONOS_INFURA_ARBITRUM_URL", "https://example.invalid/v3/do-not-print")
    config = {
        "providers": {
            "arbitrum": {
                "sentio": "https://arbitrum-one.rpc.sentio.xyz",
                "alchemy-blast": "https://arbitrum-one.public.blastapi.io",
            }
        }
    }

    with pytest.raises(ValueError, match="invalid CHRONOS_INFURA_ARBITRUM_URL") as error:
        runner._providers(config, "arbitrum", tmp_path)
    assert "do-not-print" not in str(error.value)


def test_arbitrum_alchemy_override_is_secret_safe_and_independent_from_infura(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _load_pilot_runner()
    infura_endpoint = "https://arbitrum-mainnet.infura.io/v3/test-infura-secret"
    alchemy_endpoint = "https://arb-mainnet.g.alchemy.com/v2/test-alchemy-secret"
    monkeypatch.setenv("CHRONOS_INFURA_ARBITRUM_URL", infura_endpoint)
    monkeypatch.setenv("CHRONOS_ALCHEMY_ARBITRUM_URL", alchemy_endpoint)
    config = {
        "providers": {
            "arbitrum": {
                "sentio": "https://arbitrum-one.rpc.sentio.xyz",
                "alchemy-blast": "https://arbitrum-one.public.blastapi.io",
            }
        }
    }

    providers = runner._providers(config, "arbitrum", tmp_path)

    assert [(provider.provider_id, provider.provider_family) for provider in providers] == [
        ("infura-arbitrum", "infura"),
        ("alchemy-arbitrum", "alchemy"),
    ]
    assert providers[0].url == infura_endpoint
    assert providers[1].url == alchemy_endpoint
    assert all("secret" not in provider.provider_id for provider in providers)


def test_alchemy_override_rejects_wrong_endpoint_without_disclosing_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _load_pilot_runner()
    monkeypatch.setenv("CHRONOS_ALCHEMY_ARBITRUM_URL", "https://example.invalid/v2/do-not-print")
    config = {
        "providers": {
            "arbitrum": {
                "sentio": "https://arbitrum-one.rpc.sentio.xyz",
                "alchemy-blast": "https://arbitrum-one.public.blastapi.io",
            }
        }
    }

    with pytest.raises(ValueError, match="invalid CHRONOS_ALCHEMY_ARBITRUM_URL") as error:
        runner._providers(config, "arbitrum", tmp_path)
    assert "do-not-print" not in str(error.value)


def test_snapshot_receipt_binding_requires_two_distinct_families_and_hashes(tmp_path: Path) -> None:
    params = ["0x" + "11" * 20, {"blockHash": "0x" + "ab" * 32, "requireCanonical": True}]
    response = {"jsonrpc": "2.0", "id": 1, "result": "0x6000"}
    raw = json.dumps(response, separators=(",", ":")).encode()
    response_sha = hashlib.sha256(raw).hexdigest()
    raw_path = tmp_path / f"{response_sha}.json"
    raw_path.write_bytes(raw)
    request_sha = hashlib.sha256(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": params}, separators=(",", ":")).encode()
    ).hexdigest()

    observations = [
        {
            "provider_id": "one",
            "provider_family": "family-one",
            "method": "eth_getCode",
            "params": params,
            "result": "0x6000",
            "error": None,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
            "raw_response_path": str(raw_path),
        },
        {
            "provider_id": "two",
            "provider_family": "family-two",
            "method": "eth_getCode",
            "params": params,
            "result": "0x6000",
            "error": None,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
            "raw_response_path": str(raw_path),
        },
    ]

    verified = verify_snapshot_receipt_bindings(
        {"runtime_code": {"status": "consensus", "value": "0x6000", "observations": observations}},
        required_cells=("runtime_code",),
        allowed_root=tmp_path,
    )
    assert verified["complete"] is True
    assert verified["cells"]["runtime_code"]["provider_families"] == ["family-one", "family-two"]

    observations[1]["provider_family"] = "family-one"
    rejected = verify_snapshot_receipt_bindings(
        {"runtime_code": {"status": "consensus", "value": "0x6000", "observations": observations}},
        required_cells=("runtime_code",),
        allowed_root=tmp_path,
    )
    assert rejected["complete"] is False
    assert "insufficient_independent_provider_families" in rejected["cells"]["runtime_code"]["errors"]


def test_snapshot_receipt_binding_derives_block_capability_selector_from_block_number(tmp_path: Path) -> None:
    params = ["0x10", False]
    result = {"hash": "0x" + "ab" * 32, "number": "0x10"}
    response = {"jsonrpc": "2.0", "id": 1, "result": result}
    raw = json.dumps(response, separators=(",", ":")).encode()
    response_sha = hashlib.sha256(raw).hexdigest()
    raw_path = tmp_path / f"{response_sha}.json"
    raw_path.write_bytes(raw)
    request_sha = hashlib.sha256(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber", "params": params}, separators=(",", ":")).encode()
    ).hexdigest()
    observations = [
        {
            "provider_id": "one",
            "provider_family": "family-one",
            "method": "eth_getBlockByNumber",
            "params": params,
            "result": result,
            "error": None,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
            "raw_response_path": str(raw_path),
        },
        {
            "provider_id": "two",
            "provider_family": "family-two",
            "method": "eth_getBlockByNumber",
            "params": params,
            "result": result,
            "error": None,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
            "raw_response_path": str(raw_path),
        },
    ]

    verified = verify_snapshot_receipt_bindings(
        {"block_capability": {"status": "consensus", "value": result, "observations": observations}},
        required_cells=("block_capability",),
        allowed_root=tmp_path,
    )

    assert verified["complete"] is True
    assert verified["cells"]["block_capability"]["errors"] == []


class _FakeProvider:
    def __init__(self, provider_id: str, provider_family: str, timestamps: dict[int, int], tmp_path: Path):
        self.provider_id = provider_id
        self.provider_family = provider_family
        self.timestamps = timestamps
        self.tmp_path = tmp_path

    def call(self, method: str, params: list[object]):
        from chronosaudit_stage2.onchain import ProviderObservation

        block = int(str(params[0]), 16)
        result = {"number": hex(block), "hash": "0x" + f"{block:064x}", "timestamp": hex(self.timestamps[block])}
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}, separators=(",", ":")).encode()
        response_sha = hashlib.sha256(raw).hexdigest()
        path = self.tmp_path / f"{response_sha}.json"
        path.write_bytes(raw)
        request_sha = _sha256_json({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        return ProviderObservation(
            self.provider_id,
            method,
            params,
            result,
            1,
            provider_family=self.provider_family,
            request_sha256=request_sha,
            response_sha256=response_sha,
            raw_response_path=str(path),
        )


def test_timestamp_landmark_and_two_family_bracket(tmp_path: Path) -> None:
    timestamps = {number: 1_000 + number * 10 for number in range(1, 11)}
    one = _FakeProvider("one", "family-one", timestamps, tmp_path)
    two = _FakeProvider("two", "family-two", timestamps, tmp_path)

    landmark = first_block_at_or_after_timestamp(
        one,
        target_timestamp=1_055,
        lower_block=1,
        upper_block=10,
    )
    assert landmark["previous_block"]["number"] == 5
    assert landmark["cutoff_block"]["number"] == 6

    verified = verify_cutoff_block_bracket(
        [one, two],
        target_timestamp=1_055,
        previous_block_number=5,
        cutoff_block_number=6,
    )
    assert verified["status"] == "VERIFIED"
    assert verified["cutoff"]["agreement_provider_families"] == ["family-one", "family-two"]


def test_snapshot_cells_resolve_minimal_proxy_target(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, list[object]]] = []

    def fake_consensus(providers, method, params, normalizer, **kwargs):
        calls.append((method, params))
        return {"status": "consensus", "value": "0x6000", "observations": []}

    monkeypatch.setattr("chronosaudit_stage2.public_acquisition.pilot.provider_consensus", fake_consensus)
    base = {"status": "consensus", "value": None, "observations": []}
    snapshot = {
        "block": base,
        "code": base,
        "implementation": base,
        "beacon": base,
        "admin": base,
        "beacon_implementation": {"status": "not_applicable", "value": None, "observations": []},
        "eip1167_target": "0x" + "12" * 20,
        "canonical_block_hash": "0x" + "ab" * 32,
    }
    cells = snapshot_state_cells(snapshot, providers=[])
    assert cells["implementation_runtime_code"]["status"] == "consensus"
    assert calls[0][0] == "eth_getCode"
    assert calls[0][1][0] == "0x" + "12" * 20


def test_run_case_blocks_missing_deployment_block_without_exception(tmp_path: Path) -> None:
    runner = _load_pilot_runner()
    result = runner._run_case(
        {
            "case_id": "pilot-missing-deployment-block",
            "case_name": "pilot-missing-deployment-block",
            "chain": "ethereum",
            "address": "0x" + "11" * 20,
            "incident_block": 250,
            "deployment_block": None,
        },
        config={"cutoff_policy": {"rule": "deployment_timestamp_plus_24h", "primary_landmark_hours": 24, "minimum_incident_lead_hours": 1.0}},
        provider_identity_verification={"complete": True, "families": []},
        receipt_root=tmp_path / "receipts",
    )

    assert result["strict_snapshot_closed"] is False
    assert result["blocked_reason"] == "missing_deployment_block"
    assert "missing_deployment_block" in result["blockers"]
    assert result["strict_snapshot_validation"]["ok"] is False
    _assert_runtime_hashes_sealed(result)


def test_run_continues_after_blocked_deployment_cases_and_records_zero_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_pilot_runner()
    amended = pd.DataFrame(
        [
            {
                "case_id": "pilot-blocked-one",
                "case_name": "pilot-blocked-one",
                "chain": "ethereum",
                "address": "0x" + "11" * 20,
                "incident_block": 250,
                "deployment_block": None,
                "pilot_member": True,
            },
            {
                "case_id": "pilot-blocked-two",
                "case_name": "pilot-blocked-two",
                "chain": "ethereum",
                "address": "0x" + "22" * 20,
                "incident_block": 350,
                "deployment_block": None,
                "pilot_member": True,
            },
        ]
    )
    config = {
        "amendment_id": "pilot-amendment-test",
        "cutoff_policy": {
            "rule": "deployment_timestamp_plus_24h",
            "primary_landmark_hours": 24,
            "minimum_incident_lead_hours": 1.0,
        },
    }

    monkeypatch.setattr(runner, "_load_config", lambda path: config)
    monkeypatch.setattr(runner, "_verify_provider_identity", lambda cfg: {"complete": True, "families": []})
    monkeypatch.setattr(runner, "_load_amended_pilot", lambda cfg: (amended, {"amendment_id": cfg["amendment_id"]}))

    report = runner.run(
        tmp_path / "pilot-config.yaml",
        tmp_path / "run",
        tmp_path / "raw",
        tmp_path / "processed",
    )

    assert report["status"] == "partial"
    assert report["cases_attempted"] == 2
    assert report["strict_snapshots_closed"] == 0
    assert len(report["cases"]) == 2
