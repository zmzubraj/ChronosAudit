from __future__ import annotations

import json
from dataclasses import dataclass

import yaml

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_candidate_rpc_capability import (
    assess_candidate_rpc_capability,
    verify_candidate_rpc_capability,
)


@dataclass
class FakeProvider:
    provider_id: str
    provider_family: str
    chain: str = "ethereum"

    def call(self, method, params):
        results = {
            "eth_chainId": "0x1",
            "eth_getTransactionReceipt": {
                "transactionHash": "0x" + "1" * 64,
                "blockHash": "0x" + "2" * 64,
                "blockNumber": "0x10",
            },
            "eth_getBlockByHash": {
                "hash": "0x" + "2" * 64,
                "number": "0x10",
                "timestamp": "0x20",
            },
        }
        return ProviderObservation(
            provider_id=self.provider_id,
            provider_family=self.provider_family,
            method=method,
            params=params,
            result=results[method],
            observed_at_unix=1,
            observed_at_utc="1970-01-01T00:00:01Z",
        )


def test_candidate_capability_is_hash_bound_and_non_authorizing(tmp_path):
    fixtures = [{
        "chain": "ethereum",
        "chain_id": "0x1",
        "transaction_hash": "0x" + "1" * 64,
        "block_hash": "0x" + "2" * 64,
        "block_number": 16,
    }]
    providers = [FakeProvider("alpha", "alpha"), FakeProvider("beta", "beta")]
    raw = tmp_path / "raw"
    report = assess_candidate_rpc_capability(
        fixtures=fixtures, providers=providers, raw_root=raw
    )
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(report), encoding="utf-8")
    registry_file = tmp_path / "registry.yaml"
    registry_providers = [
        {
            "provider_id": provider.provider_id,
            "chain": "ethereum",
            "endpoint": f"https://{provider.provider_id}.example/rpc",
            "operator_family": provider.provider_family,
            "tracking_enabled": True,
            "operator_verified": True,
        }
        for provider in providers
    ]
    registry_providers.append(
        {
            "provider_id": "unrelated-bsc-provider",
            "chain": "bsc",
            "endpoint": "https://bsc.example/rpc",
            "operator_family": "unrelated",
            "tracking_enabled": True,
            "operator_verified": True,
        }
    )
    registry_file.write_text(
        yaml.safe_dump({"providers": registry_providers}), encoding="utf-8"
    )

    verification = verify_candidate_rpc_capability(
        report_path=report_file,
        raw_root=raw,
        provider_registry_path=registry_file,
    )

    assert verification["complete"] is True
    assert verification["errors"] == []
    assert verification["rpc_authorized"] is False
    assert report["raw_evidence_count"] == 6
