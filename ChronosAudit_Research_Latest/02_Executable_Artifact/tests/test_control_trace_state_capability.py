from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml
import preflight_stage2_control_trace_state_capability as capability_preflight

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_trace_state_capability import (
    ControlTraceStateCapabilityError,
    assess_trace_state_capability,
    verify_trace_state_capability,
)
from preflight_stage2_control_trace_state_capability import (
    _assess_provider_readiness,
    _failure_report,
    _failure_verification,
    _verified_scope_chains,
)


BLOCK_HASH = "0x" + "aa" * 32
TRANSACTION_HASH = "0x" + "bb" * 32
CREATED_ADDRESS = "0x" + "22" * 20
CREATOR_ADDRESS = "0x" + "11" * 20
ZERO_SLOT = "0x" + "00" * 32


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


class CapabilityProvider:
    def __init__(
        self,
        provider_id: str,
        family: str,
        backend: str,
        *,
        created_address: str | None = CREATED_ADDRESS,
        chain_id: str = "0x1",
    ) -> None:
        self.provider_id = provider_id
        self.provider_family = family
        self.chain = "ethereum"
        self.backend = backend
        self.created_address = created_address
        self.chain_id = chain_id

    def _observation(self, method: str, params: list[object], result: object,
                     error: str | None = None) -> ProviderObservation:
        return ProviderObservation(
            provider_id=self.provider_id,
            method=method,
            params=params,
            result=result,
            observed_at_unix=1,
            error=error,
            response_sha256="f" * 64,
            provider_family=self.provider_family,
            request_sha256="e" * 64,
            observed_at_utc="2026-08-21T00:00:00Z",
        )

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        if method == "eth_chainId":
            return self._observation(method, params, self.chain_id)
        if method in {"eth_getBlockByNumber", "eth_getBlockByHash"}:
            return self._observation(
                method,
                params,
                {"number": "0xa", "hash": BLOCK_HASH, "timestamp": "0x64"},
            )
        if method == "eth_getTransactionReceipt":
            return self._observation(
                method,
                params,
                {
                    "transactionHash": TRANSACTION_HASH,
                    "blockNumber": "0xa",
                    "blockHash": BLOCK_HASH,
                    "contractAddress": None,
                },
            )
        if method == "trace_transaction" and self.backend == "parity":
            rows = []
            if self.created_address is not None:
                rows = [{
                    "type": "create",
                    "transactionHash": TRANSACTION_HASH,
                    "traceAddress": [0],
                    "action": {
                        "from": CREATOR_ADDRESS,
                        "creationMethod": "create2",
                    },
                    "result": {"address": self.created_address},
                }]
            return self._observation(method, params, rows)
        if method == "trace_transaction":
            return self._observation(method, params, None, "unsupported")
        if method == "debug_traceTransaction" and self.backend == "geth":
            calls = []
            if self.created_address is not None:
                calls = [{
                    "type": "CREATE2",
                    "from": CREATOR_ADDRESS,
                    "to": self.created_address,
                }]
            return self._observation(method, params, {"type": "CALL", "calls": calls})
        if method == "debug_traceTransaction":
            return self._observation(method, params, None, "unsupported")
        if method == "eth_getCode":
            return self._observation(method, params, "0x6000")
        if method == "eth_getStorageAt":
            return self._observation(method, params, ZERO_SLOT)
        return self._observation(method, params, None, "unexpected_method")


class BlockMismatchProvider(CapabilityProvider):
    def call(self, method: str, params: list[object]) -> ProviderObservation:
        observation = super().call(method, params)
        if method == "eth_getBlockByHash" and observation.error is None:
            return self._observation(
                method,
                params,
                {"number": "0xa", "hash": "0x" + "cc" * 32, "timestamp": "0x64"},
            )
        return observation


class CodeErrorProvider(CapabilityProvider):
    def call(self, method: str, params: list[object]) -> ProviderObservation:
        if method == "eth_getCode":
            return self._observation(method, params, None, "archive_state_unavailable")
        return super().call(method, params)


def fixture() -> dict[str, object]:
    return {
        "chain": "ethereum",
        "chain_id": "0x1",
        "block_number": 10,
        "block_hash": BLOCK_HASH,
        "transaction_hash": TRANSACTION_HASH,
        "created_address": CREATED_ADDRESS,
    }


def providers() -> list[CapabilityProvider]:
    return [
        CapabilityProvider("provider-a", "family-a", "parity"),
        CapabilityProvider("provider-b", "family-b", "geth"),
    ]


def test_capability_requires_two_families_and_known_creation(tmp_path: Path):
    result = assess_trace_state_capability(
        fixtures=[fixture()],
        providers=providers(),
        raw_root=tmp_path / "raw",
    )
    assert result["complete"] is True
    assert result["selection_authorized"] is False
    assert result["stage_promotion_authorized"] is False
    assert result["recovery3_mutation_authorized"] is False
    assert result["rpc_authorized"] is False
    assert result["chains"][0]["known_creation_recovered_by_both"] is True
    assert result["chains"][0]["verified_operator_families"] == [
        "family-a",
        "family-b",
    ]
    assert result["raw_evidence_count"] > 0
    assert not any(
        row["method"] == "eth_call" for row in result["raw_evidence"]
    )


def test_empty_trace_does_not_establish_capability(tmp_path: Path):
    empty = [
        CapabilityProvider("provider-a", "family-a", "parity", created_address=None),
        CapabilityProvider("provider-b", "family-b", "geth", created_address=None),
    ]
    with pytest.raises(ControlTraceStateCapabilityError, match="known_creation_missing"):
        assess_trace_state_capability(
            fixtures=[fixture()],
            providers=empty,
            raw_root=tmp_path / "raw",
        )


def test_same_operator_family_does_not_establish_capability(tmp_path: Path):
    same_family = [
        CapabilityProvider("provider-a", "shared", "parity"),
        CapabilityProvider("provider-b", "shared", "geth"),
    ]
    with pytest.raises(ControlTraceStateCapabilityError, match="provider_family_independence"):
        assess_trace_state_capability(
            fixtures=[fixture()],
            providers=same_family,
            raw_root=tmp_path / "raw",
        )


def test_chain_mismatch_fails_closed(tmp_path: Path):
    mismatched = providers()
    mismatched[1].chain_id = "0x38"
    with pytest.raises(ControlTraceStateCapabilityError, match="chain_id_mismatch"):
        assess_trace_state_capability(
            fixtures=[fixture()],
            providers=mismatched,
            raw_root=tmp_path / "raw",
        )


def test_historical_block_disagreement_fails_closed(tmp_path: Path):
    mismatched = [
        CapabilityProvider("provider-a", "family-a", "parity"),
        BlockMismatchProvider("provider-b", "family-b", "geth"),
    ]
    with pytest.raises(ControlTraceStateCapabilityError, match="historical_block_mismatch"):
        assess_trace_state_capability(
            fixtures=[fixture()],
            providers=mismatched,
            raw_root=tmp_path / "raw",
        )


def test_exhaustive_diagnostic_preserves_partial_provider_evidence(
    tmp_path: Path,
) -> None:
    failing = BlockMismatchProvider("provider-a", "family-a", "parity")
    passing = CapabilityProvider("provider-b", "family-b", "geth")

    report = assess_trace_state_capability(
        fixtures=[fixture()],
        providers=[failing, passing],
        raw_root=tmp_path / "raw",
        exhaustive_failures=True,
    )

    assert report["complete"] is False
    assert report["selection_authorized"] is False
    assert report["stage_promotion_authorized"] is False
    assert report["recovery3_mutation_authorized"] is False
    chain = report["chains"][0]
    assert chain["complete"] is False
    assert chain["provider_count"] == 2
    by_id = {row["provider_id"]: row for row in chain["providers"]}
    assert by_id["provider-a"]["complete"] is False
    assert by_id["provider-a"]["errors"] == ["historical_block_mismatch"]
    assert by_id["provider-b"]["known_creation_recovered"] is True
    assert any(
        row["provider_id"] == "provider-b" for row in report["raw_evidence"]
    )
    assert report["errors"] == [
        "ethereum:provider-a:historical_block_mismatch"
    ]


def test_historical_state_error_is_not_normalized_to_unknown(tmp_path: Path):
    errored = [
        CapabilityProvider("provider-a", "family-a", "parity"),
        CodeErrorProvider("provider-b", "family-b", "geth"),
    ]
    with pytest.raises(ControlTraceStateCapabilityError, match="rpc_error:eth_getCode"):
        assess_trace_state_capability(
            fixtures=[fixture()],
            providers=errored,
            raw_root=tmp_path / "raw",
        )


def test_verifier_rehashes_raw_evidence(tmp_path: Path):
    raw_root = tmp_path / "raw"
    report = assess_trace_state_capability(
        fixtures=[fixture()],
        providers=providers(),
        raw_root=raw_root,
    )
    report_path = tmp_path / "capability.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    verified = verify_trace_state_capability(
        report_path=report_path,
        raw_root=raw_root,
    )
    assert verified["complete"] is True
    assert verified["report_sha256"] == report["report_sha256"]

    first_path = raw_root / report["raw_evidence"][0]["path"]
    first_path.write_text("{}", encoding="utf-8")
    with pytest.raises(ControlTraceStateCapabilityError, match="raw_evidence_hash_mismatch"):
        verify_trace_state_capability(report_path=report_path, raw_root=raw_root)


def test_capability_cli_is_non_authorizing_and_exposes_only_preflight_inputs():
    script = Path(__file__).resolve().parents[1] / "preflight_stage2_control_trace_state_capability.py"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--fixtures" in result.stdout
    assert "--raw-root" in result.stdout
    assert "--output-report" in result.stdout
    assert "--selection" not in result.stdout
    assert "--qualification" not in result.stdout


def test_preflight_accepts_verified_identity_superset_for_fixture_scope(tmp_path: Path):
    identity = {
        "chains": [
            {"chain": "arbitrum"},
            {"chain": "base"},
            {"chain": "bsc"},
            {"chain": "ethereum"},
        ]
    }
    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    assert _verified_scope_chains(
        fixtures=[
            {"chain": "base"},
            {"chain": "bsc"},
            {"chain": "ethereum"},
        ],
        provider_identity_verification_path=identity_path,
    ) == ["arbitrum", "base", "bsc", "ethereum"]


def test_preflight_failure_artifacts_are_self_hashed_and_non_authorizing(
    tmp_path: Path,
):
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    raw = raw_root / "00001-provider-trace-response.json"
    raw.write_text('{"error":"unsupported"}\n', encoding="utf-8")
    report = _failure_report(
        error="trace_method_unsupported",
        fixtures=[{"chain": "base"}],
        raw_root=raw_root,
    )
    assert report["complete"] is False
    assert report["rpc_authorized"] is False
    assert report["selection_authorized"] is False
    assert report["raw_evidence_count"] == 1
    assert report["report_sha256"] == _canonical_sha(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )

    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    verification = _failure_verification(
        report_path=report_path,
        report=report,
    )
    assert verification["complete"] is False
    assert verification["rpc_authorized"] is False
    assert verification["verification_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in verification.items()
            if key != "verification_sha256"
        }
    )


def test_preflight_accepts_self_hashed_legacy_alias_identity_projection(
    tmp_path: Path,
) -> None:
    providers = []
    identity_rows = []
    for provider_id, family in (("provider-a", "family-a"), ("provider-b", "family-b")):
        endpoint = f"https://{provider_id}.example"
        providers.append(
            {
                "provider_id": provider_id,
                "chain": "ethereum",
                "endpoint": endpoint,
                "operator_family": family,
                "operator_verified": True,
                "operator_evidence_url": f"https://docs.example/{provider_id}",
                "operator_evidence_sha256": "a" * 64,
                "tracking_enabled": True,
                "discovery_source": "test",
            }
        )
        identity_rows.append(
            {
                "provider_id": provider_id,
                "verified_operator_family": family,
                "identity_basis": "SIGNED_LOCAL_TEST_LEGACY_ALIAS_REVISION",
                "complete": True,
            }
        )
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        yaml.safe_dump({"schema_version": "historical_snapshot_provider_registry.v1", "providers": providers}),
        encoding="utf-8",
    )
    from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry

    registry = ProviderRegistry.from_path(registry_path)
    first_record = next(
        row for row in registry.providers if row.provider_id == "provider-a"
    )
    providers[0].pop("operator_evidence_url")
    providers[0].pop("operator_evidence_sha256")
    registry_path.write_text(
        yaml.safe_dump({"schema_version": "historical_snapshot_provider_registry.v1", "providers": providers}),
        encoding="utf-8",
    )
    identity_rows[0]["endpoint_template_sha256"] = (
        first_record.public_endpoint_id
    )
    identity = {
        "schema_version": "chronosaudit.control_provider_identity_legacy_alias_verification.v1",
        "decision": "LEGACY_ALIAS_PROVIDER_IDENTITY_VERIFIED_LOCAL_TEST_ONLY",
        "revision_request_sha256": "b" * 64,
        "chain_count": 1,
        "chains": [
            {
                "chain": "ethereum",
                "complete": True,
                "errors": [],
                "provider_count": 2,
                "providers": identity_rows,
                "verified_operator_families": ["family-a", "family-b"],
            }
        ],
        "complete": True,
        "errors": [],
        "provider_identity_verified": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
    }
    identity["report_sha256"] = _canonical_sha(identity)
    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    readiness = _assess_provider_readiness(
        provider_registry_path=registry_path,
        provider_identity_verification_path=identity_path,
        required_chains=["ethereum"],
    )

    assert readiness["blockers"] == []
    assert readiness["rpc_authorized"] is False
    assert readiness["chains"][0]["fully_matching_provider_ids"] == [
        "provider-a",
        "provider-b",
    ]


def test_provider_family_pacing_is_shared_across_same_family() -> None:
    clock = {"now": 0.0}
    sleeps: list[float] = []

    def monotonic() -> float:
        return clock["now"]

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["now"] += seconds

    class Provider:
        provider_family = "shared-family"
        chain = "ethereum"

        def __init__(self, provider_id: str) -> None:
            self.provider_id = provider_id
            self.calls = 0

        def call(self, method: str, params: list[object]) -> str:
            self.calls += 1
            return self.provider_id

    shared_state: dict[str, float] = {}
    first = capability_preflight._PacedProvider(
        Provider("first"),
        family_intervals={"shared-family": 2.5},
        family_last_started=shared_state,
        monotonic=monotonic,
        sleep=sleep,
    )
    second = capability_preflight._PacedProvider(
        Provider("second"),
        family_intervals={"shared-family": 2.5},
        family_last_started=shared_state,
        monotonic=monotonic,
        sleep=sleep,
    )

    assert first.call("eth_chainId", []) == "first"
    assert second.call("eth_chainId", []) == "second"
    assert sleeps == [2.5]


def test_provider_family_interval_parser_rejects_duplicates_and_invalid_values() -> None:
    assert capability_preflight._parse_family_intervals(
        ["merkle=3.2", "drpc=1"]
    ) == {"drpc": 1.0, "merkle": 3.2}
    with pytest.raises(ValueError, match="provider_family_interval_duplicate"):
        capability_preflight._parse_family_intervals(["merkle=1", "MERKLE=2"])
    with pytest.raises(ValueError, match="provider_family_interval_invalid"):
        capability_preflight._parse_family_intervals(["merkle=-1"])
