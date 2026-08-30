from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.historical_snapshot_run import (
    discover_deployment_transition,
)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


class FakeProvider:
    def __init__(
        self,
        provider_id: str,
        provider_family: str,
        receipt_root: Path,
        *,
        public_endpoint_id: str | None = None,
        provider_identity_evidence: dict[str, Any] | None = None,
        headers: dict[int, dict[str, Any]] | None = None,
        codes: dict[int, str] | None = None,
        code_sequences: dict[int, list[str]] | None = None,
        header_error_blocks: set[int] | None = None,
        code_error_blocks: set[int] | None = None,
        tamper_response_for: set[tuple[str, int]] | None = None,
        noncanonical_response_for: set[tuple[str, int]] | None = None,
        url: str = "https://rpc.example.invalid/v1/secret-token",
    ) -> None:
        self.provider_id = provider_id
        self.provider_family = provider_family
        self.receipt_root = receipt_root
        self.public_endpoint_id = public_endpoint_id or f"identity-{provider_id}"
        self.provider_identity_evidence = provider_identity_evidence or {
            "provider_id": provider_id,
            "endpoint_template_sha256": hashlib.sha256(provider_id.encode("utf-8")).hexdigest(),
            "operator_evidence_url": f"https://operators.example/{provider_family}",
            "public_endpoint_template": "https://rpc.example.invalid/{api_key}",
        }
        self.headers = headers or {}
        self.codes = {int(block): str(code) for block, code in (codes or {}).items()}
        self.code_sequences = {int(block): list(values) for block, values in (code_sequences or {}).items()}
        self.header_error_blocks = {int(block) for block in (header_error_blocks or set())}
        self.code_error_blocks = {int(block) for block in (code_error_blocks or set())}
        self.tamper_response_for = set(tamper_response_for or set())
        self.noncanonical_response_for = set(noncanonical_response_for or set())
        self.url = url
        self.calls: list[tuple[str, Any]] = []

    def call(self, method: str, params: list[Any]) -> ProviderObservation:
        request_payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        request_sha = _sha256_json(request_payload)
        observed_at_utc = "2026-08-08T12:00:00Z"

        if method == "eth_getBlockByNumber":
            block_number = int(str(params[0]), 16)
            self.calls.append((method, block_number))
            if block_number in self.header_error_blocks:
                return ProviderObservation(
                    self.provider_id,
                    method,
                    params,
                    None,
                    1,
                    error="missing_header",
                    provider_family=self.provider_family,
                    request_sha256=request_sha,
                    response_sha256=None,
                    raw_response_path=None,
                    observed_at_utc=observed_at_utc,
                )
            result = self.headers[block_number]
            return self._observation(
                method,
                params,
                result,
                request_sha=request_sha,
                observed_at_utc=observed_at_utc,
                block_number=block_number,
            )

        if method == "eth_getCode":
            selector = params[1]
            if isinstance(selector, dict):
                block_hash = str(selector["blockHash"]).strip().lower()
                for known_block, header in self.headers.items():
                    if str(header["hash"]).strip().lower() == block_hash:
                        block_number = known_block
                        break
                else:  # pragma: no cover - defensive fixture guard
                    raise AssertionError(f"unknown block hash {block_hash}")
            else:
                block_number = int(str(selector), 16)
            self.calls.append((method, block_number))
            if block_number in self.code_error_blocks:
                return ProviderObservation(
                    self.provider_id,
                    method,
                    params,
                    None,
                    1,
                    error="missing_code",
                    provider_family=self.provider_family,
                    request_sha256=request_sha,
                    response_sha256=None,
                    raw_response_path=None,
                    observed_at_utc=observed_at_utc,
                )
            if block_number in self.code_sequences:
                sequence = self.code_sequences[block_number]
                result = sequence.pop(0) if len(sequence) > 1 else sequence[0]
            else:
                result = self.codes[block_number]
            return self._observation(
                method,
                params,
                result,
                request_sha=request_sha,
                observed_at_utc=observed_at_utc,
                block_number=block_number,
            )

        raise AssertionError(method)

    def _observation(
        self,
        method: str,
        params: list[Any],
        result: Any,
        *,
        request_sha: str,
        observed_at_utc: str,
        block_number: int,
    ) -> ProviderObservation:
        payload = {"jsonrpc": "2.0", "id": 1, "result": result}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        response_sha = hashlib.sha256(raw).hexdigest()
        path = self.receipt_root / response_sha[:2] / f"{response_sha}.json"
        if (method, block_number) in self.noncanonical_response_for:
            path = self.receipt_root / "alt" / f"{response_sha}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        if (method, block_number) in self.tamper_response_for:
            path.write_text("tampered", encoding="utf-8")
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
            observed_at_utc=observed_at_utc,
        )


def _case(*, incident_block: int = 10) -> dict[str, Any]:
    return {
        "case_id": "ca2-test-transition",
        "chain": "ethereum",
        "address": "0x" + "11" * 20,
        "incident_block": incident_block,
        "input_row_sha256": "a" * 64,
    }


def _identity(provider_id: str, family: str, *, complete: bool = True) -> dict[str, Any]:
    payload = {"provider_id": provider_id, "operator_evidence_url": f"https://operators.example/{family}"}
    if complete:
        payload["endpoint_template_sha256"] = hashlib.sha256(f"{provider_id}:{family}".encode("utf-8")).hexdigest()
    return payload


def _headers(limit: int, *, base_timestamp: int = 1_000) -> dict[int, dict[str, Any]]:
    return {
        block: {
            "number": hex(block),
            "hash": "0x" + f"{block + 1:064x}",
            "timestamp": hex(base_timestamp + block),
        }
        for block in range(limit + 1)
    }


def _providers_for_transition(
    receipt_root: Path,
    *,
    incident_block: int = 10,
    transition_block: int = 4,
    same_family: bool = False,
    identity_complete: bool = True,
    provider_b_codes: dict[int, str] | None = None,
    provider_b_header_error_blocks: set[int] | None = None,
    provider_b_code_error_blocks: set[int] | None = None,
    provider_b_tamper: set[tuple[str, int]] | None = None,
    provider_b_noncanonical: set[tuple[str, int]] | None = None,
    provider_a_code_sequences: dict[int, list[str]] | None = None,
    provider_a_url: str = "https://rpc.example.invalid/v1/secret-one",
    provider_b_url: str = "https://rpc.example.invalid/v1/secret-two",
) -> list[FakeProvider]:
    headers = _headers(incident_block)
    codes = {block: ("0x" if block < transition_block else "0x6000") for block in range(incident_block + 1)}
    provider_b_codes = provider_b_codes or dict(codes)
    family_b = "family-one" if same_family else "family-two"
    return [
        FakeProvider(
            "provider-a",
            "family-one",
            receipt_root,
            public_endpoint_id="identity-a",
            provider_identity_evidence=_identity("provider-a", "family-one", complete=identity_complete),
            headers=headers,
            codes=codes,
            code_sequences=provider_a_code_sequences,
            url=provider_a_url,
        ),
        FakeProvider(
            "provider-b",
            family_b,
            receipt_root,
            public_endpoint_id="identity-b",
            provider_identity_evidence=_identity("provider-b", family_b, complete=identity_complete),
            headers=headers,
            codes=provider_b_codes,
            header_error_blocks=provider_b_header_error_blocks,
            code_error_blocks=provider_b_code_error_blocks,
            tamper_response_for=provider_b_tamper,
            noncanonical_response_for=provider_b_noncanonical,
            url=provider_b_url,
        ),
    ]


def _remove_hashes(result: dict[str, Any]) -> dict[str, Any]:
    stripped = dict(result)
    stripped.pop("proof_sha256_without_self_hash", None)
    stripped.pop("proof_sha256", None)
    return stripped


def test_discover_deployment_transition_verifies_successful_boundary(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, transition_block=4)

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "VERIFIED", result
    assert result["candidate_block"] == 4
    assert result["candidate_timestamp"] == 1_004
    assert result["blockers"] == []
    assert result["search"]["candidate_block"] == 4
    assert result["search"]["calls_used"] >= 3
    assert result["proof"]["headers"]["candidate"]["value"]["hash"] == "0x" + f"{5:064x}"
    assert result["proof"]["code"]["previous"]["value"] == "0x"
    assert result["proof"]["code"]["candidate"]["value"] == "0x6000"
    assert result["provider_identity"]["complete"] is True
    assert result["proof_sha256_without_self_hash"] == _sha256_json(_remove_hashes(result))
    payload = _remove_hashes(result)
    payload["proof_sha256_without_self_hash"] = result["proof_sha256_without_self_hash"]
    assert result["proof_sha256"] == _sha256_json(payload)


def test_discover_deployment_transition_handles_exact_incident_boundary(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, incident_block=6, transition_block=6)

    result = discover_deployment_transition(_case(incident_block=6), providers, tmp_path)

    assert result["status"] == "VERIFIED"
    assert result["candidate_block"] == 6
    assert result["proof"]["code"]["candidate"]["value"] == "0x6000"


def test_discover_deployment_transition_falls_back_when_genesis_code_is_unavailable(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, incident_block=64, transition_block=33)
    for provider in providers:
        provider.code_error_blocks.add(0)

    result = discover_deployment_transition(_case(incident_block=64), providers, tmp_path)

    assert result["status"] == "VERIFIED", result
    assert result["candidate_block"] == 33
    assert result["blockers"] == []
    assert all(observation["error"] in (None, "") for observation in result["search"]["observations"])
    assert result["search"]["optional_unbound_probe_failures"] == [
        {
            "method": "eth_getCode",
            "provider_id": "provider-a",
            "search_block_number": 0,
            "status": "receipt_unavailable",
        }
    ]


def test_discover_deployment_transition_requires_distinct_families(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, same_family=True)

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "same_family" in result["blockers"]
    assert result["candidate_block"] == 4


def test_discover_deployment_transition_requires_complete_identity(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, identity_complete=False)

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "incomplete_identity" in result["blockers"]


def test_discover_deployment_transition_blocks_when_fork_code_is_empty(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, transition_block=11)

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert result["candidate_block"] is None
    assert "fork_code_empty" in result["blockers"]


def test_discover_deployment_transition_blocks_when_historical_header_is_missing(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, provider_b_header_error_blocks={3})

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "missing_historical_header" in result["blockers"]


def test_discover_deployment_transition_blocks_when_providers_disagree(tmp_path: Path) -> None:
    disagreeing_codes = {block: ("0x" if block < 4 else "0x7000") for block in range(11)}
    providers = _providers_for_transition(tmp_path, provider_b_codes=disagreeing_codes)

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "provider_disagreement" in result["blockers"]


def test_discover_deployment_transition_blocks_candidate_zero(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, transition_block=0)

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert result["candidate_block"] == 0
    assert "candidate0" in result["blockers"]


def test_discover_deployment_transition_respects_search_budget(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, incident_block=64, transition_block=33)

    result = discover_deployment_transition(_case(incident_block=64), providers, tmp_path, max_search_calls=2)

    assert result["status"] == "PARTIAL"
    assert "search_budget_exceeded" in result["blockers"]


def test_discover_deployment_transition_detects_tampered_receipt(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, provider_b_tamper={("eth_getCode", 4)})

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "receipt_hash_path_error" in result["blockers"]


def test_discover_deployment_transition_rejects_in_root_noncanonical_receipt_path(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, provider_b_noncanonical={("eth_getCode", 4)})

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "receipt_hash_path_error" in result["blockers"]


def test_discover_deployment_transition_blocks_when_historical_code_is_missing(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path, provider_b_code_error_blocks={4})

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "missing_historical_code" in result["blockers"]


def test_discover_deployment_transition_detects_ambiguous_discovery_observations(tmp_path: Path) -> None:
    providers = _providers_for_transition(
        tmp_path,
        provider_a_code_sequences={4: ["0x6000", "0x"]},
    )

    result = discover_deployment_transition(_case(), providers, tmp_path)

    assert result["status"] == "PARTIAL"
    assert "nonmonotonic_or_ambiguous_observations" in result["blockers"]


def test_discover_deployment_transition_omits_secrets_from_result(tmp_path: Path) -> None:
    providers = _providers_for_transition(tmp_path)

    result = discover_deployment_transition(_case(), providers, tmp_path)
    serialized = json.dumps(result, sort_keys=True)

    assert "secret-one" not in serialized
    assert "secret-two" not in serialized
    assert "secret-token" not in serialized
