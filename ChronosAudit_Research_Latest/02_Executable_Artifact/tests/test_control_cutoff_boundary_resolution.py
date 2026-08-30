from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition import control_cutoff_boundary_resolution as resolution_module
from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_resolution import (
    ControlCutoffBoundaryResolutionError,
    execute_cutoff_boundary_batch,
    resume_cutoff_boundary_batch,
    resolve_cutoff_boundary,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


class _Provider:
    def __init__(
        self,
        provider_id: str,
        family: str,
        *,
        hash_override: dict[int, str] | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.provider_family = family
        self.hash_override = hash_override or {}
        self.calls: list[int] = []

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        assert method == "eth_getBlockByNumber"
        number = int(str(params[0]), 16)
        self.calls.append(number)
        timestamp = 1_000 + number * 10
        block_hash = self.hash_override.get(number, "0x" + f"{number:064x}")
        return ProviderObservation(
            provider_id=self.provider_id,
            provider_family=self.provider_family,
            method=method,
            params=params,
            result={
                "number": hex(number),
                "hash": block_hash,
                "timestamp": hex(timestamp),
            },
            observed_at_unix=2_000,
            error=None,
        )


class _ErrorOnCallProvider(_Provider):
    def __init__(self, provider_id: str, family: str, *, fail_on_call: int) -> None:
        super().__init__(provider_id, family)
        self.fail_on_call = fail_on_call

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        if len(self.calls) + 1 == self.fail_on_call:
            number = int(str(params[0]), 16)
            self.calls.append(number)
            return ProviderObservation(
                provider_id=self.provider_id,
                provider_family=self.provider_family,
                method=method,
                params=params,
                result=None,
                observed_at_unix=2_000,
                error="temporary provider failure",
            )
        return super().call(method, params)


def _target() -> dict[str, object]:
    target: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirement.v1",
        "target_id": "cutoff-boundary:" + "1" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "cutoff_timestamp": "1970-01-01T00:31:45Z",
        "block_window_sha256": "2" * 64,
        "chain_id": 1,
        "lower_bound_block": 80,
        "upper_bound_block": 100,
        "lower_boundary_evidence_sha256": "3" * 64,
        "upper_boundary_evidence_sha256": "4" * 64,
        "expansion_requirement_sha256": "5" * 64,
        "pair_scope_record_count": 2,
        "pair_scope_record_sha256s": ["6" * 64, "7" * 64],
        "search_algorithm": "DETERMINISTIC_INTEGER_BINARY_SEARCH_V1",
        "maximum_block_header_queries_per_provider": 7,
        "required_result": (
            "LAST_CANONICAL_BLOCK_NOT_AFTER_CUTOFF_AND_ADJACENT_NEXT_BLOCK_AFTER_CUTOFF"
        ),
        "source_window_evidence_status": (
            "LOCAL_TEST_SINGLE_PROVIDER_NON_INDEPENDENT_RANGE_BOUND_ONLY"
        ),
        "provider_registry_verified": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    target["target_sha256"] = _canonical_sha(target)
    return target


def _activation(target: dict[str, object]) -> dict[str, object]:
    scopes = []
    for provider_id, family in (("provider-a", "family-a"), ("provider-b", "family-b")):
        scope: dict[str, object] = {
            "target_id": target["target_id"],
            "target_sha256": target["target_sha256"],
            "case_id": target["case_id"],
            "chain": "ethereum",
            "provider_id": provider_id,
            "operator_family": family,
            "method": "eth_getBlockByNumber",
            "include_transactions": False,
            "minimum_block_number": 80,
            "maximum_block_number": 100,
            "maximum_block_header_queries": 7,
            "search_algorithm": "DETERMINISTIC_INTEGER_BINARY_SEARCH_V1",
            "cutoff_timestamp": target["cutoff_timestamp"],
        }
        scope["range_scope_sha256"] = _canonical_sha(scope)
        scopes.append(scope)
    return {
        "schema_version": "stage2_control_cutoff_boundary_activation_approval.v1",
        "decision": "ACTIVATE_RANGE_BOUND_CUTOFF_BLOCK_RPC",
        "range_scopes": scopes,
        "retry_limit": 0,
        "maximum_request_count": 14,
        "activation_start_utc": "2026-08-21T00:00:00Z",
        "activation_expires_utc": "2026-08-22T00:00:00Z",
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def test_resolves_last_block_at_cutoff_and_adjacent_next_block(tmp_path: Path):
    target = _target()
    providers = [
        _Provider("provider-a", "family-a"),
        _Provider("provider-b", "family-b"),
    ]
    result = resolve_cutoff_boundary(
        target=target,
        providers=providers,
        activation=_activation(target),
        raw_root=tmp_path / "raw",
        now_utc="2026-08-21T01:00:00Z",
    )

    assert result["evidence_block_number"] == 90
    assert result["evidence_block_timestamp"] == 1900
    assert result["next_block_number"] == 91
    assert result["next_block_timestamp"] == 1910
    assert result["provider_agreement"] is True
    assert result["disposition"] == "complete"
    assert len(result["provider_results"]) == 2
    assert result["selection_authorized"] is False
    assert all(Path(item["path"]).is_file() for item in result["raw_evidence"])
    assert result["result_sha256"] == _canonical_sha(
        {key: value for key, value in result.items() if key != "result_sha256"}
    )


def test_applies_only_the_named_provider_minimum_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    target = _target()
    providers = [
        _Provider("provider-a", "family-a"),
        _Provider("provider-b", "family-b"),
    ]
    sleeps: list[float] = []
    monkeypatch.setattr(
        resolution_module.time,
        "sleep",
        lambda seconds: sleeps.append(float(seconds)),
    )

    resolve_cutoff_boundary(
        target=target,
        providers=providers,
        activation=_activation(target),
        raw_root=tmp_path / "raw",
        now_utc="2026-08-21T01:00:00Z",
        provider_min_intervals={"provider-b": 0.5},
    )

    assert sleeps == [0.5] * len(providers[1].calls)


def test_rejects_provider_hash_disagreement(tmp_path: Path):
    target = _target()
    providers = [
        _Provider("provider-a", "family-a"),
        _Provider(
            "provider-b",
            "family-b",
            hash_override={90: "0x" + "ff" * 32},
        ),
    ]
    with pytest.raises(
        ControlCutoffBoundaryResolutionError, match="provider_boundary_disagreement"
    ):
        resolve_cutoff_boundary(
            target=target,
            providers=providers,
            activation=_activation(target),
            raw_root=tmp_path / "raw",
            now_utc="2026-08-21T01:00:00Z",
        )


def test_rejects_same_family_providers(tmp_path: Path):
    target = _target()
    providers = [
        _Provider("provider-a", "family-a"),
        _Provider("provider-b", "family-a"),
    ]
    with pytest.raises(
        ControlCutoffBoundaryResolutionError, match="provider_family_independence"
    ):
        resolve_cutoff_boundary(
            target=target,
            providers=providers,
            activation=_activation(target),
            raw_root=tmp_path / "raw",
            now_utc="2026-08-21T01:00:00Z",
        )


def test_batch_resume_preserves_global_sequence_and_exact_membership(tmp_path: Path):
    first = _target()
    second = dict(first)
    second["target_id"] = "cutoff-boundary:" + "2" * 64
    second["case_id"] = "case-2"
    second["pair_scope_record_sha256s"] = ["8" * 64]
    second["pair_scope_record_count"] = 1
    second["target_sha256"] = _canonical_sha(
        {key: value for key, value in second.items() if key != "target_sha256"}
    )
    requirements: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirements.v1",
        "decision": "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION",
        "boundary_target_count": 2,
        "pair_scope_record_count": 3,
        "complete": True,
        "targets": [first, second],
        "final_cutoff_brackets_resolved": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    requirements["requirements_sha256"] = _canonical_sha(requirements)
    requirements_path = tmp_path / "requirements.json"
    requirements_path.write_text(json.dumps(requirements), encoding="utf-8")

    activation = _activation(first)
    second_activation = _activation(second)
    activation["range_scopes"] += second_activation["range_scopes"]
    activation["maximum_request_count"] = 28
    activation.update(
        {
            "schema_version": "stage2_control_cutoff_boundary_activation_verification.v1",
            "decision": "CUTOFF_BOUNDARY_RPC_ACTIVATION_VERIFIED",
            "requirements_file_sha256": hashlib.sha256(
                requirements_path.read_bytes()
            ).hexdigest(),
            "requirements_sha256": requirements["requirements_sha256"],
        }
    )
    activation["verification_sha256"] = _canonical_sha(activation)
    providers = {
        "provider-a": _Provider("provider-a", "family-a"),
        "provider-b": _Provider("provider-b", "family-b"),
    }
    output = tmp_path / "batch"
    partial = execute_cutoff_boundary_batch(
        requirements_path=requirements_path,
        activation=activation,
        providers_by_id=providers,
        output_root=output,
        now_utc="2026-08-21T01:00:00Z",
        max_targets=1,
    )
    assert partial["status"] == "IN_PROGRESS_NON_AUTHORIZING"
    assert partial["processed_target_count"] == 1
    assert partial["request_count"] == 8

    complete = resume_cutoff_boundary_batch(
        requirements_path=requirements_path,
        activation=activation,
        providers_by_id=providers,
        output_root=output,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert complete["status"] == "COMPLETE_NON_AUTHORIZING"
    assert complete["processed_target_count"] == 2
    assert complete["completed_target_count"] == 2
    assert complete["request_count"] == 16
    results_path = Path(complete["results_path"])
    results = json.loads(results_path.read_text())
    assert results["complete"] is True
    assert {row["target_id"] for row in results["targets"]} == {
        first["target_id"],
        second["target_id"],
    }
    sequences = sorted(
        item["sequence_number"]
        for row in results["targets"]
        for item in row["raw_evidence"]
    )
    assert sequences == list(range(1, 17))
    assert len({item["path"] for row in results["targets"] for item in row["raw_evidence"]}) == 16


def test_resume_rejects_checkpoint_tampering(tmp_path: Path):
    target = _target()
    requirements: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirements.v1",
        "decision": "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION",
        "boundary_target_count": 1,
        "pair_scope_record_count": 2,
        "complete": True,
        "targets": [target],
        "final_cutoff_brackets_resolved": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    requirements["requirements_sha256"] = _canonical_sha(requirements)
    requirements_path = tmp_path / "requirements.json"
    requirements_path.write_text(json.dumps(requirements), encoding="utf-8")
    activation = _activation(target)
    activation.update(
        {
            "schema_version": "stage2_control_cutoff_boundary_activation_verification.v1",
            "decision": "CUTOFF_BOUNDARY_RPC_ACTIVATION_VERIFIED",
            "requirements_file_sha256": hashlib.sha256(
                requirements_path.read_bytes()
            ).hexdigest(),
            "requirements_sha256": requirements["requirements_sha256"],
        }
    )
    activation["verification_sha256"] = _canonical_sha(activation)
    providers = {
        "provider-a": _Provider("provider-a", "family-a"),
        "provider-b": _Provider("provider-b", "family-b"),
    }
    output = tmp_path / "batch"
    execute_cutoff_boundary_batch(
        requirements_path=requirements_path,
        activation=activation,
        providers_by_id=providers,
        output_root=output,
        now_utc="2026-08-21T01:00:00Z",
    )
    checkpoint_path = output / "checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text())
    checkpoint["request_count"] += 1
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")

    with pytest.raises(
        ControlCutoffBoundaryResolutionError, match="checkpoint_self_hash_invalid"
    ):
        resume_cutoff_boundary_batch(
            requirements_path=requirements_path,
            activation=activation,
            providers_by_id=providers,
            output_root=output,
            now_utc="2026-08-21T01:00:00Z",
        )


def test_provider_failure_persists_consumed_sequences_and_resumes_next_target(
    tmp_path: Path,
):
    first = _target()
    second = dict(first)
    second["target_id"] = "cutoff-boundary:" + "2" * 64
    second["case_id"] = "case-2"
    second["pair_scope_record_sha256s"] = ["8" * 64]
    second["pair_scope_record_count"] = 1
    second["target_sha256"] = _canonical_sha(
        {key: value for key, value in second.items() if key != "target_sha256"}
    )
    requirements: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirements.v1",
        "decision": "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION",
        "boundary_target_count": 2,
        "pair_scope_record_count": 3,
        "complete": True,
        "targets": [first, second],
        "final_cutoff_brackets_resolved": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    requirements["requirements_sha256"] = _canonical_sha(requirements)
    requirements_path = tmp_path / "requirements.json"
    requirements_path.write_text(json.dumps(requirements), encoding="utf-8")
    activation = _activation(first)
    activation["range_scopes"] += _activation(second)["range_scopes"]
    activation["retry_limit"] = 1
    activation["maximum_request_count"] = 56
    activation.update(
        {
            "schema_version": "stage2_control_cutoff_boundary_activation_verification.v1",
            "decision": "CUTOFF_BOUNDARY_RPC_ACTIVATION_VERIFIED",
            "requirements_file_sha256": hashlib.sha256(
                requirements_path.read_bytes()
            ).hexdigest(),
            "requirements_sha256": requirements["requirements_sha256"],
        }
    )
    activation["verification_sha256"] = _canonical_sha(activation)
    output = tmp_path / "batch"

    partial = execute_cutoff_boundary_batch(
        requirements_path=requirements_path,
        activation=activation,
        providers_by_id={
            "provider-a": _Provider("provider-a", "family-a"),
            "provider-b": _ErrorOnCallProvider(
                "provider-b", "family-b", fail_on_call=5
            ),
        },
        output_root=output,
        now_utc="2026-08-21T01:00:00Z",
    )

    assert partial["status"] == "PARTIAL_NON_AUTHORIZING"
    assert partial["processed_target_count"] == 1
    assert partial["completed_target_count"] == 1
    assert partial["request_count"] == 13
    assert partial["last_failure"] == {
        "error_code": "provider_error",
        "target_id": second["target_id"],
    }
    checkpoint = json.loads((output / "checkpoint.json").read_text())
    assert checkpoint["used_sequences"] == list(range(1, 14))
    assert checkpoint["request_evidence_count"] == 13
    assert len(checkpoint["request_evidence"]) == 13

    complete = resume_cutoff_boundary_batch(
        requirements_path=requirements_path,
        activation=activation,
        providers_by_id={
            "provider-a": _Provider("provider-a", "family-a"),
            "provider-b": _Provider("provider-b", "family-b"),
        },
        output_root=output,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert complete["status"] == "COMPLETE_NON_AUTHORIZING"
    assert complete["processed_target_count"] == 2
    assert complete["request_count"] == 21
    completed_checkpoint = json.loads((output / "checkpoint.json").read_text())
    assert completed_checkpoint["used_sequences"] == list(range(1, 22))
    assert completed_checkpoint["request_evidence_count"] == 21
    assert "last_failure" not in completed_checkpoint
