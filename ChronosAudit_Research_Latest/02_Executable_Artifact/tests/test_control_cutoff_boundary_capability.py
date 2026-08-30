from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_activation import (
    build_boundary_activation_request,
)
from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_capability import (
    ControlCutoffBoundaryCapabilityError,
    assess_cutoff_boundary_capability,
    verify_cutoff_boundary_capability,
)
import preflight_stage2_control_cutoff_boundary_capability as preflight


CHAIN_IDS = {"ethereum": 1, "base": 8453}


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _target(chain: str, lower: int, upper: int, suffix: str) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirement.v1",
        "target_id": f"cutoff-boundary:{suffix * 64}",
        "case_id": f"case-{chain}",
        "chain": chain,
        "cutoff_timestamp": "2020-01-10T00:00:00Z",
        "block_window_sha256": "2" * 64,
        "chain_id": CHAIN_IDS[chain],
        "lower_bound_block": lower,
        "upper_bound_block": upper,
        "lower_boundary_evidence_sha256": "3" * 64,
        "upper_boundary_evidence_sha256": "4" * 64,
        "expansion_requirement_sha256": "5" * 64,
        "pair_scope_record_count": 1,
        "pair_scope_record_sha256s": ["6" * 64],
        "search_algorithm": "DETERMINISTIC_INTEGER_BINARY_SEARCH_V1",
        "maximum_block_header_queries_per_provider": 9,
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
    row["target_sha256"] = _canonical_sha(row)
    return row


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    targets = [_target("ethereum", 10, 20, "1"), _target("base", 30, 40, "2")]
    requirements: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirements.v1",
        "decision": "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION",
        "reserve_pair_scope_file_sha256": "8" * 64,
        "reserve_pair_scope_projection_sha256": "9" * 64,
        "block_windows_file_sha256": "a" * 64,
        "block_windows_manifest_file_sha256": "b" * 64,
        "pair_scope_record_count": 2,
        "boundary_target_count": 2,
        "case_count": 2,
        "complete": True,
        "targets": targets,
        "final_cutoff_brackets_resolved": False,
        "provider_registry_verified": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    requirements["requirements_sha256"] = _canonical_sha(requirements)
    requirements_path = tmp_path / "requirements.json"
    requirements_path.write_text(json.dumps(requirements), encoding="utf-8")

    providers = []
    for chain in ("ethereum", "base"):
        for suffix in ("a", "b"):
            providers.append(
                {
                    "provider_id": f"{chain}-{suffix}",
                    "chain": chain,
                    "endpoint": f"https://{chain}-{suffix}.example/rpc",
                    "operator_family": f"family-{suffix}",
                    "operator_verified": True,
                    "tracking_enabled": True,
                    "discovery_source": f"https://family-{suffix}.example/docs",
                    "operator_evidence_url": f"https://family-{suffix}.example/about",
                    "operator_evidence_sha256": suffix * 64,
                }
            )
    registry_path = tmp_path / "providers.yaml"
    registry_path.write_text(
        yaml.safe_dump({"version": "test", "providers": providers}),
        encoding="utf-8",
    )
    return requirements_path, registry_path


class BoundaryProvider:
    def __init__(
        self,
        provider_id: str,
        family: str,
        chain: str,
        *,
        mismatched_block: int | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.provider_family = family
        self.chain = chain
        self.mismatched_block = mismatched_block

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        if method == "eth_chainId":
            result: object = hex(CHAIN_IDS[self.chain])
        else:
            number = int(str(params[0]), 16)
            marker = number + (1 if self.mismatched_block == number else 0)
            result = {
                "number": hex(number),
                "hash": "0x" + f"{marker:064x}",
                "timestamp": hex(number * 10),
            }
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
            observed_at_utc="2026-08-21T00:00:00Z",
        )


def _providers(*, mismatch: tuple[str, int] | None = None) -> list[BoundaryProvider]:
    rows = []
    for chain in ("ethereum", "base"):
        for suffix in ("a", "b"):
            provider_id = f"{chain}-{suffix}"
            rows.append(
                BoundaryProvider(
                    provider_id,
                    f"family-{suffix}",
                    chain,
                    mismatched_block=(
                        mismatch[1]
                        if mismatch is not None and mismatch[0] == provider_id
                        else None
                    ),
                )
            )
    return rows


def test_complete_preflight_is_activation_compatible(tmp_path: Path) -> None:
    requirements_path, registry_path = _inputs(tmp_path)
    raw_root = tmp_path / "raw"
    capability = assess_cutoff_boundary_capability(
        requirements_path=requirements_path,
        provider_registry_path=registry_path,
        providers=_providers(),
        raw_root=raw_root,
    )

    assert capability["decision"] == "DUAL_PROVIDER_CUTOFF_BOUNDARY_CAPABILITY_VERIFIED"
    assert capability["complete"] is True
    assert capability["raw_evidence_count"] == 24
    assert capability["rpc_authorized"] is False
    assert capability["selection_authorized"] is False
    assert capability["stage_promotion_authorized"] is False
    assert capability["recovery3_mutation_authorized"] is False
    assert [row["chain"] for row in capability["chains"]] == ["base", "ethereum"]
    assert all(len(row["probe_blocks"]) == 2 for row in capability["chains"])

    capability_path = tmp_path / "capability.json"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")
    verification = verify_cutoff_boundary_capability(
        capability_path=capability_path,
        requirements_path=requirements_path,
        provider_registry_path=registry_path,
        raw_root=raw_root,
    )
    assert verification["decision"] == "CUTOFF_BOUNDARY_CAPABILITY_VERIFIED_NON_AUTHORIZING"

    request = build_boundary_activation_request(
        requirements_path=requirements_path,
        capability_path=capability_path,
        provider_registry_path=registry_path,
        activation_start_utc="2026-08-21T00:00:00Z",
        activation_expires_utc="2026-08-22T00:00:00Z",
        retry_limit=1,
    )
    assert request["range_scope_count"] == 4


def test_cross_provider_block_disagreement_fails_closed(tmp_path: Path) -> None:
    requirements_path, registry_path = _inputs(tmp_path)
    capability = assess_cutoff_boundary_capability(
        requirements_path=requirements_path,
        provider_registry_path=registry_path,
        providers=_providers(mismatch=("ethereum-b", 20)),
        raw_root=tmp_path / "raw",
    )

    assert capability["complete"] is False
    assert capability["decision"] == "CUTOFF_BOUNDARY_CAPABILITY_INCOMPLETE"
    assert "ethereum:provider_semantic_disagreement:block:20" in capability["errors"]
    assert capability["rpc_authorized"] is False


def test_missing_second_operator_family_fails_closed(tmp_path: Path) -> None:
    requirements_path, registry_path = _inputs(tmp_path)
    providers = [row for row in _providers() if row.provider_id != "base-b"]
    capability = assess_cutoff_boundary_capability(
        requirements_path=requirements_path,
        provider_registry_path=registry_path,
        providers=providers,
        raw_root=tmp_path / "raw",
    )

    assert capability["complete"] is False
    assert "base:provider_family_independence" in capability["errors"]


def test_verifier_rejects_tampered_raw_receipt(tmp_path: Path) -> None:
    requirements_path, registry_path = _inputs(tmp_path)
    raw_root = tmp_path / "raw"
    capability = assess_cutoff_boundary_capability(
        requirements_path=requirements_path,
        provider_registry_path=registry_path,
        providers=_providers(),
        raw_root=raw_root,
    )
    capability_path = tmp_path / "capability.json"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")
    raw_path = raw_root / capability["raw_evidence"][0]["path"]
    raw_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(
        ControlCutoffBoundaryCapabilityError, match="raw_evidence_hash_mismatch"
    ):
        verify_cutoff_boundary_capability(
            capability_path=capability_path,
            requirements_path=requirements_path,
            provider_registry_path=registry_path,
            raw_root=raw_root,
        )


def test_capability_binds_exact_input_file_hashes(tmp_path: Path) -> None:
    requirements_path, registry_path = _inputs(tmp_path)
    capability = assess_cutoff_boundary_capability(
        requirements_path=requirements_path,
        provider_registry_path=registry_path,
        providers=_providers(),
        raw_root=tmp_path / "raw",
    )

    assert capability["requirements_file_sha256"] == _file_sha(requirements_path)
    assert capability["provider_registry_sha256"] == _file_sha(registry_path)


def test_cli_constructs_only_two_verified_families_per_required_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Record:
        def __init__(
            self,
            provider_id: str,
            chain: str,
            family: str,
            *,
            verified: bool = True,
            tracking: bool = True,
        ) -> None:
            self.provider_id = provider_id
            self.chain = chain
            self.operator_family = family
            self.operator_verified = verified
            self.tracking_enabled = tracking
            self.public_endpoint = "https://public.example/rpc"
            self.public_endpoint_id = provider_id + "-endpoint-id"

        def resolved_endpoint(self) -> str:
            return f"https://private.example/{self.provider_id}/secret"

    records = [
        Record("eth-a", "ethereum", "family-a"),
        Record("eth-b", "ethereum", "family-b"),
        Record("eth-c", "ethereum", "family-c"),
        Record("base-a", "base", "family-a", verified=False),
    ]
    monkeypatch.setattr(
        preflight.ProviderRegistry,
        "from_path",
        lambda path: SimpleNamespace(providers=records),
    )
    constructed: list[dict[str, object]] = []

    class RuntimeProvider:
        def __init__(self, **kwargs: object) -> None:
            constructed.append(kwargs)
            self.provider_id = kwargs["provider_id"]
            self.provider_family = kwargs["provider_family"]

    monkeypatch.setattr(preflight, "JsonRpcProvider", RuntimeProvider)
    providers = preflight.build_runtime_providers(
        provider_registry_path=Path("registry.yaml"),
        required_chains={"ethereum"},
        timeout_seconds=7,
        max_retries=2,
        backoff_seconds=1.25,
        minimum_interval_seconds=0.75,
    )

    assert [row.provider_id for row in providers] == ["eth-a", "eth-b"]
    assert len(constructed) == 2
    assert all(row["timeout"] == 7 for row in constructed)
    assert all(row["max_retries"] == 2 for row in constructed)
    assert all(row["backoff_seconds"] == 1.25 for row in constructed)
    assert all("private.example" in str(row["url"]) for row in constructed)
    assert all(row._interval == 0.75 for row in providers)


def test_cli_help_exposes_only_non_authorizing_preflight_inputs() -> None:
    script = (
        Path(__file__).resolve().parents[1]
        / "preflight_stage2_control_cutoff_boundary_capability.py"
    )
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--requirements" in result.stdout
    assert "--provider-registry" in result.stdout
    assert "--raw-root" in result.stdout
    assert "--output-capability" in result.stdout
    assert "--output-verification" in result.stdout
    assert "--minimum-interval-seconds" in result.stdout
    assert "--selection" not in result.stdout
    assert "--qualification" not in result.stdout
