from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_activation import (
    ControlCutoffBoundaryActivationError,
    authorize_boundary_rpc_call,
    build_boundary_activation_approval,
    build_boundary_activation_request,
    canonical_signed_payload,
    verify_boundary_activation,
)


PRINCIPAL = "chronosaudit-local-test"
NAMESPACE = "chronosaudit-stage2-control-cutoff-boundary-activation-v1"


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> dict[str, Path]:
    target: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirement.v1",
        "target_id": "cutoff-boundary:" + "1" * 64,
        "case_id": "case-1",
        "chain": "ethereum",
        "cutoff_timestamp": "2020-01-10T00:00:00Z",
        "block_window_sha256": "2" * 64,
        "chain_id": 1,
        "lower_bound_block": 900,
        "upper_bound_block": 1000,
        "lower_boundary_evidence_sha256": "3" * 64,
        "upper_boundary_evidence_sha256": "4" * 64,
        "expansion_requirement_sha256": "5" * 64,
        "pair_scope_record_count": 2,
        "pair_scope_record_sha256s": ["6" * 64, "7" * 64],
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
    target["target_sha256"] = _canonical_sha(target)
    requirements: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_requirements.v1",
        "decision": "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION",
        "reserve_pair_scope_file_sha256": "8" * 64,
        "reserve_pair_scope_projection_sha256": "9" * 64,
        "block_windows_file_sha256": "a" * 64,
        "block_windows_manifest_file_sha256": "b" * 64,
        "pair_scope_record_count": 2,
        "boundary_target_count": 1,
        "case_count": 1,
        "complete": True,
        "targets": [target],
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

    registry = {
        "version": "test",
        "providers": [
            {
                "provider_id": "provider-a",
                "chain": "ethereum",
                "endpoint": "https://provider-a.example/rpc",
                "operator_family": "family-a",
                "operator_verified": True,
                "tracking_enabled": True,
                "discovery_source": "https://family-a.example/docs",
                "operator_evidence_url": "https://family-a.example/about",
                "operator_evidence_sha256": "c" * 64,
            },
            {
                "provider_id": "provider-b",
                "chain": "ethereum",
                "endpoint": "https://provider-b.example/rpc",
                "operator_family": "family-b",
                "operator_verified": True,
                "tracking_enabled": True,
                "discovery_source": "https://family-b.example/docs",
                "operator_evidence_url": "https://family-b.example/about",
                "operator_evidence_sha256": "d" * 64,
            },
        ],
    }
    registry_path = tmp_path / "providers.yaml"
    registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")

    capability: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_boundary_capability.v1",
        "decision": "DUAL_PROVIDER_CUTOFF_BOUNDARY_CAPABILITY_VERIFIED",
        "requirements_file_sha256": _file_sha(requirements_path),
        "requirements_sha256": requirements["requirements_sha256"],
        "provider_registry_sha256": _file_sha(registry_path),
        "complete": True,
        "chains": [
            {
                "chain": "ethereum",
                "providers": [
                    {
                        "provider_id": "provider-a",
                        "operator_family": "family-a",
                        "chain_id_verified": True,
                        "historical_block_by_number_verified": True,
                    },
                    {
                        "provider_id": "provider-b",
                        "operator_family": "family-b",
                        "chain_id_verified": True,
                        "historical_block_by_number_verified": True,
                    },
                ],
            }
        ],
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["capability_sha256"] = _canonical_sha(capability)
    capability_path = tmp_path / "capability.json"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")
    return {
        "requirements": requirements_path,
        "registry": registry_path,
        "capability": capability_path,
    }


def _request(paths: dict[str, Path]) -> dict[str, object]:
    return build_boundary_activation_request(
        requirements_path=paths["requirements"],
        capability_path=paths["capability"],
        provider_registry_path=paths["registry"],
        activation_start_utc="2026-08-21T00:00:00Z",
        activation_expires_utc="2026-08-22T00:00:00Z",
        retry_limit=1,
    )


def _sign(
    tmp_path: Path, approval: dict[str, object]
) -> tuple[Path, Path, Path]:
    key = tmp_path / "activation-key"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public = Path(str(key) + ".pub").read_text(encoding="utf-8").strip()
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(f"{PRINCIPAL} {public}\n", encoding="utf-8")
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(canonical_signed_payload(approval))
    subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(key),
            "-n",
            NAMESPACE,
            str(approval_path),
        ],
        check=True,
        capture_output=True,
    )
    return approval_path, Path(str(approval_path) + ".sig"), allowed


def test_builds_exact_range_bound_scopes_and_budget(tmp_path: Path):
    paths = _inputs(tmp_path)
    request = _request(paths)

    assert request["boundary_target_count"] == 1
    assert request["range_scope_count"] == 2
    assert request["maximum_request_count"] == 36
    assert request["rpc_authorized"] is False
    assert request["selection_authorized"] is False
    assert {scope["provider_id"] for scope in request["range_scopes"]} == {
        "provider-a",
        "provider-b",
    }
    assert all(scope["minimum_block_number"] == 900 for scope in request["range_scopes"])
    assert all(scope["maximum_block_number"] == 1000 for scope in request["range_scopes"])


def test_authorizes_only_block_by_number_inside_frozen_range(tmp_path: Path):
    paths = _inputs(tmp_path)
    approval = build_boundary_activation_approval(
        request=_request(paths), signer_principal=PRINCIPAL
    )
    result = authorize_boundary_rpc_call(
        approval,
        target_id="cutoff-boundary:" + "1" * 64,
        chain="ethereum",
        provider_id="provider-a",
        method="eth_getBlockByNumber",
        params=[hex(950), False],
        sequence_number=1,
        used_sequences=set(),
        requests_used=0,
        scope_requests_used=0,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["authorized"] is True

    with pytest.raises(ControlCutoffBoundaryActivationError, match="block_outside_range"):
        authorize_boundary_rpc_call(
            approval,
            target_id="cutoff-boundary:" + "1" * 64,
            chain="ethereum",
            provider_id="provider-a",
            method="eth_getBlockByNumber",
            params=[hex(1001), False],
            sequence_number=2,
            used_sequences=set(),
            requests_used=1,
            scope_requests_used=1,
            now_utc="2026-08-21T01:00:00Z",
        )


def test_rejects_incomplete_chain_coverage(tmp_path: Path):
    paths = _inputs(tmp_path)
    capability = json.loads(paths["capability"].read_text())
    capability["chains"] = []
    capability["capability_sha256"] = _canonical_sha(
        {
            key: value
            for key, value in capability.items()
            if key != "capability_sha256"
        }
    )
    paths["capability"].write_text(json.dumps(capability), encoding="utf-8")

    with pytest.raises(ControlCutoffBoundaryActivationError, match="chain_coverage"):
        _request(paths)


def test_verifies_detached_activation_signature(tmp_path: Path):
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval = build_boundary_activation_approval(
        request=request, signer_principal=PRINCIPAL
    )
    approval_path, signature_path, allowed = _sign(tmp_path, approval)
    verification = verify_boundary_activation(
        request=request,
        approval_path=approval_path,
        signature_path=signature_path,
        allowed_signers_path=allowed,
        expected_principal=PRINCIPAL,
        verification_time_utc="2026-08-21T01:00:00Z",
    )
    assert verification["decision"] == "CUTOFF_BOUNDARY_RPC_ACTIVATION_VERIFIED"
    assert verification["rpc_authorized"] is True
    assert verification["selection_authorized"] is False


def test_activation_cli_surfaces_only_exact_build_and_verify_inputs():
    root = Path(__file__).resolve().parents[1]
    build = subprocess.run(
        [sys.executable, str(root / "build_stage2_control_cutoff_boundary_activation.py"), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    verify = subprocess.run(
        [sys.executable, str(root / "verify_stage2_control_cutoff_boundary_activation.py"), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0
    assert "--requirements" in build.stdout
    assert "--capability" in build.stdout
    assert "--provider-registry" in build.stdout
    assert "--output-request" in build.stdout
    assert "--output-approval" in build.stdout
    assert verify.returncode == 0
    assert "--signature" in verify.stdout
    assert "--allowed-signers" in verify.stdout
    assert "--output-verification" in verify.stdout
    assert "--selection" not in build.stdout + verify.stdout
