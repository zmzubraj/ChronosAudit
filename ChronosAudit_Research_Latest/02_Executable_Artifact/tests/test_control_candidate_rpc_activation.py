from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pandas as pd
import pytest
import yaml

import chronosaudit_stage2.public_acquisition.control_candidate_rpc_activation as module
from chronosaudit_stage2.public_acquisition.control_candidate_rpc_activation import (
    ControlCandidateRpcActivationError,
    assess_control_candidate_rpc_provider_readiness,
    build_control_candidate_rpc_activation_approval,
    build_control_candidate_rpc_activation_request,
    build_control_candidate_retry_rpc_activation_request,
    build_control_candidate_next_batch_rpc_activation_request,
    canonical_signed_payload,
    verify_control_candidate_rpc_activation,
)
from chronosaudit_stage2.public_acquisition.providers import endpoint_id


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _inputs(tmp_path: Path) -> dict[str, Path]:
    queue = tmp_path / "queue.csv"
    pd.DataFrame(
        [
            {"case_name": "case-a", "chain": "ethereum", "control_identity": "1:0x" + "1" * 40},
            {"case_name": "case-a", "chain": "ethereum", "control_identity": "1:0x" + "2" * 40},
            {"case_name": "case-b", "chain": "bsc", "control_identity": "56:0x" + "3" * 40},
        ]
    ).to_csv(queue, index=False)
    manifest = tmp_path / "queue-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "chronosaudit.control_historical_candidate_reserve_queue.v1",
                "decision": "RESERVE_QUEUE_FROZEN_REQUIRES_HASH_BOUND_RPC_ACTIVATION",
                "queue_sha256": _sha(queue),
                "queue_row_count": 3,
                "reserve_target": 3,
                "reserve_allocated": 3,
                "reserve_shortfall": 0,
                "global_no_reuse_verified": True,
                "rpc_authorized": False,
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            }
        ),
        encoding="utf-8",
    )
    dependencies = {}
    for name in (
        "query_plan",
        "chunk_plan",
        "positive_projection",
        "authority_projection",
        "import_manifest",
    ):
        path = tmp_path / f"{name}.fixture"
        path.write_text(name, encoding="utf-8")
        dependencies[name] = path

    providers = []
    report_chains = []
    for chain in ("bsc", "ethereum"):
        report_providers = []
        for family in ("alpha", "beta"):
            provider_id = f"{family}-{chain}"
            endpoint = f"https://{provider_id}.example/rpc"
            identity = endpoint_id(endpoint)
            providers.append(
                {
                    "provider_id": provider_id,
                    "chain": chain,
                    "endpoint": endpoint,
                    "operator_family": family,
                    "discovery_source": f"https://{family}.example/docs",
                    "tracking_enabled": True,
                    "operator_evidence_url": f"https://{family}.example/about",
                    "operator_evidence_sha256": family[0] * 64,
                    "operator_verified": True,
                }
            )
            evidence = {
                "chain": chain,
                "provider_id": provider_id,
                "provider_identity_id": identity,
                "endpoint_template_sha256": identity,
                "verified_operator_family": family,
            }
            report_providers.append(
                {
                    "chain": chain,
                    "complete": True,
                    "provider_id": provider_id,
                    "verified_operator_family": family,
                    "public_endpoint_identity_id": identity,
                    "public_endpoint_identity_sha256": _canonical_sha(identity),
                    "endpoint_template_sha256": identity,
                    "identity_evidence_sha256": _canonical_sha(evidence),
                }
            )
        report_chains.append(
            {
                "chain": chain,
                "complete": True,
                "errors": [],
                "provider_count": 2,
                "providers": report_providers,
                "verified_operator_families": ["alpha", "beta"],
            }
        )
    registry = tmp_path / "providers.yaml"
    registry.write_text(yaml.safe_dump({"version": "test", "providers": providers}), encoding="utf-8")
    provider_report = {
        "schema_version": "historical_snapshot_provider_identity_verification.v1",
        "chain_count": 2,
        "chains": report_chains,
        "complete": True,
        "errors": [],
    }
    provider_report["report_sha256"] = _canonical_sha(provider_report)
    report = tmp_path / "provider-identity.json"
    report.write_text(json.dumps(provider_report), encoding="utf-8")
    return {
        "queue": queue,
        "manifest": manifest,
        "provider_registry": registry,
        "provider_identity": report,
        **dependencies,
    }


def _stub_queue_verifier(monkeypatch: pytest.MonkeyPatch, paths: dict[str, Path]) -> None:
    monkeypatch.setattr(
        module,
        "verify_historical_candidate_queue",
        lambda **_: {
            "decision": "RESERVE_QUEUE_VERIFIED_NON_AUTHORIZING",
            "queue_sha256": _sha(paths["queue"]),
            "manifest_sha256": _sha(paths["manifest"]),
            "queue_row_count": 3,
            "reserve_target": 3,
            "reserve_shortfall": 0,
            "global_no_reuse_verified": True,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
    )


def _build(paths: dict[str, Path]) -> dict[str, object]:
    return build_control_candidate_rpc_activation_request(
        queue_path=paths["queue"],
        queue_manifest_path=paths["manifest"],
        query_plan_path=paths["query_plan"],
        chunk_plan_path=paths["chunk_plan"],
        positive_projection_path=paths["positive_projection"],
        authority_projection_path=paths["authority_projection"],
        import_manifest_path=paths["import_manifest"],
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
    )


def test_activation_request_is_queue_hash_bound_deterministic_and_non_authorizing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    _stub_queue_verifier(monkeypatch, paths)

    request = _build(paths)
    repeated = _build(paths)

    assert request == repeated
    assert request["decision"] == "AWAITING_ACCOUNTABLE_RPC_ACTIVATION_SIGNATURE"
    assert request["queue_sha256"] == _sha(paths["queue"])
    assert request["queue_manifest_sha256"] == _sha(paths["manifest"])
    assert request["queue_row_count"] == 3
    assert request["chain_candidate_counts"] == {"bsc": 1, "ethereum": 2}
    assert request["maximum_rpc_requests"] == 16
    assert request["rpc_methods"] == [
        "eth_chainId",
        "eth_getTransactionReceipt",
        "eth_getBlockByHash",
    ]
    assert request["acquisition_authorized"] is False
    assert request["rpc_authorized"] is False
    assert request["selection_authorized"] is False
    assert request["stage_promotion_authorized"] is False
    assert request["recovery3_mutation_authorized"] is False


def test_activation_request_binds_optional_exact_block_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    _stub_queue_verifier(monkeypatch, paths)
    block_window = tmp_path / "block-window.csv"
    block_window.write_text("case_name,start_block,end_block\ncase-a,1,2\n", encoding="utf-8")

    request = build_control_candidate_rpc_activation_request(
        queue_path=paths["queue"],
        queue_manifest_path=paths["manifest"],
        query_plan_path=paths["query_plan"],
        chunk_plan_path=paths["chunk_plan"],
        positive_projection_path=paths["positive_projection"],
        authority_projection_path=paths["authority_projection"],
        import_manifest_path=paths["import_manifest"],
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
        block_window_path=block_window,
    )

    assert request["block_window_sha256"] == _sha(block_window)


def test_next_batch_activation_binds_minimum_prefix_and_capability(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    queue = pd.read_csv(paths["queue"], dtype=str)
    queue["reserve_assignment_sha256"] = ["1" * 64, "2" * 64, "3" * 64]
    queue.to_csv(paths["queue"], index=False)
    next_manifest = tmp_path / "next-batch-manifest.json"
    manifest = {
        "schema_version": "chronosaudit.control_candidate_next_batch.v1",
        "decision": "MINIMUM_FROZEN_PENDING_PREFIX_IF_ALL_ROWS_ARE_VALID",
        "minimum_pending_prefix_row_count": 3,
        "output_queue_sha256": _sha(paths["queue"]),
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    next_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    capability_file = tmp_path / "candidate-capability-verification.json"
    capability = {
        "schema_version": "stage2_control_candidate_rpc_capability_verification.v1",
        "complete": True,
        "provider_registry_sha256": _sha(paths["provider_registry"]),
        "chain_count": 2,
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["verification_sha256"] = _canonical_sha(capability)
    capability_file.write_text(json.dumps(capability), encoding="utf-8")

    request = build_control_candidate_next_batch_rpc_activation_request(
        queue_path=paths["queue"],
        next_batch_manifest_path=next_manifest,
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
        candidate_rpc_capability_verification_path=capability_file,
    )

    assert request["queue_row_count"] == 3
    assert request["maximum_rpc_requests"] == 16
    assert request["next_batch_manifest_sha256"] == manifest["manifest_sha256"]
    assert request["candidate_rpc_capability_verification_sha256"] == _sha(
        capability_file
    )
    assert request["rpc_authorized"] is False


def test_next_batch_activation_accepts_verified_attrition_extension(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    queue = pd.read_csv(paths["queue"], dtype=str)
    queue["reserve_assignment_sha256"] = ["1" * 64, "2" * 64, "3" * 64]
    queue.to_csv(paths["queue"], index=False)
    manifest_path = tmp_path / "attrition-extension.json"
    manifest = {
        "schema_version": "chronosaudit.control_candidate_attrition_extension.v1",
        "decision": "MINIMUM_FROZEN_REMAINING_PREFIX_AFTER_VERIFIED_ATTRITION_IF_ALL_ROWS_VALID",
        "minimum_extension_prefix_row_count": 3,
        "output_queue_sha256": _sha(paths["queue"]),
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capability_file = tmp_path / "candidate-capability-verification.json"
    capability = {
        "schema_version": "stage2_control_candidate_rpc_capability_verification.v1",
        "complete": True,
        "provider_registry_sha256": _sha(paths["provider_registry"]),
        "chain_count": 2,
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["verification_sha256"] = _canonical_sha(capability)
    capability_file.write_text(json.dumps(capability), encoding="utf-8")

    request = build_control_candidate_next_batch_rpc_activation_request(
        queue_path=paths["queue"],
        next_batch_manifest_path=manifest_path,
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
        candidate_rpc_capability_verification_path=capability_file,
    )

    assert request["queue_row_count"] == 3
    assert request["maximum_rpc_requests"] == 16
    assert request["next_batch_manifest_sha256"] == manifest["manifest_sha256"]


def test_retry_activation_binds_exact_partial_scope_manifest_and_fresh_budget(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    queue = pd.read_csv(paths["queue"], dtype=str)
    queue = queue.loc[queue["chain"] == "bsc"].copy()
    queue["reserve_assignment_sha256"] = ["3" * 64]
    queue.to_csv(paths["queue"], index=False)
    retry_manifest_path = tmp_path / "retry-manifest.json"
    retry_manifest = {
        "schema_version": "chronosaudit.control_candidate_rpc_retry_targets.v1",
        "decision": "RETRY_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION",
        "retry_reason": "TERMINAL_PARTIAL_SCOPE_ONLY",
        "retry_queue_sha256": _sha(paths["queue"]),
        "retry_row_count": 1,
        "source_request_ledger_sha256": "a" * 64,
        "source_request_ledger_terminal_hash": "b" * 64,
        "retry_scopes": [
            {
                "reserve_assignment_sha256": "3" * 64,
                "source_partial_event_sha256": "c" * 64,
                "attempted_request_sequences": [9],
                "attempted_request_event_sha256s": ["d" * 64],
                "attempted_request_dispositions": ["TRANSPORT_ERROR"],
            }
        ],
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    retry_manifest["manifest_sha256"] = _canonical_sha(retry_manifest)
    retry_manifest_path.write_text(json.dumps(retry_manifest), encoding="utf-8")
    capability_file = tmp_path / "candidate-capability-verification.json"
    capability = {
        "schema_version": "stage2_control_candidate_rpc_capability_verification.v1",
        "complete": True,
        "provider_registry_sha256": _sha(paths["provider_registry"]),
        "chain_count": 1,
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["verification_sha256"] = _canonical_sha(capability)
    capability_file.write_text(json.dumps(capability), encoding="utf-8")

    request = build_control_candidate_retry_rpc_activation_request(
        queue_path=paths["queue"],
        retry_manifest_path=retry_manifest_path,
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
        candidate_rpc_capability_verification_path=capability_file,
    )

    assert request["queue_row_count"] == 1
    assert request["chain_candidate_counts"] == {"bsc": 1}
    assert request["maximum_rpc_requests"] == 6
    assert request["candidate_retry_manifest_sha256"] == retry_manifest["manifest_sha256"]
    assert request["source_request_ledger_sha256"] == "a" * 64
    assert request["source_request_ledger_terminal_hash"] == "b" * 64
    approval = build_control_candidate_rpc_activation_approval(
        request=request,
        signer_principal="methods-owner@example.org",
        activation_start_utc="2026-08-20T00:00:00Z",
        activation_expires_utc="2026-08-21T00:00:00Z",
    )
    assert approval["candidate_retry_manifest_sha256"] == retry_manifest["manifest_sha256"]
    assert approval["selection_authorized"] is False


def test_retry_activation_accepts_hash_bound_unattempted_continuation_manifest(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    queue = pd.read_csv(paths["queue"], dtype=str)
    queue = queue.loc[queue["chain"] == "bsc"].copy()
    queue["reserve_assignment_sha256"] = ["3" * 64]
    queue.to_csv(paths["queue"], index=False)
    manifest_path = tmp_path / "unattempted-manifest.json"
    manifest = {
        "schema_version": "chronosaudit.control_candidate_rpc_unattempted_targets.v1",
        "decision": "UNATTEMPTED_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION",
        "unattempted_queue_sha256": _sha(paths["queue"]),
        "unattempted_row_count": 1,
        "source_request_ledger_sha256": "a" * 64,
        "source_request_ledger_terminal_hash": "b" * 64,
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capability_file = tmp_path / "candidate-capability-verification.json"
    capability = {
        "schema_version": "stage2_control_candidate_rpc_capability_verification.v1",
        "complete": True,
        "provider_registry_sha256": _sha(paths["provider_registry"]),
        "chain_count": 1,
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["verification_sha256"] = _canonical_sha(capability)
    capability_file.write_text(json.dumps(capability), encoding="utf-8")

    request = build_control_candidate_retry_rpc_activation_request(
        queue_path=paths["queue"],
        retry_manifest_path=manifest_path,
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
        candidate_rpc_capability_verification_path=capability_file,
    )

    assert request["queue_row_count"] == 1
    assert request["maximum_rpc_requests"] == 6
    assert request["candidate_retry_manifest_sha256"] == manifest["manifest_sha256"]
    assert request["rpc_authorized"] is False


def test_activation_approval_builder_is_deterministic_and_rpc_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    _stub_queue_verifier(monkeypatch, paths)
    request = _build(paths)

    approval = build_control_candidate_rpc_activation_approval(
        request=request,
        signer_principal="methods-owner@example.org",
        activation_start_utc="2026-08-20T00:00:00Z",
        activation_expires_utc="2026-08-21T00:00:00Z",
    )

    assert approval == build_control_candidate_rpc_activation_approval(
        request=request,
        signer_principal="methods-owner@example.org",
        activation_start_utc="2026-08-20T00:00:00Z",
        activation_expires_utc="2026-08-21T00:00:00Z",
    )
    assert approval["request_sha256"] == request["request_sha256"]
    assert approval["rpc_authorized"] is True
    assert approval["selection_authorized"] is False
    assert approval["stage_promotion_authorized"] is False


def test_activation_request_rejects_unverified_provider_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    _stub_queue_verifier(monkeypatch, paths)
    registry = yaml.safe_load(paths["provider_registry"].read_text())
    registry["providers"][0]["operator_verified"] = False
    paths["provider_registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")

    with pytest.raises(ControlCandidateRpcActivationError, match="provider_not_verified"):
        _build(paths)


def test_activation_request_rejects_provider_identity_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    _stub_queue_verifier(monkeypatch, paths)
    report = json.loads(paths["provider_identity"].read_text())
    report["chains"][0]["providers"][0]["provider_id"] = "different-provider"
    report["report_sha256"] = _canonical_sha(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )
    paths["provider_identity"].write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ControlCandidateRpcActivationError, match="provider_identity_registry_mismatch"):
        _build(paths)


def test_provider_readiness_report_accumulates_fail_closed_blockers(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    registry = yaml.safe_load(paths["provider_registry"].read_text())
    registry["providers"][0]["operator_verified"] = False
    registry["providers"][0]["operator_evidence_sha256"] = None
    paths["provider_registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    report = json.loads(paths["provider_identity"].read_text())
    report["chains"][0]["providers"][1]["provider_id"] = "wrong-provider"
    report["report_sha256"] = _canonical_sha(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )
    paths["provider_identity"].write_text(json.dumps(report), encoding="utf-8")

    readiness = assess_control_candidate_rpc_provider_readiness(
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
        required_chains=["bsc", "ethereum"],
    )

    assert readiness["decision"] == "RPC_PROVIDER_IDENTITY_NOT_READY"
    assert "provider_not_verified:alpha-bsc" in readiness["blockers"]
    assert "provider_evidence_incomplete:alpha-bsc" in readiness["blockers"]
    assert "provider_identity_registry_mismatch:beta-bsc" in readiness["blockers"]
    assert readiness["rpc_authorized"] is False
    assert readiness["selection_authorized"] is False


def test_provider_readiness_allows_exact_required_subset_of_signed_identity_report(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)

    readiness = assess_control_candidate_rpc_provider_readiness(
        provider_registry_path=paths["provider_registry"],
        provider_identity_verification_path=paths["provider_identity"],
        required_chains=["bsc"],
        allow_extra_chains=True,
    )

    assert readiness["decision"] == "RPC_PROVIDER_IDENTITY_READY_NON_AUTHORIZING"
    assert readiness["blockers"] == []
    assert [row["chain"] for row in readiness["chains"]] == ["bsc"]
    assert readiness["rpc_authorized"] is False
    assert readiness["selection_authorized"] is False


def _approval(request: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "chronosaudit.control_candidate_rpc_activation.v1",
        "request_sha256": request["request_sha256"],
        "signer_principal": "methods-owner@example.org",
        "decision": "ACTIVATE_FROZEN_CONTROL_CANDIDATE_QUEUE_RPC",
        "purpose": "CONTROL_CANDIDATE_DEPLOYMENT_VERIFICATION_ONLY",
        "activation_start_utc": "2026-08-20T00:00:00Z",
        "activation_expires_utc": "2026-08-21T00:00:00Z",
        "queue_sha256": request["queue_sha256"],
        "queue_manifest_sha256": request["queue_manifest_sha256"],
        "provider_registry_sha256": request["provider_registry_sha256"],
        "provider_identity_verification_sha256": request[
            "provider_identity_verification_sha256"
        ],
        "block_window_sha256": request["block_window_sha256"],
        "provider_bindings": request["provider_bindings"],
        "rpc_methods": request["rpc_methods"],
        "maximum_rpc_requests": request["maximum_rpc_requests"],
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def _sign(tmp_path: Path, approval: dict[str, object]) -> tuple[Path, Path, Path]:
    key = tmp_path / "activation-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    message = tmp_path / "activation.json"
    message.write_bytes(canonical_signed_payload(approval))
    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-q",
            "-f",
            str(key),
            "-n",
            "chronosaudit-stage2-control-candidate-rpc-activation-v1",
            str(message),
        ],
        check=True,
    )
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        "methods-owner@example.org "
        + Path(f"{key}.pub").read_text(encoding="utf-8").strip()
        + "\n",
        encoding="utf-8",
    )
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    return approval_path, Path(f"{message}.sig"), allowed


def test_signed_activation_authorizes_only_bounded_rpc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    _stub_queue_verifier(monkeypatch, paths)
    request = _build(paths)
    approval_path, signature, allowed = _sign(tmp_path, _approval(request))

    report = verify_control_candidate_rpc_activation(
        request=request,
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="methods-owner@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
    )

    assert report["decision"] == "RPC_ACTIVATION_VERIFIED"
    assert report["maximum_rpc_requests"] == 16
    assert report["acquisition_authorized"] is False
    assert report["rpc_authorized"] is True
    assert report["selection_authorized"] is False
    assert report["stage_promotion_authorized"] is False
    assert report["recovery3_mutation_authorized"] is False


def test_signed_activation_cannot_authorize_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    _stub_queue_verifier(monkeypatch, paths)
    request = _build(paths)
    approval = _approval(request)
    approval["selection_authorized"] = True
    approval_path, signature, allowed = _sign(tmp_path, approval)

    with pytest.raises(
        ControlCandidateRpcActivationError,
        match="approval_selection_authorized_invalid",
    ):
        verify_control_candidate_rpc_activation(
            request=request,
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="methods-owner@example.org",
            verification_time_utc="2026-08-20T12:00:00Z",
        )
