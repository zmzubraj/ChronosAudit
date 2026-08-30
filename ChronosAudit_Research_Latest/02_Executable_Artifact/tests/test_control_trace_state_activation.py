from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

import chronosaudit_stage2.public_acquisition.control_trace_state_activation as module
from chronosaudit_stage2.public_acquisition.control_trace_state_activation import (
    ControlTraceStateActivationError,
    authorize_rpc_call,
    build_trace_state_activation_approval,
    build_trace_state_activation_request,
    build_trace_only_activation_request,
    canonical_signed_payload,
    expected_request_ceiling,
    verify_trace_state_activation,
)
from chronosaudit_stage2.public_acquisition.control_trace_acquisition import (
    reverify_trace_activation_for_execution,
)


BLOCK_HASH = "0x" + "aa" * 32
TRANSACTION_HASH = "0x" + "bb" * 32
ADDRESS = "0x" + "22" * 20
PRINCIPAL = "chronosaudit-local-test"
NAMESPACE = "chronosaudit-stage2-control-trace-state-activation-v1"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _write_inputs(tmp_path: Path) -> dict[str, Path]:
    capability = {
        "schema_version": "stage2_control_trace_state_capability.v1",
        "complete": True,
        "chains": [{
            "chain": "ethereum",
            "complete": True,
            "verified_operator_families": ["family-a", "family-b"],
            "providers": [
                {"provider_id": "provider-a", "provider_family": "family-a"},
                {"provider_id": "provider-b", "provider_family": "family-b"},
            ],
        }],
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability["report_sha256"] = _canonical_sha(capability)
    capability_path = tmp_path / "capability.json"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")

    trace_targets = {
        "schema_version": "stage2_control_trace_targets.v1",
        "targets": [{
            "target_id": "trace-1",
            "case_id": "case-1",
            "chain": "ethereum",
            "chain_address": f"ethereum:{ADDRESS}",
            "transaction_hash": TRANSACTION_HASH,
            "block_number": 10,
            "block_hash": BLOCK_HASH,
            "reserve_record_sha256": "1" * 64,
            "calls": [
                {
                    "provider_id": "provider-a",
                    "operator_family": "family-a",
                    "method": "trace_transaction",
                    "params": [TRANSACTION_HASH],
                },
                {
                    "provider_id": "provider-b",
                    "operator_family": "family-b",
                    "method": "debug_traceTransaction",
                    "params": [TRANSACTION_HASH, {"tracer": "callTracer", "timeout": "120s"}],
                },
            ],
        }],
    }
    trace_path = tmp_path / "trace-targets.json"
    trace_path.write_text(json.dumps(trace_targets), encoding="utf-8")

    selector = {"blockHash": BLOCK_HASH, "requireCanonical": True}
    state_targets = {
        "schema_version": "stage2_control_state_targets.v1",
        "targets": [{
            "target_id": "state-1",
            "case_id": "case-1",
            "chain": "ethereum",
            "chain_address": f"ethereum:{ADDRESS}",
            "pair_scope_record_sha256": "2" * 64,
            "denominator_record_sha256": "3" * 64,
            "calls": [
                {
                    "provider_id": "provider-a",
                    "operator_family": "family-a",
                    "method": "eth_getCode",
                    "params": [ADDRESS, selector],
                },
                {
                    "provider_id": "provider-b",
                    "operator_family": "family-b",
                    "method": "eth_getCode",
                    "params": [ADDRESS, selector],
                },
            ],
        }],
    }
    state_path = tmp_path / "state-targets.json"
    state_path.write_text(json.dumps(state_targets), encoding="utf-8")

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
                "operator_evidence_sha256": "a" * 64,
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
                "operator_evidence_sha256": "b" * 64,
            },
        ],
    }
    registry_path = tmp_path / "providers.yaml"
    registry_path.write_text(yaml.safe_dump(registry), encoding="utf-8")
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    return {
        "capability": capability_path,
        "trace": trace_path,
        "state": state_path,
        "registry": registry_path,
        "raw_root": raw_root,
    }


def _request(monkeypatch: pytest.MonkeyPatch, paths: dict[str, Path]) -> dict[str, object]:
    monkeypatch.setattr(
        module,
        "verify_trace_state_capability",
        lambda **_: {
            "complete": True,
            "report_sha256": json.loads(paths["capability"].read_text())["report_sha256"],
        },
    )
    return build_trace_state_activation_request(
        capability_report_path=paths["capability"],
        capability_raw_root=paths["raw_root"],
        provider_registry_path=paths["registry"],
        trace_targets_path=paths["trace"],
        state_targets_path=paths["state"],
        activation_start_utc="2026-08-21T00:00:00Z",
        activation_expires_utc="2026-08-22T00:00:00Z",
        retry_limit=2,
    )


def _sign(
    tmp_path: Path,
    approval: dict[str, object],
    *,
    namespace: str = NAMESPACE,
) -> tuple[Path, Path, Path]:
    key = tmp_path / "activation-key"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    allowed = tmp_path / "allowed_signers"
    public = (tmp_path / "activation-key.pub").read_text(encoding="utf-8").strip()
    allowed.write_text(f"{PRINCIPAL} {public}\n", encoding="utf-8")
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(canonical_signed_payload(approval))
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace, str(approval_path)],
        check=True,
        capture_output=True,
    )
    return approval_path, Path(str(approval_path) + ".sig"), allowed


def test_activation_binds_exact_targets_and_false_authority_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    request = _request(monkeypatch, paths)
    assert request["selection_authorized"] is False
    assert request["stage_promotion_authorized"] is False
    assert request["recovery3_mutation_authorized"] is False
    assert request["rpc_authorized"] is False
    assert request["maximum_request_count"] == expected_request_ceiling(request)
    assert request["maximum_request_count"] == 12
    assert len(request["rpc_call_scopes"]) == 4
    assert request["trace_targets_sha256"] == _sha(paths["trace"])
    assert request["state_targets_sha256"] == _sha(paths["state"])


def test_trace_only_activation_precedes_state_derivation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    monkeypatch.setattr(
        module,
        "verify_trace_state_capability",
        lambda **_: {
            "complete": True,
            "report_sha256": json.loads(paths["capability"].read_text())[
                "report_sha256"
            ],
        },
    )
    request = build_trace_only_activation_request(
        capability_report_path=paths["capability"],
        capability_raw_root=paths["raw_root"],
        provider_registry_path=paths["registry"],
        trace_targets_path=paths["trace"],
        activation_start_utc="2026-08-21T00:00:00Z",
        activation_expires_utc="2026-08-22T00:00:00Z",
        retry_limit=2,
    )
    assert request["activation_stage"] == "TRACE_ONLY_PRE_STATE_DERIVATION"
    assert request["trace_target_count"] == 1
    assert request["state_target_count"] == 0
    assert request["state_targets_sha256"] is None
    assert request["unmaterialized_state_calls_authorized"] is False
    assert request["rpc_call_scope_count"] == 2
    assert request["maximum_request_count"] == 6
    assert {scope["target_type"] for scope in request["rpc_call_scopes"]} == {
        "trace"
    }
    approval = build_trace_state_activation_approval(
        request=request, signer_principal=PRINCIPAL
    )
    assert approval["activation_stage"] == "TRACE_ONLY_PRE_STATE_DERIVATION"
    assert approval["unmaterialized_state_calls_authorized"] is False
    with pytest.raises(ControlTraceStateActivationError, match="method_not_activated"):
        authorize_rpc_call(
            approval,
            target_id="trace-1",
            chain="ethereum",
            provider_id="provider-a",
            method="eth_getCode",
            params=[ADDRESS, "latest"],
            sequence_number=1,
            used_sequences=set(),
            requests_used=0,
            now_utc="2026-08-21T01:00:00Z",
        )


def test_trace_only_activation_accepts_reconstruction_verified_retry_subset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    retry_payload = json.loads(paths["trace"].read_text(encoding="utf-8"))
    retry_payload["schema_version"] = "stage2_control_trace_retry_targets.v1"
    paths["trace"].write_text(json.dumps(retry_payload), encoding="utf-8")
    monkeypatch.setattr(
        module,
        "verify_trace_state_capability",
        lambda **_: {"complete": True},
    )
    import chronosaudit_stage2.public_acquisition.control_trace_retry_overlay as retry_module

    monkeypatch.setattr(
        retry_module,
        "verify_trace_retry_targets",
        lambda **_: {
            "decision": "TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING"
        },
    )
    request = build_trace_only_activation_request(
        capability_report_path=paths["capability"],
        capability_raw_root=paths["raw_root"],
        provider_registry_path=paths["registry"],
        trace_targets_path=paths["trace"],
        activation_start_utc="2026-08-21T00:00:00Z",
        activation_expires_utc="2026-08-22T00:00:00Z",
        retry_limit=0,
        retry_reconstruction_inputs={},
    )
    assert request["trace_target_count"] == 1
    assert request["trace_targets_sha256"] == _sha(paths["trace"])
    assert request["rpc_authorized"] is False


def test_trace_only_request_rejects_injected_state_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    monkeypatch.setattr(
        module,
        "verify_trace_state_capability",
        lambda **_: {
            "complete": True,
            "report_sha256": json.loads(paths["capability"].read_text())[
                "report_sha256"
            ],
        },
    )
    request = build_trace_only_activation_request(
        capability_report_path=paths["capability"],
        capability_raw_root=paths["raw_root"],
        provider_registry_path=paths["registry"],
        trace_targets_path=paths["trace"],
        activation_start_utc="2026-08-21T00:00:00Z",
        activation_expires_utc="2026-08-22T00:00:00Z",
        retry_limit=0,
    )
    injected = dict(request["rpc_call_scopes"][0])
    injected["target_type"] = "state"
    injected["method"] = "eth_getCode"
    injected["params"] = [ADDRESS, "latest"]
    injected["params_sha256"] = _canonical_sha(injected["params"])
    injected["call_scope_sha256"] = _canonical_sha(
        {key: value for key, value in injected.items() if key != "call_scope_sha256"}
    )
    request["rpc_call_scopes"].append(injected)
    request["rpc_call_scope_count"] += 1
    request["maximum_request_count"] = expected_request_ceiling(request)
    request["request_sha256"] = _canonical_sha(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )
    with pytest.raises(
        ControlTraceStateActivationError, match="trace_only_scope_invalid"
    ):
        build_trace_state_activation_approval(
            request=request, signer_principal=PRINCIPAL
        )


def test_activation_rejects_unlisted_method(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    request = _request(monkeypatch, paths)
    approval = build_trace_state_activation_approval(request=request, signer_principal=PRINCIPAL)
    with pytest.raises(ControlTraceStateActivationError, match="method_not_activated"):
        authorize_rpc_call(
            approval,
            target_id="trace-1",
            chain="ethereum",
            provider_id="provider-a",
            method="eth_getLogs",
            params=["0x0"],
            sequence_number=1,
            used_sequences=set(),
            requests_used=0,
            now_utc="2026-08-21T01:00:00Z",
        )


def test_activation_rejects_param_escape_and_sequence_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    request = _request(monkeypatch, paths)
    approval = build_trace_state_activation_approval(request=request, signer_principal=PRINCIPAL)
    with pytest.raises(ControlTraceStateActivationError, match="rpc_scope_not_activated"):
        authorize_rpc_call(
            approval,
            target_id="trace-1",
            chain="ethereum",
            provider_id="provider-a",
            method="trace_transaction",
            params=["0x" + "ff" * 32],
            sequence_number=1,
            used_sequences=set(),
            requests_used=0,
            now_utc="2026-08-21T01:00:00Z",
        )
    with pytest.raises(ControlTraceStateActivationError, match="sequence_replay"):
        authorize_rpc_call(
            approval,
            target_id="trace-1",
            chain="ethereum",
            provider_id="provider-a",
            method="trace_transaction",
            params=[TRANSACTION_HASH],
            sequence_number=1,
            used_sequences={1},
            requests_used=0,
            now_utc="2026-08-21T01:00:00Z",
        )


def test_signed_activation_verifies_and_remains_non_authorizing_beyond_rpc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    request = _request(monkeypatch, paths)
    approval = build_trace_state_activation_approval(request=request, signer_principal=PRINCIPAL)
    approval_path, signature_path, allowed_path = _sign(tmp_path, approval)
    verification = verify_trace_state_activation(
        request=request,
        approval_path=approval_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_path,
        expected_principal=PRINCIPAL,
        verification_time_utc="2026-08-21T01:00:00Z",
    )
    assert verification["decision"] == "TRACE_STATE_RPC_ACTIVATION_VERIFIED"
    assert verification["rpc_authorized"] is True
    assert verification["trace_target_count"] == request["trace_target_count"]
    assert verification["state_target_count"] == request["state_target_count"]
    assert verification["trace_targets_sha256"] == _sha(paths["trace"])
    semantic = {
        key: value for key, value in verification.items()
        if key != "verification_sha256"
    }
    assert verification["verification_sha256"] == _canonical_sha(semantic)
    assert verification["selection_authorized"] is False
    assert verification["stage_promotion_authorized"] is False
    assert verification["recovery3_mutation_authorized"] is False
    assert verification["identity_binding_limit"] == (
        "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY"
    )


def test_expired_activation_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    request = _request(monkeypatch, paths)
    approval = build_trace_state_activation_approval(request=request, signer_principal=PRINCIPAL)
    approval_path, signature_path, allowed_path = _sign(tmp_path, approval)
    with pytest.raises(ControlTraceStateActivationError, match="activation_expired"):
        verify_trace_state_activation(
            request=request,
            approval_path=approval_path,
            signature_path=signature_path,
            allowed_signers_path=allowed_path,
            expected_principal=PRINCIPAL,
            verification_time_utc="2026-08-23T00:00:00Z",
        )


def test_capability_authority_overclaim_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    capability = json.loads(paths["capability"].read_text(encoding="utf-8"))
    capability["selection_authorized"] = True
    capability.pop("report_sha256")
    capability["report_sha256"] = _canonical_sha(capability)
    paths["capability"].write_text(json.dumps(capability), encoding="utf-8")
    with pytest.raises(ControlTraceStateActivationError, match="capability_selection_authorized_invalid"):
        _request(monkeypatch, paths)


def test_provider_substitution_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    trace = json.loads(paths["trace"].read_text(encoding="utf-8"))
    trace["targets"][0]["calls"][0]["provider_id"] = "provider-substitute"
    paths["trace"].write_text(json.dumps(trace), encoding="utf-8")
    with pytest.raises(ControlTraceStateActivationError, match="capability_provider_binding_mismatch"):
        _request(monkeypatch, paths)


def test_request_budget_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    request = _request(monkeypatch, paths)
    approval = build_trace_state_activation_approval(request=request, signer_principal=PRINCIPAL)
    with pytest.raises(ControlTraceStateActivationError, match="request_budget_exhausted"):
        authorize_rpc_call(
            approval,
            target_id="trace-1",
            chain="ethereum",
            provider_id="provider-a",
            method="trace_transaction",
            params=[TRANSACTION_HASH],
            sequence_number=13,
            used_sequences=set(),
            requests_used=12,
            now_utc="2026-08-21T01:00:00Z",
        )


def test_wrong_signature_namespace_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    request = _request(monkeypatch, paths)
    approval = build_trace_state_activation_approval(request=request, signer_principal=PRINCIPAL)
    approval_path, signature_path, allowed_path = _sign(
        tmp_path, approval, namespace="wrong-purpose-namespace"
    )
    with pytest.raises(ControlTraceStateActivationError, match="signature_invalid"):
        verify_trace_state_activation(
            request=request,
            approval_path=approval_path,
            signature_path=signature_path,
            allowed_signers_path=allowed_path,
            expected_principal=PRINCIPAL,
            verification_time_utc="2026-08-21T01:00:00Z",
        )


def test_execution_reverifies_detached_trace_only_activation_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_inputs(tmp_path)
    monkeypatch.setattr(
        module,
        "verify_trace_state_capability",
        lambda **kwargs: {"complete": True, "verification_sha256": "9" * 64},
    )
    request = build_trace_only_activation_request(
        capability_report_path=paths["capability"],
        capability_raw_root=tmp_path,
        provider_registry_path=paths["registry"],
        trace_targets_path=paths["trace"],
        activation_start_utc="2026-08-21T00:00:00Z",
        activation_expires_utc="2026-08-22T00:00:00Z",
        retry_limit=0,
    )
    approval = build_trace_state_activation_approval(
        request=request, signer_principal=PRINCIPAL
    )
    approval_path, signature_path, allowed_path = _sign(tmp_path, approval)
    verification = verify_trace_state_activation(
        request=request,
        approval_path=approval_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_path,
        expected_principal=PRINCIPAL,
        verification_time_utc="2026-08-21T01:00:00Z",
    )
    verification_path = tmp_path / "activation-verification.json"
    verification_path.write_text(json.dumps(verification), encoding="utf-8")

    reverified = reverify_trace_activation_for_execution(
        activation_verification_path=verification_path,
        request=request,
        approval_path=approval_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_path,
        expected_principal=PRINCIPAL,
        verification_time_utc="2026-08-21T01:00:00Z",
    )

    assert reverified == verification


@pytest.mark.parametrize(
    ("script_name", "required_flag"),
    [
        ("build_stage2_control_trace_state_activation_request.py", "--trace-targets"),
        ("build_stage2_control_trace_only_activation_request.py", "--trace-targets"),
        ("build_stage2_control_trace_state_activation_approval.py", "--signer-principal"),
        ("verify_stage2_control_trace_state_activation.py", "--allowed-signers"),
        ("verify_stage2_control_trace_only_activation.py", "--allowed-signers"),
    ],
)
def test_activation_clis_expose_exact_scope_inputs(script_name: str, required_flag: str):
    script = Path(__file__).resolve().parents[1] / script_name
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert required_flag in result.stdout
    assert "--selection" not in result.stdout
    assert "--qualification" not in result.stdout
