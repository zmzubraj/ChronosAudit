from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_trace_acquisition import (
    CHECKPOINT_NAMESPACE,
    ControlTraceAcquisitionError,
    canonical_checkpoint_payload,
    execute_control_trace_acquisition,
    resume_trace_acquisition,
    verify_trace_checkpoint_signature,
)


BLOCK_HASH = "0x" + "aa" * 32
TRANSACTION_HASH = "0x" + "bb" * 32
ADDRESS = "0x" + "22" * 20
CREATOR = "0x" + "11" * 20


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _targets(tmp_path: Path) -> Path:
    path = tmp_path / "trace-targets.json"
    path.write_text(json.dumps({
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
    }), encoding="utf-8")
    return path


def test_retry_schema_requires_reconstruction_before_transport(
    tmp_path: Path,
):
    targets = _targets(tmp_path)
    payload = json.loads(targets.read_text(encoding="utf-8"))
    payload["schema_version"] = "stage2_control_trace_retry_targets.v1"
    targets.write_text(json.dumps(payload), encoding="utf-8")
    activation = _activation(targets)
    transport = FixtureTransport()
    with pytest.raises(ControlTraceAcquisitionError, match="trace_targets_schema_invalid"):
        execute_control_trace_acquisition(
            activation=activation,
            unresolved_trace_path=targets,
            output_root=tmp_path / "run",
            transport=transport,
            now_utc="2026-08-21T01:00:00Z",
        )
    assert transport.calls == []


def test_retry_schema_executes_only_after_reconstruction_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    targets = _targets(tmp_path)
    payload = json.loads(targets.read_text(encoding="utf-8"))
    payload["schema_version"] = "stage2_control_trace_retry_targets.v1"
    targets.write_text(json.dumps(payload), encoding="utf-8")
    import chronosaudit_stage2.public_acquisition.control_trace_retry_overlay as retry_module

    monkeypatch.setattr(
        retry_module,
        "verify_trace_retry_targets",
        lambda **_: {
            "decision": "TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING"
        },
    )
    result = execute_control_trace_acquisition(
        activation=_activation(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=FixtureTransport(),
        now_utc="2026-08-21T01:00:00Z",
        retry_reconstruction_inputs={},
    )
    assert result["status"] == "COMPLETE"


def _activation(targets: Path, *, same_family: bool = False) -> dict[str, object]:
    family_b = "family-a" if same_family else "family-b"
    scopes = [
        {
            "target_type": "trace",
            "target_id": "trace-1",
            "case_id": "case-1",
            "chain": "ethereum",
            "chain_address": f"ethereum:{ADDRESS}",
            "provider_id": "provider-a",
            "operator_family": "family-a",
            "method": "trace_transaction",
            "params": [TRANSACTION_HASH],
        },
        {
            "target_type": "trace",
            "target_id": "trace-1",
            "case_id": "case-1",
            "chain": "ethereum",
            "chain_address": f"ethereum:{ADDRESS}",
            "provider_id": "provider-b",
            "operator_family": family_b,
            "method": "debug_traceTransaction",
            "params": [TRANSACTION_HASH, {"tracer": "callTracer", "timeout": "120s"}],
        },
    ]
    for scope in scopes:
        scope["params_sha256"] = _canonical_sha(scope["params"])
        scope["call_scope_sha256"] = _canonical_sha(scope)
    activation = {
        "schema_version": "stage2_control_trace_state_activation_verification.v1",
        "decision": "TRACE_STATE_RPC_ACTIVATION_VERIFIED",
        "activation_stage": "TRACE_ONLY_PRE_STATE_DERIVATION",
        "unmaterialized_state_calls_authorized": False,
        "request_sha256": "2" * 64,
        "trace_targets_sha256": _sha(targets),
        "state_targets_sha256": None,
        "state_target_count": 0,
        "rpc_call_scopes": scopes,
        "rpc_call_scope_count": 2,
        "retry_limit": 0,
        "maximum_request_count": 2,
        "activation_start_utc": "2026-08-21T00:00:00Z",
        "activation_expires_utc": "2026-08-22T00:00:00Z",
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    activation["verification_sha256"] = _canonical_sha(activation)
    return activation


def _activation_with_retry(targets: Path) -> dict[str, object]:
    activation = _activation(targets)
    activation["retry_limit"] = 1
    activation["maximum_request_count"] = 4
    activation.pop("verification_sha256")
    activation["verification_sha256"] = _canonical_sha(activation)
    return activation


class FixtureTransport:
    def __init__(self, *, parity_address: str | None = ADDRESS,
                 geth_address: str | None = ADDRESS) -> None:
        self.parity_address = parity_address
        self.geth_address = geth_address
        self.calls: list[tuple[str, str, list[object]]] = []

    def __call__(self, provider_id: str, method: str,
                 params: list[object]) -> ProviderObservation:
        self.calls.append((provider_id, method, params))
        if method == "trace_transaction":
            result = [] if self.parity_address is None else [{
                "type": "create",
                "transactionHash": TRANSACTION_HASH,
                "traceAddress": [0],
                "action": {"from": CREATOR, "creationMethod": "create2"},
                "result": {"address": self.parity_address},
            }]
        elif method == "debug_traceTransaction":
            calls = [] if self.geth_address is None else [{
                "type": "CREATE2",
                "from": CREATOR,
                "to": self.geth_address,
            }]
            result = {"type": "CALL", "calls": calls}
        else:
            result = None
        return ProviderObservation(
            provider_id=provider_id,
            method=method,
            params=params,
            result=result,
            observed_at_unix=1,
            error=None,
            response_sha256="a" * 64,
            request_sha256="b" * 64,
            observed_at_utc="2026-08-21T01:00:00Z",
        )


class TransientOnceTransport(FixtureTransport):
    def __call__(self, provider_id: str, method: str,
                 params: list[object]) -> ProviderObservation:
        if not self.calls:
            self.calls.append((provider_id, method, params))
            return ProviderObservation(
                provider_id=provider_id,
                method=method,
                params=params,
                result=None,
                observed_at_unix=1,
                error="temporary timeout",
                response_sha256="c" * 64,
                request_sha256="d" * 64,
                observed_at_utc="2026-08-21T01:00:00Z",
            )
        return super().__call__(provider_id, method, params)


def test_trace_acquisition_requires_cross_family_semantic_agreement(tmp_path: Path):
    targets = _targets(tmp_path)
    transport = FixtureTransport()
    result = execute_control_trace_acquisition(
        activation=_activation(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["status"] == "COMPLETE"
    assert result["completed_target_count"] == 1
    assert result["selection_authorized"] is False
    assert result["stage_promotion_authorized"] is False
    assert result["recovery3_mutation_authorized"] is False
    assert [call[1] for call in transport.calls] == [
        "trace_transaction",
        "debug_traceTransaction",
    ]


def test_resume_rehashes_completed_trace_before_skip(tmp_path: Path):
    targets = _targets(tmp_path)
    first = execute_control_trace_acquisition(
        activation=_activation(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=FixtureTransport(),
        now_utc="2026-08-21T01:00:00Z",
    )
    normalized = Path(first["normalized_results_path"])
    normalized.write_text("{}", encoding="utf-8")

    def no_calls_allowed(*args, **kwargs):
        raise AssertionError("resume must validate before transport")

    with pytest.raises(ControlTraceAcquisitionError, match="resume_hash_mismatch"):
        resume_trace_acquisition(
            Path(first["checkpoint_path"]), transport=no_calls_allowed
        )


def test_complete_resume_is_idempotent_and_does_not_call_transport(tmp_path: Path):
    targets = _targets(tmp_path)
    first = execute_control_trace_acquisition(
        activation=_activation(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=FixtureTransport(),
        now_utc="2026-08-21T01:00:00Z",
    )

    def no_calls_allowed(*args, **kwargs):
        raise AssertionError("completed targets must be skipped")

    resumed = resume_trace_acquisition(
        Path(first["checkpoint_path"]), transport=no_calls_allowed
    )
    assert resumed["status"] == "COMPLETE"
    assert resumed["completed_target_count"] == 1


def test_trace_disagreement_is_terminal_non_authorizing(tmp_path: Path):
    targets = _targets(tmp_path)
    result = execute_control_trace_acquisition(
        activation=_activation(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=FixtureTransport(geth_address="0x" + "99" * 20),
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["status"] == "PARTIAL_NON_AUTHORIZING"
    assert result["completed_target_count"] == 0
    assert result["dispositions"] == {"trace_disagreement": 1}


def test_candidate_missing_is_not_completed(tmp_path: Path):
    targets = _targets(tmp_path)
    result = execute_control_trace_acquisition(
        activation=_activation(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=FixtureTransport(parity_address=None, geth_address=None),
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["completed_target_count"] == 0
    assert result["dispositions"] == {"candidate_missing": 1}


def test_same_family_activation_fails_before_transport(tmp_path: Path):
    targets = _targets(tmp_path)
    transport = FixtureTransport()
    with pytest.raises(ControlTraceAcquisitionError, match="provider_family_independence"):
        execute_control_trace_acquisition(
            activation=_activation(targets, same_family=True),
            unresolved_trace_path=targets,
            output_root=tmp_path / "run",
            transport=transport,
            now_utc="2026-08-21T01:00:00Z",
        )
    assert transport.calls == []


def test_trace_only_activation_rejects_injected_state_scope_before_transport(
    tmp_path: Path,
):
    targets = _targets(tmp_path)
    activation = _activation(targets)
    state_scope = {
        "target_type": "state",
        "target_id": "state-injected",
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": f"ethereum:{ADDRESS}",
        "provider_id": "provider-a",
        "operator_family": "family-a",
        "method": "eth_getCode",
        "params": [ADDRESS, "0xa"],
    }
    state_scope["params_sha256"] = _canonical_sha(state_scope["params"])
    state_scope["call_scope_sha256"] = _canonical_sha(state_scope)
    activation["rpc_call_scopes"].append(state_scope)
    activation["rpc_call_scope_count"] = 3
    activation["maximum_request_count"] = 3
    activation.pop("verification_sha256")
    activation["verification_sha256"] = _canonical_sha(activation)
    transport = FixtureTransport()

    with pytest.raises(ControlTraceAcquisitionError, match="trace_only_scope_invalid"):
        execute_control_trace_acquisition(
            activation=activation,
            unresolved_trace_path=targets,
            output_root=tmp_path / "run",
            transport=transport,
            now_utc="2026-08-21T01:00:00Z",
        )
    assert transport.calls == []


def test_trace_target_hash_tamper_fails_before_transport(tmp_path: Path):
    targets = _targets(tmp_path)
    activation = _activation(targets)
    payload = json.loads(targets.read_text(encoding="utf-8"))
    payload["targets"][0]["transaction_hash"] = "0x" + "ff" * 32
    targets.write_text(json.dumps(payload), encoding="utf-8")
    transport = FixtureTransport()
    with pytest.raises(ControlTraceAcquisitionError, match="trace_targets_hash_mismatch"):
        execute_control_trace_acquisition(
            activation=activation,
            unresolved_trace_path=targets,
            output_root=tmp_path / "run",
            transport=transport,
            now_utc="2026-08-21T01:00:00Z",
        )
    assert transport.calls == []


def test_activation_semantic_tamper_fails_before_transport(tmp_path: Path):
    targets = _targets(tmp_path)
    activation = _activation(targets)
    activation["maximum_request_count"] = 99
    transport = FixtureTransport()
    with pytest.raises(ControlTraceAcquisitionError, match="activation_self_hash_invalid"):
        execute_control_trace_acquisition(
            activation=activation,
            unresolved_trace_path=targets,
            output_root=tmp_path / "run",
            transport=transport,
            now_utc="2026-08-21T01:00:00Z",
        )
    assert transport.calls == []


def test_transient_retry_is_bounded_and_hash_chained(tmp_path: Path):
    targets = _targets(tmp_path)
    transport = TransientOnceTransport()
    result = execute_control_trace_acquisition(
        activation=_activation_with_retry(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["status"] == "COMPLETE"
    assert len(transport.calls) == 3
    events = [
        json.loads(line)
        for line in Path(result["event_ledger_path"]).read_text(encoding="utf-8").splitlines()
    ]
    assert events[0]["disposition"] == "retrying"
    assert events[1]["previous_event_sha256"] == events[0]["event_sha256"]
    assert events[2]["previous_event_sha256"] == events[1]["event_sha256"]


def test_trace_acquisition_cli_exposes_activation_and_resume_inputs():
    script = Path(__file__).resolve().parents[1] / "run_stage2_control_trace_acquisition.py"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--activation-verification" in result.stdout
    assert "--activation-request" in result.stdout
    assert "--activation-approval" in result.stdout
    assert "--activation-signature" in result.stdout
    assert "--activation-allowed-signers" in result.stdout
    assert "--activation-expected-principal" in result.stdout
    assert "--trace-targets" in result.stdout
    assert "--resume-checkpoint" in result.stdout
    assert "--provider-min-interval" in result.stdout
    assert "--checkpoint-signing-key" in result.stdout
    assert "--checkpoint-allowed-signers" in result.stdout
    assert "--selection" not in result.stdout


def test_checkpoint_signature_uses_purpose_specific_namespace(tmp_path: Path):
    targets = _targets(tmp_path)
    result = execute_control_trace_acquisition(
        activation=_activation(targets),
        unresolved_trace_path=targets,
        output_root=tmp_path / "run",
        transport=FixtureTransport(),
        now_utc="2026-08-21T01:00:00Z",
    )
    checkpoint = json.loads(Path(result["checkpoint_path"]).read_text(encoding="utf-8"))
    payload_path = tmp_path / "checkpoint-signing-payload.json"
    payload_path.write_bytes(canonical_checkpoint_payload(checkpoint))
    key = tmp_path / "checkpoint-key"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(
        "checkpoint-test " + (tmp_path / "checkpoint-key.pub").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key),
            "-n", CHECKPOINT_NAMESPACE, str(payload_path),
        ],
        check=True,
        capture_output=True,
    )
    verification = verify_trace_checkpoint_signature(
        checkpoint_path=Path(result["checkpoint_path"]),
        signature_path=Path(str(payload_path) + ".sig"),
        allowed_signers_path=allowed,
        expected_principal="checkpoint-test",
    )
    assert verification["complete"] is True
    assert verification["signature_namespace"] == CHECKPOINT_NAMESPACE
    assert verification["selection_authorized"] is False
