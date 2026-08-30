from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from chronosaudit_stage2.onchain import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    ProviderObservation,
)
from chronosaudit_stage2.public_acquisition.control_cutoff_state_acquisition import (
    CHECKPOINT_NAMESPACE,
    ControlCutoffStateAcquisitionError,
    CutoffStateTarget,
    acquire_base_state,
    acquire_cutoff_state,
    canonical_checkpoint_payload,
    execute_control_cutoff_state_acquisition,
    resume_cutoff_state_acquisition,
    verify_cutoff_state_checkpoint_signature,
)


ADDRESS = "0x" + "11" * 20
IMPLEMENTATION = "0x" + "22" * 20
EVIDENCE_HASH = "0x" + "aa" * 32
NEXT_HASH = "0x" + "bb" * 32
ZERO_WORD = "0x" + "00" * 32
IMPLEMENTATION_WORD = "0x" + "00" * 12 + IMPLEMENTATION[2:]
IMPLEMENTATION_CODE = "0x60016000"
IMPLEMENTATION_CODE_HASH = hashlib.sha256(bytes.fromhex(IMPLEMENTATION_CODE[2:])).hexdigest()


class StateProvider:
    def __init__(self, provider_id: str, family: str, *, code: str = "0x6000",
                 implementation_word: str = IMPLEMENTATION_WORD) -> None:
        self.provider_id = provider_id
        self.provider_family = family
        self.code = code
        self.implementation_word = implementation_word

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        error = None
        if method == "eth_getBlockByNumber":
            number = int(str(params[0]), 16)
            result = (
                {"number": "0x9", "hash": EVIDENCE_HASH, "timestamp": "0x5a"}
                if number == 9
                else {"number": "0xa", "hash": NEXT_HASH, "timestamp": "0x6e"}
            )
        elif method == "eth_getCode":
            result = IMPLEMENTATION_CODE if str(params[0]).lower() == IMPLEMENTATION else self.code
        elif method == "eth_getStorageAt" and params[1] == EIP1967_IMPLEMENTATION_SLOT:
            result = self.implementation_word
        elif method == "eth_getStorageAt" and params[1] in {
            EIP1967_BEACON_SLOT,
            EIP1967_ADMIN_SLOT,
        }:
            result = ZERO_WORD
        else:
            result = None
            error = "unexpected_method"
        return ProviderObservation(
            provider_id=self.provider_id,
            method=method,
            params=params,
            result=result,
            observed_at_unix=1,
            error=error,
            response_sha256="a" * 64,
            request_sha256="b" * 64,
            observed_at_utc="2026-08-21T01:00:00Z",
        )


def target() -> CutoffStateTarget:
    return CutoffStateTarget(
        target_id="state-1",
        case_id="case-1",
        chain="ethereum",
        chain_address=f"ethereum:{ADDRESS}",
        cutoff_timestamp=100,
        evidence_block_number=9,
        evidence_block_hash=EVIDENCE_HASH,
        next_block_number=10,
        next_block_hash=NEXT_HASH,
        pair_scope_record_sha256="1" * 64,
        denominator_record_sha256="2" * 64,
        deployment_result_sha256="3" * 64,
    )


def providers() -> list[StateProvider]:
    return [
        StateProvider("provider-a", "family-a"),
        StateProvider("provider-b", "family-b"),
    ]


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _batch_inputs(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, StateProvider]]:
    selector = {"blockHash": EVIDENCE_HASH, "requireCanonical": True}
    call_specs: list[dict[str, object]] = []
    for provider_id, family in (("provider-a", "family-a"), ("provider-b", "family-b")):
        for method, params in (
            ("eth_getBlockByNumber", ["0x9", False]),
            ("eth_getBlockByNumber", ["0xa", False]),
            ("eth_getCode", [ADDRESS, selector]),
            ("eth_getStorageAt", [ADDRESS, EIP1967_IMPLEMENTATION_SLOT, selector]),
            ("eth_getStorageAt", [ADDRESS, EIP1967_BEACON_SLOT, selector]),
            ("eth_getStorageAt", [ADDRESS, EIP1967_ADMIN_SLOT, selector]),
            ("eth_getCode", [IMPLEMENTATION, selector]),
        ):
            call_specs.append({
                "provider_id": provider_id,
                "operator_family": family,
                "method": method,
                "params": params,
            })
    target_row = {**target().__dict__, "calls": call_specs}
    targets = {
        "schema_version": "stage2_control_state_targets.v1",
        "targets": [target_row],
    }
    targets_path = tmp_path / "state-targets.json"
    targets_path.write_text(json.dumps(targets), encoding="utf-8")
    scopes: list[dict[str, object]] = []
    for call in call_specs:
        scope = {
            "target_type": "state",
            "target_id": "state-1",
            "case_id": "case-1",
            "chain": "ethereum",
            "chain_address": f"ethereum:{ADDRESS}",
            **call,
            "params_sha256": _canonical_sha(call["params"]),
        }
        scope["call_scope_sha256"] = _canonical_sha(scope)
        scopes.append(scope)
    activation: dict[str, object] = {
        "schema_version": "stage2_control_trace_state_activation_verification.v1",
        "decision": "TRACE_STATE_RPC_ACTIVATION_VERIFIED",
        "rpc_authorized": True,
        "acquisition_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "activation_start_utc": "2026-08-21T00:00:00Z",
        "activation_expires_utc": "2026-08-22T00:00:00Z",
        "retry_limit": 0,
        "maximum_request_count": len(scopes),
        "state_targets_sha256": hashlib.sha256(targets_path.read_bytes()).hexdigest(),
        "rpc_call_scopes": scopes,
    }
    activation["verification_sha256"] = _canonical_sha(activation)
    provider_map = {provider.provider_id: provider for provider in providers()}
    return targets_path, activation, provider_map


def test_cutoff_state_uses_last_block_not_after_cutoff(tmp_path: Path):
    result = acquire_cutoff_state(
        target=target(),
        providers=providers(),
        raw_root=tmp_path / "raw",
    )
    assert result["evidence_block_timestamp"] == 90
    assert result["evidence_block_timestamp"] <= result["cutoff_timestamp"]
    assert result["next_block_timestamp"] == 110
    assert result["next_block_timestamp"] > result["cutoff_timestamp"]
    assert result["evidence_block_hash"] == EVIDENCE_HASH
    assert result["provider_agreement"] is True


def test_eip1967_proxy_and_implementation_are_cutoff_block_bound(tmp_path: Path):
    result = acquire_cutoff_state(
        target=target(),
        providers=providers(),
        raw_root=tmp_path / "raw",
    )
    assert result["status"] == "complete"
    assert result["proxy_status"] == "proxy"
    assert result["proxy_family"] == "eip1967_implementation"
    assert result["implementation_address"] == IMPLEMENTATION
    assert result["implementation_code_hash"] == IMPLEMENTATION_CODE_HASH
    assert result["runtime_code_size"] == 2
    assert result["clone_family"] == IMPLEMENTATION_CODE_HASH
    assert result["raw_evidence_hashes"]


def test_cutoff_block_provider_disagreement_fails_closed(tmp_path: Path):
    mismatched = providers()

    class MismatchProvider(StateProvider):
        def call(self, method: str, params: list[object]) -> ProviderObservation:
            observation = super().call(method, params)
            if method == "eth_getBlockByNumber" and int(str(params[0]), 16) == 9:
                return ProviderObservation(
                    self.provider_id,
                    method,
                    params,
                    {"number": "0x9", "hash": "0x" + "cc" * 32, "timestamp": "0x5a"},
                    1,
                    None,
                )
            return observation

    mismatched[1] = MismatchProvider("provider-b", "family-b")
    with pytest.raises(ControlCutoffStateAcquisitionError, match="evidence_block_disagreement"):
        acquire_cutoff_state(
            target=target(),
            providers=mismatched,
            raw_root=tmp_path / "raw",
        )


def test_base_state_transport_error_is_not_labeled_value_disagreement(tmp_path: Path):
    class TimeoutProvider(StateProvider):
        def call(self, method: str, params: list[object]) -> ProviderObservation:
            observation = super().call(method, params)
            if method == "eth_getCode":
                return ProviderObservation(
                    provider_id=self.provider_id,
                    method=method,
                    params=params,
                    result=None,
                    observed_at_unix=1,
                    error="TimeoutError: read operation timed out",
                    provider_family=self.provider_family,
                    observed_at_utc="2026-08-21T01:00:00Z",
                )
            return observation

    with pytest.raises(
        ControlCutoffStateAcquisitionError,
        match="runtime_code_provider_error",
    ):
        acquire_base_state(
            target=target(),
            providers=[
                StateProvider("provider-a", "family-a"),
                TimeoutProvider("provider-b", "family-b"),
            ],
            raw_root=tmp_path / "raw",
        )


def test_same_family_fails_before_state_reads(tmp_path: Path):
    same_family = [
        StateProvider("provider-a", "shared"),
        StateProvider("provider-b", "shared"),
    ]
    with pytest.raises(ControlCutoffStateAcquisitionError, match="provider_family_independence"):
        acquire_cutoff_state(
            target=target(),
            providers=same_family,
            raw_root=tmp_path / "raw",
        )


def test_unrecognized_proxy_mechanism_is_explicit_unknown(tmp_path: Path):
    ordinary = [
        StateProvider("provider-a", "family-a", implementation_word=ZERO_WORD),
        StateProvider("provider-b", "family-b", implementation_word=ZERO_WORD),
    ]
    result = acquire_cutoff_state(
        target=target(), providers=ordinary, raw_root=tmp_path / "raw"
    )
    assert result["proxy_status"] == "unknown"
    assert result["proxy_family"] == "unknown"
    assert result["field_statuses"]["proxy_classification"] == "unavailable"


def test_result_self_hash_is_deterministic_across_output_roots(tmp_path: Path):
    first = acquire_cutoff_state(
        target=target(), providers=providers(), raw_root=tmp_path / "one"
    )
    second = acquire_cutoff_state(
        target=target(), providers=providers(), raw_root=tmp_path / "two"
    )
    assert first["result_sha256"] == second["result_sha256"]
    material = {key: value for key, value in first.items() if key != "result_sha256"}
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    assert first["result_sha256"] == hashlib.sha256(encoded).hexdigest()


def test_agreed_numeric_block_is_not_requeried_before_eip1898_reads(tmp_path: Path):
    class CountingProvider(StateProvider):
        def __init__(self, provider_id: str, family: str) -> None:
            super().__init__(provider_id, family)
            self.calls: list[tuple[str, list[object]]] = []

        def call(self, method: str, params: list[object]) -> ProviderObservation:
            self.calls.append((method, params))
            return super().call(method, params)

    counted = [
        CountingProvider("provider-a", "family-a"),
        CountingProvider("provider-b", "family-b"),
    ]
    acquire_cutoff_state(
        target=target(), providers=counted, raw_root=tmp_path / "raw"
    )
    for provider in counted:
        evidence_reads = [
            params
            for method, params in provider.calls
            if method == "eth_getBlockByNumber" and params[0] == "0x9"
        ]
        assert len(evidence_reads) == 1
        historical_reads = [
            params
            for method, params in provider.calls
            if method in {"eth_getCode", "eth_getStorageAt", "eth_call"}
        ]
        assert historical_reads
        assert all(
            isinstance(params[-1], dict)
            and params[-1] == {"blockHash": EVIDENCE_HASH, "requireCanonical": True}
            for params in historical_reads
        )


def test_phase1_base_state_never_reads_a_derived_address(tmp_path: Path):
    class CountingProvider(StateProvider):
        def __init__(self, provider_id: str, family: str) -> None:
            super().__init__(provider_id, family)
            self.calls: list[tuple[str, list[object]]] = []

        def call(self, method: str, params: list[object]) -> ProviderObservation:
            self.calls.append((method, params))
            return super().call(method, params)

    counted = [
        CountingProvider("provider-a", "family-a"),
        CountingProvider("provider-b", "family-b"),
    ]
    result = acquire_base_state(
        target=target(), providers=counted, raw_root=tmp_path / "raw"
    )

    assert result["phase"] == "FIXED_ADDRESS_BASE_STATE_DISCOVERY_ONLY"
    assert result["direct_implementation_address"] == IMPLEMENTATION
    assert result["derived_address_reads_authorized"] is False
    for provider in counted:
        assert len(provider.calls) == 6
        assert not any(method == "eth_call" for method, _ in provider.calls)
        assert not any(
            method == "eth_getCode" and str(params[0]).lower() == IMPLEMENTATION
            for method, params in provider.calls
        )


def test_batch_accepts_separate_base_state_activation_and_targets(tmp_path: Path):
    targets_path, activation, provider_map = _batch_inputs(tmp_path)
    targets = json.loads(targets_path.read_text())
    targets["schema_version"] = "stage2_control_base_state_targets.v1"
    targets["targets"][0]["cutoff_timestamp"] = "1970-01-01T00:01:40Z"
    targets["targets"][0]["cutoff_timestamp_unix"] = 100
    targets["targets"][0]["calls"] = [
        call
        for call in targets["targets"][0]["calls"]
        if not (
            call["method"] == "eth_getCode"
            and str(call["params"][0]).lower() == IMPLEMENTATION
        )
    ]
    targets_path.write_text(json.dumps(targets), encoding="utf-8")
    activation["schema_version"] = (
        "stage2_control_base_state_activation_verification.v1"
    )
    activation["decision"] = "BASE_STATE_RPC_ACTIVATION_VERIFIED"
    activation["derived_address_reads_authorized"] = False
    activation["base_state_targets_file_sha256"] = hashlib.sha256(
        targets_path.read_bytes()
    ).hexdigest()
    activation.pop("state_targets_sha256")
    activation["rpc_call_scopes"] = [
        {**scope, "target_type": "base_state"}
        for scope in activation["rpc_call_scopes"]
        if not (
            scope["method"] == "eth_getCode"
            and str(scope["params"][0]).lower() == IMPLEMENTATION
        )
    ]
    for scope in activation["rpc_call_scopes"]:
        material = {
            key: value for key, value in scope.items() if key != "call_scope_sha256"
        }
        scope["call_scope_sha256"] = _canonical_sha(material)
    activation["maximum_request_count"] = len(activation["rpc_call_scopes"])
    activation["verification_sha256"] = _canonical_sha(
        {
            key: value
            for key, value in activation.items()
            if key != "verification_sha256"
        }
    )

    def transport(provider_id: str, method: str, params: list[object]):
        return provider_map[provider_id].call(method, params)

    result = execute_control_cutoff_state_acquisition(
        activation=activation,
        state_targets_path=targets_path,
        output_root=tmp_path / "base-run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["status"] == "COMPLETE"
    checkpoint = json.loads(Path(result["checkpoint_path"]).read_text())
    assert checkpoint["request_count"] == 12
    normalized = json.loads(Path(result["normalized_results_path"]).read_text())
    assert normalized["targets"][0]["phase"] == (
        "FIXED_ADDRESS_BASE_STATE_DISCOVERY_ONLY"
    )


def test_batch_acquisition_emits_complete_checkpoint_and_event_chain(tmp_path: Path):
    targets_path, activation, provider_map = _batch_inputs(tmp_path)

    def transport(provider_id: str, method: str, params: list[object]):
        return provider_map[provider_id].call(method, params)

    result = execute_control_cutoff_state_acquisition(
        activation=activation,
        state_targets_path=targets_path,
        output_root=tmp_path / "run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["status"] == "COMPLETE"
    assert result["completed_target_count"] == 1
    assert result["selection_authorized"] is False
    checkpoint = json.loads(Path(result["checkpoint_path"]).read_text())
    assert checkpoint["request_count"] == 14
    events = Path(result["event_ledger_path"]).read_text().splitlines()
    assert len(events) == 14
    previous = None
    for line in events:
        event = json.loads(line)
        assert event["previous_event_sha256"] == previous
        previous = event["event_sha256"]
    assert checkpoint["event_tip_sha256"] == previous


def test_batch_transient_provider_error_retries_with_hash_chained_evidence(
    tmp_path: Path,
):
    targets_path, activation, provider_map = _batch_inputs(tmp_path)
    activation["retry_limit"] = 1
    activation["maximum_request_count"] = len(activation["rpc_call_scopes"]) * 2
    activation.pop("verification_sha256")
    activation["verification_sha256"] = _canonical_sha(activation)

    original = provider_map["provider-b"]
    calls = 0

    def transport(provider_id: str, method: str, params: list[object]):
        nonlocal calls
        if provider_id == "provider-b" and method == "eth_getCode" and calls == 0:
            calls += 1
            return ProviderObservation(
                provider_id=provider_id,
                method=method,
                params=params,
                result=None,
                observed_at_unix=1,
                error="TimeoutError: read operation timed out",
                provider_family="family-b",
                observed_at_utc="2026-08-21T01:00:00Z",
            )
        return provider_map[provider_id].call(method, params)

    result = execute_control_cutoff_state_acquisition(
        activation=activation,
        state_targets_path=targets_path,
        output_root=tmp_path / "retry-run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert original.provider_id == "provider-b"
    assert result["status"] == "COMPLETE"
    events = [
        json.loads(line)
        for line in Path(result["event_ledger_path"])
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert any(event["disposition"] == "retrying" for event in events)
    for previous, current in zip(events, events[1:]):
        assert current["previous_event_sha256"] == previous["event_sha256"]


def test_batch_resume_rehashes_results_before_skipping(tmp_path: Path):
    targets_path, activation, provider_map = _batch_inputs(tmp_path)

    def transport(provider_id: str, method: str, params: list[object]):
        return provider_map[provider_id].call(method, params)

    result = execute_control_cutoff_state_acquisition(
        activation=activation,
        state_targets_path=targets_path,
        output_root=tmp_path / "run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    results_path = Path(result["normalized_results_path"])
    results_path.write_text(results_path.read_text() + " ", encoding="utf-8")
    with pytest.raises(ControlCutoffStateAcquisitionError, match="resume_hash_mismatch"):
        resume_cutoff_state_acquisition(
            Path(result["checkpoint_path"]), transport=transport
        )


def test_cutoff_state_checkpoint_uses_distinct_local_test_signature_namespace(
    tmp_path: Path,
):
    targets_path, activation, provider_map = _batch_inputs(tmp_path)

    def transport(provider_id: str, method: str, params: list[object]):
        return provider_map[provider_id].call(method, params)

    result = execute_control_cutoff_state_acquisition(
        activation=activation,
        state_targets_path=targets_path,
        output_root=tmp_path / "run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    checkpoint_path = Path(result["checkpoint_path"])
    checkpoint = json.loads(checkpoint_path.read_text())
    payload_path = tmp_path / "checkpoint-payload.json"
    payload_path.write_bytes(canonical_checkpoint_payload(checkpoint))
    key = tmp_path / "checkpoint-key"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    subprocess.run(
        [
            "/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key),
            "-n", CHECKPOINT_NAMESPACE, str(payload_path),
        ],
        check=True,
        capture_output=True,
    )
    principal = "chronosaudit-cutoff-local-test"
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        f"{principal} {(tmp_path / 'checkpoint-key.pub').read_text().strip()}\n",
        encoding="utf-8",
    )
    verification = verify_cutoff_state_checkpoint_signature(
        checkpoint_path=checkpoint_path,
        signature_path=Path(str(payload_path) + ".sig"),
        allowed_signers_path=allowed,
        expected_principal=principal,
    )
    assert verification["complete"] is True
    assert verification["signature_namespace"] == CHECKPOINT_NAMESPACE
    assert verification["selection_authorized"] is False


def test_cutoff_state_cli_exposes_activation_and_resume_inputs():
    script = Path(__file__).resolve().parents[1] / "run_stage2_control_cutoff_state_acquisition.py"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--activation-verification" in result.stdout
    assert "--state-targets" in result.stdout
    assert "--resume-checkpoint" in result.stdout
    assert "--provider-min-interval" in result.stdout
    assert "--selection" not in result.stdout
    source = script.read_text(encoding="utf-8")
    assert "Activated retries are recorded by the acquisition layer" in source
