from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_derived_state_acquisition import (
    DERIVED_STATE_CHECKPOINT_NAMESPACE,
    canonical_derived_state_checkpoint_payload,
    execute_control_derived_state_acquisition,
    verify_derived_state_checkpoint_signature,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class Provider:
    def __init__(self, provider_id: str, family: str):
        self.provider_id = provider_id
        self.provider_family = family

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        result: object
        if method == "eth_getCode":
            result = "0x6001600055"
        else:
            result = "0x" + "00" * 12 + "44" * 20
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
            observed_at_utc="2026-08-23T00:00:00Z",
        )


def _inputs(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, Provider]]:
    selector = {"blockHash": "0x" + "aa" * 32, "requireCanonical": True}
    targets = []
    for index, (role, address, method, params) in enumerate(
        (
            ("direct_implementation_runtime_code", "0x" + "22" * 20, "eth_getCode", ["0x" + "22" * 20, selector]),
            ("beacon_implementation_call", "0x" + "33" * 20, "eth_call", [{"to": "0x" + "33" * 20, "data": "0x5c60da1b"}, selector]),
        ),
        start=1,
    ):
        target: dict[str, object] = {
            "schema_version": "stage2_control_derived_state_target.v1",
            "target_id": "derived-state:" + str(index) * 64,
            "case_id": "case-1",
            "chain": "ethereum",
            "chain_address": "ethereum:0x" + "11" * 20,
            "source_base_state_target_id": "base-state:" + "4" * 64,
            "base_state_result_sha256": "5" * 64,
            "derived_role": role,
            "derived_address": address,
            "evidence_block_number": 100,
            "evidence_block_hash": selector["blockHash"],
            "calls": [
                {"provider_id": provider, "operator_family": family, "method": method, "params": params}
                for provider, family in (("eth-a", "family-a"), ("eth-b", "family-b"))
            ],
            "call_count": 2,
            "phase": "RESULT_BOUND_DERIVED_STATE_READS_ONLY",
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        target["target_sha256"] = _canonical_sha(target)
        targets.append(target)
    payload: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_targets.v1",
        "decision": "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION",
        "target_count": 2,
        "call_count": 4,
        "complete": True,
        "targets": targets,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    payload["targets_sha256"] = _canonical_sha(payload)
    targets_path = tmp_path / "targets.json"
    targets_path.write_text(json.dumps(payload), encoding="utf-8")
    scopes = []
    for target in targets:
        for call in target["calls"]:
            scope: dict[str, object] = {
                "target_type": "derived_state",
                "target_id": target["target_id"],
                "target_sha256": target["target_sha256"],
                "base_state_result_sha256": target["base_state_result_sha256"],
                "derived_role": target["derived_role"],
                "case_id": target["case_id"],
                "chain": target["chain"],
                "chain_address": target["chain_address"],
                "provider_id": call["provider_id"],
                "operator_family": call["operator_family"],
                "method": call["method"],
                "params": call["params"],
                "params_sha256": _canonical_sha(call["params"]),
            }
            scope["call_scope_sha256"] = _canonical_sha(scope)
            scopes.append(scope)
    activation: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_activation_verification.v1",
        "decision": "DERIVED_STATE_RPC_ACTIVATION_VERIFIED",
        "derived_state_targets_file_sha256": hashlib.sha256(targets_path.read_bytes()).hexdigest(),
        "rpc_call_scopes": scopes,
        "rpc_call_scope_count": len(scopes),
        "maximum_request_count": len(scopes),
        "activation_start_utc": "2026-08-23T00:00:00Z",
        "activation_expires_utc": "2026-08-24T00:00:00Z",
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    activation["verification_sha256"] = _canonical_sha(activation)
    providers = {"eth-a": Provider("eth-a", "family-a"), "eth-b": Provider("eth-b", "family-b")}
    return targets_path, activation, providers


def test_executes_only_frozen_phase2_reads_and_checkpoints(tmp_path: Path) -> None:
    targets, activation, providers = _inputs(tmp_path)

    result = execute_control_derived_state_acquisition(
        activation=activation,
        derived_state_targets_path=targets,
        output_root=tmp_path / "run",
        transport=lambda provider, method, params: providers[provider].call(method, params),
        now_utc="2026-08-23T01:00:00Z",
    )

    assert result["status"] == "COMPLETE"
    assert result["completed_target_count"] == 2
    normalized = json.loads(Path(result["normalized_results_path"]).read_text())
    by_role = {row["derived_role"]: row for row in normalized["targets"]}
    assert by_role["direct_implementation_runtime_code"]["runtime_code_hash"]
    assert by_role["beacon_implementation_call"]["beacon_implementation_address"] == "0x" + "44" * 20
    assert all(row["selection_authorized"] is False for row in normalized["targets"])
    assert len(Path(result["event_ledger_path"]).read_text().splitlines()) == 4


def test_phase2_cli_requires_checkpoint_signature_inputs() -> None:
    script = Path(__file__).parents[1] / "run_stage2_control_derived_state_acquisition.py"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert "--checkpoint-signing-key" in result.stdout
    assert "--checkpoint-signer-principal" in result.stdout
    assert "--checkpoint-allowed-signers" in result.stdout
    assert "--checkpoint-verification-output" in result.stdout


def test_phase2_checkpoint_signature_uses_distinct_namespace(tmp_path: Path) -> None:
    targets, activation, providers = _inputs(tmp_path)
    result = execute_control_derived_state_acquisition(
        activation=activation,
        derived_state_targets_path=targets,
        output_root=tmp_path / "run",
        transport=lambda provider, method, params: providers[provider].call(method, params),
        now_utc="2026-08-23T01:00:00Z",
    )
    checkpoint_path = Path(result["checkpoint_path"])
    checkpoint = json.loads(checkpoint_path.read_text())
    payload_path = tmp_path / "checkpoint-signing-payload.json"
    payload_path.write_bytes(canonical_derived_state_checkpoint_payload(checkpoint))
    key_path = tmp_path / "checkpoint-key"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
        check=True,
    )
    signature_path = Path(str(payload_path) + ".sig")
    subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(key_path),
            "-n",
            DERIVED_STATE_CHECKPOINT_NAMESPACE,
            str(payload_path),
        ],
        check=True,
        capture_output=True,
    )
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f"local-test {key_path.with_suffix('.pub').read_text()}")

    verification = verify_derived_state_checkpoint_signature(
        checkpoint_path=checkpoint_path,
        signature_path=signature_path,
        allowed_signers_path=allowed,
        expected_principal="local-test",
    )

    assert verification["complete"] is True
    assert verification["signature_namespace"] == DERIVED_STATE_CHECKPOINT_NAMESPACE
    assert verification["checkpoint_sha256"] == checkpoint["checkpoint_sha256"]
    assert verification["selection_authorized"] is False
