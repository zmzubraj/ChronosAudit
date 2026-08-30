from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

from chronosaudit_stage2.onchain import (
    ProviderObservation,
    normalize_hex,
    provider_consensus,
    storage_word_to_address,
    strip_solidity_metadata,
)

from .control_cutoff_state_acquisition import (
    ControlCutoffStateAcquisitionError,
    STATE_CHECKPOINT_SCHEMA,
    _ActivatedProvider,
    _RecordingProvider,
    _canonical_sha,
    _file_sha,
    _load_json,
    _ordinary,
    _persist_batch_progress,
    canonical_checkpoint_payload,
)


DERIVED_STATE_CHECKPOINT_NAMESPACE = (
    "chronosaudit-stage2-control-derived-state-acquisition-local-test-v1"
)


class ControlDerivedStateAcquisitionError(ValueError):
    """Raised when an exact Phase 2 target cannot be acquired safely."""


def canonical_derived_state_checkpoint_payload(
    checkpoint: Mapping[str, object],
) -> bytes:
    """Return the exact bytes signed for a Phase 2 mechanical checkpoint."""
    return canonical_checkpoint_payload(checkpoint)


def verify_derived_state_checkpoint_signature(
    *,
    checkpoint_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
) -> dict[str, object]:
    """Verify a purpose-separated local-test signature on one Phase 2 checkpoint."""
    checkpoint_file = _ordinary(checkpoint_path, "checkpoint")
    signature_file = _ordinary(signature_path, "signature")
    allowed_signers_file = _ordinary(allowed_signers_path, "allowed_signers")
    checkpoint = _load_json(checkpoint_file, "checkpoint")
    if checkpoint.get("schema_version") != STATE_CHECKPOINT_SCHEMA:
        raise ControlDerivedStateAcquisitionError("checkpoint_schema_invalid")
    material = {
        key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"
    }
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(material):
        raise ControlDerivedStateAcquisitionError("checkpoint_self_hash_invalid")
    for flag in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if checkpoint.get(flag) is not False:
            raise ControlDerivedStateAcquisitionError(f"checkpoint_{flag}_invalid")
    principal = expected_principal.strip()
    if not principal:
        raise ControlDerivedStateAcquisitionError("signer_principal_invalid")
    verification = subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed_signers_file),
            "-I",
            principal,
            "-n",
            DERIVED_STATE_CHECKPOINT_NAMESPACE,
            "-s",
            str(signature_file),
        ],
        input=canonical_derived_state_checkpoint_payload(checkpoint),
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise ControlDerivedStateAcquisitionError("checkpoint_signature_invalid")
    result: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_checkpoint_verification.v1",
        "complete": True,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "checkpoint_file_sha256": _file_sha(checkpoint_file),
        "signature_sha256": _file_sha(signature_file),
        "allowed_signers_sha256": _file_sha(allowed_signers_file),
        "signature_namespace": DERIVED_STATE_CHECKPOINT_NAMESPACE,
        "signer_principal": principal,
        "status": checkpoint["status"],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
        "errors": [],
    }
    result["verification_sha256"] = _canonical_sha(result)
    return result


def _targets(path: Path) -> list[dict[str, object]]:
    payload = _load_json(path, "derived_state_targets")
    if (
        payload.get("schema_version") != "stage2_control_derived_state_targets.v1"
        or payload.get("decision")
        != "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION"
        or payload.get("complete") is not True
    ):
        raise ControlDerivedStateAcquisitionError("derived_state_targets_invalid")
    material = {key: value for key, value in payload.items() if key != "targets_sha256"}
    if payload.get("targets_sha256") != _canonical_sha(material):
        raise ControlDerivedStateAcquisitionError("derived_state_targets_self_hash_invalid")
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        raise ControlDerivedStateAcquisitionError("derived_state_targets_invalid")
    if payload.get("target_count") != len(rows):
        raise ControlDerivedStateAcquisitionError("derived_state_target_count_invalid")
    seen: set[str] = set()
    for row in rows:
        row_material = {key: value for key, value in row.items() if key != "target_sha256"}
        if row.get("target_sha256") != _canonical_sha(row_material):
            raise ControlDerivedStateAcquisitionError("derived_state_target_self_hash_invalid")
        target_id = str(row.get("target_id", ""))
        if not target_id or target_id in seen:
            raise ControlDerivedStateAcquisitionError("derived_state_target_identity_invalid")
        seen.add(target_id)
    return sorted(rows, key=lambda row: str(row["target_id"]))


def _validate_activation(activation: Mapping[str, object], targets_file_sha: str) -> None:
    if activation.get("schema_version") != "stage2_control_derived_state_activation_verification.v1":
        raise ControlDerivedStateAcquisitionError("activation_schema_invalid")
    if activation.get("decision") != "DERIVED_STATE_RPC_ACTIVATION_VERIFIED":
        raise ControlDerivedStateAcquisitionError("activation_not_verified")
    material = {key: value for key, value in activation.items() if key != "verification_sha256"}
    if activation.get("verification_sha256") != _canonical_sha(material):
        raise ControlDerivedStateAcquisitionError("activation_self_hash_invalid")
    if activation.get("derived_state_targets_file_sha256") != targets_file_sha:
        raise ControlDerivedStateAcquisitionError("derived_state_targets_hash_mismatch")
    if activation.get("rpc_authorized") is not True:
        raise ControlDerivedStateAcquisitionError("rpc_not_authorized")
    for flag in (
        "acquisition_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if activation.get(flag) is not False:
            raise ControlDerivedStateAcquisitionError(f"activation_{flag}_invalid")


def _code(value: object) -> str:
    try:
        return normalize_hex(str(value))
    except ValueError as exc:
        raise ControlDerivedStateAcquisitionError("runtime_code_invalid") from exc


def _beacon_implementation(value: object) -> str:
    try:
        address = storage_word_to_address(value)
    except (TypeError, ValueError) as exc:
        raise ControlDerivedStateAcquisitionError("beacon_implementation_invalid") from exc
    if address is None:
        raise ControlDerivedStateAcquisitionError("beacon_implementation_zero")
    return address


def acquire_derived_state_target(
    *,
    target: Mapping[str, object],
    providers: list[object],
    raw_root: Path,
) -> dict[str, object]:
    families = {
        str(getattr(provider, "provider_family", "")).strip().lower()
        for provider in providers
    }
    if "" in families or "unverified" in families or len(families) < 2:
        raise ControlDerivedStateAcquisitionError("provider_family_independence")
    calls = target.get("calls")
    if not isinstance(calls, list) or len(calls) != 2:
        raise ControlDerivedStateAcquisitionError("derived_state_calls_invalid")
    methods = {str(call.get("method", "")) for call in calls if isinstance(call, Mapping)}
    params_values = [call.get("params") for call in calls if isinstance(call, Mapping)]
    if len(methods) != 1 or len(params_values) != 2 or params_values[0] != params_values[1]:
        raise ControlDerivedStateAcquisitionError("derived_state_calls_invalid")
    method = next(iter(methods))
    role = str(target.get("derived_role", ""))
    expected_method = "eth_call" if role == "beacon_implementation_call" else "eth_getCode"
    if method != expected_method:
        raise ControlDerivedStateAcquisitionError("derived_state_method_invalid")
    evidence: list[dict[str, str]] = []
    recording = [_RecordingProvider(provider, raw_root, evidence) for provider in providers]
    normalizer = _beacon_implementation if method == "eth_call" else _code
    consensus = provider_consensus(
        recording,
        method,
        list(params_values[0]),
        normalizer,
        require_distinct_provider_families=True,
    )
    if consensus.get("status") != "consensus":
        raise ControlDerivedStateAcquisitionError("derived_state_disagreement")
    value = consensus.get("value")
    result: dict[str, object] = {
        "schema_version": "stage2_control_derived_state_result.v1",
        "status": "complete",
        "phase": "RESULT_BOUND_DERIVED_STATE_READS_ONLY",
        "target_id": target["target_id"],
        "target_sha256": target["target_sha256"],
        "case_id": target["case_id"],
        "chain": target["chain"],
        "chain_address": target["chain_address"],
        "source_base_state_target_id": target["source_base_state_target_id"],
        "base_state_result_sha256": target["base_state_result_sha256"],
        "derived_role": role,
        "derived_address": target["derived_address"],
        "evidence_block_number": target["evidence_block_number"],
        "evidence_block_hash": target["evidence_block_hash"],
        "provider_agreement": True,
        "provider_families": sorted(families),
        "eip1898_pinned": True,
        "raw_evidence_hashes": [row["sha256"] for row in evidence],
        "raw_evidence": evidence,
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    if method == "eth_getCode":
        code = str(value)
        stripped, metadata_status = strip_solidity_metadata(code)
        result.update(
            {
                "runtime_code_size": len(bytes.fromhex(code[2:])),
                "runtime_code_hash": hashlib.sha256(bytes.fromhex(code[2:])).hexdigest(),
                "metadata_stripped_code_hash": hashlib.sha256(bytes.fromhex(stripped[2:])).hexdigest(),
                "metadata_status": metadata_status,
            }
        )
    else:
        result["beacon_implementation_address"] = value
    result["result_sha256"] = _canonical_sha(result)
    return result


def execute_control_derived_state_acquisition(
    *,
    activation: Mapping[str, object],
    derived_state_targets_path: Path,
    output_root: Path,
    transport: Callable[[str, str, list[object]], ProviderObservation],
    now_utc: str,
) -> dict[str, object]:
    targets_file = _ordinary(derived_state_targets_path, "derived_state_targets")
    targets_file_sha = _file_sha(targets_file)
    _validate_activation(activation, targets_file_sha)
    targets = _targets(targets_file)
    output = output_root.expanduser()
    if output.is_symlink():
        raise ControlDerivedStateAcquisitionError("output_root_symlink")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    ledger_path = output / "cutoff-state-events.jsonl"
    if ledger_path.exists():
        raise ControlDerivedStateAcquisitionError("existing_run_requires_resume")
    raw_root = output / "raw"
    raw_root.mkdir()
    run_state: dict[str, object] = {
        "sequence": 0,
        "request_count": 0,
        "used_sequences": set(),
        "event_tip_sha256": None,
    }
    target_results: list[dict[str, object]] = []
    scopes = activation.get("rpc_call_scopes")
    if not isinstance(scopes, list):
        raise ControlDerivedStateAcquisitionError("rpc_call_scopes_invalid")
    for target in targets:
        target_scopes = [
            scope
            for scope in scopes
            if isinstance(scope, Mapping)
            and scope.get("target_type") == "derived_state"
            and scope.get("target_id") == target["target_id"]
        ]
        bindings = {
            str(scope["provider_id"]): str(scope["operator_family"])
            for scope in target_scopes
        }
        if len(bindings) != 2 or len(set(bindings.values())) != 2:
            raise ControlDerivedStateAcquisitionError("provider_family_independence")
        providers = [
            _ActivatedProvider(
                provider_id=provider_id,
                provider_family=family,
                target=target,
                activation=activation,
                transport=transport,
                now_utc=now_utc,
                output=output,
                raw_root=raw_root,
                ledger_path=ledger_path,
                run_state=run_state,
            )
            for provider_id, family in sorted(bindings.items())
        ]
        try:
            projection = acquire_derived_state_target(
                target=target, providers=providers, raw_root=raw_root
            )
            row = {**projection, "disposition": "complete"}
        except (ControlDerivedStateAcquisitionError, ControlCutoffStateAcquisitionError, ValueError) as exc:
            row = {
                "target_id": target["target_id"],
                "case_id": target["case_id"],
                "chain": target["chain"],
                "chain_address": target["chain_address"],
                "target_sha256": target["target_sha256"],
                "derived_role": target["derived_role"],
                "base_state_result_sha256": target["base_state_result_sha256"],
                "disposition": str(exc),
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            }
            row["record_sha256"] = _canonical_sha(row)
        target_results.append(row)
        _persist_batch_progress(
            output=output,
            ledger_path=ledger_path,
            activation_sha256=str(activation["verification_sha256"]),
            targets_sha256=targets_file_sha,
            target_count=len(targets),
            target_results=target_results,
            run_state=run_state,
        )
    results, checkpoint, status = _persist_batch_progress(
        output=output,
        ledger_path=ledger_path,
        activation_sha256=str(activation["verification_sha256"]),
        targets_sha256=targets_file_sha,
        target_count=len(targets),
        target_results=target_results,
        run_state=run_state,
    )
    summary = {
        "status": status,
        "target_count": len(targets),
        "completed_target_count": results["completed_target_count"],
        "dispositions": results["dispositions"],
        "checkpoint_path": str(output / "checkpoint.json"),
        "normalized_results_path": str(output / "normalized-cutoff-state-results.json"),
        "event_ledger_path": str(ledger_path),
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    return summary
