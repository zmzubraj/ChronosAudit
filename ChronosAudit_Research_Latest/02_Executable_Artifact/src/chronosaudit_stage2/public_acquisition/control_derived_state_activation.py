from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from .control_trace_state_activation import (
    ControlTraceStateActivationError,
    authorize_rpc_call,
)
from .providers import ProviderRegistry


REQUEST_SCHEMA = "stage2_control_derived_state_activation_request.v1"
APPROVAL_SCHEMA = "stage2_control_derived_state_activation_approval.v1"
VERIFICATION_SCHEMA = "stage2_control_derived_state_activation_verification.v1"
SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-derived-state-activation-v1"
ALLOWED_METHODS = frozenset({"eth_getCode", "eth_call"})
_FALSE_FLAGS = (
    "acquisition_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)


class ControlDerivedStateActivationError(ValueError):
    """Raised when exact Phase 2 RPC authority is absent or invalid."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlDerivedStateActivationError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlDerivedStateActivationError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlDerivedStateActivationError(f"{label}_not_ordinary_file")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlDerivedStateActivationError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlDerivedStateActivationError(f"{label}_root_invalid")
    return payload


def _time(value: object, label: str) -> datetime:
    try:
        return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ControlDerivedStateActivationError(f"{label}_invalid") from exc


def canonical_signed_payload(approval: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(approval)) + "\n").encode()


def _request_sha(request: Mapping[str, object]) -> str:
    return _canonical_sha(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def expected_request_ceiling(request: Mapping[str, object]) -> int:
    scopes = request.get("rpc_call_scopes")
    if not isinstance(scopes, list):
        raise ControlDerivedStateActivationError("rpc_call_scopes_invalid")
    try:
        retries = int(request.get("retry_limit", -1))
    except (TypeError, ValueError) as exc:
        raise ControlDerivedStateActivationError("retry_limit_invalid") from exc
    if retries < 0 or retries > 5:
        raise ControlDerivedStateActivationError("retry_limit_invalid")
    return len(scopes) * (1 + retries)


def _validate_request(request: Mapping[str, object]) -> None:
    if request.get("schema_version") != REQUEST_SCHEMA:
        raise ControlDerivedStateActivationError("request_schema_invalid")
    if request.get("decision") != "AWAITING_LOCAL_TEST_DERIVED_STATE_RPC_SIGNATURE":
        raise ControlDerivedStateActivationError("request_decision_invalid")
    if request.get("request_sha256") != _request_sha(request):
        raise ControlDerivedStateActivationError("request_sha256_invalid")
    if request.get("rpc_authorized") is not False:
        raise ControlDerivedStateActivationError("request_rpc_authorized_invalid")
    for flag in _FALSE_FLAGS:
        if request.get(flag) is not False:
            raise ControlDerivedStateActivationError(f"request_{flag}_invalid")
    if request.get("maximum_request_count") != expected_request_ceiling(request):
        raise ControlDerivedStateActivationError("maximum_request_count_invalid")
    if _time(request.get("activation_expires_utc"), "activation_expires_utc") <= _time(
        request.get("activation_start_utc"), "activation_start_utc"
    ):
        raise ControlDerivedStateActivationError("activation_window_invalid")


def _capability(path: Path, *, targets_path: Path, registry_path: Path) -> dict[str, object]:
    payload = _load(path, "capability_verification")
    if payload.get("schema_version") != "stage2_control_derived_state_capability_verification.v1":
        raise ControlDerivedStateActivationError("capability_schema_invalid")
    material = {key: value for key, value in payload.items() if key != "verification_sha256"}
    if payload.get("verification_sha256") != _canonical_sha(material):
        raise ControlDerivedStateActivationError("capability_self_hash_invalid")
    if payload.get("decision") != "DERIVED_STATE_CAPABILITY_VERIFIED_NON_AUTHORIZING" or payload.get("complete") is not True:
        raise ControlDerivedStateActivationError("capability_not_complete")
    for flag in ("rpc_authorized", "selection_authorized", "counter_authority", "stage_promotion_authorized", "recovery3_mutation_authorized"):
        if payload.get(flag) is not False:
            raise ControlDerivedStateActivationError(f"capability_{flag}_invalid")
    if payload.get("derived_state_targets_file_sha256") != _file_sha(targets_path):
        raise ControlDerivedStateActivationError("capability_targets_hash_mismatch")
    if payload.get("provider_registry_sha256") != _file_sha(registry_path):
        raise ControlDerivedStateActivationError("capability_registry_hash_mismatch")
    return payload


def _target_scopes(targets_path: Path, registry_path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    payload = _load(targets_path, "derived_state_targets")
    if (
        payload.get("schema_version") != "stage2_control_derived_state_targets.v1"
        or payload.get("decision") != "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION"
        or payload.get("complete") is not True
        or payload.get("rpc_authorized") is not False
    ):
        raise ControlDerivedStateActivationError("derived_state_targets_status_invalid")
    material = {key: value for key, value in payload.items() if key != "targets_sha256"}
    if payload.get("targets_sha256") != _canonical_sha(material):
        raise ControlDerivedStateActivationError("derived_state_targets_self_hash_invalid")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not all(isinstance(row, Mapping) for row in targets):
        raise ControlDerivedStateActivationError("derived_state_targets_invalid")
    if payload.get("target_count") != len(targets):
        raise ControlDerivedStateActivationError("derived_state_target_count_invalid")
    try:
        registry = ProviderRegistry.from_path(registry_path)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlDerivedStateActivationError("provider_registry_invalid") from exc
    bindings = {
        (record.chain, record.provider_id): record.operator_family
        for record in registry.providers
        if record.tracking_enabled and record.operator_verified
    }
    scopes: list[dict[str, object]] = []
    seen_targets: set[str] = set()
    seen_scopes: set[str] = set()
    for target in targets:
        target_material = {key: value for key, value in target.items() if key != "target_sha256"}
        if target.get("target_sha256") != _canonical_sha(target_material):
            raise ControlDerivedStateActivationError("derived_state_target_self_hash_invalid")
        target_id = str(target.get("target_id", "")).strip()
        case_id = str(target.get("case_id", "")).strip()
        chain = str(target.get("chain", "")).strip().lower()
        chain_address = str(target.get("chain_address", "")).strip().lower()
        role = str(target.get("derived_role", "")).strip()
        if not target_id or target_id in seen_targets or not case_id or not chain or not chain_address or not role:
            raise ControlDerivedStateActivationError("target_identity_invalid")
        seen_targets.add(target_id)
        calls = target.get("calls")
        if not isinstance(calls, list) or len(calls) != 2:
            raise ControlDerivedStateActivationError("derived_state_target_calls_invalid")
        families: set[str] = set()
        for call in calls:
            if not isinstance(call, Mapping):
                raise ControlDerivedStateActivationError("derived_state_call_invalid")
            provider_id = str(call.get("provider_id", "")).strip()
            family = str(call.get("operator_family", "")).strip().lower()
            method = str(call.get("method", "")).strip()
            params = call.get("params")
            expected_method = "eth_call" if role == "beacon_implementation_call" else "eth_getCode"
            if method != expected_method or method not in ALLOWED_METHODS or not isinstance(params, list) or bindings.get((chain, provider_id)) != family:
                raise ControlDerivedStateActivationError("derived_state_call_invalid")
            scope: dict[str, object] = {
                "target_type": "derived_state",
                "target_id": target_id,
                "target_sha256": target["target_sha256"],
                "base_state_result_sha256": target.get("base_state_result_sha256"),
                "derived_role": role,
                "case_id": case_id,
                "chain": chain,
                "chain_address": chain_address,
                "provider_id": provider_id,
                "operator_family": family,
                "method": method,
                "params": params,
                "params_sha256": _canonical_sha(params),
            }
            scope["call_scope_sha256"] = _canonical_sha(scope)
            scope_sha = str(scope["call_scope_sha256"])
            if scope_sha in seen_scopes:
                raise ControlDerivedStateActivationError("call_scope_duplicate")
            seen_scopes.add(scope_sha)
            scopes.append(scope)
            families.add(family)
        if len(families) != 2:
            raise ControlDerivedStateActivationError("provider_family_independence")
    scopes.sort(key=lambda row: (str(row["target_id"]), str(row["provider_id"])))
    return payload, scopes


def build_derived_state_activation_request(
    *,
    capability_verification_path: Path,
    provider_registry_path: Path,
    derived_state_targets_path: Path,
    activation_start_utc: str,
    activation_expires_utc: str,
    retry_limit: int,
) -> dict[str, object]:
    capability_file = _ordinary(capability_verification_path, "capability_verification")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    targets_file = _ordinary(derived_state_targets_path, "derived_state_targets")
    capability = _capability(capability_file, targets_path=targets_file, registry_path=registry_file)
    targets, scopes = _target_scopes(targets_file, registry_file)
    request: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA,
        "decision": "AWAITING_LOCAL_TEST_DERIVED_STATE_RPC_SIGNATURE",
        "purpose": "CONTROL_CUTOFF_STATE_PHASE2_RESULT_BOUND_DERIVED_READS_ONLY",
        "capability_verification_file_sha256": _file_sha(capability_file),
        "capability_verification_sha256": capability["verification_sha256"],
        "provider_registry_sha256": _file_sha(registry_file),
        "derived_state_targets_file_sha256": _file_sha(targets_file),
        "derived_state_targets_sha256": targets["targets_sha256"],
        "base_state_results_sha256": targets.get("base_state_results_sha256"),
        "derived_state_target_count": len(targets["targets"]),
        "rpc_call_scopes": scopes,
        "rpc_call_scope_count": len(scopes),
        "retry_limit": int(retry_limit),
        "request_count_formula": "rpc_call_scope_count*(1+retry_limit)",
        "activation_start_utc": activation_start_utc,
        "activation_expires_utc": activation_expires_utc,
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    request["maximum_request_count"] = expected_request_ceiling(request)
    request["request_sha256"] = _request_sha(request)
    _validate_request(request)
    return request


def build_derived_state_activation_approval(*, request: Mapping[str, object], signer_principal: str) -> dict[str, object]:
    _validate_request(request)
    principal = signer_principal.strip()
    if not principal:
        raise ControlDerivedStateActivationError("signer_principal_invalid")
    fields = (
        "purpose", "capability_verification_file_sha256", "capability_verification_sha256",
        "provider_registry_sha256", "derived_state_targets_file_sha256",
        "derived_state_targets_sha256", "base_state_results_sha256",
        "derived_state_target_count", "rpc_call_scopes", "rpc_call_scope_count",
        "retry_limit", "maximum_request_count", "activation_start_utc", "activation_expires_utc",
    )
    return {
        "schema_version": APPROVAL_SCHEMA,
        "decision": "ACTIVATE_EXACT_CONTROL_DERIVED_STATE_RPC",
        "request_sha256": request["request_sha256"],
        "signer_principal": principal,
        **{field: request[field] for field in fields},
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
    }


def verify_derived_state_activation(
    *, request: Mapping[str, object], approval_path: Path, signature_path: Path,
    allowed_signers_path: Path, expected_principal: str, verification_time_utc: str,
) -> dict[str, object]:
    _validate_request(request)
    approval_file = _ordinary(approval_path, "approval")
    signature_file = _ordinary(signature_path, "signature")
    signers_file = _ordinary(allowed_signers_path, "allowed_signers")
    approval = _load(approval_file, "approval")
    principal = str(approval.get("signer_principal", "")).strip()
    if not principal or principal != expected_principal:
        raise ControlDerivedStateActivationError("signer_principal_mismatch")
    expected = build_derived_state_activation_approval(request=request, signer_principal=principal)
    if approval != expected:
        raise ControlDerivedStateActivationError("approval_payload_mismatch")
    now = _time(verification_time_utc, "verification_time_utc")
    if now < _time(approval["activation_start_utc"], "activation_start_utc"):
        raise ControlDerivedStateActivationError("activation_not_yet_valid")
    if now > _time(approval["activation_expires_utc"], "activation_expires_utc"):
        raise ControlDerivedStateActivationError("activation_expired")
    check = subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(signers_file), "-I", principal,
         "-n", SIGNATURE_NAMESPACE, "-s", str(signature_file)],
        input=canonical_signed_payload(approval), capture_output=True, check=False,
    )
    if check.returncode != 0:
        raise ControlDerivedStateActivationError("signature_invalid")
    result: dict[str, object] = {
        **approval,
        "schema_version": VERIFICATION_SCHEMA,
        "decision": "DERIVED_STATE_RPC_ACTIVATION_VERIFIED",
        "approval_sha256": _file_sha(approval_file),
        "signature_sha256": _file_sha(signature_file),
        "allowed_signers_sha256": _file_sha(signers_file),
        "signature_namespace": SIGNATURE_NAMESPACE,
    }
    result["verification_sha256"] = _canonical_sha(result)
    return result


def authorize_derived_state_rpc_call(activation: Mapping[str, object], **kwargs: object) -> dict[str, object]:
    if activation.get("schema_version") != VERIFICATION_SCHEMA:
        raise ControlDerivedStateActivationError("activation_schema_invalid")
    if activation.get("decision") != "DERIVED_STATE_RPC_ACTIVATION_VERIFIED":
        raise ControlDerivedStateActivationError("activation_not_verified")
    try:
        return authorize_rpc_call(activation, **kwargs)  # type: ignore[arg-type]
    except ControlTraceStateActivationError as exc:
        raise ControlDerivedStateActivationError(str(exc)) from exc
