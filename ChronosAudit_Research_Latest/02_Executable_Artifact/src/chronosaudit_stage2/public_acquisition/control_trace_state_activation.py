from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
import subprocess

from .control_trace_state_capability import verify_trace_state_capability
from .providers import ProviderRegistry


REQUEST_SCHEMA = "stage2_control_trace_state_activation_request.v1"
APPROVAL_SCHEMA = "stage2_control_trace_state_activation_approval.v1"
VERIFICATION_SCHEMA = "stage2_control_trace_state_activation_verification.v1"
SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-trace-state-activation-v1"
ALLOWED_METHODS = frozenset({
    "eth_chainId",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getTransactionReceipt",
    "trace_transaction",
    "debug_traceTransaction",
    "trace_block",
    "debug_traceBlockByNumber",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_call",
})
TRACE_METHODS = frozenset({
    "trace_transaction",
    "debug_traceTransaction",
    "trace_block",
    "debug_traceBlockByNumber",
})
STATE_METHODS = ALLOWED_METHODS - TRACE_METHODS
_REQUEST_FALSE_FLAGS = (
    "acquisition_authorized",
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)


class ControlTraceStateActivationError(ValueError):
    """Raised when exact trace/state RPC authority is absent or invalid."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_signed_payload(approval: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(approval)) + "\n").encode("utf-8")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlTraceStateActivationError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlTraceStateActivationError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlTraceStateActivationError(f"{label}_not_ordinary_file")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlTraceStateActivationError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlTraceStateActivationError(f"{label}_root_invalid")
    return payload


def _canonical_time(value: object, label: str) -> datetime:
    text = str(value or "")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ControlTraceStateActivationError(f"{label}_invalid") from exc
    return parsed


def _is_sha(value: object) -> bool:
    text = str(value or "").lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _request_sha(request: Mapping[str, object]) -> str:
    return _canonical_sha(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def _validate_request(request: Mapping[str, object]) -> None:
    if request.get("schema_version") != REQUEST_SCHEMA:
        raise ControlTraceStateActivationError("request_schema_invalid")
    if request.get("decision") != "AWAITING_LOCAL_TEST_TRACE_STATE_RPC_SIGNATURE":
        raise ControlTraceStateActivationError("request_decision_invalid")
    if request.get("request_sha256") != _request_sha(request):
        raise ControlTraceStateActivationError("request_sha256_invalid")
    for flag in _REQUEST_FALSE_FLAGS:
        if request.get(flag) is not False:
            raise ControlTraceStateActivationError(f"request_{flag}_invalid")
    if request.get("unmaterialized_state_calls_authorized") is not False:
        raise ControlTraceStateActivationError(
            "request_unmaterialized_state_calls_authorized_invalid"
        )
    if request.get("activation_stage") == "TRACE_ONLY_PRE_STATE_DERIVATION":
        scopes = request.get("rpc_call_scopes")
        if (
            request.get("state_target_count") != 0
            or request.get("state_targets_sha256") is not None
            or not isinstance(scopes, list)
            or any(
                not isinstance(scope, Mapping)
                or scope.get("target_type") != "trace"
                or scope.get("method") not in TRACE_METHODS
                for scope in scopes
            )
        ):
            raise ControlTraceStateActivationError("trace_only_scope_invalid")
    if expected_request_ceiling(request) != request.get("maximum_request_count"):
        raise ControlTraceStateActivationError("maximum_request_count_invalid")
    start = _canonical_time(request.get("activation_start_utc"), "activation_start_utc")
    expiry = _canonical_time(request.get("activation_expires_utc"), "activation_expires_utc")
    if expiry <= start:
        raise ControlTraceStateActivationError("activation_window_invalid")


def _load_targets(
    path: Path,
    expected_schema: str,
    target_type: str,
    *,
    retry_reconstruction_inputs: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = _load_json(path, f"{target_type}_targets")
    schema = payload.get("schema_version")
    if schema != expected_schema:
        if (
            target_type == "trace"
            and schema == "stage2_control_trace_retry_targets.v1"
            and retry_reconstruction_inputs is not None
        ):
            try:
                from .control_trace_retry_overlay import verify_trace_retry_targets

                verification = verify_trace_retry_targets(
                    artifact_path=path,
                    **dict(retry_reconstruction_inputs),
                )
            except Exception as exc:
                raise ControlTraceStateActivationError(
                    "trace_retry_targets_invalid"
                ) from exc
            if verification.get("decision") != (
                "TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING"
            ):
                raise ControlTraceStateActivationError(
                    "trace_retry_targets_invalid"
                )
        else:
            raise ControlTraceStateActivationError(
                f"{target_type}_targets_schema_invalid"
            )
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ControlTraceStateActivationError(f"{target_type}_targets_invalid")
    if not all(isinstance(target, dict) for target in targets):
        raise ControlTraceStateActivationError(f"{target_type}_target_invalid")
    return targets


def _capability_bindings(capability: Mapping[str, object]) -> dict[tuple[str, str], str]:
    if capability.get("schema_version") != "stage2_control_trace_state_capability.v1":
        raise ControlTraceStateActivationError("capability_schema_invalid")
    material = {key: value for key, value in capability.items() if key != "report_sha256"}
    if capability.get("report_sha256") != _canonical_sha(material):
        raise ControlTraceStateActivationError("capability_self_hash_invalid")
    if capability.get("complete") is not True or capability.get("errors") != []:
        raise ControlTraceStateActivationError("capability_not_complete")
    for flag in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if capability.get(flag) is not False:
            raise ControlTraceStateActivationError(f"capability_{flag}_invalid")
    bindings: dict[tuple[str, str], str] = {}
    chains = capability.get("chains")
    if not isinstance(chains, list):
        raise ControlTraceStateActivationError("capability_chains_invalid")
    for chain_entry in chains:
        if not isinstance(chain_entry, Mapping):
            raise ControlTraceStateActivationError("capability_chain_invalid")
        chain = str(chain_entry.get("chain", "")).strip().lower()
        providers = chain_entry.get("providers")
        if not isinstance(providers, list):
            raise ControlTraceStateActivationError("capability_providers_invalid")
        families: set[str] = set()
        for provider in providers:
            if not isinstance(provider, Mapping):
                raise ControlTraceStateActivationError("capability_provider_invalid")
            provider_id = str(provider.get("provider_id", "")).strip()
            family = str(provider.get("provider_family", "")).strip().lower()
            if not provider_id or not family or family == "unverified":
                raise ControlTraceStateActivationError("capability_provider_invalid")
            key = (chain, provider_id)
            if key in bindings:
                raise ControlTraceStateActivationError("capability_provider_duplicate")
            bindings[key] = family
            families.add(family)
        if len(families) < 2:
            raise ControlTraceStateActivationError("provider_family_independence")
    return bindings


def _normalize_call_scopes(
    *,
    trace_targets: list[dict[str, object]],
    state_targets: list[dict[str, object]],
    capability_bindings: Mapping[tuple[str, str], str],
    registry: ProviderRegistry,
) -> list[dict[str, object]]:
    registry_bindings = {
        (record.chain, record.provider_id): record
        for record in registry.providers
        if record.tracking_enabled and record.operator_verified
    }
    scopes: list[dict[str, object]] = []
    seen_targets: set[str] = set()
    seen_scopes: set[str] = set()
    for target_type, targets, allowed in (
        ("trace", trace_targets, TRACE_METHODS),
        ("state", state_targets, STATE_METHODS),
    ):
        for target in targets:
            target_id = str(target.get("target_id", "")).strip()
            case_id = str(target.get("case_id", "")).strip()
            chain = str(target.get("chain", "")).strip().lower()
            chain_address = str(target.get("chain_address", "")).strip().lower()
            if not target_id or target_id in seen_targets or not case_id or not chain or not chain_address:
                raise ControlTraceStateActivationError("target_identity_invalid")
            seen_targets.add(target_id)
            calls = target.get("calls")
            if not isinstance(calls, list) or len(calls) < 2:
                raise ControlTraceStateActivationError("target_calls_invalid")
            families: set[str] = set()
            for call in calls:
                if not isinstance(call, Mapping):
                    raise ControlTraceStateActivationError("target_call_invalid")
                provider_id = str(call.get("provider_id", "")).strip()
                family = str(call.get("operator_family", "")).strip().lower()
                method = str(call.get("method", "")).strip()
                params = call.get("params")
                if method not in ALLOWED_METHODS or method not in allowed:
                    raise ControlTraceStateActivationError("method_not_allowed_for_target")
                if not isinstance(params, list):
                    raise ControlTraceStateActivationError("call_params_invalid")
                if capability_bindings.get((chain, provider_id)) != family:
                    raise ControlTraceStateActivationError("capability_provider_binding_mismatch")
                record = registry_bindings.get((chain, provider_id))
                if record is None or record.operator_family != family:
                    raise ControlTraceStateActivationError("provider_registry_mismatch")
                scope: dict[str, object] = {
                    "target_type": target_type,
                    "target_id": target_id,
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
                if scope["call_scope_sha256"] in seen_scopes:
                    raise ControlTraceStateActivationError("call_scope_duplicate")
                seen_scopes.add(str(scope["call_scope_sha256"]))
                scopes.append(scope)
                families.add(family)
            if len(families) < 2:
                raise ControlTraceStateActivationError("provider_family_independence")
    return sorted(
        scopes,
        key=lambda row: (
            str(row["target_type"]),
            str(row["target_id"]),
            str(row["provider_id"]),
            str(row["method"]),
            str(row["params_sha256"]),
        ),
    )


def expected_request_ceiling(request: Mapping[str, object]) -> int:
    scopes = request.get("rpc_call_scopes")
    if not isinstance(scopes, list):
        raise ControlTraceStateActivationError("rpc_call_scopes_invalid")
    try:
        retry_limit = int(request.get("retry_limit", -1))
    except (TypeError, ValueError) as exc:
        raise ControlTraceStateActivationError("retry_limit_invalid") from exc
    if retry_limit < 0 or retry_limit > 5:
        raise ControlTraceStateActivationError("retry_limit_invalid")
    return len(scopes) * (1 + retry_limit)


def build_trace_state_activation_request(
    *,
    capability_report_path: Path,
    capability_raw_root: Path,
    provider_registry_path: Path,
    trace_targets_path: Path,
    state_targets_path: Path,
    activation_start_utc: str,
    activation_expires_utc: str,
    retry_limit: int,
) -> dict[str, object]:
    """Build a non-authorizing request for exact trace/state calls."""
    capability_path = _ordinary(capability_report_path, "capability_report")
    registry_path = _ordinary(provider_registry_path, "provider_registry")
    trace_path = _ordinary(trace_targets_path, "trace_targets")
    state_path = _ordinary(state_targets_path, "state_targets")
    verification = verify_trace_state_capability(
        report_path=capability_path,
        raw_root=capability_raw_root,
        provider_registry_path=registry_path,
    )
    if verification.get("complete") is not True:
        raise ControlTraceStateActivationError("capability_verification_incomplete")
    capability = _load_json(capability_path, "capability_report")
    capability_bindings = _capability_bindings(capability)
    try:
        registry = ProviderRegistry.from_path(registry_path)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlTraceStateActivationError("provider_registry_invalid") from exc
    trace_targets = _load_targets(
        trace_path, "stage2_control_trace_targets.v1", "trace"
    )
    state_targets = _load_targets(
        state_path, "stage2_control_state_targets.v1", "state"
    )
    scopes = _normalize_call_scopes(
        trace_targets=trace_targets,
        state_targets=state_targets,
        capability_bindings=capability_bindings,
        registry=registry,
    )
    start = _canonical_time(activation_start_utc, "activation_start_utc")
    expiry = _canonical_time(activation_expires_utc, "activation_expires_utc")
    if expiry <= start:
        raise ControlTraceStateActivationError("activation_window_invalid")
    request: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA,
        "decision": "AWAITING_LOCAL_TEST_TRACE_STATE_RPC_SIGNATURE",
        "purpose": "CONTROL_TRACE_AND_CUTOFF_STATE_ACQUISITION_ONLY",
        "activation_stage": "TRACE_AND_STATE_EXACT_SCOPE",
        "unmaterialized_state_calls_authorized": False,
        "capability_report_sha256": _sha(capability_path),
        "capability_semantic_sha256": capability["report_sha256"],
        "capability_verification_sha256": verification.get("verification_sha256"),
        "provider_registry_sha256": _sha(registry_path),
        "trace_targets_sha256": _sha(trace_path),
        "state_targets_sha256": _sha(state_path),
        "trace_target_count": len(trace_targets),
        "state_target_count": len(state_targets),
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
    return request


def build_trace_only_activation_request(
    *,
    capability_report_path: Path,
    capability_raw_root: Path,
    provider_registry_path: Path,
    trace_targets_path: Path,
    activation_start_utc: str,
    activation_expires_utc: str,
    retry_limit: int,
    retry_reconstruction_inputs: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a non-authorizing request for trace calls before state derivation."""
    capability_path = _ordinary(capability_report_path, "capability_report")
    registry_path = _ordinary(provider_registry_path, "provider_registry")
    trace_path = _ordinary(trace_targets_path, "trace_targets")
    verification = verify_trace_state_capability(
        report_path=capability_path,
        raw_root=capability_raw_root,
        provider_registry_path=registry_path,
    )
    if verification.get("complete") is not True:
        raise ControlTraceStateActivationError("capability_verification_incomplete")
    capability = _load_json(capability_path, "capability_report")
    capability_bindings = _capability_bindings(capability)
    try:
        registry = ProviderRegistry.from_path(registry_path)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlTraceStateActivationError("provider_registry_invalid") from exc
    trace_targets = _load_targets(
        trace_path,
        "stage2_control_trace_targets.v1",
        "trace",
        retry_reconstruction_inputs=retry_reconstruction_inputs,
    )
    scopes = _normalize_call_scopes(
        trace_targets=trace_targets,
        state_targets=[],
        capability_bindings=capability_bindings,
        registry=registry,
    )
    start = _canonical_time(activation_start_utc, "activation_start_utc")
    expiry = _canonical_time(activation_expires_utc, "activation_expires_utc")
    if expiry <= start:
        raise ControlTraceStateActivationError("activation_window_invalid")
    request: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA,
        "decision": "AWAITING_LOCAL_TEST_TRACE_STATE_RPC_SIGNATURE",
        "purpose": "CONTROL_TRACE_ACQUISITION_PRE_STATE_DERIVATION_ONLY",
        "activation_stage": "TRACE_ONLY_PRE_STATE_DERIVATION",
        "unmaterialized_state_calls_authorized": False,
        "capability_report_sha256": _sha(capability_path),
        "capability_semantic_sha256": capability["report_sha256"],
        "capability_verification_sha256": verification.get("verification_sha256"),
        "provider_registry_sha256": _sha(registry_path),
        "trace_targets_sha256": _sha(trace_path),
        "state_targets_sha256": None,
        "trace_target_count": len(trace_targets),
        "state_target_count": 0,
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
    return request


def build_trace_state_activation_approval(
    *, request: Mapping[str, object], signer_principal: str
) -> dict[str, object]:
    """Build the exact unsigned approval granting only request-bound RPC."""
    _validate_request(request)
    principal = signer_principal.strip()
    if not principal:
        raise ControlTraceStateActivationError("signer_principal_invalid")
    return {
        "schema_version": APPROVAL_SCHEMA,
        "decision": "ACTIVATE_EXACT_CONTROL_TRACE_STATE_RPC",
        "request_sha256": request["request_sha256"],
        "signer_principal": principal,
        "purpose": request["purpose"],
        "activation_stage": request["activation_stage"],
        "unmaterialized_state_calls_authorized": False,
        "capability_report_sha256": request["capability_report_sha256"],
        "capability_semantic_sha256": request["capability_semantic_sha256"],
        "provider_registry_sha256": request["provider_registry_sha256"],
        "trace_targets_sha256": request["trace_targets_sha256"],
        "state_targets_sha256": request["state_targets_sha256"],
        "trace_target_count": request["trace_target_count"],
        "state_target_count": request["state_target_count"],
        "rpc_call_scopes": request["rpc_call_scopes"],
        "rpc_call_scope_count": request["rpc_call_scope_count"],
        "retry_limit": request["retry_limit"],
        "maximum_request_count": request["maximum_request_count"],
        "activation_start_utc": request["activation_start_utc"],
        "activation_expires_utc": request["activation_expires_utc"],
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
    }


def verify_trace_state_activation(
    *,
    request: Mapping[str, object],
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    """Verify a detached signature and the complete exact-scope activation."""
    _validate_request(request)
    approval_file = _ordinary(approval_path, "approval")
    signature_file = _ordinary(signature_path, "signature")
    allowed_signers_file = _ordinary(allowed_signers_path, "allowed_signers")
    approval = _load_json(approval_file, "approval")
    principal = str(approval.get("signer_principal", "")).strip()
    if not expected_principal or principal != expected_principal:
        raise ControlTraceStateActivationError("signer_principal_mismatch")
    expected = build_trace_state_activation_approval(
        request=request, signer_principal=principal
    )
    if approval != expected:
        raise ControlTraceStateActivationError("approval_payload_mismatch")
    now = _canonical_time(verification_time_utc, "verification_time_utc")
    start = _canonical_time(approval["activation_start_utc"], "activation_start_utc")
    expiry = _canonical_time(approval["activation_expires_utc"], "activation_expires_utc")
    if now < start:
        raise ControlTraceStateActivationError("activation_not_yet_valid")
    if now > expiry:
        raise ControlTraceStateActivationError("activation_expired")
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
            SIGNATURE_NAMESPACE,
            "-s",
            str(signature_file),
        ],
        input=canonical_signed_payload(approval),
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise ControlTraceStateActivationError("signature_invalid")
    result: dict[str, object] = {
        "schema_version": VERIFICATION_SCHEMA,
        "decision": "TRACE_STATE_RPC_ACTIVATION_VERIFIED",
        "request_sha256": request["request_sha256"],
        "approval_sha256": _sha(approval_file),
        "signature_sha256": _sha(signature_file),
        "allowed_signers_sha256": _sha(allowed_signers_file),
        "signature_namespace": SIGNATURE_NAMESPACE,
        "signer_principal": principal,
        "activation_stage": approval["activation_stage"],
        "unmaterialized_state_calls_authorized": False,
        "capability_report_sha256": approval["capability_report_sha256"],
        "capability_semantic_sha256": approval["capability_semantic_sha256"],
        "provider_registry_sha256": approval["provider_registry_sha256"],
        "trace_targets_sha256": approval["trace_targets_sha256"],
        "state_targets_sha256": approval["state_targets_sha256"],
        "trace_target_count": approval["trace_target_count"],
        "state_target_count": approval["state_target_count"],
        "rpc_call_scopes": approval["rpc_call_scopes"],
        "rpc_call_scope_count": approval["rpc_call_scope_count"],
        "retry_limit": approval["retry_limit"],
        "maximum_request_count": approval["maximum_request_count"],
        "activation_start_utc": approval["activation_start_utc"],
        "activation_expires_utc": approval["activation_expires_utc"],
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
    }
    result["verification_sha256"] = _canonical_sha(result)
    return result


def authorize_rpc_call(
    activation: Mapping[str, object],
    *,
    target_id: str,
    chain: str,
    provider_id: str,
    method: str,
    params: list[object],
    sequence_number: int,
    used_sequences: set[int],
    requests_used: int,
    now_utc: str,
) -> dict[str, object]:
    """Authorize one exact call without performing transport or mutating state."""
    if activation.get("rpc_authorized") is not True:
        raise ControlTraceStateActivationError("rpc_not_authorized")
    for flag in (
        "acquisition_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if activation.get(flag) is not False:
            raise ControlTraceStateActivationError(f"{flag}_must_be_false")
    if method not in ALLOWED_METHODS:
        raise ControlTraceStateActivationError("method_not_activated")
    scopes = activation.get("rpc_call_scopes")
    if not isinstance(scopes, list):
        raise ControlTraceStateActivationError("rpc_call_scopes_invalid")
    if not any(scope.get("method") == method for scope in scopes if isinstance(scope, Mapping)):
        raise ControlTraceStateActivationError("method_not_activated")
    if sequence_number <= 0:
        raise ControlTraceStateActivationError("sequence_invalid")
    if sequence_number in used_sequences:
        raise ControlTraceStateActivationError("sequence_replay")
    maximum = int(activation.get("maximum_request_count", 0))
    if requests_used < 0 or requests_used >= maximum:
        raise ControlTraceStateActivationError("request_budget_exhausted")
    now = _canonical_time(now_utc, "now_utc")
    start = _canonical_time(activation.get("activation_start_utc"), "activation_start_utc")
    expiry = _canonical_time(activation.get("activation_expires_utc"), "activation_expires_utc")
    if now < start:
        raise ControlTraceStateActivationError("activation_not_yet_valid")
    if now > expiry:
        raise ControlTraceStateActivationError("activation_expired")
    params_sha = _canonical_sha(params)
    matches = [
        scope
        for scope in scopes
        if isinstance(scope, Mapping)
        and scope.get("target_id") == target_id
        and scope.get("chain") == chain.strip().lower()
        and scope.get("provider_id") == provider_id
        and scope.get("method") == method
        and scope.get("params_sha256") == params_sha
        and scope.get("params") == params
    ]
    if len(matches) != 1:
        raise ControlTraceStateActivationError("rpc_scope_not_activated")
    return {
        "authorized": True,
        "sequence_number": sequence_number,
        "call_scope_sha256": matches[0]["call_scope_sha256"],
        "request_sha256": _canonical_sha({
            "target_id": target_id,
            "chain": chain.strip().lower(),
            "provider_id": provider_id,
            "method": method,
            "params": params,
            "sequence_number": sequence_number,
        }),
        "remaining_request_count_after_call": maximum - requests_used - 1,
    }
