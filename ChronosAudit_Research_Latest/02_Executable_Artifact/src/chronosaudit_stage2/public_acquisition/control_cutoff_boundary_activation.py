from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
import subprocess

from .providers import ProviderRegistry


REQUEST_SCHEMA = "stage2_control_cutoff_boundary_activation_request.v1"
APPROVAL_SCHEMA = "stage2_control_cutoff_boundary_activation_approval.v1"
VERIFICATION_SCHEMA = "stage2_control_cutoff_boundary_activation_verification.v1"
SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-cutoff-boundary-activation-v1"
METHOD = "eth_getBlockByNumber"
_FALSE_REQUEST_FLAGS = (
    "acquisition_authorized",
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)


class ControlCutoffBoundaryActivationError(ValueError):
    """Raised when range-bound cutoff-block RPC authority is invalid."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_signed_payload(approval: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(approval)) + "\n").encode("utf-8")


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCutoffBoundaryActivationError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCutoffBoundaryActivationError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCutoffBoundaryActivationError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCutoffBoundaryActivationError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCutoffBoundaryActivationError(f"{label}_root_invalid")
    return payload


def _time(value: object, label: str) -> datetime:
    try:
        return datetime.strptime(str(value or ""), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ControlCutoffBoundaryActivationError(f"{label}_invalid") from exc


def _require_false(payload: Mapping[str, object], label: str) -> None:
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(field) is not False:
            raise ControlCutoffBoundaryActivationError(f"{label}_{field}_invalid")


def _require_self_hash(
    payload: Mapping[str, object], field: str, label: str
) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlCutoffBoundaryActivationError(f"{label}_self_hash_invalid")


def _load_requirements(path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    requirements = _load(path, "requirements")
    if requirements.get("schema_version") != (
        "stage2_control_cutoff_boundary_requirements.v1"
    ):
        raise ControlCutoffBoundaryActivationError("requirements_schema_invalid")
    _require_self_hash(requirements, "requirements_sha256", "requirements")
    _require_false(requirements, "requirements")
    if (
        requirements.get("decision")
        != "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION"
        or requirements.get("complete") is not True
        or requirements.get("final_cutoff_brackets_resolved") is not False
        or requirements.get("counter_authority") is not False
        or requirements.get("rpc_authorized") is not False
    ):
        raise ControlCutoffBoundaryActivationError("requirements_status_invalid")
    targets = requirements.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or len(targets) != requirements.get("boundary_target_count")
        or not all(isinstance(target, dict) for target in targets)
    ):
        raise ControlCutoffBoundaryActivationError("requirements_targets_invalid")
    seen: set[str] = set()
    for target in targets:
        if target.get("schema_version") != (
            "stage2_control_cutoff_boundary_requirement.v1"
        ):
            raise ControlCutoffBoundaryActivationError("target_schema_invalid")
        _require_self_hash(target, "target_sha256", "target")
        _require_false(target, "target")
        if target.get("rpc_authorized") is not False:
            raise ControlCutoffBoundaryActivationError("target_rpc_authorized_invalid")
        target_id = str(target.get("target_id", ""))
        if not target_id or target_id in seen:
            raise ControlCutoffBoundaryActivationError("target_identity_invalid")
        seen.add(target_id)
        try:
            lower = int(target.get("lower_bound_block", -1))
            upper = int(target.get("upper_bound_block", -1))
            maximum = int(target.get("maximum_block_header_queries_per_provider", -1))
        except (TypeError, ValueError) as exc:
            raise ControlCutoffBoundaryActivationError("target_range_invalid") from exc
        if lower < 0 or upper <= lower or maximum <= 0:
            raise ControlCutoffBoundaryActivationError("target_range_invalid")
    return requirements, targets


def _capability_bindings(
    *,
    capability: Mapping[str, object],
    requirements_file_sha256: str,
    requirements_sha256: str,
    registry_file_sha256: str,
    registry: ProviderRegistry,
    target_chains: set[str],
) -> dict[str, list[tuple[str, str]]]:
    if capability.get("schema_version") != (
        "stage2_control_cutoff_boundary_capability.v1"
    ):
        raise ControlCutoffBoundaryActivationError("capability_schema_invalid")
    _require_self_hash(capability, "capability_sha256", "capability")
    _require_false(capability, "capability")
    if (
        capability.get("decision")
        != "DUAL_PROVIDER_CUTOFF_BOUNDARY_CAPABILITY_VERIFIED"
        or capability.get("complete") is not True
        or capability.get("errors") != []
        or capability.get("rpc_authorized") is not False
        or capability.get("requirements_file_sha256") != requirements_file_sha256
        or capability.get("requirements_sha256") != requirements_sha256
        or capability.get("provider_registry_sha256") != registry_file_sha256
    ):
        raise ControlCutoffBoundaryActivationError("capability_status_invalid")
    registry_bindings = {
        (record.chain, record.provider_id): record
        for record in registry.providers
        if record.operator_verified and record.tracking_enabled
    }
    chains = capability.get("chains")
    if not isinstance(chains, list):
        raise ControlCutoffBoundaryActivationError("capability_chains_invalid")
    bindings: dict[str, list[tuple[str, str]]] = {}
    for chain_entry in chains:
        if not isinstance(chain_entry, Mapping):
            raise ControlCutoffBoundaryActivationError("capability_chain_invalid")
        chain = str(chain_entry.get("chain", "")).strip().lower()
        if not chain or chain in bindings:
            raise ControlCutoffBoundaryActivationError("capability_chain_invalid")
        providers = chain_entry.get("providers")
        if not isinstance(providers, list):
            raise ControlCutoffBoundaryActivationError("capability_providers_invalid")
        normalized: list[tuple[str, str]] = []
        provider_ids: set[str] = set()
        families: set[str] = set()
        for provider in providers:
            if not isinstance(provider, Mapping):
                raise ControlCutoffBoundaryActivationError("capability_provider_invalid")
            provider_id = str(provider.get("provider_id", "")).strip()
            family = str(provider.get("operator_family", "")).strip().lower()
            record = registry_bindings.get((chain, provider_id))
            if (
                not provider_id
                or provider_id in provider_ids
                or not family
                or family == "unverified"
                or provider.get("chain_id_verified") is not True
                or provider.get("historical_block_by_number_verified") is not True
                or record is None
                or record.operator_family != family
            ):
                raise ControlCutoffBoundaryActivationError(
                    "capability_provider_invalid"
                )
            provider_ids.add(provider_id)
            families.add(family)
            normalized.append((provider_id, family))
        if len(families) < 2:
            raise ControlCutoffBoundaryActivationError(
                "provider_family_independence"
            )
        bindings[chain] = sorted(normalized)
    if not target_chains.issubset(bindings):
        raise ControlCutoffBoundaryActivationError("chain_coverage_incomplete")
    return bindings


def expected_request_ceiling(request: Mapping[str, object]) -> int:
    scopes = request.get("range_scopes")
    if not isinstance(scopes, list):
        raise ControlCutoffBoundaryActivationError("range_scopes_invalid")
    try:
        retry_limit = int(request.get("retry_limit", -1))
        base = sum(int(scope["maximum_block_header_queries"]) for scope in scopes)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlCutoffBoundaryActivationError("request_budget_invalid") from exc
    if retry_limit < 0 or retry_limit > 5 or base <= 0:
        raise ControlCutoffBoundaryActivationError("request_budget_invalid")
    return base * (1 + retry_limit)


def _request_sha(request: Mapping[str, object]) -> str:
    return _canonical_sha(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def _validate_request(request: Mapping[str, object]) -> None:
    if request.get("schema_version") != REQUEST_SCHEMA:
        raise ControlCutoffBoundaryActivationError("request_schema_invalid")
    if (
        request.get("decision")
        != "AWAITING_LOCAL_TEST_CUTOFF_BOUNDARY_RPC_SIGNATURE"
    ):
        raise ControlCutoffBoundaryActivationError("request_decision_invalid")
    if request.get("request_sha256") != _request_sha(request):
        raise ControlCutoffBoundaryActivationError("request_self_hash_invalid")
    for field in _FALSE_REQUEST_FLAGS:
        if request.get(field) is not False:
            raise ControlCutoffBoundaryActivationError(f"request_{field}_invalid")
    if request.get("maximum_request_count") != expected_request_ceiling(request):
        raise ControlCutoffBoundaryActivationError("request_budget_invalid")
    if _time(request.get("activation_expires_utc"), "activation_expires_utc") <= _time(
        request.get("activation_start_utc"), "activation_start_utc"
    ):
        raise ControlCutoffBoundaryActivationError("activation_window_invalid")


def build_boundary_activation_request(
    *,
    requirements_path: Path,
    capability_path: Path,
    provider_registry_path: Path,
    activation_start_utc: str,
    activation_expires_utc: str,
    retry_limit: int,
) -> dict[str, object]:
    requirements_file = _ordinary(requirements_path, "requirements")
    capability_file = _ordinary(capability_path, "capability")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    requirements, targets = _load_requirements(requirements_file)
    capability = _load(capability_file, "capability")
    try:
        registry = ProviderRegistry.from_path(registry_file)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlCutoffBoundaryActivationError("provider_registry_invalid") from exc
    target_chains = {str(target["chain"]).strip().lower() for target in targets}
    bindings = _capability_bindings(
        capability=capability,
        requirements_file_sha256=_file_sha(requirements_file),
        requirements_sha256=str(requirements["requirements_sha256"]),
        registry_file_sha256=_file_sha(registry_file),
        registry=registry,
        target_chains=target_chains,
    )
    scopes: list[dict[str, object]] = []
    for target in targets:
        chain = str(target["chain"]).strip().lower()
        for provider_id, family in bindings[chain]:
            scope: dict[str, object] = {
                "target_id": target["target_id"],
                "target_sha256": target["target_sha256"],
                "case_id": target["case_id"],
                "chain": chain,
                "provider_id": provider_id,
                "operator_family": family,
                "method": METHOD,
                "include_transactions": False,
                "minimum_block_number": int(target["lower_bound_block"]),
                "maximum_block_number": int(target["upper_bound_block"]),
                "maximum_block_header_queries": int(
                    target["maximum_block_header_queries_per_provider"]
                ),
                "search_algorithm": target["search_algorithm"],
                "cutoff_timestamp": target["cutoff_timestamp"],
            }
            scope["range_scope_sha256"] = _canonical_sha(scope)
            scopes.append(scope)
    scopes.sort(
        key=lambda scope: (
            str(scope["target_id"]),
            str(scope["provider_id"]),
        )
    )
    start = _time(activation_start_utc, "activation_start_utc")
    expiry = _time(activation_expires_utc, "activation_expires_utc")
    if expiry <= start:
        raise ControlCutoffBoundaryActivationError("activation_window_invalid")
    request: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA,
        "decision": "AWAITING_LOCAL_TEST_CUTOFF_BOUNDARY_RPC_SIGNATURE",
        "purpose": "DETERMINISTIC_CUTOFF_BLOCK_BOUNDARY_RESOLUTION_ONLY",
        "requirements_file_sha256": _file_sha(requirements_file),
        "requirements_sha256": requirements["requirements_sha256"],
        "capability_file_sha256": _file_sha(capability_file),
        "capability_sha256": capability["capability_sha256"],
        "provider_registry_sha256": _file_sha(registry_file),
        "boundary_target_count": len(targets),
        "target_chains": sorted(target_chains),
        "range_scopes": scopes,
        "range_scope_count": len(scopes),
        "retry_limit": int(retry_limit),
        "request_count_formula": (
            "sum(range_scope.maximum_block_header_queries)*(1+retry_limit)"
        ),
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


def build_boundary_activation_approval(
    *, request: Mapping[str, object], signer_principal: str
) -> dict[str, object]:
    _validate_request(request)
    principal = signer_principal.strip()
    if not principal:
        raise ControlCutoffBoundaryActivationError("signer_principal_invalid")
    return {
        "schema_version": APPROVAL_SCHEMA,
        "decision": "ACTIVATE_RANGE_BOUND_CUTOFF_BLOCK_RPC",
        "request_sha256": request["request_sha256"],
        "signer_principal": principal,
        "purpose": request["purpose"],
        "requirements_file_sha256": request["requirements_file_sha256"],
        "requirements_sha256": request["requirements_sha256"],
        "capability_file_sha256": request["capability_file_sha256"],
        "capability_sha256": request["capability_sha256"],
        "provider_registry_sha256": request["provider_registry_sha256"],
        "boundary_target_count": request["boundary_target_count"],
        "target_chains": request["target_chains"],
        "range_scopes": request["range_scopes"],
        "range_scope_count": request["range_scope_count"],
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
        "identity_binding_limit": (
            "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY"
        ),
    }


def verify_boundary_activation(
    *,
    request: Mapping[str, object],
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    _validate_request(request)
    approval_file = _ordinary(approval_path, "approval")
    signature_file = _ordinary(signature_path, "signature")
    allowed_file = _ordinary(allowed_signers_path, "allowed_signers")
    approval = _load(approval_file, "approval")
    principal = str(approval.get("signer_principal", "")).strip()
    if principal != expected_principal:
        raise ControlCutoffBoundaryActivationError("signer_principal_mismatch")
    expected = build_boundary_activation_approval(
        request=request, signer_principal=principal
    )
    if approval != expected:
        raise ControlCutoffBoundaryActivationError("approval_payload_mismatch")
    now = _time(verification_time_utc, "verification_time_utc")
    if now < _time(approval["activation_start_utc"], "activation_start_utc"):
        raise ControlCutoffBoundaryActivationError("activation_not_yet_valid")
    if now > _time(approval["activation_expires_utc"], "activation_expires_utc"):
        raise ControlCutoffBoundaryActivationError("activation_expired")
    verification = subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed_file),
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
        raise ControlCutoffBoundaryActivationError("signature_invalid")
    result: dict[str, object] = {
        "schema_version": VERIFICATION_SCHEMA,
        "decision": "CUTOFF_BOUNDARY_RPC_ACTIVATION_VERIFIED",
        "request_sha256": request["request_sha256"],
        "approval_sha256": _file_sha(approval_file),
        "signature_sha256": _file_sha(signature_file),
        "allowed_signers_sha256": _file_sha(allowed_file),
        "signature_namespace": SIGNATURE_NAMESPACE,
        "signer_principal": principal,
        "requirements_file_sha256": approval["requirements_file_sha256"],
        "requirements_sha256": approval["requirements_sha256"],
        "capability_file_sha256": approval["capability_file_sha256"],
        "capability_sha256": approval["capability_sha256"],
        "provider_registry_sha256": approval["provider_registry_sha256"],
        "boundary_target_count": approval["boundary_target_count"],
        "target_chains": approval["target_chains"],
        "range_scopes": approval["range_scopes"],
        "range_scope_count": approval["range_scope_count"],
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
        "identity_binding_limit": (
            "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY"
        ),
    }
    result["verification_sha256"] = _canonical_sha(result)
    return result


def authorize_boundary_rpc_call(
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
    scope_requests_used: int,
    now_utc: str,
) -> dict[str, object]:
    if activation.get("rpc_authorized") is not True:
        raise ControlCutoffBoundaryActivationError("rpc_not_authorized")
    for field in (
        "acquisition_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if activation.get(field) is not False:
            raise ControlCutoffBoundaryActivationError(f"{field}_must_be_false")
    if method != METHOD:
        raise ControlCutoffBoundaryActivationError("method_not_activated")
    if (
        not isinstance(params, list)
        or len(params) != 2
        or params[1] is not False
        or not isinstance(params[0], str)
    ):
        raise ControlCutoffBoundaryActivationError("params_invalid")
    try:
        block_number = int(params[0], 16)
    except ValueError as exc:
        raise ControlCutoffBoundaryActivationError("block_number_invalid") from exc
    if params[0] != hex(block_number):
        raise ControlCutoffBoundaryActivationError("block_number_not_canonical")
    scopes = activation.get("range_scopes")
    if not isinstance(scopes, list):
        raise ControlCutoffBoundaryActivationError("range_scopes_invalid")
    matches = [
        scope
        for scope in scopes
        if isinstance(scope, Mapping)
        and scope.get("target_id") == target_id
        and scope.get("chain") == chain.strip().lower()
        and scope.get("provider_id") == provider_id
        and scope.get("method") == method
    ]
    if len(matches) != 1:
        raise ControlCutoffBoundaryActivationError("range_scope_not_activated")
    scope = matches[0]
    if not int(scope["minimum_block_number"]) <= block_number <= int(
        scope["maximum_block_number"]
    ):
        raise ControlCutoffBoundaryActivationError("block_outside_range")
    if sequence_number <= 0:
        raise ControlCutoffBoundaryActivationError("sequence_invalid")
    if sequence_number in used_sequences:
        raise ControlCutoffBoundaryActivationError("sequence_replay")
    maximum = int(activation.get("maximum_request_count", 0))
    if requests_used < 0 or requests_used >= maximum:
        raise ControlCutoffBoundaryActivationError("request_budget_exhausted")
    retry_limit = int(activation.get("retry_limit", -1))
    scope_maximum = int(scope["maximum_block_header_queries"]) * (1 + retry_limit)
    if scope_requests_used < 0 or scope_requests_used >= scope_maximum:
        raise ControlCutoffBoundaryActivationError("scope_budget_exhausted")
    now = _time(now_utc, "now_utc")
    if now < _time(activation.get("activation_start_utc"), "activation_start_utc"):
        raise ControlCutoffBoundaryActivationError("activation_not_yet_valid")
    if now > _time(activation.get("activation_expires_utc"), "activation_expires_utc"):
        raise ControlCutoffBoundaryActivationError("activation_expired")
    return {
        "authorized": True,
        "sequence_number": sequence_number,
        "range_scope_sha256": scope["range_scope_sha256"],
        "request_sha256": _canonical_sha(
            {
                "target_id": target_id,
                "chain": chain.strip().lower(),
                "provider_id": provider_id,
                "method": method,
                "params": params,
                "sequence_number": sequence_number,
            }
        ),
        "remaining_scope_request_count_after_call": (
            scope_maximum - scope_requests_used - 1
        ),
        "remaining_request_count_after_call": maximum - requests_used - 1,
    }
