from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator
import pandas as pd

from chronosaudit_stage2.onchain import (
    JsonRpcProvider,
    call_word_to_address,
    canonical_block_selector,
    historical_identity_snapshot,
    normalize_block_header,
    normalize_hex,
    provider_consensus,
    storage_word_to_address,
)


STRICT_SNAPSHOT_SCHEMA_VERSION = "chronosaudit-strict-historical-snapshot-v1"
STRICT_HISTORICAL_STATUS = "HISTORICAL_SNAPSHOT_VERIFIED"
RPC_RECEIPT_MANIFEST_SCHEMA_VERSION = "chronosaudit-rpc-receipt-manifest-v1"
REQUIRED_STATE_CELLS = (
    "block_capability",
    "runtime_code",
    "eip1967_implementation_slot",
    "eip1967_beacon_slot",
    "eip1967_admin_slot",
    "beacon_implementation_call",
    "implementation_runtime_code",
)
_SHA256_HEX = set("0123456789abcdef")
_ROOT = Path(__file__).resolve().parents[3]


class InsufficientIncidentLeadTimeError(ValueError):
    """The preregistered cutoff landmark occurs after the incident boundary."""


def _optional_block_number(value: Any) -> int | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        if bool(pd.isna(value)):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(value, float) and math.isnan(value):
        return None
    return int(value)


@dataclass(frozen=True)
class StrictSnapshotValidation:
    ok: bool
    errors: tuple[str, ...]
    receipt_binding_complete: bool
    schema_valid: bool
    artifact_sha256_valid: bool
    case_input_sha256: str
    policy_sha256: str
    provider_identity_sha256: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["errors"] = list(self.errors)
        return payload


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in _SHA256_HEX for ch in text)


def _normalize_chain(value: Any) -> str:
    normalized = str(value).strip().lower()
    if normalized == "mainnet":
        return "ethereum"
    if normalized in {"arb", "arbi"}:
        return "arbitrum"
    return normalized


def _verified_family_name(value: str | None) -> str | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if not lowered or lowered.startswith("unverified"):
        return None
    return lowered


def _distinct_verified_families(providers: list[JsonRpcProvider]) -> list[str]:
    return sorted({family for family in (_verified_family_name(provider.provider_family) for provider in providers) if family})


def _safe_receipt_path(value: Any, allowed_root: Path) -> Path:
    try:
        path = Path(str(value or "")).resolve(strict=False)
    except Exception as exc:  # pragma: no cover - defensive normalization
        raise ValueError("receipt_path_escapes_root") from exc
    root = allowed_root.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("receipt_path_escapes_root") from exc
    if not path.is_file() or path.is_symlink():
        raise ValueError("receipt_path_escapes_root")
    return path


def _block_selector(params: list[Any], method: str | None = None) -> Any:
    if method == "eth_getBlockByNumber" and params:
        return params[0]
    return params[-1] if params else None


def _is_eip1898_selector(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("requireCanonical") is True
        and isinstance(value.get("blockHash"), str)
        and str(value["blockHash"]).startswith("0x")
        and len(str(value["blockHash"])) == 66
    )


def _annotate_observations(
    consensus_result: dict[str, Any],
    providers: list[JsonRpcProvider],
) -> dict[str, Any]:
    observations = []
    identities = {provider.provider_id: getattr(provider, "public_endpoint_id", provider.provider_id) for provider in providers}
    for observation in consensus_result.get("observations", []):
        item = dict(observation)
        item["block_selector"] = _block_selector(list(item.get("params", [])), str(item.get("method", "")))
        item["provider_identity"] = identities.get(str(item.get("provider_id", "")), str(item.get("provider_id", "")))
        observations.append(item)
    return {**consensus_result, "observations": observations}


def _annotate_cutoff_search(search: dict[str, Any], providers: list[JsonRpcProvider]) -> dict[str, Any]:
    annotated = _annotate_observations(
        {"observations": list(search.get("binary_search_observations", []) or [])},
        providers,
    )
    return {**search, "binary_search_observations": annotated["observations"]}


def _provider_identity_index(provider_identity: dict[str, Any]) -> dict[str, Any]:
    providers: dict[str, dict[str, str]] = {}
    valid_families: set[str] = set()
    errors: list[str] = []
    for family in list(provider_identity.get("families", []) or []):
        family_id = _verified_family_name(family.get("family_id"))
        evidence = list(family.get("evidence", []) or [])
        evidence_has_hash = bool(
            _is_sha256(family.get("endpoint_template_sha256"))
            or any(
                _is_sha256(item.get("endpoint_template_sha256"))
                or _is_sha256(item.get("sha256"))
                or _is_sha256(item.get("actual_sha256"))
                for item in evidence
            )
        )
        family_complete = bool(
            family_id
            and family.get("operator_verified") is True
            and family.get("complete") is True
            and evidence
            and evidence_has_hash
        )
        if not family_complete:
            errors.append("provider_identity_incomplete")
        for item in evidence:
            provider_id = str(item.get("provider_id", "")).strip()
            provider_identity_value = str(item.get("provider_identity", "")).strip()
            if not provider_id or not provider_identity_value or not family_id:
                errors.append("provider_identity_incomplete")
                continue
            providers[provider_id] = {
                "family_id": family_id,
                "provider_identity": provider_identity_value,
            }
        if family_complete:
            valid_families.add(family_id)
    complete = bool(provider_identity.get("complete") is True and len(valid_families) >= 2 and providers)
    if not complete:
        errors.append("provider_identity_incomplete")
    return {
        "complete": complete,
        "families": sorted(valid_families),
        "providers": providers,
        "errors": list(dict.fromkeys(errors)),
    }


def _validate_observation_bindings(
    observations: list[dict[str, Any]],
    *,
    allowed_root: Path,
    normalizer: Callable[[Any], Any] | None,
    expected_value: Any | None,
    require_distinct_families: bool,
    require_eip1898: bool,
    provider_index: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    successful = [dict(item) for item in observations if item.get("error") in (None, "")]
    families: set[str] = set()
    if not successful:
        return ["missing_decision_observations"]
    expected_json = _canonical_json(expected_value) if expected_value is not None else None
    for observation in successful:
        provider_id = str(observation.get("provider_id", "")).strip()
        provider_family = _verified_family_name(observation.get("provider_family"))
        provider_identity_value = str(observation.get("provider_identity", "")).strip()
        selector = observation.get("block_selector")
        if not _is_sha256(observation.get("request_sha256")):
            errors.append("missing_request_sha256")
        response_sha = str(observation.get("response_sha256", "")).lower()
        if not _is_sha256(response_sha):
            errors.append("missing_response_sha256")
        if not str(observation.get("method", "")).strip():
            errors.append("missing_method")
        if not str(observation.get("observed_at_utc", "")).strip():
            errors.append("missing_observed_at_utc")
        if require_eip1898:
            if not _is_eip1898_selector(selector):
                errors.append("non_eip1898_block_selector")
        elif selector in (None, "", False):
            errors.append("missing_block_selector")
        if not provider_id or not provider_family or not provider_identity_value:
            errors.append("provider_identity_incomplete")
        else:
            if provider_index is not None:
                binding = (provider_index.get("providers") or {}).get(provider_id)
                if (
                    binding is None
                    or binding.get("family_id") != provider_family
                    or binding.get("provider_identity") != provider_identity_value
                ):
                    errors.append("provider_identity_observation_mismatch")
            families.add(provider_family)
        try:
            raw_path = _safe_receipt_path(observation.get("raw_response_path"), allowed_root)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if _is_sha256(response_sha):
            actual_response_sha = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            if actual_response_sha != response_sha:
                errors.append("response_hash_mismatch")
        if normalizer is not None:
            try:
                normalized_result = normalizer(observation.get("result"))
            except Exception:
                errors.append("observation_normalization_failed")
                continue
            if expected_json is not None and _canonical_json(normalized_result) != expected_json:
                errors.append("observation_result_mismatch")
    if require_distinct_families and len(families) < 2:
        errors.append("same_provider_family")
    return list(dict.fromkeys(errors))


def _normalize_consensus_header_value(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("malformed block header")
    return {
        "number": int(str(value["number"]), 16),
        "hash": normalize_hex(value["hash"]),
        "timestamp": int(str(value["timestamp"]), 16),
    }


def verify_snapshot_receipt_bindings(
    cells: dict[str, dict[str, Any]],
    *,
    required_cells: tuple[str, ...] | list[str],
    allowed_root: str | Path,
    provider_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(allowed_root)
    provider_index = (
        _provider_identity_index(provider_identity)
        if provider_identity is not None
        else None
    )
    output: dict[str, Any] = {"complete": True, "cells": {}}
    for cell_name in required_cells:
        if cell_name not in cells:
            output["complete"] = False
            output["cells"][cell_name] = {
                "status": "missing",
                "complete": False,
                "provider_families": [],
                "receipt_sha256": [],
                "errors": ["missing_required_state_cell"],
            }
            continue
        cell = dict(cells.get(cell_name, {}))
        errors: list[str] = []
        status = str(cell.get("status", ""))
        if status == "not_applicable":
            output["cells"][cell_name] = {
                "status": status,
                "complete": True,
                "provider_families": [],
                "receipt_sha256": [],
                "errors": [],
            }
            continue
        if status != "consensus":
            errors.append("non_consensus_status")

        observations = [dict(item) for item in cell.get("observations", [])]
        successful = [item for item in observations if item.get("error") in (None, "")]
        families = sorted(
            {
                str(item.get("provider_family", "")).strip().lower()
                for item in successful
                if str(item.get("provider_family", "")).strip()
                and not str(item.get("provider_family", "")).strip().lower().startswith("unverified")
            }
        )
        if len(families) < 2:
            errors.append("same_provider_family")

        normalizer = {
            "block_capability": normalize_block_header,
            "runtime_code": normalize_hex,
            "eip1967_implementation_slot": storage_word_to_address,
            "eip1967_beacon_slot": storage_word_to_address,
            "eip1967_admin_slot": storage_word_to_address,
            "beacon_implementation_call": call_word_to_address,
            "implementation_runtime_code": normalize_hex,
        }.get(cell_name, lambda value: value)
        errors.extend(
            _validate_observation_bindings(
                observations,
                allowed_root=root,
                normalizer=normalizer,
                expected_value=cell.get("value"),
                require_distinct_families=True,
                require_eip1898=cell_name != "block_capability",
                provider_index=provider_index,
            )
        )
        receipt_hashes: list[str] = []
        for observation in successful:
            response_sha = str(observation.get("response_sha256", "")).lower()
            if not _is_sha256(response_sha):
                continue
            try:
                raw_path = _safe_receipt_path(observation.get("raw_response_path"), root)
            except ValueError as exc:
                continue
            actual_response_sha = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            if actual_response_sha == response_sha:
                receipt_hashes.append(response_sha)

        complete = not errors
        output["complete"] = bool(output["complete"] and complete)
        output["cells"][cell_name] = {
            "status": status,
            "complete": complete,
            "provider_families": families,
            "receipt_sha256": sorted(set(receipt_hashes)),
            "errors": list(dict.fromkeys(errors)),
        }
    return output


def first_block_at_or_after_timestamp(
    provider: JsonRpcProvider,
    *,
    target_timestamp: int,
    lower_block: int,
    upper_block: int,
) -> dict[str, Any]:
    if lower_block < 0 or upper_block <= lower_block:
        raise ValueError("invalid timestamp-search bounds")

    def header(block_number: int) -> tuple[dict[str, Any], dict[str, Any]]:
        observation = provider.call("eth_getBlockByNumber", [hex(block_number), False])
        if observation.error or not isinstance(observation.result, dict):
            raise RuntimeError(f"block header unavailable at {block_number}: {observation.error}")
        timestamp = int(str(observation.result["timestamp"]), 16)
        return observation.__dict__, {
            "number": int(str(observation.result["number"]), 16),
            "hash": normalize_hex(observation.result["hash"]),
            "timestamp": timestamp,
        }

    lower_observation, lower = header(lower_block)
    upper_observation, upper = header(upper_block)
    if lower["timestamp"] >= target_timestamp:
        raise ValueError("lower search bound is not before the target timestamp")
    if upper["timestamp"] < target_timestamp:
        raise InsufficientIncidentLeadTimeError(
            "upper search bound is before the target timestamp"
        )

    observations = [lower_observation, upper_observation]
    lo = lower_block
    hi = upper_block
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        observation, value = header(mid)
        observations.append(observation)
        if value["timestamp"] >= target_timestamp:
            hi = mid
        else:
            lo = mid

    previous_observation, previous = header(lo)
    cutoff_observation, cutoff = header(hi)
    observations.extend([previous_observation, cutoff_observation])
    if not (previous["timestamp"] < target_timestamp <= cutoff["timestamp"]):
        raise RuntimeError("timestamp landmark bracket invariant failed")
    return {
        "target_timestamp": target_timestamp,
        "previous_block": previous,
        "cutoff_block": cutoff,
        "binary_search_observations": observations,
    }


def _first_block_at_or_after_timestamp_from_providers(
    providers: list[JsonRpcProvider],
    *,
    target_timestamp: int,
    lower_block: int,
    upper_block: int,
) -> dict[str, Any]:
    if not providers:
        raise ValueError("timestamp search requires at least one provider")
    preferred_order = providers[1:] + providers[:1]
    last_error: RuntimeError | None = None
    attempted_provider_ids: list[str] = []
    provider_failures: list[dict[str, str]] = []
    for provider in preferred_order:
        provider_id = str(getattr(provider, "provider_id", "")).strip()
        attempted_provider_ids.append(provider_id)
        try:
            result = first_block_at_or_after_timestamp(
                provider,
                target_timestamp=target_timestamp,
                lower_block=lower_block,
                upper_block=upper_block,
            )
        except RuntimeError as exc:
            last_error = exc
            provider_failures.append(
                {
                    "provider_id": provider_id,
                    "error_type": "header_unavailable",
                }
            )
            continue
        result["attempted_provider_ids"] = list(attempted_provider_ids)
        result["failed_provider_ids"] = [failure["provider_id"] for failure in provider_failures]
        result["fallback_used"] = bool(provider_failures)
        result["provider_selection_basis"] = "provider_list_secondary_then_primary"
        result["provider_failures"] = provider_failures
        return result
    assert last_error is not None
    raise last_error


def verify_cutoff_block_bracket(
    providers: list[JsonRpcProvider],
    *,
    target_timestamp: int,
    previous_block_number: int,
    cutoff_block_number: int,
    consensus_fn: Callable[..., dict[str, Any]] = provider_consensus,
) -> dict[str, Any]:
    if cutoff_block_number != previous_block_number + 1:
        raise ValueError("cutoff bracket must contain adjacent blocks")

    def normalize_header(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("malformed block header")
        return {
            "number": int(str(value["number"]), 16),
            "hash": normalize_hex(value["hash"]),
            "timestamp": int(str(value["timestamp"]), 16),
        }

    previous = _annotate_observations(
        consensus_fn(
            providers,
            "eth_getBlockByNumber",
            [hex(previous_block_number), False],
            normalize_header,
            require_distinct_provider_families=True,
        ),
        providers,
    )
    cutoff = _annotate_observations(
        consensus_fn(
            providers,
            "eth_getBlockByNumber",
            [hex(cutoff_block_number), False],
            normalize_header,
            require_distinct_provider_families=True,
        ),
        providers,
    )
    blockers: list[str] = []
    if previous.get("status") != "consensus":
        blockers.append("previous_block_no_independent_consensus")
    if cutoff.get("status") != "consensus":
        blockers.append("cutoff_block_no_independent_consensus")
    if not blockers and not (previous["value"]["timestamp"] < target_timestamp <= cutoff["value"]["timestamp"]):
        blockers.append("timestamp_bracket_invariant_failed")
    return {"status": "VERIFIED" if not blockers else "PARTIAL", "blockers": blockers, "previous": previous, "cutoff": cutoff}


def snapshot_state_cells(
    snapshot: dict[str, Any],
    *,
    providers: list[JsonRpcProvider],
    consensus_fn: Callable[..., dict[str, Any]] = provider_consensus,
) -> dict[str, dict[str, Any]]:
    cells: dict[str, dict[str, Any]] = {
        "block_capability": dict(snapshot.get("block", {"status": "missing"})),
        "runtime_code": dict(snapshot.get("code", {"status": "missing"})),
        "eip1967_implementation_slot": dict(snapshot.get("implementation", {"status": "missing"})),
        "eip1967_beacon_slot": dict(snapshot.get("beacon", {"status": "missing"})),
        "eip1967_admin_slot": dict(snapshot.get("admin", {"status": "missing"})),
        "beacon_implementation_call": dict(
            snapshot.get("beacon_implementation", {"status": "missing", "value": None, "observations": []})
        ),
    }
    implementation_address = (
        snapshot.get("implementation", {}).get("value")
        or snapshot.get("beacon_implementation", {}).get("value")
        or snapshot.get("eip1167_target")
    )
    if not implementation_address:
        cells["implementation_runtime_code"] = {"status": "not_applicable", "value": None, "observations": []}
        return cells
    block_hash = snapshot.get("canonical_block_hash")
    if not block_hash:
        cells["implementation_runtime_code"] = {"status": "missing", "value": None, "observations": []}
        return cells
    cells["implementation_runtime_code"] = _annotate_observations(
        consensus_fn(
            providers,
            "eth_getCode",
            [implementation_address, canonical_block_selector(block_hash)],
            normalize_hex,
            require_distinct_provider_families=True,
        ),
        providers,
    )
    return cells


def _verify_code_transition(
    providers: list[JsonRpcProvider],
    *,
    address: str,
    deployment_block: int,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    code: dict[str, Any] = {}
    for label, block_number in (("previous", deployment_block - 1), ("deployment", deployment_block)):
        header = _annotate_observations(
            provider_consensus(
                providers,
                "eth_getBlockByNumber",
                [hex(block_number), False],
                lambda value: {
                    "number": int(str(value["number"]), 16),
                    "hash": normalize_hex(value["hash"]),
                    "timestamp": int(str(value["timestamp"]), 16),
                },
                require_distinct_provider_families=True,
            ),
            providers,
        )
        headers[label] = header
        if header.get("status") != "consensus":
            code[label] = {"status": "blocked_no_canonical_block_consensus", "value": None, "observations": []}
            continue
        code[label] = _annotate_observations(
            provider_consensus(
                providers,
                "eth_getCode",
                [address, canonical_block_selector(header["value"]["hash"])],
                normalize_hex,
                require_distinct_provider_families=True,
            ),
            providers,
        )
    blockers: list[str] = []
    if code["previous"].get("status") != "consensus" or code["previous"].get("value") != "0x":
        blockers.append("code_not_absent_immediately_before_deployment")
    if code["deployment"].get("status") != "consensus" or code["deployment"].get("value") in (None, "0x"):
        blockers.append("code_not_present_at_deployment")
    return {"status": "VERIFIED" if not blockers else "PARTIAL", "blockers": blockers, "headers": headers, "code": code}


def _provider_identity_material(
    providers: list[JsonRpcProvider],
    policy: dict[str, Any],
) -> dict[str, Any]:
    provided = policy.get("provider_identity")
    if isinstance(provided, dict):
        return provided
    families_by_id: dict[str, dict[str, Any]] = {}
    for provider in providers:
        family = _verified_family_name(getattr(provider, "provider_family", None))
        identity = dict(getattr(provider, "provider_identity_evidence", {}) or {})
        if not family or not identity or not _is_sha256(identity.get("endpoint_template_sha256")):
            continue
        provider_id = str(identity.get("provider_id") or getattr(provider, "provider_id", "")).strip()
        provider_identity_value = str(getattr(provider, "public_endpoint_id", "")).strip()
        if not provider_id or not provider_identity_value:
            continue
        family_entry = families_by_id.setdefault(
            family,
            {
                "family_id": family,
                "operator_verified": True,
                "complete": True,
                "endpoint_template_sha256": str(identity.get("endpoint_template_sha256")),
                "evidence": [],
            },
        )
        family_entry["evidence"].append(
            {
                "provider_id": provider_id,
                "provider_identity": provider_identity_value,
                "endpoint_template_sha256": str(identity.get("endpoint_template_sha256")),
                "operator_evidence_url": str(identity.get("operator_evidence_url", "")),
            }
        )
    families = list(families_by_id.values())
    return {"complete": len(families) >= 2, "families": families}


def _policy_material(policy: dict[str, Any]) -> dict[str, Any]:
    material = dict(policy)
    material.pop("provider_identity", None)
    cutoff_policy = material.get("cutoff_policy")
    if isinstance(cutoff_policy, dict):
        material["cutoff_policy"] = dict(cutoff_policy)
    return material


def _cutoff_policy_values(policy_input: dict[str, Any] | None) -> tuple[int, float]:
    cutoff_policy = {}
    if isinstance(policy_input, dict):
        nested = policy_input.get("cutoff_policy")
        if isinstance(nested, dict):
            cutoff_policy = nested
    try:
        primary_hours = int(cutoff_policy.get("primary_landmark_hours", 24))
    except (TypeError, ValueError):
        primary_hours = 24
    try:
        minimum_lead_hours = float(cutoff_policy.get("minimum_incident_lead_hours", 1.0))
    except (TypeError, ValueError):
        minimum_lead_hours = 1.0
    return primary_hours, minimum_lead_hours


def _load_schema(name: str) -> dict[str, Any]:
    path = _ROOT / "schemas" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact_hash_payload(snapshot: dict[str, Any]) -> dict[str, Any]:
    payload = dict(snapshot)
    # Validation metadata and runtime delivery fields are excluded so the
    # artifact can be sealed first and annotated afterward without recursive
    # hash instability.
    payload.pop("strict_snapshot_validation", None)
    payload.pop("artifact_sha256_without_self_hash", None)
    payload.pop("artifact_sha256", None)
    payload.pop("cached_artifact_reused", None)
    payload.pop("status", None)
    payload.pop("blocked_reason", None)
    return payload


def _attach_self_hashes(snapshot: dict[str, Any]) -> dict[str, Any]:
    payload = _artifact_hash_payload(snapshot)
    payload["artifact_sha256_without_self_hash"] = _sha256_json(payload)
    payload["artifact_sha256"] = _sha256_json(payload)
    return payload


def _seal_strict_snapshot_artifact(
    artifact: dict[str, Any],
    *,
    schema: dict[str, Any],
    receipt_root: Path,
    provider_identity: dict[str, Any],
    include_runtime_status: bool,
) -> dict[str, Any]:
    source_payload = dict(artifact)
    if not source_payload.get("artifact_sha256_without_self_hash") or not source_payload.get("artifact_sha256"):
        source_payload = _attach_self_hashes(source_payload)
    source_validation = validate_strict_historical_snapshot(
        source_payload,
        schema=schema,
        receipt_root=receipt_root,
        provider_identity=provider_identity,
    )
    working = dict(artifact)
    if not source_validation.ok:
        working["strict_snapshot_closed"] = False
        working["blockers"] = sorted(set(list(working.get("blockers", [])) + list(source_validation.errors)))
    if include_runtime_status:
        working["status"] = "VERIFIED" if working.get("strict_snapshot_closed") else "PARTIAL"
        working["blocked_reason"] = None if working.get("strict_snapshot_closed") else (
            working["blockers"][0] if working.get("blockers") else "strict_snapshot_not_closed"
        )
    sealed = _attach_self_hashes(working)
    # `strict_snapshot_validation` is attached after sealing and excluded from
    # the hash domain, so this second validation pass remains stable.
    sealed_validation = validate_strict_historical_snapshot(
        sealed,
        schema=schema,
        receipt_root=receipt_root,
        provider_identity=provider_identity,
    )
    sealed["strict_snapshot_validation"] = sealed_validation.to_dict()
    return sealed


def _cached_snapshot_valid(
    cached_artifact: dict[str, Any],
    *,
    case: dict[str, Any],
    policy: dict[str, Any],
    receipt_root: Path,
    provider_identity: dict[str, Any],
) -> bool:
    if not isinstance(cached_artifact, dict):
        return False
    if cached_artifact.get("case_input_sha256") != _sha256_json(case):
        return False
    if cached_artifact.get("policy_sha256") != _sha256_json(_policy_material(policy)):
        return False
    validation = validate_strict_historical_snapshot(
        cached_artifact,
        schema=_load_schema("strict_historical_snapshot.schema.json"),
        receipt_root=receipt_root,
        provider_identity=provider_identity,
    )
    return validation.ok


def _build_strict_historical_snapshot(
    case: dict[str, Any],
    *,
    providers: list[JsonRpcProvider],
    policy: dict[str, Any],
    receipt_root: Path,
    provider_identity: dict[str, Any],
) -> dict[str, Any]:
    normalized_chain = _normalize_chain(case["chain"])
    address = str(case["address"]).lower()
    incident_block = int(case["incident_block"])
    verified_families = _distinct_verified_families(providers)
    policy_input = _policy_material(policy)
    target_hours, minimum_lead_hours = _cutoff_policy_values(policy_input)
    prediction_cutoff_block = _optional_block_number(case.get("prediction_cutoff_block"))
    raw_deployment_block = case.get("deployment_block")
    try:
        deployment_block = int(raw_deployment_block)
    except (TypeError, ValueError):
        return _attach_self_hashes(
            {
                "schema_version": STRICT_SNAPSHOT_SCHEMA_VERSION,
                "case_id": case["case_id"],
                "case_name": case.get("case_name", ""),
                "chain": normalized_chain,
                "address": address,
                "case_input": dict(case),
                "case_input_sha256": _sha256_json(case),
                "policy_input": policy_input,
                "policy_sha256": _sha256_json(policy_input),
                "provider_identity": provider_identity,
                "provider_identity_sha256": _sha256_json(provider_identity),
                "provider_families": verified_families,
                "deployment_block": raw_deployment_block,
                "deployment_timestamp": None,
                "prediction_cutoff_policy": str(policy_input.get("cutoff_policy", {}).get("rule", "")),
                "prediction_cutoff_target_timestamp": None,
                "prediction_cutoff_block": prediction_cutoff_block,
                "prediction_cutoff_timestamp": None,
                "prediction_cutoff_block_hash": None,
                "incident_block": incident_block,
                "incident_timestamp": None,
                "cutoff_lead_hours": None,
                "deployment_transition": {"status": "PARTIAL", "blockers": ["missing_deployment_block"], "headers": {}, "code": {}},
                "cutoff_search": {},
                "cutoff_bracket": {"status": "PARTIAL", "blockers": ["missing_deployment_block"]},
                "incident_block_consensus": {"status": "PARTIAL", "value": None, "observations": []},
                "snapshot": {"status": "partial_or_disputed"},
                "state_cells": {},
                "receipt_bindings": {"complete": False, "cells": {}},
                "required_state_cells": list(REQUIRED_STATE_CELLS),
                "strict_snapshot_closed": False,
                "blockers": ["missing_deployment_block"],
            }
        )
    transition = _verify_code_transition(providers, address=address, deployment_block=deployment_block)
    deployment_header = transition["headers"]["deployment"]
    deployment_timestamp = (
        int(deployment_header["value"]["timestamp"])
        if deployment_header.get("status") == "consensus" and deployment_header.get("value")
        else None
    )
    target_timestamp = deployment_timestamp + (target_hours * 3600) if deployment_timestamp is not None else None
    if deployment_timestamp is None:
        blockers = list(transition.get("blockers", []))
        if deployment_header.get("status") != "consensus":
            blockers.append("deployment_header_no_independent_consensus")
        else:
            blockers.append("missing_deployment_timestamp")
        return _attach_self_hashes(
            {
                "schema_version": STRICT_SNAPSHOT_SCHEMA_VERSION,
                "case_id": case["case_id"],
                "case_name": case.get("case_name", ""),
                "chain": normalized_chain,
                "address": address,
                "case_input": dict(case),
                "case_input_sha256": _sha256_json(case),
                "policy_input": policy_input,
                "policy_sha256": _sha256_json(policy_input),
                "provider_identity": provider_identity,
                "provider_identity_sha256": _sha256_json(provider_identity),
                "provider_families": verified_families,
                "deployment_block": deployment_block,
                "deployment_timestamp": None,
                "prediction_cutoff_policy": str(policy_input.get("cutoff_policy", {}).get("rule", "")),
                "prediction_cutoff_target_timestamp": None,
                "prediction_cutoff_block": prediction_cutoff_block,
                "prediction_cutoff_timestamp": None,
                "prediction_cutoff_block_hash": None,
                "incident_block": incident_block,
                "incident_timestamp": None,
                "cutoff_lead_hours": None,
                "deployment_transition": transition,
                "cutoff_search": {},
                "cutoff_bracket": {"status": "PARTIAL", "blockers": list(dict.fromkeys(blockers))},
                "incident_block_consensus": {"status": "PARTIAL", "value": None, "observations": []},
                "snapshot": {"status": "partial_or_disputed"},
                "state_cells": {},
                "receipt_bindings": {"complete": False, "cells": {}},
                "required_state_cells": list(REQUIRED_STATE_CELLS),
                "strict_snapshot_closed": False,
                "blockers": list(dict.fromkeys(blockers)),
            }
        )

    if prediction_cutoff_block is not None:
        cutoff_number = prediction_cutoff_block
        previous_number = cutoff_number - 1
        search = {
            "target_timestamp": target_timestamp,
            "previous_block": {"number": previous_number},
            "cutoff_block": {"number": cutoff_number},
            "binary_search_observations": [],
            "reused_from_case_input": True,
        }
    else:
        search = _first_block_at_or_after_timestamp_from_providers(
            providers,
            target_timestamp=int(target_timestamp),
            lower_block=deployment_block,
            upper_block=incident_block,
        )
        search = _annotate_cutoff_search(search, providers)
        cutoff_number = int(search["cutoff_block"]["number"])
        previous_number = int(search["previous_block"]["number"])

    bracket = verify_cutoff_block_bracket(
        providers,
        target_timestamp=int(target_timestamp),
        previous_block_number=previous_number,
        cutoff_block_number=cutoff_number,
    )
    incident = _annotate_observations(
        provider_consensus(
            providers,
            "eth_getBlockByNumber",
            [hex(incident_block), False],
            lambda value: {
                "number": int(str(value["number"]), 16),
                "hash": normalize_hex(value["hash"]),
                "timestamp": int(str(value["timestamp"]), 16),
            },
            require_distinct_provider_families=True,
        ),
        providers,
    )
    incident_timestamp = int(incident["value"]["timestamp"]) if incident.get("status") == "consensus" else None
    cutoff_timestamp = int(bracket["cutoff"]["value"]["timestamp"]) if bracket.get("status") == "VERIFIED" else None
    lead_hours = (
        (incident_timestamp - cutoff_timestamp) / 3600 if incident_timestamp is not None and cutoff_timestamp is not None else None
    )

    snapshot = _annotate_observations(
        historical_identity_snapshot(address, cutoff_number, providers, strict_provider_families=True),
        providers,
    )
    for key in ("block", "code", "implementation", "beacon", "admin", "beacon_implementation"):
        if isinstance(snapshot.get(key), dict):
            snapshot[key] = _annotate_observations(snapshot[key], providers)
    cells = snapshot_state_cells(snapshot, providers=providers)
    bindings = verify_snapshot_receipt_bindings(
        cells,
        required_cells=REQUIRED_STATE_CELLS,
        allowed_root=receipt_root,
        provider_identity=provider_identity,
    )

    blockers: list[str] = []
    provider_identity_index = _provider_identity_index(provider_identity)
    if not provider_identity_index["complete"]:
        blockers.append("provider_identity_incomplete")
    if len(verified_families) < 2:
        blockers.append("insufficient_independent_provider_families")
    blockers.extend(transition["blockers"])
    blockers.extend(bracket["blockers"])
    if incident.get("status") != "consensus":
        blockers.append("incident_block_no_independent_consensus")
    if lead_hours is None or lead_hours < minimum_lead_hours:
        blockers.append("insufficient_incident_lead_time")
    if snapshot.get("status") != "complete":
        blockers.append(f"snapshot_status:{snapshot.get('status', 'missing')}")
    if not bindings["complete"]:
        blockers.append("receipt_binding_incomplete")

    artifact = {
        "schema_version": STRICT_SNAPSHOT_SCHEMA_VERSION,
        "case_id": case["case_id"],
        "case_name": case.get("case_name", ""),
        "chain": normalized_chain,
        "address": address,
        "case_input": dict(case),
        "case_input_sha256": _sha256_json(case),
        "policy_input": policy_input,
        "policy_sha256": _sha256_json(policy_input),
        "provider_identity": provider_identity,
        "provider_identity_sha256": _sha256_json(provider_identity),
        "provider_families": verified_families,
        "deployment_block": deployment_block,
        "deployment_timestamp": deployment_timestamp,
        "prediction_cutoff_policy": str(policy_input.get("cutoff_policy", {}).get("rule", "")),
        "prediction_cutoff_target_timestamp": target_timestamp,
        "prediction_cutoff_block": cutoff_number,
        "prediction_cutoff_timestamp": cutoff_timestamp,
        "prediction_cutoff_block_hash": bracket.get("cutoff", {}).get("value", {}).get("hash"),
        "incident_block": incident_block,
        "incident_timestamp": incident_timestamp,
        "cutoff_lead_hours": lead_hours,
        "deployment_transition": transition,
        "cutoff_search": search,
        "cutoff_bracket": bracket,
        "incident_block_consensus": incident,
        "snapshot": snapshot,
        "state_cells": cells,
        "receipt_bindings": bindings,
        "required_state_cells": list(REQUIRED_STATE_CELLS),
        "strict_snapshot_closed": not blockers,
        "blockers": sorted(set(blockers)),
    }
    return _attach_self_hashes(artifact)


def acquire_strict_historical_snapshot(
    case: dict[str, Any],
    *,
    providers: list[JsonRpcProvider],
    policy: dict[str, Any],
    receipt_root: str | Path,
    cached_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(receipt_root)
    provider_identity = _provider_identity_material(providers, policy)
    schema = _load_schema("strict_historical_snapshot.schema.json")
    if cached_artifact and _cached_snapshot_valid(
        cached_artifact,
        case=case,
        policy=policy,
        receipt_root=root,
        provider_identity=provider_identity,
    ):
        validation = validate_strict_historical_snapshot(
            cached_artifact,
            schema=schema,
            receipt_root=root,
            provider_identity=provider_identity,
        )
        cached = dict(cached_artifact)
        cached["cached_artifact_reused"] = True
        cached["strict_snapshot_validation"] = validation.to_dict()
        cached["status"] = "VERIFIED" if cached.get("strict_snapshot_closed") else "PARTIAL"
        cached["blocked_reason"] = None if cached.get("strict_snapshot_closed") else (
            cached["blockers"][0] if cached.get("blockers") else "strict_snapshot_not_closed"
        )
        return cached

    built = _build_strict_historical_snapshot(
        case,
        providers=providers,
        policy=policy,
        receipt_root=root,
        provider_identity=provider_identity,
    )
    return _seal_strict_snapshot_artifact(
        dict(built),
        schema=schema,
        receipt_root=root,
        provider_identity=provider_identity,
        include_runtime_status=True,
    )


def validate_strict_historical_snapshot(
    snapshot: dict[str, Any],
    *,
    schema: dict[str, Any],
    receipt_root: str | Path,
    provider_identity: dict[str, Any],
) -> StrictSnapshotValidation:
    errors: list[str] = []
    receipt_root_path = Path(receipt_root)
    validator = Draft202012Validator(schema)
    schema_errors = list(validator.iter_errors(snapshot))
    if schema_errors:
        errors.append("schema_validation_failed")

    case_input_sha256 = _sha256_json(snapshot.get("case_input"))
    policy_sha256 = _sha256_json(snapshot.get("policy_input"))
    provider_identity_sha256 = _sha256_json(provider_identity)
    if snapshot.get("case_input_sha256") != case_input_sha256:
        errors.append("case_input_mismatch")
    if snapshot.get("policy_sha256") != policy_sha256:
        errors.append("policy_input_mismatch")
    if snapshot.get("provider_identity_sha256") != provider_identity_sha256:
        errors.append("provider_identity_hash_mismatch")
    provider_index = _provider_identity_index(provider_identity)
    errors.extend(provider_index["errors"])

    case_input = dict(snapshot.get("case_input") or {})
    if (
        str(snapshot.get("case_id", "")) != str(case_input.get("case_id", ""))
        or _normalize_chain(snapshot.get("chain")) != _normalize_chain(case_input.get("chain"))
        or str(snapshot.get("address", "")).lower() != str(case_input.get("address", "")).lower()
    ):
        errors.append("case_input_mismatch")

    families = [str(item).strip().lower() for item in snapshot.get("provider_families", []) if str(item).strip()]
    if len(set(families)) < 2:
        errors.append("same_provider_family")

    deployment_timestamp = snapshot.get("deployment_timestamp")
    target_timestamp = snapshot.get("prediction_cutoff_target_timestamp")
    target_hours, minimum_lead_hours = _cutoff_policy_values(snapshot.get("policy_input"))
    if target_timestamp != (deployment_timestamp + target_hours * 3600 if deployment_timestamp is not None else None):
        errors.append("invalid_target_timestamp")

    previous_number = ((snapshot.get("cutoff_bracket") or {}).get("previous") or {}).get("value", {}).get("number")
    cutoff_number = ((snapshot.get("cutoff_bracket") or {}).get("cutoff") or {}).get("value", {}).get("number")
    if previous_number is None or cutoff_number is None or int(cutoff_number) != int(previous_number) + 1:
        errors.append("non_adjacent_cutoff_bracket")

    if float(snapshot.get("cutoff_lead_hours", 0) or 0) < minimum_lead_hours:
        errors.append("insufficient_incident_lead_time")

    historical_snapshot = dict(snapshot.get("snapshot") or {})
    if historical_snapshot.get("eip1898_pinned") is not True:
        errors.append("snapshot_not_eip1898_pinned")

    for cell_name in REQUIRED_STATE_CELLS:
        if cell_name not in snapshot.get("state_cells", {}):
            errors.append("missing_required_state_cell")
            break

    artifact_without_self = _artifact_hash_payload(snapshot)
    if snapshot.get("artifact_sha256_without_self_hash") != _sha256_json(artifact_without_self):
        errors.append("artifact_sha256_without_self_hash_mismatch")
    artifact_with_inner = dict(artifact_without_self)
    artifact_with_inner["artifact_sha256_without_self_hash"] = snapshot.get("artifact_sha256_without_self_hash")
    if snapshot.get("artifact_sha256") != _sha256_json(artifact_with_inner):
        errors.append("artifact_sha256_mismatch")

    bindings = verify_snapshot_receipt_bindings(
        snapshot.get("state_cells", {}),
        required_cells=tuple(snapshot.get("required_state_cells", REQUIRED_STATE_CELLS)),
        allowed_root=receipt_root_path,
        provider_identity=provider_identity,
    )
    for detail in bindings["cells"].values():
        errors.extend(detail.get("errors", []))

    for label in ("previous", "deployment"):
        header = (((snapshot.get("deployment_transition") or {}).get("headers") or {}).get(label) or {})
        errors.extend(
            _validate_observation_bindings(
                list(header.get("observations", []) or []),
                allowed_root=receipt_root_path,
                normalizer=_normalize_consensus_header_value,
                expected_value=header.get("value"),
                require_distinct_families=True,
                require_eip1898=False,
                provider_index=provider_index,
            )
        )
        code = (((snapshot.get("deployment_transition") or {}).get("code") or {}).get(label) or {})
        errors.extend(
            _validate_observation_bindings(
                list(code.get("observations", []) or []),
                allowed_root=receipt_root_path,
                normalizer=normalize_hex,
                expected_value=code.get("value"),
                require_distinct_families=True,
                require_eip1898=True,
                provider_index=provider_index,
            )
        )

    cutoff_search = dict(snapshot.get("cutoff_search") or {})
    search_observations = list(cutoff_search.get("binary_search_observations", []) or [])
    if search_observations or not cutoff_search.get("reused_from_case_input"):
        errors.extend(
            _validate_observation_bindings(
                search_observations,
                allowed_root=receipt_root_path,
                normalizer=_normalize_consensus_header_value,
                expected_value=None,
                require_distinct_families=False,
                require_eip1898=False,
                provider_index=provider_index,
            )
        )

    for label in ("previous", "cutoff"):
        bracket = (((snapshot.get("cutoff_bracket") or {}).get(label)) or {})
        errors.extend(
            _validate_observation_bindings(
                list(bracket.get("observations", []) or []),
                allowed_root=receipt_root_path,
                normalizer=_normalize_consensus_header_value,
                expected_value=bracket.get("value"),
                require_distinct_families=True,
                require_eip1898=False,
                provider_index=provider_index,
            )
        )

    incident = dict(snapshot.get("incident_block_consensus") or {})
    errors.extend(
        _validate_observation_bindings(
            list(incident.get("observations", []) or []),
            allowed_root=receipt_root_path,
            normalizer=_normalize_consensus_header_value,
            expected_value=incident.get("value"),
            require_distinct_families=True,
            require_eip1898=False,
            provider_index=provider_index,
        )
    )

    unique_errors = tuple(dict.fromkeys(errors))
    return StrictSnapshotValidation(
        ok=not unique_errors,
        errors=unique_errors,
        receipt_binding_complete=bool(bindings["complete"]),
        schema_valid=not schema_errors,
        artifact_sha256_valid="artifact_sha256_mismatch" not in unique_errors,
        case_input_sha256=case_input_sha256,
        policy_sha256=policy_sha256,
        provider_identity_sha256=provider_identity_sha256,
    )


def snapshot_counter_projection(
    snapshot: dict[str, Any],
    case_artifact_path: str | Path,
    case_artifact_sha256: str,
) -> dict[str, Any]:
    blank = {
        "historical_snapshot_status": "",
        "historical_snapshot_source_receipt_sha256": "",
        "historical_snapshot_identity_receipt_sha256": "",
        "historical_snapshot_source_provider_family": "",
        "historical_snapshot_identity_provider_family": "",
        "historical_snapshot_schema_valid": False,
        "historical_snapshot_hash_bound": False,
        "case_artifact_path": str(case_artifact_path),
        "case_artifact_sha256": case_artifact_sha256,
    }
    validation = dict(snapshot.get("strict_snapshot_validation") or {})
    if (
        not validation.get("ok")
        or snapshot.get("strict_snapshot_closed") is not True
        or list(snapshot.get("blockers", []) or [])
        or ((snapshot.get("deployment_transition") or {}).get("status") != "VERIFIED")
        or ((snapshot.get("cutoff_bracket") or {}).get("status") != "VERIFIED")
        or ((snapshot.get("incident_block_consensus") or {}).get("status") != "consensus")
        or ((snapshot.get("snapshot") or {}).get("status") != "complete")
        or ((snapshot.get("receipt_bindings") or {}).get("complete") is not True)
    ):
        return blank
    if not _is_sha256(case_artifact_sha256):
        return blank

    observations = [
        dict(item)
        for item in ((snapshot.get("state_cells") or {}).get("runtime_code") or {}).get("observations", [])
        if item.get("error") in (None, "")
    ]
    distinct: list[dict[str, Any]] = []
    seen: set[str] = set()
    for observation in observations:
        family = str(observation.get("provider_family", "")).strip()
        if not family or family in seen:
            continue
        seen.add(family)
        distinct.append(observation)
        if len(distinct) == 2:
            break
    if len(distinct) < 2:
        return blank

    return {
        **blank,
        "historical_snapshot_status": STRICT_HISTORICAL_STATUS,
        "historical_snapshot_source_receipt_sha256": str(distinct[0].get("response_sha256", "")),
        "historical_snapshot_identity_receipt_sha256": str(distinct[1].get("response_sha256", "")),
        "historical_snapshot_source_provider_family": str(distinct[0].get("provider_family", "")),
        "historical_snapshot_identity_provider_family": str(distinct[1].get("provider_family", "")),
        "historical_snapshot_schema_valid": True,
        "historical_snapshot_hash_bound": True,
    }


__all__ = [
    "REQUIRED_STATE_CELLS",
    "RPC_RECEIPT_MANIFEST_SCHEMA_VERSION",
    "STRICT_HISTORICAL_STATUS",
    "STRICT_SNAPSHOT_SCHEMA_VERSION",
    "StrictSnapshotValidation",
    "acquire_strict_historical_snapshot",
    "first_block_at_or_after_timestamp",
    "snapshot_counter_projection",
    "snapshot_state_cells",
    "validate_strict_historical_snapshot",
    "verify_cutoff_block_bracket",
    "verify_snapshot_receipt_bindings",
]
