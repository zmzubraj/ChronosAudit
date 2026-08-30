from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from chronosaudit_stage2.onchain import ProviderObservation

from .providers import ProviderRegistry


SCHEMA_VERSION = "stage2_control_derived_state_capability.v1"
VERIFICATION_SCHEMA_VERSION = "stage2_control_derived_state_capability_verification.v1"
COMPLETE_DECISION = "DUAL_PROVIDER_DERIVED_STATE_CAPABILITY_VERIFIED"
INCOMPLETE_DECISION = "DERIVED_STATE_CAPABILITY_INCOMPLETE"
_FALSE_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "counter_authority",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_CHAIN_IDS = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}
_HEX_DATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_ADDRESS_WORD = re.compile(r"0x[0-9a-fA-F]{64}")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


class ControlDerivedStateCapabilityError(ValueError):
    """Raised when target-bound Phase 2 capability evidence is invalid."""


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
        raise ControlDerivedStateCapabilityError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlDerivedStateCapabilityError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlDerivedStateCapabilityError(f"{label}_not_ordinary_file")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlDerivedStateCapabilityError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlDerivedStateCapabilityError(f"{label}_root_invalid")
    return payload


def _require_false(payload: Mapping[str, object], label: str) -> None:
    for flag in _FALSE_FLAGS:
        if payload.get(flag) is not False:
            raise ControlDerivedStateCapabilityError(f"{label}_{flag}_invalid")


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlDerivedStateCapabilityError("raw_evidence_symlink")
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_canonical_json(dict(payload)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _load_targets(path: Path) -> tuple[Path, dict[str, object], list[dict[str, object]]]:
    targets_file = _ordinary(path, "derived_state_targets")
    payload = _load(targets_file, "derived_state_targets")
    if payload.get("schema_version") != "stage2_control_derived_state_targets.v1":
        raise ControlDerivedStateCapabilityError("derived_state_targets_schema_invalid")
    if payload.get("decision") != "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION" or payload.get("complete") is not True:
        raise ControlDerivedStateCapabilityError("derived_state_targets_status_invalid")
    _require_false(payload, "derived_state_targets")
    material = {key: value for key, value in payload.items() if key != "targets_sha256"}
    if payload.get("targets_sha256") != _canonical_sha(material):
        raise ControlDerivedStateCapabilityError("derived_state_targets_self_hash_invalid")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets or not all(isinstance(row, dict) for row in targets):
        raise ControlDerivedStateCapabilityError("derived_state_targets_invalid")
    if payload.get("target_count") != len(targets) or payload.get("call_count") != sum(len(row.get("calls", [])) for row in targets):
        raise ControlDerivedStateCapabilityError("derived_state_target_count_invalid")
    seen: set[str] = set()
    for target in targets:
        target_material = {key: value for key, value in target.items() if key != "target_sha256"}
        if target.get("schema_version") != "stage2_control_derived_state_target.v1" or target.get("target_sha256") != _canonical_sha(target_material):
            raise ControlDerivedStateCapabilityError("derived_state_target_self_hash_invalid")
        target_id = str(target.get("target_id", ""))
        calls = target.get("calls")
        if not target_id or target_id in seen or not isinstance(calls, list) or len(calls) != 2:
            raise ControlDerivedStateCapabilityError("derived_state_target_invalid")
        seen.add(target_id)
        providers = {
            (str(call.get("provider_id", "")), str(call.get("operator_family", "")).lower())
            for call in calls if isinstance(call, Mapping)
        }
        methods = {str(call.get("method", "")) for call in calls if isinstance(call, Mapping)}
        expected_method = "eth_call" if target.get("derived_role") == "beacon_implementation_call" else "eth_getCode"
        if len(providers) != 2 or len({family for _, family in providers}) != 2 or methods != {expected_method}:
            raise ControlDerivedStateCapabilityError("derived_state_target_calls_invalid")
    return targets_file, payload, targets


class _Recorder:
    def __init__(self, raw_root: Path) -> None:
        raw_root.mkdir(parents=True, exist_ok=True)
        if raw_root.is_symlink():
            raise ControlDerivedStateCapabilityError("raw_root_symlink")
        self.raw_root = raw_root.resolve(strict=True)
        self.entries: list[dict[str, object]] = []
        self.sequence = 0

    def call(self, provider: Any, method: str, params: list[object]) -> ProviderObservation:
        observation = provider.call(method, params)
        if not isinstance(observation, ProviderObservation):
            raise ControlDerivedStateCapabilityError("provider_observation_invalid")
        self.sequence += 1
        provider_id = str(getattr(provider, "provider_id", ""))
        family = str(getattr(provider, "provider_family", ""))
        prefix = f"{self.sequence:05d}-{_SAFE_NAME.sub('_', provider_id)}-{_SAFE_NAME.sub('_', method)}"
        request = {"schema_version": "stage2_control_derived_state_capability_request.v1", "provider_id": provider_id, "provider_family": family, "method": method, "params": params}
        response = {"schema_version": "stage2_control_derived_state_capability_response.v1", "provider_id": observation.provider_id, "provider_family": family, "method": observation.method, "params": observation.params, "result": observation.result, "error": observation.error, "observed_at_unix": observation.observed_at_unix, "observed_at_utc": observation.observed_at_utc, "http_status": observation.http_status, "attempt": observation.attempt, "transport_request_sha256": observation.request_sha256, "transport_response_sha256": observation.response_sha256}
        for kind, payload in (("request", request), ("response", response)):
            path = self.raw_root / f"{prefix}-{kind}.json"
            _atomic_write(path, payload)
            self.entries.append({"sequence": self.sequence, "kind": kind, "provider_id": provider_id, "method": method, "path": path.relative_to(self.raw_root).as_posix(), "sha256": _file_sha(path)})
        return observation


def _quantity(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise ControlDerivedStateCapabilityError("chain_id_invalid")
    return int(value, 16)


def _semantic(method: str, value: object) -> str:
    text = str(value or "")
    if method == "eth_getCode" and _HEX_DATA.fullmatch(text):
        return text.lower()
    if method == "eth_call" and _ADDRESS_WORD.fullmatch(text):
        return text.lower()
    raise ControlDerivedStateCapabilityError(f"historical_{method}_invalid")


def _probe_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for target in targets:
        method = str(target["calls"][0]["method"])
        groups.setdefault((str(target["chain"]).lower(), method), []).append(target)
    selected: list[dict[str, object]] = []
    for key in sorted(groups):
        rows = sorted(groups[key], key=lambda row: (int(row["evidence_block_number"]), str(row["target_id"])))
        selected.append(rows[0])
        if rows[-1]["target_id"] != rows[0]["target_id"]:
            selected.append(rows[-1])
    return selected


def assess_derived_state_capability(
    *, derived_state_targets_path: Path, provider_registry_path: Path,
    providers: Sequence[Any], raw_root: Path,
) -> dict[str, object]:
    targets_file, targets_payload, targets = _load_targets(derived_state_targets_path)
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    try:
        registry = ProviderRegistry.from_path(registry_file)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlDerivedStateCapabilityError("provider_registry_invalid") from exc
    records = {(row.chain, row.provider_id): row for row in registry.providers if row.operator_verified and row.tracking_enabled}
    runtime = {str(getattr(row, "provider_id", "")): row for row in providers}
    recorder = _Recorder(raw_root)
    probes = _probe_targets(targets)
    errors: list[str] = []
    observations: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    for target in probes:
        chain = str(target["chain"]).lower()
        for call in target["calls"]:
            provider_id = str(call["provider_id"])
            family = str(call["operator_family"]).lower()
            provider = runtime.get(provider_id)
            record = records.get((chain, provider_id))
            try:
                if provider is None or record is None or record.operator_family != family or str(getattr(provider, "provider_family", "")).lower() != family:
                    raise ControlDerivedStateCapabilityError("provider_binding_mismatch")
                chain_id = recorder.call(provider, "eth_chainId", [])
                if chain_id.error is not None or _quantity(chain_id.result) != _CHAIN_IDS.get(chain):
                    raise ControlDerivedStateCapabilityError("chain_id_mismatch")
                method = str(call["method"])
                params = list(call["params"])
                observation = recorder.call(provider, method, params)
                if observation.error is not None:
                    raise ControlDerivedStateCapabilityError(f"rpc_error:{method}")
                value = _semantic(method, observation.result)
                key = (str(target["target_id"]), method, _canonical_sha(params))
                observations.setdefault(key, []).append((family, value))
            except (ControlDerivedStateCapabilityError, KeyError) as exc:
                errors.append(f"{chain}:{provider_id}:{target['target_id']}:{exc}")
    if not errors:
        if len(observations) != len(probes):
            errors.append("probe_observation_count_invalid")
        for key, values in observations.items():
            if len(values) != 2 or len({family for family, _ in values}) != 2:
                errors.append(f"provider_family_independence:{key[0]}")
            elif values[0][1] != values[1][1]:
                errors.append(f"provider_semantic_disagreement:{key[0]}:{key[1]}")
    complete = not errors
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "decision": COMPLETE_DECISION if complete else INCOMPLETE_DECISION,
        "derived_state_targets_file_sha256": _file_sha(targets_file),
        "derived_state_targets_sha256": targets_payload["targets_sha256"],
        "provider_registry_sha256": _file_sha(registry_file),
        "probe_policy": "OLDEST_AND_NEWEST_PER_CHAIN_AND_PHASE2_METHOD_V1",
        "probe_target_count": len(probes),
        "raw_evidence_count": len(recorder.entries),
        "raw_evidence": recorder.entries,
        "complete": complete,
        "errors": errors,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    report["capability_sha256"] = _canonical_sha(report)
    return report


def verify_derived_state_capability(
    *, capability_path: Path, derived_state_targets_path: Path,
    provider_registry_path: Path, raw_root: Path,
) -> dict[str, object]:
    capability_file = _ordinary(capability_path, "capability")
    capability = _load(capability_file, "capability")
    targets_file, targets_payload, _ = _load_targets(derived_state_targets_path)
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    if capability.get("schema_version") != SCHEMA_VERSION:
        raise ControlDerivedStateCapabilityError("capability_schema_invalid")
    material = {key: value for key, value in capability.items() if key != "capability_sha256"}
    if capability.get("capability_sha256") != _canonical_sha(material):
        raise ControlDerivedStateCapabilityError("capability_self_hash_invalid")
    _require_false(capability, "capability")
    if capability.get("complete") is not True or capability.get("decision") != COMPLETE_DECISION or capability.get("errors") != []:
        raise ControlDerivedStateCapabilityError("capability_incomplete")
    if capability.get("derived_state_targets_file_sha256") != _file_sha(targets_file) or capability.get("derived_state_targets_sha256") != targets_payload["targets_sha256"]:
        raise ControlDerivedStateCapabilityError("derived_state_targets_hash_mismatch")
    if capability.get("provider_registry_sha256") != _file_sha(registry_file):
        raise ControlDerivedStateCapabilityError("provider_registry_hash_mismatch")
    resolved_root = raw_root.expanduser().resolve(strict=True)
    evidence = capability.get("raw_evidence")
    if not isinstance(evidence, list) or len(evidence) != capability.get("raw_evidence_count"):
        raise ControlDerivedStateCapabilityError("raw_evidence_count_invalid")
    seen: set[str] = set()
    for entry in evidence:
        if not isinstance(entry, Mapping):
            raise ControlDerivedStateCapabilityError("raw_evidence_entry_invalid")
        relative = Path(str(entry.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in seen:
            raise ControlDerivedStateCapabilityError("raw_evidence_path_escape")
        path = _ordinary(resolved_root / relative, "raw_evidence")
        try:
            path.relative_to(resolved_root)
        except ValueError as exc:
            raise ControlDerivedStateCapabilityError("raw_evidence_path_escape") from exc
        seen.add(relative.as_posix())
        if entry.get("sha256") != _file_sha(path):
            raise ControlDerivedStateCapabilityError("raw_evidence_hash_mismatch")
    verification: dict[str, object] = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "decision": "DERIVED_STATE_CAPABILITY_VERIFIED_NON_AUTHORIZING",
        "complete": True,
        "capability_file_sha256": _file_sha(capability_file),
        "capability_sha256": capability["capability_sha256"],
        "derived_state_targets_file_sha256": capability["derived_state_targets_file_sha256"],
        "derived_state_targets_sha256": capability["derived_state_targets_sha256"],
        "provider_registry_sha256": capability["provider_registry_sha256"],
        "probe_target_count": capability["probe_target_count"],
        "raw_evidence_count": capability["raw_evidence_count"],
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification
