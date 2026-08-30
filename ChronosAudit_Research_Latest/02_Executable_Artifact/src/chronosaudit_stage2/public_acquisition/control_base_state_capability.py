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


SCHEMA_VERSION = "stage2_control_base_state_capability.v1"
VERIFICATION_SCHEMA_VERSION = "stage2_control_base_state_capability_verification.v1"
COMPLETE_DECISION = "DUAL_PROVIDER_BASE_STATE_CAPABILITY_VERIFIED"
INCOMPLETE_DECISION = "BASE_STATE_CAPABILITY_INCOMPLETE"
_FALSE_AUTHORITY_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "counter_authority",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_TARGET_FALSE_AUTHORITY_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
_HEX_DATA = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_STORAGE_WORD = re.compile(r"0x[0-9a-fA-F]{64}")
_BLOCK_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_CHAIN_IDS = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}


class ControlBaseStateCapabilityError(ValueError):
    """Raised when target-bound Phase 1 capability evidence is invalid."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlBaseStateCapabilityError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlBaseStateCapabilityError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlBaseStateCapabilityError(f"{label}_not_ordinary_file")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlBaseStateCapabilityError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlBaseStateCapabilityError(f"{label}_root_invalid")
    return payload


def _require_false(payload: Mapping[str, object], label: str) -> None:
    for flag in _FALSE_AUTHORITY_FLAGS:
        if payload.get(flag) is not False:
            raise ControlBaseStateCapabilityError(f"{label}_{flag}_invalid")


def _require_target_false(payload: Mapping[str, object]) -> None:
    for flag in _TARGET_FALSE_AUTHORITY_FLAGS:
        if payload.get(flag) is not False:
            raise ControlBaseStateCapabilityError(
                f"base_state_target_{flag}_invalid"
            )


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlBaseStateCapabilityError("raw_evidence_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_canonical_json(dict(payload)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _prepare_raw_root(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlBaseStateCapabilityError("raw_root_symlink")
    candidate.mkdir(parents=True, exist_ok=True)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ControlBaseStateCapabilityError("raw_root_not_directory")
    return resolved


def _load_targets(path: Path) -> tuple[Path, dict[str, object], list[dict[str, object]]]:
    targets_file = _ordinary(path, "base_state_targets")
    payload = _load_json(targets_file, "base_state_targets")
    if payload.get("schema_version") != "stage2_control_base_state_targets.v1":
        raise ControlBaseStateCapabilityError("base_state_targets_schema_invalid")
    if (
        payload.get("decision")
        != "BASE_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION"
        or payload.get("complete") is not True
        or payload.get("derived_address_reads_authorized") is not False
    ):
        raise ControlBaseStateCapabilityError("base_state_targets_status_invalid")
    _require_false(payload, "base_state_targets")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets or not all(
        isinstance(row, dict) for row in targets
    ):
        raise ControlBaseStateCapabilityError("base_state_targets_invalid")
    if payload.get("target_count") != len(targets):
        raise ControlBaseStateCapabilityError("base_state_target_count_invalid")
    if payload.get("call_count") != sum(len(row.get("calls", [])) for row in targets):
        raise ControlBaseStateCapabilityError("base_state_call_count_invalid")
    aggregate_material = {
        key: value for key, value in payload.items() if key != "targets_sha256"
    }
    if payload.get("targets_sha256") != _canonical_sha(aggregate_material):
        raise ControlBaseStateCapabilityError("base_state_targets_self_hash_invalid")

    seen: set[str] = set()
    for target in targets:
        material = {key: value for key, value in target.items() if key != "target_sha256"}
        if (
            target.get("schema_version") != "stage2_control_base_state_target.v1"
            or target.get("target_sha256") != _canonical_sha(material)
        ):
            raise ControlBaseStateCapabilityError("base_state_target_self_hash_invalid")
        _require_target_false(target)
        if target.get("derived_address_reads_authorized") is not False:
            raise ControlBaseStateCapabilityError("derived_address_reads_authorized")
        target_id = str(target.get("target_id", "")).strip()
        chain = str(target.get("chain", "")).strip().lower()
        calls = target.get("calls")
        if not target_id or target_id in seen or not chain or not isinstance(calls, list):
            raise ControlBaseStateCapabilityError("base_state_target_invalid")
        seen.add(target_id)
        if len(calls) != 12:
            raise ControlBaseStateCapabilityError("base_state_target_calls_invalid")
        providers: dict[str, str] = {}
        for call in calls:
            if not isinstance(call, Mapping):
                raise ControlBaseStateCapabilityError("base_state_call_invalid")
            provider_id = str(call.get("provider_id", "")).strip()
            family = str(call.get("operator_family", "")).strip().lower()
            method = str(call.get("method", "")).strip()
            params = call.get("params")
            if (
                not provider_id
                or not family
                or family == "unverified"
                or method not in {"eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt"}
                or not isinstance(params, list)
            ):
                raise ControlBaseStateCapabilityError("base_state_call_invalid")
            if provider_id in providers and providers[provider_id] != family:
                raise ControlBaseStateCapabilityError("provider_family_binding_conflict")
            providers[provider_id] = family
        if len(providers) != 2 or len(set(providers.values())) != 2:
            raise ControlBaseStateCapabilityError("provider_family_independence")
    return targets_file, payload, targets


class _EvidenceRecorder:
    def __init__(self, raw_root: Path) -> None:
        self.raw_root = _prepare_raw_root(raw_root)
        self.entries: list[dict[str, object]] = []
        self.sequence = 0

    def call(self, provider: Any, method: str, params: list[object]) -> ProviderObservation:
        observation = provider.call(method, params)
        if not isinstance(observation, ProviderObservation):
            raise ControlBaseStateCapabilityError("provider_observation_invalid")
        self.sequence += 1
        provider_id = str(getattr(provider, "provider_id", ""))
        family = str(getattr(provider, "provider_family", ""))
        prefix = (
            f"{self.sequence:05d}-{_SAFE_NAME.sub('_', provider_id)}-"
            f"{_SAFE_NAME.sub('_', method)}"
        )
        request = {
            "schema_version": "stage2_control_base_state_capability_request.v1",
            "provider_id": provider_id,
            "provider_family": family,
            "method": method,
            "params": params,
        }
        response = {
            "schema_version": "stage2_control_base_state_capability_response.v1",
            "provider_id": observation.provider_id,
            "provider_family": family,
            "method": observation.method,
            "params": observation.params,
            "result": observation.result,
            "error": observation.error,
            "observed_at_unix": observation.observed_at_unix,
            "observed_at_utc": observation.observed_at_utc,
            "http_status": observation.http_status,
            "attempt": observation.attempt,
            "transport_request_sha256": observation.request_sha256,
            "transport_response_sha256": observation.response_sha256,
        }
        for kind, payload in (("request", request), ("response", response)):
            path = self.raw_root / f"{prefix}-{kind}.json"
            _atomic_write(path, payload)
            self.entries.append(
                {
                    "sequence": self.sequence,
                    "kind": kind,
                    "provider_id": provider_id,
                    "method": method,
                    "path": path.relative_to(self.raw_root).as_posix(),
                    "sha256": _file_sha(path),
                }
            )
        return observation


def _quantity(value: object, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise ControlBaseStateCapabilityError(f"{label}_invalid")
    return int(value, 16)


def _semantic(method: str, params: list[object], value: object) -> object:
    if method == "eth_getBlockByNumber":
        if not isinstance(value, Mapping):
            raise ControlBaseStateCapabilityError("historical_block_invalid")
        expected = _quantity(params[0], "expected_block_number")
        number = _quantity(value.get("number"), "historical_block_number")
        block_hash = str(value.get("hash", "")).lower()
        timestamp = _quantity(value.get("timestamp"), "historical_block_timestamp")
        if number != expected or not _BLOCK_HASH.fullmatch(block_hash):
            raise ControlBaseStateCapabilityError("historical_block_mismatch")
        return {"number": number, "hash": block_hash, "timestamp": timestamp}
    text = str(value or "")
    if method == "eth_getCode":
        if not _HEX_DATA.fullmatch(text):
            raise ControlBaseStateCapabilityError("historical_code_invalid")
        return text.lower()
    if method == "eth_getStorageAt":
        if not _STORAGE_WORD.fullmatch(text):
            raise ControlBaseStateCapabilityError("historical_storage_invalid")
        return text.lower()
    raise ControlBaseStateCapabilityError("method_not_allowed")


def _probe_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    by_chain: dict[str, list[dict[str, object]]] = {}
    for target in targets:
        by_chain.setdefault(str(target["chain"]).lower(), []).append(target)
    selected: list[dict[str, object]] = []
    for chain in sorted(by_chain):
        rows = sorted(
            by_chain[chain],
            key=lambda row: (int(row["evidence_block_number"]), str(row["target_id"])),
        )
        selected.append(rows[0])
        if rows[-1]["target_id"] != rows[0]["target_id"]:
            selected.append(rows[-1])
    return selected


def assess_base_state_capability(
    *,
    base_state_targets_path: Path,
    provider_registry_path: Path,
    providers: Sequence[Any],
    raw_root: Path,
) -> dict[str, object]:
    """Probe the oldest/newest exact Phase 1 target per chain through both families."""
    targets_file, targets_payload, targets = _load_targets(base_state_targets_path)
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    try:
        registry = ProviderRegistry.from_path(registry_file)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlBaseStateCapabilityError("provider_registry_invalid") from exc
    records = {
        (row.chain, row.provider_id): row
        for row in registry.providers
        if row.operator_verified and row.tracking_enabled
    }
    runtime = {str(getattr(row, "provider_id", "")): row for row in providers}
    if "" in runtime or len(runtime) != len(providers):
        raise ControlBaseStateCapabilityError("runtime_provider_identity_invalid")

    recorder = _EvidenceRecorder(raw_root)
    probe_targets = _probe_targets(targets)
    chain_rows: list[dict[str, object]] = []
    report_errors: list[str] = []
    for chain in sorted({str(row["chain"]).lower() for row in probe_targets}):
        chain_targets = [row for row in probe_targets if str(row["chain"]).lower() == chain]
        provider_bindings: dict[str, str] = {}
        for target in chain_targets:
            for call in target["calls"]:
                provider_bindings[str(call["provider_id"])] = str(
                    call["operator_family"]
                ).lower()
        chain_errors: list[str] = []
        provider_rows: list[dict[str, object]] = []
        observations: dict[tuple[str, str, str], list[tuple[str, object]]] = {}
        for provider_id, family in sorted(provider_bindings.items()):
            record = records.get((chain, provider_id))
            provider = runtime.get(provider_id)
            errors: list[str] = []
            calls_completed = 0
            if record is None or record.operator_family != family:
                errors.append(f"{chain}:{provider_id}:provider_registry_mismatch")
            elif provider is None:
                errors.append(f"{chain}:{provider_id}:runtime_provider_missing")
            elif (
                str(getattr(provider, "provider_family", "")).lower() != family
                or str(getattr(provider, "chain", chain)).lower() != chain
            ):
                errors.append(f"{chain}:{provider_id}:runtime_provider_binding_mismatch")
            else:
                try:
                    chain_id_observation = recorder.call(provider, "eth_chainId", [])
                    if chain_id_observation.error is not None:
                        raise ControlBaseStateCapabilityError("rpc_error:eth_chainId")
                    observed_chain_id = _quantity(
                        chain_id_observation.result, "observed_chain_id"
                    )
                    if chain not in _CHAIN_IDS or observed_chain_id != _CHAIN_IDS[chain]:
                        raise ControlBaseStateCapabilityError("chain_id_mismatch")
                except ControlBaseStateCapabilityError as exc:
                    errors.append(f"{chain}:{provider_id}:{exc}")
                if not errors:
                    for target in chain_targets:
                        target_calls = [
                            call
                            for call in target["calls"]
                            if call["provider_id"] == provider_id
                        ]
                        for call in target_calls:
                            method = str(call["method"])
                            params = list(call["params"])
                            try:
                                observation = recorder.call(provider, method, params)
                                if observation.error is not None:
                                    raise ControlBaseStateCapabilityError(
                                        f"rpc_error:{method}"
                                    )
                                value = _semantic(method, params, observation.result)
                                key = (
                                    str(target["target_id"]),
                                    method,
                                    _canonical_sha(params),
                                )
                                observations.setdefault(key, []).append((family, value))
                                calls_completed += 1
                            except ControlBaseStateCapabilityError as exc:
                                errors.append(
                                    f"{chain}:{provider_id}:{target['target_id']}:{method}:{exc}"
                                )
            provider_rows.append(
                {
                    "provider_id": provider_id,
                    "operator_family": family,
                    "chain_id_verified": not errors,
                    "exact_probe_call_count": calls_completed,
                    "complete": not errors,
                    "errors": errors,
                }
            )
            chain_errors.extend(errors)

        expected_keys = len(chain_targets) * 6
        if not chain_errors:
            if len(observations) != expected_keys:
                chain_errors.append(f"{chain}:probe_observation_count_invalid")
            for key, values in sorted(observations.items()):
                if len(values) != 2 or len({family for family, _ in values}) != 2:
                    chain_errors.append(f"{chain}:provider_family_independence:{key[0]}")
                elif values[0][1] != values[1][1]:
                    chain_errors.append(
                        f"{chain}:provider_semantic_disagreement:{key[0]}:{key[1]}"
                    )
        report_errors.extend(chain_errors)
        chain_rows.append(
            {
                "chain": chain,
                "probe_target_ids": [str(row["target_id"]) for row in chain_targets],
                "probe_target_count": len(chain_targets),
                "provider_count": len(provider_bindings),
                "operator_families": sorted(set(provider_bindings.values())),
                "providers": provider_rows,
                "complete": not chain_errors,
                "errors": chain_errors,
            }
        )

    complete = not report_errors and all(row["complete"] for row in chain_rows)
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "decision": COMPLETE_DECISION if complete else INCOMPLETE_DECISION,
        "base_state_targets_file_sha256": _file_sha(targets_file),
        "base_state_targets_sha256": targets_payload["targets_sha256"],
        "provider_registry_sha256": _file_sha(registry_file),
        "probe_policy": "OLDEST_AND_NEWEST_EXACT_PHASE1_TARGET_PER_CHAIN_V1",
        "probe_target_count": len(probe_targets),
        "chain_count": len(chain_rows),
        "chains": chain_rows,
        "raw_evidence_count": len(recorder.entries),
        "raw_evidence": recorder.entries,
        "complete": complete,
        "errors": report_errors,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    report["capability_sha256"] = _canonical_sha(report)
    return report


def verify_base_state_capability(
    *,
    capability_path: Path,
    base_state_targets_path: Path,
    provider_registry_path: Path,
    raw_root: Path,
) -> dict[str, object]:
    capability_file = _ordinary(capability_path, "capability")
    capability = _load_json(capability_file, "capability")
    targets_file, targets_payload, _ = _load_targets(base_state_targets_path)
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    if capability.get("schema_version") != SCHEMA_VERSION:
        raise ControlBaseStateCapabilityError("capability_schema_invalid")
    material = {
        key: value for key, value in capability.items() if key != "capability_sha256"
    }
    if capability.get("capability_sha256") != _canonical_sha(material):
        raise ControlBaseStateCapabilityError("capability_self_hash_invalid")
    _require_false(capability, "capability")
    if capability.get("complete") is not True or capability.get("decision") != COMPLETE_DECISION:
        raise ControlBaseStateCapabilityError("capability_incomplete")
    if capability.get("errors") != []:
        raise ControlBaseStateCapabilityError("capability_errors_present")
    if capability.get("base_state_targets_file_sha256") != _file_sha(targets_file):
        raise ControlBaseStateCapabilityError("base_state_targets_file_hash_mismatch")
    if capability.get("base_state_targets_sha256") != targets_payload["targets_sha256"]:
        raise ControlBaseStateCapabilityError("base_state_targets_hash_mismatch")
    if capability.get("provider_registry_sha256") != _file_sha(registry_file):
        raise ControlBaseStateCapabilityError("provider_registry_hash_mismatch")
    evidence = capability.get("raw_evidence")
    if not isinstance(evidence, list) or len(evidence) != capability.get("raw_evidence_count"):
        raise ControlBaseStateCapabilityError("raw_evidence_count_invalid")
    resolved_root = raw_root.expanduser().resolve(strict=True)
    if not resolved_root.is_dir():
        raise ControlBaseStateCapabilityError("raw_root_not_directory")
    seen_paths: set[str] = set()
    for entry in evidence:
        if not isinstance(entry, Mapping):
            raise ControlBaseStateCapabilityError("raw_evidence_entry_invalid")
        relative = Path(str(entry.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise ControlBaseStateCapabilityError("raw_evidence_path_escape")
        path = _ordinary(resolved_root / relative, "raw_evidence")
        try:
            path.relative_to(resolved_root)
        except ValueError as exc:
            raise ControlBaseStateCapabilityError("raw_evidence_path_escape") from exc
        relative_text = relative.as_posix()
        if relative_text in seen_paths:
            raise ControlBaseStateCapabilityError("raw_evidence_duplicate")
        seen_paths.add(relative_text)
        if entry.get("sha256") != _file_sha(path):
            raise ControlBaseStateCapabilityError("raw_evidence_hash_mismatch")
    verification: dict[str, object] = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "decision": "BASE_STATE_CAPABILITY_VERIFIED_NON_AUTHORIZING",
        "complete": True,
        "capability_file_sha256": _file_sha(capability_file),
        "capability_sha256": capability["capability_sha256"],
        "base_state_targets_file_sha256": capability[
            "base_state_targets_file_sha256"
        ],
        "base_state_targets_sha256": capability["base_state_targets_sha256"],
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
