from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from chronosaudit_stage2.onchain import canonical_block_selector

from .providers import ProviderRegistry


class ControlBeaconImplementationTargetsError(ValueError):
    """Raised when Phase 3 beacon-implementation code targets cannot be frozen."""


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlBeaconImplementationTargetsError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlBeaconImplementationTargetsError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlBeaconImplementationTargetsError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlBeaconImplementationTargetsError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlBeaconImplementationTargetsError(f"{label}_root_invalid")
    return payload


def _address(value: object) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 42 or not text.startswith("0x") or text == "0x" + "0" * 40 or any(character not in "0123456789abcdef" for character in text[2:]):
        raise ControlBeaconImplementationTargetsError("beacon_implementation_address_invalid")
    return text


def _block_hash(value: object) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 66 or not text.startswith("0x") or any(character not in "0123456789abcdef" for character in text[2:]):
        raise ControlBeaconImplementationTargetsError("evidence_block_hash_invalid")
    return text


def build_beacon_implementation_targets(
    *, derived_state_results_path: Path, provider_registry_path: Path
) -> dict[str, object]:
    results_file = _ordinary(derived_state_results_path, "derived_state_results")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    results = _load(results_file, "derived_state_results")
    if results.get("schema_version") != "stage2_control_cutoff_state_results.v1":
        raise ControlBeaconImplementationTargetsError("derived_state_results_schema_invalid")
    material = {key: value for key, value in results.items() if key != "results_sha256"}
    if results.get("results_sha256") != _canonical_sha(material):
        raise ControlBeaconImplementationTargetsError("derived_state_results_self_hash_invalid")
    rows = results.get("targets")
    try:
        count = int(results.get("target_count", -1))
    except (TypeError, ValueError) as exc:
        raise ControlBeaconImplementationTargetsError("derived_state_results_incomplete") from exc
    if (
        not isinstance(rows, list)
        or not all(isinstance(row, Mapping) for row in rows)
        or len(rows) != count
        or results.get("processed_target_count") != count
        or results.get("completed_target_count") != count
        or results.get("dispositions") != {"complete": count}
    ):
        raise ControlBeaconImplementationTargetsError("derived_state_results_incomplete")
    try:
        registry = ProviderRegistry.from_path(registry_file)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlBeaconImplementationTargetsError("provider_registry_invalid") from exc
    pairs: dict[str, list[tuple[str, str]]] = {}
    for record in registry.providers:
        if record.operator_verified and record.tracking_enabled:
            pairs.setdefault(record.chain, []).append((record.provider_id, record.operator_family))
    for bindings in pairs.values():
        bindings.sort()

    targets: list[dict[str, object]] = []
    for row in rows:
        if row.get("schema_version") != "stage2_control_derived_state_result.v1":
            raise ControlBeaconImplementationTargetsError("derived_state_result_schema_invalid")
        row_material = {
            key: value
            for key, value in row.items()
            if key not in {"result_sha256", "disposition"}
        }
        if row.get("result_sha256") != _canonical_sha(row_material):
            raise ControlBeaconImplementationTargetsError("derived_state_result_self_hash_invalid")
        if row.get("status") != "complete" or row.get("provider_agreement") is not True or row.get("eip1898_pinned") is not True:
            raise ControlBeaconImplementationTargetsError("derived_state_result_incomplete")
        if row.get("derived_role") != "beacon_implementation_call":
            continue
        chain = str(row.get("chain", "")).strip().lower()
        bindings = pairs.get(chain)
        if bindings is None or len(bindings) != 2 or len({family for _, family in bindings}) != 2:
            raise ControlBeaconImplementationTargetsError("provider_pair_invalid")
        address = _address(row.get("beacon_implementation_address"))
        block_hash = _block_hash(row.get("evidence_block_hash"))
        selector = canonical_block_selector(block_hash)
        calls = [
            {"provider_id": provider, "operator_family": family, "method": "eth_getCode", "params": [address, selector]}
            for provider, family in bindings
        ]
        identity = {"derived_state_result_sha256": row["result_sha256"], "beacon_implementation_address": address}
        target: dict[str, object] = {
            "schema_version": "stage2_control_beacon_implementation_target.v1",
            "target_id": "beacon-implementation:" + _canonical_sha(identity),
            "case_id": row["case_id"],
            "chain": chain,
            "chain_address": row["chain_address"],
            "source_derived_state_target_id": row["target_id"],
            "base_state_result_sha256": row["base_state_result_sha256"],
            **identity,
            "beacon_address": row["derived_address"],
            "evidence_block_number": row["evidence_block_number"],
            "evidence_block_hash": block_hash,
            "calls": calls,
            "call_count": len(calls),
            "phase": "BEACON_RETURNED_IMPLEMENTATION_CODE_ONLY",
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        target["target_sha256"] = _canonical_sha(target)
        targets.append(target)
    targets.sort(key=lambda row: (str(row["case_id"]), str(row["chain"]), str(row["beacon_implementation_address"])))
    output: dict[str, object] = {
        "schema_version": "stage2_control_beacon_implementation_targets.v1",
        "decision": (
            "BEACON_IMPLEMENTATION_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION"
            if targets
            else "NO_BEACON_IMPLEMENTATION_TARGETS_REQUIRED"
        ),
        "derived_state_results_file_sha256": _file_sha(results_file),
        "derived_state_results_sha256": results["results_sha256"],
        "provider_registry_file_sha256": _file_sha(registry_file),
        "source_derived_state_target_count": count,
        "target_count": len(targets),
        "call_count": sum(int(row["call_count"]) for row in targets),
        "complete": True,
        "targets": targets,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["targets_sha256"] = _canonical_sha(output)
    return output
