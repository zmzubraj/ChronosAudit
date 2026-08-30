from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from chronosaudit_stage2.onchain import canonical_block_selector

from .providers import ProviderRegistry


TARGETS_SCHEMA = "stage2_control_derived_state_targets.v1"
TARGET_SCHEMA = "stage2_control_derived_state_target.v1"
BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"


class ControlDerivedStateTargetsError(ValueError):
    """Raised when Phase 2 derived-address targets cannot be frozen."""


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
        raise ControlDerivedStateTargetsError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlDerivedStateTargetsError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlDerivedStateTargetsError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlDerivedStateTargetsError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlDerivedStateTargetsError(f"{label}_root_invalid")
    return payload


def _self_hash(payload: Mapping[str, object], field: str, label: str) -> None:
    excluded = {field}
    if label == "base_state_result":
        excluded.add("disposition")
    material = {key: value for key, value in payload.items() if key not in excluded}
    if payload.get(field) != _canonical_sha(material):
        raise ControlDerivedStateTargetsError(f"{label}_self_hash_invalid")


def _false_flags(payload: Mapping[str, object], label: str) -> None:
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(field) is not False:
            raise ControlDerivedStateTargetsError(f"{label}_{field}_invalid")


def _address(value: object, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    text = str(value or "").strip().lower()
    if (
        len(text) != 42
        or not text.startswith("0x")
        or any(character not in "0123456789abcdef" for character in text[2:])
        or text == "0x" + "0" * 40
    ):
        raise ControlDerivedStateTargetsError(f"{label}_invalid")
    return text


def _block_hash(value: object) -> str:
    text = str(value or "").strip().lower()
    if (
        len(text) != 66
        or not text.startswith("0x")
        or any(character not in "0123456789abcdef" for character in text[2:])
    ):
        raise ControlDerivedStateTargetsError("evidence_block_hash_invalid")
    return text


def _provider_pairs(registry_path: Path) -> dict[str, list[tuple[str, str]]]:
    try:
        registry = ProviderRegistry.from_path(registry_path)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlDerivedStateTargetsError("provider_registry_invalid") from exc
    pairs: dict[str, list[tuple[str, str]]] = {}
    for record in registry.providers:
        if record.operator_verified and record.tracking_enabled:
            pairs.setdefault(record.chain, []).append(
                (record.provider_id, record.operator_family)
            )
    for chain, bindings in pairs.items():
        bindings.sort()
        if (
            len(bindings) != 2
            or len({provider for provider, _ in bindings}) != 2
            or len({family for _, family in bindings}) != 2
            or any(not provider or not family or family == "unverified" for provider, family in bindings)
        ):
            raise ControlDerivedStateTargetsError(
                f"provider_pair_invalid:{chain}"
            )
    return pairs


def build_derived_state_targets(
    *,
    base_state_results_path: Path,
    provider_registry_path: Path,
) -> dict[str, object]:
    """Freeze Phase 2 reads from a complete, hash-bound Phase 1 result only."""
    results_file = _ordinary(base_state_results_path, "base_state_results")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    results = _load(results_file, "base_state_results")
    if results.get("schema_version") != "stage2_control_cutoff_state_results.v1":
        raise ControlDerivedStateTargetsError("base_state_results_schema_invalid")
    _self_hash(results, "results_sha256", "base_state_results")
    _false_flags(results, "base_state_results")
    rows = results.get("targets")
    try:
        target_count = int(results.get("target_count", -1))
        processed_count = int(results.get("processed_target_count", -1))
        completed_count = int(results.get("completed_target_count", -1))
    except (TypeError, ValueError) as exc:
        raise ControlDerivedStateTargetsError("base_state_results_incomplete") from exc
    if (
        not isinstance(rows, list)
        or not rows
        or not all(isinstance(row, Mapping) for row in rows)
        or len(rows) != target_count
        or processed_count != target_count
        or completed_count != target_count
        or results.get("dispositions") != {"complete": target_count}
    ):
        raise ControlDerivedStateTargetsError("base_state_results_incomplete")

    provider_pairs = _provider_pairs(registry_file)
    targets: list[dict[str, object]] = []
    seen_source_results: set[str] = set()
    for row in rows:
        if row.get("schema_version") != "stage2_control_base_state_result.v1":
            raise ControlDerivedStateTargetsError("base_state_result_schema_invalid")
        _self_hash(row, "result_sha256", "base_state_result")
        _false_flags(row, "base_state_result")
        result_sha = str(row.get("result_sha256", ""))
        if result_sha in seen_source_results:
            raise ControlDerivedStateTargetsError("base_state_result_duplicate")
        seen_source_results.add(result_sha)
        chain = str(row.get("chain", "")).strip().lower()
        case_id = str(row.get("case_id", "")).strip()
        source_target_id = str(row.get("target_id", "")).strip()
        chain_address = str(row.get("chain_address", "")).strip().lower()
        if (
            row.get("status") != "complete"
            or row.get("provider_agreement") is not True
            or row.get("eip1898_pinned") is not True
            or row.get("derived_address_reads_authorized") is not False
            or row.get("disposition") != "complete"
            or not chain
            or not case_id
            or not source_target_id
            or not chain_address
        ):
            raise ControlDerivedStateTargetsError("base_state_result_incomplete")
        bindings = provider_pairs.get(chain)
        if bindings is None:
            raise ControlDerivedStateTargetsError("provider_pair_missing")
        block_hash = _block_hash(row.get("evidence_block_hash"))
        selector = canonical_block_selector(block_hash)
        derived = (
            (
                "direct_implementation_runtime_code",
                _address(row.get("direct_implementation_address"), "direct_implementation_address", nullable=True),
                "eth_getCode",
            ),
            (
                "eip1167_target_runtime_code",
                _address(row.get("eip1167_target"), "eip1167_target", nullable=True),
                "eth_getCode",
            ),
            (
                "beacon_implementation_call",
                _address(row.get("beacon_address"), "beacon_address", nullable=True),
                "eth_call",
            ),
        )
        for role, address, method in derived:
            if address is None:
                continue
            params: list[object]
            if method == "eth_call":
                params = [{"to": address, "data": BEACON_IMPLEMENTATION_SELECTOR}, selector]
            else:
                params = [address, selector]
            calls = [
                {
                    "provider_id": provider_id,
                    "operator_family": family,
                    "method": method,
                    "params": params,
                }
                for provider_id, family in bindings
            ]
            identity = {
                "base_state_result_sha256": result_sha,
                "derived_role": role,
                "derived_address": address,
            }
            target: dict[str, object] = {
                "schema_version": TARGET_SCHEMA,
                "target_id": "derived-state:" + _canonical_sha(identity),
                "case_id": case_id,
                "chain": chain,
                "chain_address": chain_address,
                "source_base_state_target_id": source_target_id,
                **identity,
                "evidence_block_number": int(row.get("evidence_block_number", -1)),
                "evidence_block_hash": block_hash,
                "cutoff_timestamp": row.get("cutoff_timestamp"),
                "pair_scope_record_sha256": row.get("pair_scope_record_sha256"),
                "denominator_record_sha256": row.get("denominator_record_sha256"),
                "calls": calls,
                "call_count": len(calls),
                "phase": "RESULT_BOUND_DERIVED_STATE_READS_ONLY",
                "rpc_authorized": False,
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            }
            target["target_sha256"] = _canonical_sha(target)
            targets.append(target)

    targets.sort(
        key=lambda target: (
            str(target["case_id"]),
            str(target["chain"]),
            str(target["derived_role"]),
            str(target["derived_address"]),
        )
    )
    output: dict[str, object] = {
        "schema_version": TARGETS_SCHEMA,
        "decision": "DERIVED_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION",
        "base_state_results_file_sha256": _file_sha(results_file),
        "base_state_results_sha256": results["results_sha256"],
        "provider_registry_file_sha256": _file_sha(registry_file),
        "source_base_state_target_count": target_count,
        "target_count": len(targets),
        "call_count": sum(int(target["call_count"]) for target in targets),
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
