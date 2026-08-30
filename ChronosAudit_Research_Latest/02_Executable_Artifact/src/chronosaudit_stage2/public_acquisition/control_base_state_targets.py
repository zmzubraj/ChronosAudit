from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from chronosaudit_stage2.onchain import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    canonical_block_selector,
)

from .providers import ProviderRegistry


TARGETS_SCHEMA = "stage2_control_base_state_targets.v1"
TARGET_SCHEMA = "stage2_control_base_state_target.v1"


class ControlBaseStateTargetsError(ValueError):
    """Raised when fixed-address cutoff-state targets cannot be frozen."""


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
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
        raise ControlBaseStateTargetsError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlBaseStateTargetsError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlBaseStateTargetsError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlBaseStateTargetsError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlBaseStateTargetsError(f"{label}_root_invalid")
    return payload


def _require_self_hash(
    payload: Mapping[str, object], field: str, label: str
) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlBaseStateTargetsError(f"{label}_self_hash_invalid")


def _require_false(payload: Mapping[str, object], label: str) -> None:
    for field in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(field) is not False:
            raise ControlBaseStateTargetsError(f"{label}_{field}_invalid")


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ControlBaseStateTargetsError(f"{label}_invalid")
    return text


def _block_hash(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if (
        len(text) != 66
        or not text.startswith("0x")
        or any(character not in "0123456789abcdef" for character in text[2:])
    ):
        raise ControlBaseStateTargetsError(f"{label}_invalid")
    return text


def _address(value: object) -> str:
    text = str(value or "").strip().lower()
    if (
        len(text) != 42
        or not text.startswith("0x")
        or any(character not in "0123456789abcdef" for character in text[2:])
    ):
        raise ControlBaseStateTargetsError("control_address_invalid")
    return text


def _cutoff_epoch(value: object) -> int:
    try:
        parsed = datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ControlBaseStateTargetsError("cutoff_timestamp_invalid") from exc
    return int(parsed.timestamp())


def _verify_boundary_raw_evidence(
    boundary: Mapping[str, object], provider_ids: set[str]
) -> None:
    rows = boundary.get("raw_evidence")
    if (
        not isinstance(rows, list)
        or not rows
        or len(rows) != boundary.get("raw_evidence_count")
        or not all(isinstance(row, Mapping) for row in rows)
    ):
        raise ControlBaseStateTargetsError("boundary_raw_evidence_invalid")
    sequences: set[int] = set()
    paths: set[str] = set()
    observed_providers: set[str] = set()
    for row in rows:
        try:
            sequence = int(row["sequence_number"])
            provider_id = str(row["provider_id"])
            candidate = Path(str(row["path"])).expanduser()
        except (KeyError, TypeError, ValueError) as exc:
            raise ControlBaseStateTargetsError(
                "boundary_raw_evidence_invalid"
            ) from exc
        if candidate.is_symlink():
            raise ControlBaseStateTargetsError("boundary_raw_evidence_invalid")
        try:
            evidence_path = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise ControlBaseStateTargetsError(
                "boundary_raw_evidence_invalid"
            ) from exc
        path_text = str(evidence_path)
        if (
            sequence <= 0
            or sequence in sequences
            or path_text in paths
            or not evidence_path.is_file()
            or row.get("target_id") != boundary.get("target_id")
            or provider_id not in provider_ids
            or row.get("succeeded") is not True
            or row.get("sha256") != _file_sha(evidence_path)
        ):
            raise ControlBaseStateTargetsError("boundary_raw_evidence_invalid")
        sequences.add(sequence)
        paths.add(path_text)
        observed_providers.add(provider_id)
    if observed_providers != provider_ids:
        raise ControlBaseStateTargetsError("boundary_raw_evidence_invalid")


def build_base_state_targets(
    *,
    reserve_pair_scope_path: Path,
    boundary_results_path: Path,
    provider_registry_path: Path | None = None,
) -> dict[str, object]:
    """Freeze only fixed-address cutoff-state reads.

    Implementation and beacon reads are intentionally excluded. They require a
    separately hash-bound projection and activation after this base phase has
    established the cutoff slot values through two provider families.
    """
    pair_file = _ordinary(reserve_pair_scope_path, "reserve_pair_scope")
    boundary_file = _ordinary(boundary_results_path, "boundary_results")
    pair_scope = _load(pair_file, "reserve_pair_scope")
    boundary_results = _load(boundary_file, "boundary_results")

    if pair_scope.get("schema_version") != "stage2_control_reserve_pair_scope.v1":
        raise ControlBaseStateTargetsError("pair_scope_schema_invalid")
    _require_self_hash(pair_scope, "projection_sha256", "pair_scope")
    _require_false(pair_scope, "pair_scope")
    if pair_scope.get("counter_authority") is not False:
        raise ControlBaseStateTargetsError("pair_scope_counter_authority_invalid")
    pair_rows = pair_scope.get("records")
    if (
        not isinstance(pair_rows, list)
        or not pair_rows
        or len(pair_rows) != pair_scope.get("record_count")
        or not all(isinstance(row, Mapping) for row in pair_rows)
    ):
        raise ControlBaseStateTargetsError("pair_scope_records_invalid")

    registry_file: Path | None = None
    state_provider_bindings: dict[str, list[tuple[str, str]]] = {}
    if provider_registry_path is not None:
        registry_file = _ordinary(provider_registry_path, "provider_registry")
        try:
            registry = ProviderRegistry.from_path(registry_file)
        except (KeyError, TypeError, ValueError) as exc:
            raise ControlBaseStateTargetsError("provider_registry_invalid") from exc
        required_chains = {
            str(row.get("chain", "")).strip().lower() for row in pair_rows
        }
        if "" in required_chains:
            raise ControlBaseStateTargetsError("pair_chain_invalid")
        for chain in required_chains:
            bindings = sorted(
                (record.provider_id, record.operator_family)
                for record in registry.providers
                if record.chain == chain
                and record.operator_verified
                and record.tracking_enabled
            )
            if (
                len(bindings) != 2
                or len({provider_id for provider_id, _ in bindings}) != 2
                or len({family for _, family in bindings}) != 2
                or any(not provider_id or not family or family == "unverified" for provider_id, family in bindings)
            ):
                raise ControlBaseStateTargetsError("state_provider_pair_invalid")
            state_provider_bindings[chain] = bindings

    if boundary_results.get("schema_version") != (
        "stage2_control_cutoff_boundary_results.v1"
    ):
        raise ControlBaseStateTargetsError("boundary_results_schema_invalid")
    _require_self_hash(boundary_results, "results_sha256", "boundary_results")
    _require_false(boundary_results, "boundary_results")
    boundary_rows = boundary_results.get("targets")
    if (
        boundary_results.get("complete") is not True
        or boundary_results.get("counter_authority") is not False
        or not isinstance(boundary_rows, list)
        or not boundary_rows
        or len(boundary_rows) != boundary_results.get("target_count")
        or len(boundary_rows) != boundary_results.get("completed_target_count")
        or not all(isinstance(row, Mapping) for row in boundary_rows)
    ):
        raise ControlBaseStateTargetsError("boundary_results_incomplete")

    boundary_by_pair: dict[str, Mapping[str, object]] = {}
    for boundary in boundary_rows:
        if boundary.get("schema_version") != (
            "stage2_control_cutoff_boundary_result.v1"
        ):
            raise ControlBaseStateTargetsError("boundary_schema_invalid")
        _require_self_hash(boundary, "result_sha256", "boundary")
        _require_false(boundary, "boundary")
        try:
            evidence_number = int(boundary.get("evidence_block_number", -1))
            next_number = int(boundary.get("next_block_number", -1))
            evidence_timestamp = int(boundary.get("evidence_block_timestamp", -1))
            next_timestamp = int(boundary.get("next_block_timestamp", -1))
        except (TypeError, ValueError) as exc:
            raise ControlBaseStateTargetsError("boundary_number_invalid") from exc
        cutoff_epoch = _cutoff_epoch(boundary.get("cutoff_timestamp"))
        if next_number != evidence_number + 1:
            raise ControlBaseStateTargetsError("boundary_not_adjacent")
        if not evidence_timestamp <= cutoff_epoch < next_timestamp:
            raise ControlBaseStateTargetsError("boundary_cutoff_invalid")
        _block_hash(boundary.get("evidence_block_hash"), "evidence_block_hash")
        _block_hash(boundary.get("next_block_hash"), "next_block_hash")
        if (
            boundary.get("provider_agreement") is not True
            or boundary.get("disposition") != "complete"
        ):
            raise ControlBaseStateTargetsError("boundary_not_complete")
        provider_results = boundary.get("provider_results")
        if not isinstance(provider_results, list) or len(provider_results) != 2:
            raise ControlBaseStateTargetsError("boundary_provider_count_invalid")
        bindings = {
            (
                str(provider.get("provider_id", "")).strip(),
                str(provider.get("operator_family", "")).strip().lower(),
            )
            for provider in provider_results
            if isinstance(provider, Mapping)
        }
        if (
            len(bindings) != 2
            or len({provider_id for provider_id, _ in bindings}) != 2
            or len({family for _, family in bindings}) != 2
            or any(not provider_id or not family or family == "unverified" for provider_id, family in bindings)
        ):
            raise ControlBaseStateTargetsError("boundary_provider_independence")
        _verify_boundary_raw_evidence(
            boundary, {provider_id for provider_id, _ in bindings}
        )
        pair_hashes = boundary.get("pair_scope_record_sha256s")
        if (
            not isinstance(pair_hashes, list)
            or len(pair_hashes) != boundary.get("pair_scope_record_count")
        ):
            raise ControlBaseStateTargetsError("boundary_pair_membership_invalid")
        for pair_hash_value in pair_hashes:
            pair_hash = _sha(pair_hash_value, "pair_scope_record_sha256")
            if pair_hash in boundary_by_pair:
                raise ControlBaseStateTargetsError("boundary_pair_duplicate")
            boundary_by_pair[pair_hash] = boundary

    pair_hashes_seen: set[str] = set()
    targets: list[dict[str, object]] = []
    for pair in pair_rows:
        _require_self_hash(pair, "pair_scope_record_sha256", "pair")
        _require_false(pair, "pair")
        if (
            pair.get("counter_authority") is not False
            or pair.get("reserve_evidence_verified") is not True
        ):
            raise ControlBaseStateTargetsError("pair_status_invalid")
        pair_hash = _sha(pair.get("pair_scope_record_sha256"), "pair_scope_record_sha256")
        if pair_hash in pair_hashes_seen:
            raise ControlBaseStateTargetsError("pair_duplicate")
        pair_hashes_seen.add(pair_hash)
        boundary = boundary_by_pair.get(pair_hash)
        if boundary is None:
            raise ControlBaseStateTargetsError("pair_membership_incomplete")
        case_id = str(pair.get("case_name", "")).strip()
        chain = str(pair.get("chain", "")).strip().lower()
        cutoff = str(pair.get("required_covariate_cutoff_time", ""))
        if (
            not case_id
            or not chain
            or boundary.get("case_id") != case_id
            or str(boundary.get("chain", "")).strip().lower() != chain
            or boundary.get("cutoff_timestamp") != cutoff
        ):
            raise ControlBaseStateTargetsError("pair_boundary_identity_mismatch")
        address = _address(pair.get("control_address"))
        evidence_number = int(boundary["evidence_block_number"])
        next_number = int(boundary["next_block_number"])
        evidence_hash = _block_hash(
            boundary["evidence_block_hash"], "evidence_block_hash"
        )
        next_hash = _block_hash(boundary["next_block_hash"], "next_block_hash")
        selector = canonical_block_selector(evidence_hash)
        calls: list[dict[str, object]] = []
        provider_bindings = state_provider_bindings.get(chain)
        if provider_bindings is None:
            provider_bindings = sorted(
                (
                    str(provider["provider_id"]),
                    str(provider["operator_family"]).lower(),
                )
                for provider in boundary["provider_results"]
            )
        for provider_id, family in provider_bindings:
            for method, params in (
                ("eth_getBlockByNumber", [hex(evidence_number), False]),
                ("eth_getBlockByNumber", [hex(next_number), False]),
                ("eth_getCode", [address, selector]),
                (
                    "eth_getStorageAt",
                    [address, EIP1967_IMPLEMENTATION_SLOT, selector],
                ),
                ("eth_getStorageAt", [address, EIP1967_BEACON_SLOT, selector]),
                ("eth_getStorageAt", [address, EIP1967_ADMIN_SLOT, selector]),
            ):
                calls.append(
                    {
                        "provider_id": provider_id,
                        "operator_family": family,
                        "method": method,
                        "params": params,
                    }
                )
        identity = {
            "case_id": case_id,
            "chain": chain,
            "control_address": address,
            "pair_scope_record_sha256": pair_hash,
            "boundary_result_sha256": boundary["result_sha256"],
        }
        target: dict[str, object] = {
            "schema_version": TARGET_SCHEMA,
            "target_id": "base-state:" + _canonical_sha(identity),
            **identity,
            "chain_address": f"{chain}:{address}",
            "cutoff_timestamp": cutoff,
            "cutoff_timestamp_unix": _cutoff_epoch(cutoff),
            "evidence_block_number": evidence_number,
            "evidence_block_hash": evidence_hash,
            "next_block_number": next_number,
            "next_block_hash": next_hash,
            "denominator_record_sha256": _sha(
                pair.get("denominator_record_sha256"),
                "denominator_record_sha256",
            ),
            "deployment_result_sha256": _sha(
                pair.get("row_evidence_sha256"), "row_evidence_sha256"
            ),
            "calls": calls,
            "call_count": len(calls),
            "phase": "FIXED_ADDRESS_BASE_STATE_DISCOVERY_ONLY",
            "derived_address_reads_authorized": False,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        target["target_sha256"] = _canonical_sha(target)
        targets.append(target)

    if pair_hashes_seen != set(boundary_by_pair):
        raise ControlBaseStateTargetsError("pair_membership_incomplete")
    targets.sort(
        key=lambda target: (
            str(target["case_id"]),
            str(target["chain"]),
            str(target["control_address"]),
        )
    )
    output: dict[str, object] = {
        "schema_version": TARGETS_SCHEMA,
        "decision": "BASE_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION",
        "reserve_pair_scope_file_sha256": _file_sha(pair_file),
        "reserve_pair_scope_projection_sha256": pair_scope["projection_sha256"],
        "boundary_results_file_sha256": _file_sha(boundary_file),
        "boundary_results_sha256": boundary_results["results_sha256"],
        "target_count": len(targets),
        "call_count": sum(int(target["call_count"]) for target in targets),
        "complete": len(targets) == len(pair_rows),
        "targets": targets,
        "derived_address_reads_authorized": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    if registry_file is not None:
        output["provider_registry_file_sha256"] = _file_sha(registry_file)
        output["provider_pair_source"] = "EXACT_VERIFIED_PROVIDER_REGISTRY"
    output["targets_sha256"] = _canonical_sha(output)
    return output
