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

from .providers import ProviderRecord, ProviderRegistry


SCHEMA_VERSION = "stage2_control_cutoff_boundary_capability.v1"
VERIFICATION_SCHEMA_VERSION = (
    "stage2_control_cutoff_boundary_capability_verification.v1"
)
COMPLETE_DECISION = "DUAL_PROVIDER_CUTOFF_BOUNDARY_CAPABILITY_VERIFIED"
INCOMPLETE_DECISION = "CUTOFF_BOUNDARY_CAPABILITY_INCOMPLETE"
_FALSE_AUTHORITY_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


class ControlCutoffBoundaryCapabilityError(ValueError):
    """Raised when a cutoff-boundary capability artifact is invalid."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCutoffBoundaryCapabilityError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCutoffBoundaryCapabilityError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCutoffBoundaryCapabilityError(f"{label}_not_ordinary_file")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        value = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCutoffBoundaryCapabilityError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise ControlCutoffBoundaryCapabilityError(f"{label}_root_invalid")
    return value


def _prepare_raw_root(raw_root: Path) -> Path:
    candidate = raw_root.expanduser()
    if candidate.is_symlink():
        raise ControlCutoffBoundaryCapabilityError("raw_root_symlink")
    candidate.mkdir(parents=True, exist_ok=True)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ControlCutoffBoundaryCapabilityError("raw_root_not_directory")
    return resolved


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCutoffBoundaryCapabilityError("raw_evidence_symlink")
    data = (_canonical_json(dict(payload)) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _require_false(payload: Mapping[str, object], label: str) -> None:
    for flag in _FALSE_AUTHORITY_FLAGS:
        if payload.get(flag) is not False:
            raise ControlCutoffBoundaryCapabilityError(f"{label}_{flag}_invalid")


def _validate_requirements(
    path: Path,
) -> tuple[Path, dict[str, object], dict[str, dict[str, object]]]:
    requirements_file = _ordinary(path, "requirements")
    requirements = _load_json(requirements_file, "requirements")
    if requirements.get("schema_version") != (
        "stage2_control_cutoff_boundary_requirements.v1"
    ):
        raise ControlCutoffBoundaryCapabilityError("requirements_schema_invalid")
    material = {
        key: value
        for key, value in requirements.items()
        if key != "requirements_sha256"
    }
    if requirements.get("requirements_sha256") != _canonical_sha(material):
        raise ControlCutoffBoundaryCapabilityError("requirements_self_hash_invalid")
    _require_false(requirements, "requirements")
    if (
        requirements.get("decision")
        != "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION"
        or requirements.get("complete") is not True
        or requirements.get("final_cutoff_brackets_resolved") is not False
        or requirements.get("counter_authority") is not False
        or requirements.get("rpc_authorized") is not False
    ):
        raise ControlCutoffBoundaryCapabilityError("requirements_status_invalid")
    targets = requirements.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or len(targets) != requirements.get("boundary_target_count")
    ):
        raise ControlCutoffBoundaryCapabilityError("requirements_targets_invalid")

    by_chain: dict[str, dict[str, object]] = {}
    seen_ids: set[str] = set()
    for target in targets:
        if not isinstance(target, Mapping):
            raise ControlCutoffBoundaryCapabilityError("requirements_target_invalid")
        target_material = {
            key: value for key, value in target.items() if key != "target_sha256"
        }
        if (
            target.get("schema_version")
            != "stage2_control_cutoff_boundary_requirement.v1"
            or target.get("target_sha256") != _canonical_sha(target_material)
        ):
            raise ControlCutoffBoundaryCapabilityError("requirements_target_invalid")
        _require_false(target, "target")
        target_id = str(target.get("target_id", "")).strip()
        chain = str(target.get("chain", "")).strip().lower()
        if not target_id or target_id in seen_ids or not chain:
            raise ControlCutoffBoundaryCapabilityError("requirements_target_invalid")
        seen_ids.add(target_id)
        try:
            chain_id = int(target.get("chain_id", -1))
            lower = int(target.get("lower_bound_block", -1))
            upper = int(target.get("upper_bound_block", -1))
        except (TypeError, ValueError) as exc:
            raise ControlCutoffBoundaryCapabilityError(
                "requirements_target_range_invalid"
            ) from exc
        if chain_id <= 0 or lower < 0 or upper <= lower:
            raise ControlCutoffBoundaryCapabilityError(
                "requirements_target_range_invalid"
            )
        aggregate = by_chain.setdefault(
            chain,
            {
                "chain": chain,
                "chain_id": chain_id,
                "minimum_lower_bound_block": lower,
                "maximum_upper_bound_block": upper,
                "target_count": 0,
            },
        )
        if aggregate["chain_id"] != chain_id:
            raise ControlCutoffBoundaryCapabilityError("requirements_chain_id_conflict")
        aggregate["minimum_lower_bound_block"] = min(
            int(aggregate["minimum_lower_bound_block"]), lower
        )
        aggregate["maximum_upper_bound_block"] = max(
            int(aggregate["maximum_upper_bound_block"]), upper
        )
        aggregate["target_count"] = int(aggregate["target_count"]) + 1
    return requirements_file, requirements, by_chain


class _EvidenceRecorder:
    def __init__(self, raw_root: Path) -> None:
        self.raw_root = _prepare_raw_root(raw_root)
        self.entries: list[dict[str, object]] = []
        self.sequence = 0

    def call(self, provider: Any, method: str, params: list[object]) -> ProviderObservation:
        observation = provider.call(method, params)
        if not isinstance(observation, ProviderObservation):
            raise ControlCutoffBoundaryCapabilityError("provider_observation_invalid")
        self.sequence += 1
        provider_id = str(getattr(provider, "provider_id", ""))
        family = str(getattr(provider, "provider_family", ""))
        safe_provider = _SAFE_NAME.sub("_", provider_id)
        safe_method = _SAFE_NAME.sub("_", method)
        prefix = f"{self.sequence:05d}-{safe_provider}-{safe_method}"
        request = {
            "schema_version": "stage2_control_cutoff_boundary_capability_request.v1",
            "provider_id": provider_id,
            "provider_family": family,
            "method": method,
            "params": params,
        }
        response = {
            "schema_version": "stage2_control_cutoff_boundary_capability_response.v1",
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
                    "sha256": _sha(path),
                }
            )
        return observation


def _quantity(value: object, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise ControlCutoffBoundaryCapabilityError(f"{label}_invalid")
    return int(value, 16)


def _block_semantic(value: object, expected_number: int) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ControlCutoffBoundaryCapabilityError("historical_block_invalid")
    number = _quantity(value.get("number"), "historical_block_number")
    block_hash = str(value.get("hash", "")).strip().lower()
    timestamp = _quantity(value.get("timestamp"), "historical_block_timestamp")
    if number != expected_number:
        raise ControlCutoffBoundaryCapabilityError("historical_block_number_mismatch")
    if not re.fullmatch(r"0x[0-9a-f]{64}", block_hash):
        raise ControlCutoffBoundaryCapabilityError("historical_block_hash_invalid")
    return {"number": number, "hash": block_hash, "timestamp": timestamp}


def _chosen_records(
    registry: ProviderRegistry, chain: str
) -> tuple[list[ProviderRecord], str | None]:
    by_family: dict[str, ProviderRecord] = {}
    for record in sorted(
        registry.providers_for_chain(chain, verified_only=True),
        key=lambda row: (row.operator_family, row.provider_id),
    ):
        if not record.tracking_enabled or record.operator_family == "unverified":
            continue
        by_family.setdefault(record.operator_family, record)
    if len(by_family) < 2:
        return [], f"{chain}:provider_family_independence"
    families = sorted(by_family)[:2]
    return [by_family[family] for family in families], None


def _provider_row(
    *,
    chain: str,
    chain_id: int,
    probe_blocks: list[int],
    provider: Any,
    record: ProviderRecord,
    recorder: _EvidenceRecorder,
) -> tuple[dict[str, object], list[str]]:
    errors: list[str] = []
    chain_id_verified = False
    block_rows: list[dict[str, object]] = []
    try:
        observation = recorder.call(provider, "eth_chainId", [])
        if observation.error is not None:
            raise ControlCutoffBoundaryCapabilityError("rpc_error:eth_chainId")
        observed_chain_id = _quantity(observation.result, "observed_chain_id")
        if observed_chain_id != chain_id:
            raise ControlCutoffBoundaryCapabilityError("chain_id_mismatch")
        chain_id_verified = True
    except ControlCutoffBoundaryCapabilityError as exc:
        errors.append(f"{chain}:{record.provider_id}:{exc}")

    if chain_id_verified:
        for block_number in probe_blocks:
            try:
                observation = recorder.call(
                    provider, "eth_getBlockByNumber", [hex(block_number), False]
                )
                if observation.error is not None:
                    raise ControlCutoffBoundaryCapabilityError(
                        "rpc_error:eth_getBlockByNumber"
                    )
                semantic = _block_semantic(observation.result, block_number)
                block_rows.append(semantic)
            except ControlCutoffBoundaryCapabilityError as exc:
                errors.append(
                    f"{chain}:{record.provider_id}:block:{block_number}:{exc}"
                )
    row: dict[str, object] = {
        "provider_id": record.provider_id,
        "operator_family": record.operator_family,
        "chain_id_verified": chain_id_verified,
        "historical_block_by_number_verified": (
            chain_id_verified and len(block_rows) == len(probe_blocks) and not errors
        ),
        "probe_results": block_rows,
        "errors": errors,
    }
    return row, errors


def assess_cutoff_boundary_capability(
    *,
    requirements_path: Path,
    provider_registry_path: Path,
    providers: Sequence[Any],
    raw_root: Path,
) -> dict[str, object]:
    """Probe frozen range extremes through two registered families per chain."""
    requirements_file, requirements, chain_requirements = _validate_requirements(
        requirements_path
    )
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    try:
        registry = ProviderRegistry.from_path(registry_file)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlCutoffBoundaryCapabilityError("provider_registry_invalid") from exc
    runtime = {
        str(getattr(provider, "provider_id", "")): provider for provider in providers
    }
    if "" in runtime or len(runtime) != len(providers):
        raise ControlCutoffBoundaryCapabilityError("runtime_provider_identity_invalid")

    recorder = _EvidenceRecorder(raw_root)
    chain_rows: list[dict[str, object]] = []
    report_errors: list[str] = []
    for chain in sorted(chain_requirements):
        scope = chain_requirements[chain]
        probe_blocks = sorted(
            {
                int(scope["minimum_lower_bound_block"]),
                int(scope["maximum_upper_bound_block"]),
            }
        )
        records, independence_error = _chosen_records(registry, chain)
        if independence_error is not None:
            report_errors.append(independence_error)
            chain_rows.append(
                {
                    **scope,
                    "probe_blocks": probe_blocks,
                    "provider_count": 0,
                    "operator_families": [],
                    "providers": [],
                    "complete": False,
                    "errors": [independence_error],
                }
            )
            continue
        missing = [record.provider_id for record in records if record.provider_id not in runtime]
        if missing:
            errors = [f"{chain}:provider_family_independence"] + [
                f"{chain}:{provider_id}:runtime_provider_missing"
                for provider_id in missing
            ]
            report_errors.extend(errors)
            chain_rows.append(
                {
                    **scope,
                    "probe_blocks": probe_blocks,
                    "provider_count": len(records),
                    "operator_families": sorted(record.operator_family for record in records),
                    "providers": [],
                    "complete": False,
                    "errors": errors,
                }
            )
            continue

        provider_rows: list[dict[str, object]] = []
        chain_errors: list[str] = []
        for record in records:
            provider = runtime[record.provider_id]
            if (
                str(getattr(provider, "chain", chain)).strip().lower() != chain
                or str(getattr(provider, "provider_family", "")).strip().lower()
                != record.operator_family
            ):
                error = f"{chain}:{record.provider_id}:runtime_provider_binding_mismatch"
                provider_rows.append(
                    {
                        "provider_id": record.provider_id,
                        "operator_family": record.operator_family,
                        "chain_id_verified": False,
                        "historical_block_by_number_verified": False,
                        "probe_results": [],
                        "errors": [error],
                    }
                )
                chain_errors.append(error)
                continue
            row, errors = _provider_row(
                chain=chain,
                chain_id=int(scope["chain_id"]),
                probe_blocks=probe_blocks,
                provider=provider,
                record=record,
                recorder=recorder,
            )
            provider_rows.append(row)
            chain_errors.extend(errors)

        if not chain_errors and len(provider_rows) == 2:
            by_block: dict[int, list[tuple[object, object]]] = {}
            for provider_row in provider_rows:
                for block in provider_row["probe_results"]:
                    assert isinstance(block, Mapping)
                    by_block.setdefault(int(block["number"]), []).append(
                        (block["hash"], block["timestamp"])
                    )
            for block_number in probe_blocks:
                values = by_block.get(block_number, [])
                if len(values) != 2 or values[0] != values[1]:
                    chain_errors.append(
                        f"{chain}:provider_semantic_disagreement:block:{block_number}"
                    )
        report_errors.extend(chain_errors)
        chain_rows.append(
            {
                **scope,
                "probe_blocks": probe_blocks,
                "provider_count": len(records),
                "operator_families": sorted(record.operator_family for record in records),
                "providers": provider_rows,
                "complete": not chain_errors and len(provider_rows) == 2,
                "errors": chain_errors,
            }
        )

    complete = not report_errors and len(chain_rows) == len(chain_requirements)
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "decision": COMPLETE_DECISION if complete else INCOMPLETE_DECISION,
        "requirements_file_sha256": _sha(requirements_file),
        "requirements_sha256": requirements["requirements_sha256"],
        "provider_registry_sha256": _sha(registry_file),
        "complete": complete,
        "chain_count": len(chain_rows),
        "probe_method": "eth_getBlockByNumber",
        "probe_policy": "MINIMUM_FROZEN_LOWER_AND_MAXIMUM_FROZEN_UPPER_PER_CHAIN_V1",
        "chains": chain_rows,
        "raw_evidence_count": len(recorder.entries),
        "raw_evidence": recorder.entries,
        "errors": report_errors,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    report["capability_sha256"] = _canonical_sha(report)
    return report


def verify_cutoff_boundary_capability(
    *,
    capability_path: Path,
    requirements_path: Path,
    provider_registry_path: Path,
    raw_root: Path,
) -> dict[str, object]:
    """Revalidate capability semantics, input bindings, and every raw receipt."""
    capability_file = _ordinary(capability_path, "capability")
    capability = _load_json(capability_file, "capability")
    material = {
        key: value
        for key, value in capability.items()
        if key != "capability_sha256"
    }
    if (
        capability.get("schema_version") != SCHEMA_VERSION
        or capability.get("capability_sha256") != _canonical_sha(material)
    ):
        raise ControlCutoffBoundaryCapabilityError("capability_self_hash_invalid")
    _require_false(capability, "capability")
    if (
        capability.get("decision") != COMPLETE_DECISION
        or capability.get("complete") is not True
        or capability.get("errors") != []
    ):
        raise ControlCutoffBoundaryCapabilityError("capability_not_complete")

    requirements_file, requirements, chain_requirements = _validate_requirements(
        requirements_path
    )
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    try:
        registry = ProviderRegistry.from_path(registry_file)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlCutoffBoundaryCapabilityError("provider_registry_invalid") from exc
    if (
        capability.get("requirements_file_sha256") != _sha(requirements_file)
        or capability.get("requirements_sha256") != requirements["requirements_sha256"]
        or capability.get("provider_registry_sha256") != _sha(registry_file)
    ):
        raise ControlCutoffBoundaryCapabilityError("capability_input_binding_invalid")

    root = raw_root.expanduser()
    if root.is_symlink():
        raise ControlCutoffBoundaryCapabilityError("raw_root_symlink")
    try:
        root = root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCutoffBoundaryCapabilityError("raw_root_missing") from exc
    if not root.is_dir():
        raise ControlCutoffBoundaryCapabilityError("raw_root_not_directory")
    evidence = capability.get("raw_evidence")
    if (
        not isinstance(evidence, list)
        or len(evidence) != capability.get("raw_evidence_count")
    ):
        raise ControlCutoffBoundaryCapabilityError("raw_evidence_count_mismatch")
    for entry in evidence:
        if not isinstance(entry, Mapping):
            raise ControlCutoffBoundaryCapabilityError("raw_evidence_entry_invalid")
        relative = Path(str(entry.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise ControlCutoffBoundaryCapabilityError("raw_evidence_path_escape")
        evidence_file = _ordinary(root / relative, "raw_evidence")
        try:
            evidence_file.relative_to(root)
        except ValueError as exc:
            raise ControlCutoffBoundaryCapabilityError(
                "raw_evidence_path_escape"
            ) from exc
        if _sha(evidence_file) != entry.get("sha256"):
            raise ControlCutoffBoundaryCapabilityError(
                "raw_evidence_hash_mismatch"
            )

    chains = capability.get("chains")
    if (
        not isinstance(chains, list)
        or len(chains) != capability.get("chain_count")
        or {str(row.get("chain", "")) for row in chains if isinstance(row, Mapping)}
        != set(chain_requirements)
    ):
        raise ControlCutoffBoundaryCapabilityError("capability_chain_coverage_invalid")
    registry_bindings = {
        (record.chain, record.provider_id): record
        for record in registry.providers
        if record.operator_verified and record.tracking_enabled
    }
    for chain_row in chains:
        if not isinstance(chain_row, Mapping) or chain_row.get("complete") is not True:
            raise ControlCutoffBoundaryCapabilityError("capability_chain_invalid")
        chain = str(chain_row.get("chain", ""))
        expected = chain_requirements[chain]
        expected_blocks = sorted(
            {
                int(expected["minimum_lower_bound_block"]),
                int(expected["maximum_upper_bound_block"]),
            }
        )
        if chain_row.get("probe_blocks") != expected_blocks:
            raise ControlCutoffBoundaryCapabilityError("capability_probe_scope_invalid")
        provider_rows = chain_row.get("providers")
        if not isinstance(provider_rows, list) or len(provider_rows) != 2:
            raise ControlCutoffBoundaryCapabilityError("capability_provider_count_invalid")
        semantics: list[list[tuple[int, str, int]]] = []
        families: set[str] = set()
        for provider_row in provider_rows:
            if not isinstance(provider_row, Mapping):
                raise ControlCutoffBoundaryCapabilityError("capability_provider_invalid")
            provider_id = str(provider_row.get("provider_id", ""))
            family = str(provider_row.get("operator_family", ""))
            record = registry_bindings.get((chain, provider_id))
            if (
                record is None
                or record.operator_family != family
                or provider_row.get("chain_id_verified") is not True
                or provider_row.get("historical_block_by_number_verified") is not True
                or provider_row.get("errors") != []
            ):
                raise ControlCutoffBoundaryCapabilityError("capability_provider_invalid")
            families.add(family)
            probe_results = provider_row.get("probe_results")
            if not isinstance(probe_results, list) or len(probe_results) != len(expected_blocks):
                raise ControlCutoffBoundaryCapabilityError("capability_probe_results_invalid")
            normalized = []
            for result in probe_results:
                if not isinstance(result, Mapping):
                    raise ControlCutoffBoundaryCapabilityError("capability_probe_results_invalid")
                normalized.append(
                    (int(result["number"]), str(result["hash"]), int(result["timestamp"]))
                )
            if [row[0] for row in normalized] != expected_blocks:
                raise ControlCutoffBoundaryCapabilityError("capability_probe_results_invalid")
            semantics.append(normalized)
        if len(families) != 2 or semantics[0] != semantics[1]:
            raise ControlCutoffBoundaryCapabilityError("provider_semantic_disagreement")

    verification: dict[str, object] = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "decision": "CUTOFF_BOUNDARY_CAPABILITY_VERIFIED_NON_AUTHORIZING",
        "complete": True,
        "capability_file_sha256": _sha(capability_file),
        "capability_sha256": capability["capability_sha256"],
        "requirements_file_sha256": _sha(requirements_file),
        "provider_registry_sha256": _sha(registry_file),
        "chain_count": len(chains),
        "raw_evidence_count": len(evidence),
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "errors": [],
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification
