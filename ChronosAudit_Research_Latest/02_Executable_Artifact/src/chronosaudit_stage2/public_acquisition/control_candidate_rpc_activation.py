from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
import subprocess

import pandas as pd

from .control_historical_candidate_queue import verify_historical_candidate_queue
from .providers import ProviderRegistry


class ControlCandidateRpcActivationError(ValueError):
    """Raised when a frozen reserve queue cannot receive bounded RPC authority."""


_SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-candidate-rpc-activation-v1"
_RPC_METHODS = [
    "eth_chainId",
    "eth_getTransactionReceipt",
    "eth_getBlockByHash",
]


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
        raise ControlCandidateRpcActivationError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateRpcActivationError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCandidateRpcActivationError(f"{label}_not_ordinary_file")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCandidateRpcActivationError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise ControlCandidateRpcActivationError(f"{label}_root_invalid")
    return value


def _is_sha(value: object) -> bool:
    text = str(value or "").lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _time(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlCandidateRpcActivationError(f"{label}_invalid")
    if str(value) != parsed.isoformat().replace("+00:00", "Z"):
        raise ControlCandidateRpcActivationError(f"{label}_not_canonical")
    return parsed


def _request_sha(request: Mapping[str, object]) -> str:
    return _canonical_sha(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def _validate_provider_identity_report(
    *,
    report: Mapping[str, object],
    registry: ProviderRegistry,
    required_chains: list[str],
    allow_extra_chains: bool = False,
) -> list[dict[str, str]]:
    if report.get("schema_version") != (
        "historical_snapshot_provider_identity_verification.v1"
    ):
        raise ControlCandidateRpcActivationError("provider_identity_schema_invalid")
    material = {key: value for key, value in report.items() if key != "report_sha256"}
    if report.get("report_sha256") != _canonical_sha(material):
        raise ControlCandidateRpcActivationError("provider_identity_self_hash_invalid")
    if report.get("complete") is not True or report.get("errors") != []:
        raise ControlCandidateRpcActivationError("provider_identity_not_complete")
    chain_entries = report.get("chains")
    if not isinstance(chain_entries, list):
        raise ControlCandidateRpcActivationError("provider_identity_chains_invalid")
    by_chain: dict[str, Mapping[str, object]] = {}
    for entry in chain_entries:
        if not isinstance(entry, Mapping):
            raise ControlCandidateRpcActivationError("provider_identity_chain_invalid")
        chain = str(entry.get("chain") or "").strip().lower()
        if not chain or chain in by_chain:
            raise ControlCandidateRpcActivationError("provider_identity_chain_duplicate")
        by_chain[chain] = entry
    if (
        (not allow_extra_chains and sorted(by_chain) != required_chains)
        or (allow_extra_chains and not set(required_chains).issubset(by_chain))
    ):
        raise ControlCandidateRpcActivationError("provider_identity_chain_coverage_mismatch")
    expected_chain_count = len(by_chain) if allow_extra_chains else len(required_chains)
    if int(report.get("chain_count") or -1) != expected_chain_count:
        raise ControlCandidateRpcActivationError("provider_identity_chain_count_mismatch")

    bindings: list[dict[str, str]] = []
    for chain in required_chains:
        entry = by_chain[chain]
        if entry.get("complete") is not True or entry.get("errors") != []:
            raise ControlCandidateRpcActivationError("provider_identity_chain_not_complete")
        providers = entry.get("providers")
        if not isinstance(providers, list) or len(providers) < 2:
            raise ControlCandidateRpcActivationError("provider_identity_provider_count_invalid")
        report_by_id: dict[str, Mapping[str, object]] = {}
        for provider in providers:
            if not isinstance(provider, Mapping):
                raise ControlCandidateRpcActivationError("provider_identity_record_invalid")
            provider_id = str(provider.get("provider_id") or "").strip()
            if not provider_id or provider_id in report_by_id:
                raise ControlCandidateRpcActivationError("provider_identity_provider_duplicate")
            report_by_id[provider_id] = provider

        eligible = []
        for record in registry.providers_for_chain(chain):
            if not record.tracking_enabled:
                continue
            if not record.operator_verified:
                raise ControlCandidateRpcActivationError(
                    f"provider_not_verified:{record.provider_id}"
                )
            if not record.operator_evidence_url or not _is_sha(record.operator_evidence_sha256):
                raise ControlCandidateRpcActivationError(
                    f"provider_evidence_incomplete:{record.provider_id}"
                )
            observed = report_by_id.get(record.provider_id)
            if observed is None:
                continue
            identity = record.public_endpoint_id
            family = record.operator_family
            evidence = {
                "chain": chain,
                "provider_id": record.provider_id,
                "provider_identity_id": identity,
                "endpoint_template_sha256": identity,
                "verified_operator_family": family,
            }
            expected = {
                "chain": chain,
                "provider_id": record.provider_id,
                "verified_operator_family": family,
                "public_endpoint_identity_id": identity,
                "public_endpoint_identity_sha256": _canonical_sha(identity),
                "endpoint_template_sha256": identity,
                "identity_evidence_sha256": _canonical_sha(evidence),
            }
            if observed.get("complete") is not True or any(
                str(observed.get(field) or "") != value
                for field, value in expected.items()
            ):
                raise ControlCandidateRpcActivationError(
                    f"provider_identity_registry_mismatch:{record.provider_id}"
                )
            eligible.append((family, record.provider_id, record, observed))

        selected = []
        used_families: set[str] = set()
        for family, provider_id, record, observed in sorted(eligible):
            if family in used_families:
                continue
            used_families.add(family)
            selected.append((record, observed))
            if len(selected) == 2:
                break
        if len(selected) != 2:
            raise ControlCandidateRpcActivationError(
                f"provider_identity_registry_mismatch:{chain}"
            )
        expected_families = sorted(
            str(value) for value in entry.get("verified_operator_families") or []
        )
        observed_families = sorted(
            str(provider.get("verified_operator_family") or "")
            for provider in providers
            if isinstance(provider, Mapping)
        )
        if expected_families != sorted(set(observed_families)):
            raise ControlCandidateRpcActivationError("provider_identity_family_index_invalid")
        if int(entry.get("provider_count") or -1) != len(providers):
            raise ControlCandidateRpcActivationError("provider_identity_provider_count_mismatch")
        for record, observed in selected:
            bindings.append(
                {
                    "chain": chain,
                    "provider_id": record.provider_id,
                    "operator_family": record.operator_family,
                    "public_endpoint_identity_id": record.public_endpoint_id,
                    "operator_evidence_sha256": str(record.operator_evidence_sha256),
                    "identity_evidence_sha256": str(
                        observed["identity_evidence_sha256"]
                    ),
                }
            )
    return bindings


def assess_control_candidate_rpc_provider_readiness(
    *,
    provider_registry_path: Path,
    provider_identity_verification_path: Path,
    required_chains: list[str],
    allow_extra_chains: bool = False,
) -> dict[str, object]:
    """Return an exhaustive, non-authorizing provider-identity readiness report."""
    registry_path = _ordinary(provider_registry_path, "provider_registry")
    report_path = _ordinary(
        provider_identity_verification_path, "provider_identity"
    )
    chains = sorted({str(chain).strip().lower() for chain in required_chains})
    blockers: set[str] = set()
    if not chains or any(not chain for chain in chains):
        blockers.add("required_chain_scope_invalid")
    try:
        registry = ProviderRegistry.from_path(registry_path)
    except (KeyError, TypeError, ValueError):
        registry = ProviderRegistry(providers=())
        blockers.add("provider_registry_invalid")
    try:
        identity = _load(report_path, "provider_identity")
    except ControlCandidateRpcActivationError as exc:
        identity = {}
        blockers.add(str(exc))
    if identity.get("schema_version") != (
        "historical_snapshot_provider_identity_verification.v1"
    ):
        blockers.add("provider_identity_schema_invalid")
    material = {key: value for key, value in identity.items() if key != "report_sha256"}
    if identity.get("report_sha256") != _canonical_sha(material):
        blockers.add("provider_identity_self_hash_invalid")
    if identity.get("complete") is not True or identity.get("errors") != []:
        blockers.add("provider_identity_not_complete")
    entries = identity.get("chains")
    if not isinstance(entries, list):
        entries = []
        blockers.add("provider_identity_chains_invalid")
    by_chain: dict[str, Mapping[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            blockers.add("provider_identity_chain_invalid")
            continue
        chain = str(entry.get("chain") or "").strip().lower()
        if not chain or chain in by_chain:
            blockers.add("provider_identity_chain_duplicate")
            continue
        by_chain[chain] = entry
    if (
        (not allow_extra_chains and sorted(by_chain) != chains)
        or (allow_extra_chains and not set(chains).issubset(by_chain))
    ):
        blockers.add("provider_identity_chain_coverage_mismatch")
    expected_chain_count = len(by_chain) if allow_extra_chains else len(chains)
    if int(identity.get("chain_count") or -1) != expected_chain_count:
        blockers.add("provider_identity_chain_count_mismatch")

    chain_summaries: list[dict[str, object]] = []
    for chain in chains:
        entry = by_chain.get(chain, {})
        providers = entry.get("providers") if isinstance(entry, Mapping) else []
        if not isinstance(providers, list):
            providers = []
            blockers.add(f"provider_identity_provider_count_invalid:{chain}")
        report_by_id = {
            str(provider.get("provider_id") or "").strip(): provider
            for provider in providers
            if isinstance(provider, Mapping)
            and str(provider.get("provider_id") or "").strip()
        }
        matching_families: set[str] = set()
        matched_ids: list[str] = []
        registry_ids: set[str] = set()
        for record in registry.providers_for_chain(chain):
            if not record.tracking_enabled:
                continue
            registry_ids.add(record.provider_id)
            if not record.operator_verified:
                blockers.add(f"provider_not_verified:{record.provider_id}")
            if not record.operator_evidence_url or not _is_sha(
                record.operator_evidence_sha256
            ):
                blockers.add(f"provider_evidence_incomplete:{record.provider_id}")
            observed = report_by_id.get(record.provider_id)
            identity_id = record.public_endpoint_id
            evidence = {
                "chain": chain,
                "provider_id": record.provider_id,
                "provider_identity_id": identity_id,
                "endpoint_template_sha256": identity_id,
                "verified_operator_family": record.operator_family,
            }
            expected = {
                "chain": chain,
                "provider_id": record.provider_id,
                "verified_operator_family": record.operator_family,
                "public_endpoint_identity_id": identity_id,
                "public_endpoint_identity_sha256": _canonical_sha(identity_id),
                "endpoint_template_sha256": identity_id,
                "identity_evidence_sha256": _canonical_sha(evidence),
            }
            if observed is None or observed.get("complete") is not True or any(
                str(observed.get(field) or "") != value
                for field, value in expected.items()
            ):
                blockers.add(
                    f"provider_identity_registry_mismatch:{record.provider_id}"
                )
                continue
            if record.operator_verified and record.operator_evidence_url and _is_sha(
                record.operator_evidence_sha256
            ):
                matching_families.add(record.operator_family)
                matched_ids.append(record.provider_id)
        for provider_id in sorted(set(report_by_id) - registry_ids):
            blockers.add(f"provider_identity_registry_mismatch:{provider_id}")
        if len(matching_families) < 2:
            blockers.add(f"independent_verified_provider_families_insufficient:{chain}")
        chain_summaries.append(
            {
                "chain": chain,
                "registry_provider_ids": sorted(registry_ids),
                "identity_report_provider_ids": sorted(report_by_id),
                "fully_matching_provider_ids": sorted(matched_ids),
                "fully_matching_operator_families": sorted(matching_families),
            }
        )
    result: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_provider_readiness.v1",
        "decision": (
            "RPC_PROVIDER_IDENTITY_READY_NON_AUTHORIZING"
            if not blockers
            else "RPC_PROVIDER_IDENTITY_NOT_READY"
        ),
        "provider_registry_sha256": _sha(registry_path),
        "provider_identity_verification_sha256": _sha(report_path),
        "required_chains": chains,
        "chains": chain_summaries,
        "blockers": sorted(blockers),
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["readiness_report_sha256"] = _canonical_sha(result)
    return result


def build_control_candidate_rpc_activation_request(
    *,
    queue_path: Path,
    queue_manifest_path: Path,
    query_plan_path: Path,
    chunk_plan_path: Path,
    positive_projection_path: Path,
    authority_projection_path: Path,
    import_manifest_path: Path,
    provider_registry_path: Path,
    provider_identity_verification_path: Path,
    block_window_path: Path | None = None,
) -> dict[str, object]:
    """Build a non-authorizing request for one exact queue and provider pair."""
    paths = {
        "queue": _ordinary(queue_path, "queue"),
        "queue_manifest": _ordinary(queue_manifest_path, "queue_manifest"),
        "provider_registry": _ordinary(provider_registry_path, "provider_registry"),
        "provider_identity": _ordinary(
            provider_identity_verification_path, "provider_identity"
        ),
    }
    verification = verify_historical_candidate_queue(
        queue_path=paths["queue"],
        manifest_path=paths["queue_manifest"],
        query_plan_path=query_plan_path,
        chunk_plan_path=chunk_plan_path,
        positive_projection_path=positive_projection_path,
        authority_projection_path=authority_projection_path,
        import_manifest_path=import_manifest_path,
        block_window_path=block_window_path,
    )
    if verification.get("decision") != "RESERVE_QUEUE_VERIFIED_NON_AUTHORIZING":
        raise ControlCandidateRpcActivationError("queue_not_activation_ready")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if verification.get(field) is not False:
            raise ControlCandidateRpcActivationError(f"queue_verification_{field}_invalid")
    manifest = _load(paths["queue_manifest"], "queue_manifest")
    if manifest.get("decision") != (
        "RESERVE_QUEUE_FROZEN_REQUIRES_HASH_BOUND_RPC_ACTIVATION"
    ):
        raise ControlCandidateRpcActivationError("queue_manifest_not_activation_ready")
    if manifest.get("queue_sha256") != _sha(paths["queue"]):
        raise ControlCandidateRpcActivationError("queue_manifest_hash_mismatch")
    if int(manifest.get("reserve_shortfall") or 0) != 0:
        raise ControlCandidateRpcActivationError("queue_reserve_shortfall")

    queue = pd.read_csv(paths["queue"], dtype=str, keep_default_na=False)
    required_columns = {"case_name", "chain", "control_identity"}
    if missing := sorted(required_columns - set(queue.columns)):
        raise ControlCandidateRpcActivationError(
            f"queue_missing_columns:{','.join(missing)}"
        )
    if len(queue) != int(verification.get("queue_row_count") or -1):
        raise ControlCandidateRpcActivationError("queue_row_count_mismatch")
    if queue.empty:
        raise ControlCandidateRpcActivationError("queue_empty")
    if queue["control_identity"].duplicated().any():
        raise ControlCandidateRpcActivationError("queue_global_identity_reuse")
    chain_counts = {
        str(chain): int(count)
        for chain, count in sorted(queue.groupby("chain").size().to_dict().items())
    }
    required_chains = sorted(chain_counts)
    try:
        registry = ProviderRegistry.from_path(paths["provider_registry"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlCandidateRpcActivationError("provider_registry_invalid") from exc
    provider_report = _load(paths["provider_identity"], "provider_identity")
    bindings = _validate_provider_identity_report(
        report=provider_report,
        registry=registry,
        required_chains=required_chains,
    )
    provider_counts = {chain: 0 for chain in required_chains}
    for binding in bindings:
        provider_counts[binding["chain"]] += 1
    if set(provider_counts.values()) != {2}:
        raise ControlCandidateRpcActivationError("provider_pair_count_invalid")
    maximum_requests = sum(
        chain_counts[chain] * provider_counts[chain] * 2
        + provider_counts[chain]
        for chain in required_chains
    )
    request: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_activation_request.v1",
        "decision": "AWAITING_ACCOUNTABLE_RPC_ACTIVATION_SIGNATURE",
        "purpose": "CONTROL_CANDIDATE_DEPLOYMENT_VERIFICATION_ONLY",
        "queue_sha256": _sha(paths["queue"]),
        "queue_manifest_sha256": _sha(paths["queue_manifest"]),
        "queue_row_count": len(queue),
        "block_window_sha256": (
            _sha(_ordinary(block_window_path, "block_window"))
            if block_window_path is not None
            else None
        ),
        "chain_candidate_counts": chain_counts,
        "provider_registry_sha256": _sha(paths["provider_registry"]),
        "provider_identity_verification_sha256": _sha(paths["provider_identity"]),
        "provider_bindings": bindings,
        "rpc_methods": _RPC_METHODS,
        "request_count_formula": (
            "sum(chain_candidates*2_providers*2_candidate_methods"
            "+2_chain_identity_calls_per_chain)"
        ),
        "maximum_rpc_requests": maximum_requests,
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    request["request_sha256"] = _request_sha(request)
    return request


def build_control_candidate_next_batch_rpc_activation_request(
    *,
    queue_path: Path,
    next_batch_manifest_path: Path,
    provider_registry_path: Path,
    provider_identity_verification_path: Path,
    candidate_rpc_capability_verification_path: Path,
) -> dict[str, object]:
    """Build exact local-test RPC authority for a verified minimum-prefix batch."""
    queue_file = _ordinary(queue_path, "queue")
    manifest_file = _ordinary(next_batch_manifest_path, "next_batch_manifest")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    identity_file = _ordinary(
        provider_identity_verification_path, "provider_identity"
    )
    capability_file = _ordinary(
        candidate_rpc_capability_verification_path, "candidate_rpc_capability"
    )
    manifest = _load(manifest_file, "next_batch_manifest")
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    initial_prefix = (
        manifest.get("schema_version")
        == "chronosaudit.control_candidate_next_batch.v1"
        and manifest.get("decision")
        == "MINIMUM_FROZEN_PENDING_PREFIX_IF_ALL_ROWS_ARE_VALID"
    )
    attrition_extension = (
        manifest.get("schema_version")
        == "chronosaudit.control_candidate_attrition_extension.v1"
        and manifest.get("decision")
        == "MINIMUM_FROZEN_REMAINING_PREFIX_AFTER_VERIFIED_ATTRITION_IF_ALL_ROWS_VALID"
    )
    if (
        not (initial_prefix or attrition_extension)
        or manifest.get("manifest_sha256") != _canonical_sha(material)
        or manifest.get("output_queue_sha256") != _sha(queue_file)
    ):
        raise ControlCandidateRpcActivationError("next_batch_manifest_binding_invalid")
    for field in (
        "rpc_authorized",
        "denominator_admission_authorized",
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if manifest.get(field) is not False:
            raise ControlCandidateRpcActivationError(
                f"next_batch_manifest_{field}_invalid"
            )
    queue = pd.read_csv(queue_file, dtype=str, keep_default_na=False)
    required = {"case_name", "chain", "control_identity", "reserve_assignment_sha256"}
    if missing := sorted(required - set(queue.columns)):
        raise ControlCandidateRpcActivationError(
            f"queue_missing_columns:{','.join(missing)}"
        )
    count_field = (
        "minimum_pending_prefix_row_count"
        if initial_prefix
        else "minimum_extension_prefix_row_count"
    )
    expected_count = int(manifest.get(count_field) or -1)
    if len(queue) != expected_count or queue.empty:
        raise ControlCandidateRpcActivationError("next_batch_queue_row_count_mismatch")
    if queue["control_identity"].duplicated().any() or queue[
        "reserve_assignment_sha256"
    ].duplicated().any():
        raise ControlCandidateRpcActivationError("next_batch_queue_identity_duplicate")

    registry = ProviderRegistry.from_path(registry_file)
    identity = _load(identity_file, "provider_identity")
    chain_counts = {
        str(chain): int(count)
        for chain, count in sorted(queue.groupby("chain").size().to_dict().items())
    }
    bindings = _validate_provider_identity_report(
        report=identity,
        registry=registry,
        required_chains=sorted(chain_counts),
    )
    capability = _load(capability_file, "candidate_rpc_capability")
    capability_material = {
        key: value for key, value in capability.items() if key != "verification_sha256"
    }
    if (
        capability.get("schema_version")
        != "stage2_control_candidate_rpc_capability_verification.v1"
        or capability.get("verification_sha256") != _canonical_sha(capability_material)
        or capability.get("complete") is not True
        or capability.get("errors") != []
        or capability.get("provider_registry_sha256") != _sha(registry_file)
        or int(capability.get("chain_count") or -1) != len(chain_counts)
    ):
        raise ControlCandidateRpcActivationError("candidate_rpc_capability_invalid")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if capability.get(field) is not False:
            raise ControlCandidateRpcActivationError(
                f"candidate_rpc_capability_{field}_invalid"
            )
    provider_counts = {chain: 0 for chain in chain_counts}
    for binding in bindings:
        provider_counts[binding["chain"]] += 1
    maximum_requests = sum(
        chain_counts[chain] * provider_counts[chain] * 2 + provider_counts[chain]
        for chain in sorted(chain_counts)
    )
    request: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_activation_request.v1",
        "decision": "AWAITING_ACCOUNTABLE_RPC_ACTIVATION_SIGNATURE",
        "purpose": "CONTROL_CANDIDATE_DEPLOYMENT_VERIFICATION_ONLY",
        "queue_sha256": _sha(queue_file),
        "queue_manifest_sha256": _sha(manifest_file),
        "next_batch_manifest_sha256": str(manifest["manifest_sha256"]),
        "candidate_rpc_capability_verification_sha256": _sha(capability_file),
        "queue_row_count": len(queue),
        "block_window_sha256": None,
        "chain_candidate_counts": chain_counts,
        "provider_registry_sha256": _sha(registry_file),
        "provider_identity_verification_sha256": _sha(identity_file),
        "provider_bindings": bindings,
        "rpc_methods": _RPC_METHODS,
        "request_count_formula": (
            "sum(chain_candidates*2_providers*2_candidate_methods"
            "+2_chain_identity_calls_per_chain)"
        ),
        "maximum_rpc_requests": maximum_requests,
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    request["request_sha256"] = _request_sha(request)
    return request


def build_control_candidate_retry_rpc_activation_request(
    *,
    queue_path: Path,
    retry_manifest_path: Path,
    provider_registry_path: Path,
    provider_identity_verification_path: Path,
    candidate_rpc_capability_verification_path: Path,
) -> dict[str, object]:
    """Build fresh exact RPC authority for retry or unattempted continuation scopes."""
    queue_file = _ordinary(queue_path, "queue")
    manifest_file = _ordinary(retry_manifest_path, "retry_manifest")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    identity_file = _ordinary(
        provider_identity_verification_path, "provider_identity"
    )
    capability_file = _ordinary(
        candidate_rpc_capability_verification_path, "candidate_rpc_capability"
    )
    manifest = _load(manifest_file, "retry_manifest")
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    retry_manifest = (
        manifest.get("schema_version")
        == "chronosaudit.control_candidate_rpc_retry_targets.v1"
        and manifest.get("decision")
        == "RETRY_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION"
        and manifest.get("retry_reason") == "TERMINAL_PARTIAL_SCOPE_ONLY"
        and manifest.get("retry_queue_sha256") == _sha(queue_file)
    )
    unattempted_manifest = (
        manifest.get("schema_version")
        == "chronosaudit.control_candidate_rpc_unattempted_targets.v1"
        and manifest.get("decision")
        == "UNATTEMPTED_QUEUE_FROZEN_REQUIRES_FRESH_HASH_BOUND_RPC_ACTIVATION"
        and manifest.get("unattempted_queue_sha256") == _sha(queue_file)
    )
    if manifest.get("manifest_sha256") != _canonical_sha(material) or not (
        retry_manifest or unattempted_manifest
    ):
        raise ControlCandidateRpcActivationError("candidate_retry_manifest_binding_invalid")
    for field in (
        "rpc_authorized",
        "denominator_admission_authorized",
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if manifest.get(field) is not False:
            raise ControlCandidateRpcActivationError(
                f"candidate_retry_manifest_{field}_invalid"
            )

    queue = pd.read_csv(queue_file, dtype=str, keep_default_na=False)
    required = {"case_name", "chain", "reserve_assignment_sha256"}
    if missing := sorted(required - set(queue.columns)):
        raise ControlCandidateRpcActivationError(
            f"queue_missing_columns:{','.join(missing)}"
        )
    expected_row_count = manifest.get(
        "retry_row_count" if retry_manifest else "unattempted_row_count"
    )
    if len(queue) != int(expected_row_count or -1) or queue.empty:
        raise ControlCandidateRpcActivationError("candidate_retry_queue_row_count_mismatch")
    if queue["reserve_assignment_sha256"].duplicated().any():
        raise ControlCandidateRpcActivationError("candidate_retry_queue_identity_duplicate")
    if retry_manifest:
        scopes = manifest.get("retry_scopes")
        if not isinstance(scopes, list) or len(scopes) != len(queue):
            raise ControlCandidateRpcActivationError("candidate_retry_scopes_invalid")
        scope_ids: set[str] = set()
        for scope in scopes:
            if not isinstance(scope, Mapping):
                raise ControlCandidateRpcActivationError("candidate_retry_scope_invalid")
            assignment = str(scope.get("reserve_assignment_sha256") or "")
            if not assignment or assignment in scope_ids:
                raise ControlCandidateRpcActivationError("candidate_retry_scope_duplicate")
            scope_ids.add(assignment)
            dispositions = scope.get("attempted_request_dispositions")
            if not isinstance(dispositions, list) or not any(
                disposition in {"TRANSPORT_ERROR", "RPC_ERROR"}
                for disposition in dispositions
            ):
                raise ControlCandidateRpcActivationError(
                    "candidate_retry_scope_failure_evidence_missing"
                )
        if scope_ids != set(queue["reserve_assignment_sha256"]):
            raise ControlCandidateRpcActivationError("candidate_retry_scope_queue_mismatch")

    registry = ProviderRegistry.from_path(registry_file)
    identity = _load(identity_file, "provider_identity")
    chain_counts = {
        str(chain): int(count)
        for chain, count in sorted(queue.groupby("chain").size().to_dict().items())
    }
    bindings = _validate_provider_identity_report(
        report=identity,
        registry=registry,
        required_chains=sorted(chain_counts),
        allow_extra_chains=True,
    )
    capability = _load(capability_file, "candidate_rpc_capability")
    capability_material = {
        key: value for key, value in capability.items() if key != "verification_sha256"
    }
    if (
        capability.get("schema_version")
        != "stage2_control_candidate_rpc_capability_verification.v1"
        or capability.get("verification_sha256") != _canonical_sha(capability_material)
        or capability.get("complete") is not True
        or capability.get("errors") != []
        or capability.get("provider_registry_sha256") != _sha(registry_file)
        or int(capability.get("chain_count") or -1) < len(chain_counts)
    ):
        raise ControlCandidateRpcActivationError("candidate_rpc_capability_invalid")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if capability.get(field) is not False:
            raise ControlCandidateRpcActivationError(
                f"candidate_rpc_capability_{field}_invalid"
            )
    provider_counts = {chain: 0 for chain in chain_counts}
    for binding in bindings:
        provider_counts[binding["chain"]] += 1
    if set(provider_counts.values()) != {2}:
        raise ControlCandidateRpcActivationError("provider_pair_count_invalid")
    maximum_requests = sum(
        chain_counts[chain] * provider_counts[chain] * 2 + provider_counts[chain]
        for chain in sorted(chain_counts)
    )
    request: dict[str, object] = {
        "schema_version": "chronosaudit.control_candidate_rpc_activation_request.v1",
        "decision": "AWAITING_ACCOUNTABLE_RPC_ACTIVATION_SIGNATURE",
        "purpose": "CONTROL_CANDIDATE_DEPLOYMENT_VERIFICATION_ONLY",
        "queue_sha256": _sha(queue_file),
        "queue_manifest_sha256": _sha(manifest_file),
        "candidate_retry_manifest_sha256": manifest["manifest_sha256"],
        "source_request_ledger_sha256": manifest[
            "source_request_ledger_sha256"
        ],
        "source_request_ledger_terminal_hash": manifest[
            "source_request_ledger_terminal_hash"
        ],
        "candidate_rpc_capability_verification_sha256": _sha(capability_file),
        "queue_row_count": len(queue),
        "block_window_sha256": None,
        "chain_candidate_counts": chain_counts,
        "provider_registry_sha256": _sha(registry_file),
        "provider_identity_verification_sha256": _sha(identity_file),
        "provider_bindings": bindings,
        "rpc_methods": _RPC_METHODS,
        "request_count_formula": (
            "sum(chain_candidates*2_providers*2_candidate_methods"
            "+2_chain_identity_calls_per_chain)"
        ),
        "maximum_rpc_requests": maximum_requests,
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    request["request_sha256"] = _request_sha(request)
    return request


def build_control_candidate_rpc_activation_approval(
    *,
    request: Mapping[str, object],
    signer_principal: str,
    activation_start_utc: str,
    activation_expires_utc: str,
) -> dict[str, object]:
    """Build the exact unsigned approval for bounded deployment-verification RPC."""
    if request.get("schema_version") != (
        "chronosaudit.control_candidate_rpc_activation_request.v1"
    ):
        raise ControlCandidateRpcActivationError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_RPC_ACTIVATION_SIGNATURE":
        raise ControlCandidateRpcActivationError("request_not_approvable")
    if request.get("request_sha256") != _request_sha(request):
        raise ControlCandidateRpcActivationError("request_sha256_invalid")
    for field in (
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if request.get(field) is not False:
            raise ControlCandidateRpcActivationError(f"request_{field}_invalid")
    principal = signer_principal.strip()
    if not principal:
        raise ControlCandidateRpcActivationError("signer_principal_invalid")
    start = _time(activation_start_utc, "activation_start_utc")
    expiry = _time(activation_expires_utc, "activation_expires_utc")
    if expiry <= start:
        raise ControlCandidateRpcActivationError("activation_window_invalid")
    approval = {
        "schema_version": "chronosaudit.control_candidate_rpc_activation.v1",
        "request_sha256": request["request_sha256"],
        "signer_principal": principal,
        "decision": "ACTIVATE_FROZEN_CONTROL_CANDIDATE_QUEUE_RPC",
        "purpose": request["purpose"],
        "activation_start_utc": activation_start_utc,
        "activation_expires_utc": activation_expires_utc,
        "queue_sha256": request["queue_sha256"],
        "queue_manifest_sha256": request["queue_manifest_sha256"],
        "provider_registry_sha256": request["provider_registry_sha256"],
        "provider_identity_verification_sha256": request[
            "provider_identity_verification_sha256"
        ],
        "block_window_sha256": request["block_window_sha256"],
        "provider_bindings": request["provider_bindings"],
        "rpc_methods": request["rpc_methods"],
        "maximum_rpc_requests": request["maximum_rpc_requests"],
        "raw_request_response_receipts_required": True,
        "hash_chained_no_repeat_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    for field in (
        "next_batch_manifest_sha256",
        "candidate_retry_manifest_sha256",
        "source_request_ledger_sha256",
        "source_request_ledger_terminal_hash",
        "candidate_rpc_capability_verification_sha256",
    ):
        if field in request:
            approval[field] = request[field]
    return approval


def verify_control_candidate_rpc_activation(
    *,
    request: Mapping[str, object],
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    """Verify a signed activation granting only exact, bounded deployment RPC."""
    if request.get("schema_version") != (
        "chronosaudit.control_candidate_rpc_activation_request.v1"
    ):
        raise ControlCandidateRpcActivationError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_RPC_ACTIVATION_SIGNATURE":
        raise ControlCandidateRpcActivationError("request_not_approvable")
    if request.get("request_sha256") != _request_sha(request):
        raise ControlCandidateRpcActivationError("request_sha256_invalid")
    for field in (
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if request.get(field) is not False:
            raise ControlCandidateRpcActivationError(f"request_{field}_invalid")

    approval_path = _ordinary(approval_path, "approval")
    signature_path = _ordinary(signature_path, "signature")
    allowed_signers_path = _ordinary(allowed_signers_path, "allowed_signers")
    approval = _load(approval_path, "approval")
    if approval.get("schema_version") != (
        "chronosaudit.control_candidate_rpc_activation.v1"
    ):
        raise ControlCandidateRpcActivationError("approval_schema_invalid")
    principal = str(approval.get("signer_principal") or "").strip()
    if not expected_principal or principal != expected_principal:
        raise ControlCandidateRpcActivationError("signer_principal_mismatch")
    if approval.get("request_sha256") != request["request_sha256"]:
        raise ControlCandidateRpcActivationError("approval_request_mismatch")
    if approval.get("decision") != "ACTIVATE_FROZEN_CONTROL_CANDIDATE_QUEUE_RPC":
        raise ControlCandidateRpcActivationError("approval_decision_invalid")
    if approval.get("purpose") != request["purpose"]:
        raise ControlCandidateRpcActivationError("approval_purpose_invalid")
    for field in (
        "queue_sha256",
        "queue_manifest_sha256",
        "provider_registry_sha256",
        "provider_identity_verification_sha256",
        "block_window_sha256",
        "provider_bindings",
        "rpc_methods",
        "maximum_rpc_requests",
    ):
        if approval.get(field) != request[field]:
            raise ControlCandidateRpcActivationError(f"approval_{field}_mismatch")
    for field in (
        "next_batch_manifest_sha256",
        "candidate_retry_manifest_sha256",
        "source_request_ledger_sha256",
        "source_request_ledger_terminal_hash",
        "candidate_rpc_capability_verification_sha256",
    ):
        if field in request and approval.get(field) != request[field]:
            raise ControlCandidateRpcActivationError(f"approval_{field}_mismatch")
    for field, expected in (
        ("raw_request_response_receipts_required", True),
        ("hash_chained_no_repeat_ledger_required", True),
        ("acquisition_authorized", False),
        ("rpc_authorized", True),
        ("selection_authorized", False),
        ("stage_promotion_authorized", False),
        ("recovery3_mutation_authorized", False),
    ):
        if approval.get(field) is not expected:
            raise ControlCandidateRpcActivationError(f"approval_{field}_invalid")
    start = _time(approval.get("activation_start_utc"), "activation_start_utc")
    expiry = _time(approval.get("activation_expires_utc"), "activation_expires_utc")
    now = _time(verification_time_utc, "verification_time_utc")
    if expiry <= start:
        raise ControlCandidateRpcActivationError("activation_window_invalid")
    if now < start:
        raise ControlCandidateRpcActivationError("activation_not_yet_valid")
    if now > expiry:
        raise ControlCandidateRpcActivationError("activation_expired")
    verification = subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed_signers_path),
            "-I",
            principal,
            "-n",
            _SIGNATURE_NAMESPACE,
            "-s",
            str(signature_path),
        ],
        input=canonical_signed_payload(approval),
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise ControlCandidateRpcActivationError("signature_invalid")
    result = {
        "schema_version": "chronosaudit.control_candidate_rpc_activation_verification.v1",
        "decision": "RPC_ACTIVATION_VERIFIED",
        "request_sha256": request["request_sha256"],
        "approval_sha256": _sha(approval_path),
        "signature_sha256": _sha(signature_path),
        "allowed_signers_sha256": _sha(allowed_signers_path),
        "signature_namespace": _SIGNATURE_NAMESPACE,
        "signer_principal": principal,
        "queue_sha256": request["queue_sha256"],
        "queue_row_count": request["queue_row_count"],
        "provider_registry_sha256": request["provider_registry_sha256"],
        "provider_bindings": request["provider_bindings"],
        "rpc_methods": request["rpc_methods"],
        "maximum_rpc_requests": request["maximum_rpc_requests"],
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
    for field in (
        "next_batch_manifest_sha256",
        "candidate_retry_manifest_sha256",
        "source_request_ledger_sha256",
        "source_request_ledger_terminal_hash",
        "candidate_rpc_capability_verification_sha256",
    ):
        if field in request:
            result[field] = request[field]
    return result
