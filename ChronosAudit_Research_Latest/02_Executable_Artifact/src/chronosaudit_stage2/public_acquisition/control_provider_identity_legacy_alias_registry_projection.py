from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import yaml

from .providers import ProviderRecord, ProviderRegistry


class ControlProviderIdentityLegacyAliasRegistryProjectionError(ValueError):
    """Raised when a signed legacy-alias projection cannot form one registry."""


_CHAINS = ("base", "bsc", "ethereum")
_FALSE_AUTHORITY = {
    "rpc_authorized": False,
    "denominator_admission_authorized": False,
    "row_admission_authorized": False,
    "selection_authorized": False,
    "qualification_authorized": False,
    "counter_authority": False,
    "stage_promotion_authorized": False,
    "recovery3_mutation_authorized": False,
    "independent_review_established": False,
    "r5_authorized": False,
    "release_authorized": False,
    "publication_authorized": False,
}


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


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
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            f"{label}_not_ordinary"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            f"{label}_missing"
        ) from exc
    if not resolved.is_file():
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            f"{label}_not_ordinary"
        )
    return resolved


def _load_json(path: Path, label: str) -> tuple[Path, dict[str, object]]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            f"{label}_json_invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            f"{label}_root_invalid"
        )
    return ordinary, payload


def _self_hash(
    payload: Mapping[str, object], field: str, label: str
) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            f"{label}_self_hash_invalid"
        )


def _false_authority(payload: Mapping[str, object], label: str) -> None:
    for field, expected in _FALSE_AUTHORITY.items():
        if field in payload and payload.get(field) is not expected:
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                f"{label}_{field}_invalid"
            )


def _validate_revision_verification(
    payload: Mapping[str, object],
) -> None:
    if payload.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_revision_approval_verification.v1"
    ) or payload.get("decision") != (
        "LEGACY_ALIAS_PROVIDER_IDENTITY_REVISION_VERIFIED_LOCAL_TEST_ONLY"
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "revision_verification_header_invalid"
        )
    _self_hash(payload, "verification_sha256", "revision_verification")
    for field in (
        "provider_identity_revision_authorized",
        "provider_identity_verified",
        "provider_registry_fragment_verified",
    ):
        if payload.get(field) is not True:
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                f"revision_verification_{field}_invalid"
            )
    _false_authority(payload, "revision_verification")


def _validate_fragment(
    payload: Mapping[str, object], verification: Mapping[str, object]
) -> dict[tuple[str, str], Mapping[str, object]]:
    if payload.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_registry_fragment.v1"
    ) or payload.get("decision") != (
        "LEGACY_ALIAS_REGISTRY_FRAGMENT_VERIFIED_LOCAL_TEST_ONLY"
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "registry_fragment_header_invalid"
        )
    _self_hash(payload, "fragment_sha256", "registry_fragment")
    if (
        payload.get("revision_request_sha256")
        != verification.get("revision_request_sha256")
        or payload.get("reviewer_principal")
        != verification.get("reviewer_principal")
        or payload.get("review_expires_utc")
        != verification.get("review_expires_utc")
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "registry_fragment_revision_binding_mismatch"
        )
    if (
        payload.get("rpc_authorized") is not False
        or payload.get("selection_authorized") is not False
        or payload.get("counter_authority") is not False
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "registry_fragment_authority_invalid"
        )
    providers = payload.get("providers")
    if not isinstance(providers, list) or len(providers) != 3:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "registry_fragment_provider_scope_invalid"
        )
    result: dict[tuple[str, str], Mapping[str, object]] = {}
    for row in providers:
        if not isinstance(row, Mapping):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "registry_fragment_provider_invalid"
            )
        chain = str(row.get("chain", ""))
        provider_id = str(row.get("provider_id", ""))
        endpoint = str(row.get("endpoint", ""))
        if (
            chain not in _CHAINS
            or provider_id != f"merkle-{chain}"
            or row.get("operator_family") != "merkle"
            or row.get("operator_identity_family") != "merkle_blink"
            or row.get("operator_verified") is not True
            or row.get("rpc_authorized") is not False
            or row.get("endpoint_template_sha256")
            != hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
        ):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "registry_fragment_provider_invalid"
            )
        result[(chain, provider_id)] = row
    if len(result) != 3:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "registry_fragment_provider_scope_invalid"
        )
    return result


def _validate_identity_report(
    payload: Mapping[str, object], verification: Mapping[str, object]
) -> dict[tuple[str, str], str]:
    if payload.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_verification.v1"
    ) or payload.get("decision") != (
        "LEGACY_ALIAS_PROVIDER_IDENTITY_VERIFIED_LOCAL_TEST_ONLY"
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "identity_report_header_invalid"
        )
    _self_hash(payload, "report_sha256", "identity_report")
    if (
        payload.get("revision_request_sha256")
        != verification.get("revision_request_sha256")
        or payload.get("complete") is not True
        or payload.get("errors") != []
        or payload.get("provider_identity_verified") is not True
        or payload.get("rpc_authorized") is not False
        or payload.get("selection_authorized") is not False
        or payload.get("counter_authority") is not False
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "identity_report_binding_invalid"
        )
    chains = payload.get("chains")
    if not isinstance(chains, list) or len(chains) != 3:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "identity_report_chain_scope_invalid"
        )
    result: dict[tuple[str, str], str] = {}
    for chain_row in chains:
        if not isinstance(chain_row, Mapping):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "identity_report_chain_invalid"
            )
        chain = str(chain_row.get("chain", ""))
        providers = chain_row.get("providers")
        if (
            chain not in _CHAINS
            or chain_row.get("complete") is not True
            or chain_row.get("errors") != []
            or chain_row.get("provider_count") != 2
            or not isinstance(providers, list)
            or len(providers) != 2
        ):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "identity_report_chain_invalid"
            )
        for provider in providers:
            if (
                not isinstance(provider, Mapping)
                or provider.get("complete") is not True
            ):
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "identity_report_provider_invalid"
                )
            key = (chain, str(provider.get("provider_id", "")))
            family = str(provider.get("verified_operator_family", ""))
            if not key[1] or not family or key in result:
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "identity_report_provider_invalid"
                )
            result[key] = family
    if len(result) != 6:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "identity_report_provider_scope_invalid"
        )
    return result


def _validate_capability(payload: Mapping[str, object]) -> dict[tuple[str, str], str]:
    if payload.get("schema_version") != "stage2_control_trace_state_capability.v1":
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "capability_header_invalid"
        )
    _self_hash(payload, "report_sha256", "capability")
    if payload.get("complete") is not True or payload.get("errors") != []:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "capability_incomplete"
        )
    _false_authority(payload, "capability")
    result: dict[tuple[str, str], str] = {}
    chains = payload.get("chains")
    if not isinstance(chains, list):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "capability_chains_invalid"
        )
    for chain_row in chains:
        if not isinstance(chain_row, Mapping):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "capability_chain_invalid"
            )
        chain = str(chain_row.get("chain", ""))
        providers = chain_row.get("providers")
        if chain not in _CHAINS or not isinstance(providers, list):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "capability_chain_invalid"
            )
        for provider in providers:
            if not isinstance(provider, Mapping):
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "capability_provider_invalid"
                )
            key = (chain, str(provider.get("provider_id", "")))
            family = str(provider.get("provider_family", ""))
            if not key[1] or not family or key in result:
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "capability_provider_invalid"
                )
            result[key] = family
    if len(result) != 6:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "capability_provider_scope_invalid"
        )
    return result


def _validate_trace_targets(
    payload: Mapping[str, object],
    verification: Mapping[str, object],
    capability_file: Path,
    capability: Mapping[str, object],
) -> dict[tuple[str, str], str]:
    if payload.get("schema_version") != "stage2_control_trace_targets.v1":
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "trace_targets_header_invalid"
        )
    _self_hash(payload, "trace_targets_sha256", "trace_targets")
    if (
        payload.get("trace_targets_sha256")
        != verification.get("trace_targets_sha256")
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "trace_targets_revision_binding_mismatch"
        )
    if (
        payload.get("target_identities_sha256")
        != verification.get("target_identities_sha256")
        or payload.get("capability_report_file_sha256") != _file_sha(capability_file)
        or payload.get("capability_report_sha256") != capability.get("report_sha256")
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "trace_targets_source_binding_mismatch"
        )
    _false_authority(payload, "trace_targets")
    targets = payload.get("targets")
    if (
        not isinstance(targets, list)
        or len(targets) != payload.get("target_count")
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "trace_targets_scope_invalid"
        )
    result: dict[tuple[str, str], str] = {}
    call_count = 0
    for target in targets:
        if not isinstance(target, Mapping):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "trace_target_invalid"
            )
        chain = str(target.get("chain", ""))
        calls = target.get("calls")
        if chain not in _CHAINS or not isinstance(calls, list) or len(calls) != 2:
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "trace_target_invalid"
            )
        families: set[str] = set()
        for call in calls:
            if not isinstance(call, Mapping):
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "trace_target_call_invalid"
                )
            key = (chain, str(call.get("provider_id", "")))
            family = str(call.get("operator_family", ""))
            previous = result.setdefault(key, family)
            if not key[1] or not family or previous != family:
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "trace_target_provider_binding_invalid"
                )
            families.add(family)
            call_count += 1
        if len(families) != 2:
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "trace_target_family_independence_invalid"
            )
    if call_count != payload.get("rpc_call_count") or len(result) != 6:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "trace_targets_provider_scope_invalid"
        )
    return result


def _record_mapping(record: ProviderRecord) -> dict[str, object]:
    return {
        "provider_id": record.provider_id,
        "chain": record.chain,
        "endpoint": record.endpoint,
        "operator_family": record.operator_family,
        "discovery_source": record.discovery_source,
        "tracking_enabled": record.tracking_enabled,
        "operator_evidence_url": record.operator_evidence_url,
        "operator_evidence_sha256": record.operator_evidence_sha256,
        "operator_verified": record.operator_verified,
        **({"api_key_env": record.api_key_env} if record.api_key_env else {}),
        **({"endpoint_env": record.endpoint_env} if record.endpoint_env else {}),
    }


def build_legacy_alias_full_registry_projection(
    *,
    revision_verification_path: Path,
    registry_fragment_path: Path,
    identity_report_path: Path,
    candidate_registry_path: Path,
    capability_report_path: Path,
    trace_targets_path: Path,
) -> dict[str, object]:
    """Project the exact six-provider non-RPC registry for frozen trace calls."""
    verification_file, verification = _load_json(
        revision_verification_path, "revision_verification"
    )
    fragment_file, fragment = _load_json(
        registry_fragment_path, "registry_fragment"
    )
    identity_file, identity = _load_json(identity_report_path, "identity_report")
    capability_file, capability = _load_json(
        capability_report_path, "capability_report"
    )
    trace_file, trace_targets = _load_json(trace_targets_path, "trace_targets")
    candidate_file = _ordinary(candidate_registry_path, "candidate_registry")
    _validate_revision_verification(verification)
    fragment_bindings = _validate_fragment(fragment, verification)
    identity_bindings = _validate_identity_report(identity, verification)
    capability_bindings = _validate_capability(capability)
    trace_bindings = _validate_trace_targets(
        trace_targets, verification, capability_file, capability
    )
    if not (
        identity_bindings == capability_bindings == trace_bindings
        and set(fragment_bindings).issubset(trace_bindings)
    ):
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "provider_binding_sets_mismatch"
        )
    try:
        raw_registry = yaml.safe_load(candidate_file.read_text(encoding="utf-8"))
        if not isinstance(raw_registry, dict):
            raise ValueError("registry root")
        candidate = ProviderRegistry.from_mapping(raw_registry)
    except (KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
            "candidate_registry_invalid"
        ) from exc
    candidate_bindings = {
        (record.chain, record.provider_id): record for record in candidate.providers
    }
    projected_rows: list[dict[str, object]] = []
    for key in sorted(trace_bindings):
        chain, provider_id = key
        family = trace_bindings[key]
        candidate_record = candidate_bindings.get(key)
        if (
            candidate_record is None
            or candidate_record.operator_family != family
            or candidate_record.tracking_enabled is not True
        ):
            raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                "candidate_registry_provider_binding_mismatch"
            )
        if key in fragment_bindings:
            legacy = fragment_bindings[key]
            if candidate_record.endpoint != legacy.get("endpoint"):
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "candidate_registry_legacy_endpoint_mismatch"
                )
            projected_rows.append(
                {
                    "provider_id": provider_id,
                    "chain": chain,
                    "endpoint": legacy["endpoint"],
                    "operator_family": family,
                    "discovery_source": (
                        "signed-local-test-legacy-alias-revision:"
                        + str(verification["revision_request_sha256"])
                    ),
                    "tracking_enabled": True,
                    "operator_evidence_url": None,
                    "operator_evidence_sha256": fragment["fragment_sha256"],
                    "operator_verified": True,
                }
            )
        else:
            if candidate_record.operator_verified is not True:
                raise ControlProviderIdentityLegacyAliasRegistryProjectionError(
                    "candidate_registry_paired_provider_unverified"
                )
            projected_rows.append(_record_mapping(candidate_record))
    registry: dict[str, object] = {
        "version": "1.3.0-local-test-legacy-alias-revision-projection",
        "projection_provenance": {
            "revision_request_sha256": verification["revision_request_sha256"],
            "revision_verification_file_sha256": _file_sha(verification_file),
            "revision_verification_sha256": verification["verification_sha256"],
            "registry_fragment_file_sha256": _file_sha(fragment_file),
            "registry_fragment_sha256": fragment["fragment_sha256"],
            "identity_report_file_sha256": _file_sha(identity_file),
            "identity_report_sha256": identity["report_sha256"],
            "candidate_registry_file_sha256": _file_sha(candidate_file),
            "capability_report_file_sha256": _file_sha(capability_file),
            "capability_report_sha256": capability["report_sha256"],
            "trace_targets_file_sha256": _file_sha(trace_file),
            "trace_targets_sha256": trace_targets["trace_targets_sha256"],
            "provider_identity_verified": True,
            **dict(_FALSE_AUTHORITY),
        },
        "providers": projected_rows,
    }
    registry_sha = _canonical_sha(registry)
    projection_verification: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_full_registry_projection_verification.v1"
        ),
        "decision": (
            "LEGACY_ALIAS_FULL_PROVIDER_REGISTRY_PROJECTED_LOCAL_TEST_ONLY"
        ),
        "revision_request_sha256": verification["revision_request_sha256"],
        "provider_registry_sha256": registry_sha,
        "provider_count": len(projected_rows),
        "chain_count": 3,
        "provider_registry_verified": True,
        **dict(_FALSE_AUTHORITY),
    }
    projection_verification["verification_sha256"] = _canonical_sha(
        projection_verification
    )
    return {
        "provider_registry": registry,
        "projection_verification": projection_verification,
    }
