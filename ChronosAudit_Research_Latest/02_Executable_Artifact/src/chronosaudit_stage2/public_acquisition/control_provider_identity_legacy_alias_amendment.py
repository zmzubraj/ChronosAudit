from __future__ import annotations

from datetime import datetime
import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path


class ControlProviderIdentityLegacyAliasAmendmentError(ValueError):
    """Raised when the local-test legacy-alias decision packet is invalid."""


_FALSE_TRACE_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_EXPECTED_FAMILIES = {
    "base": ["drpc", "merkle"],
    "bsc": ["nodereal", "merkle"],
    "ethereum": ["quicknode", "merkle"],
}
_EXPECTED_FRESH_FAILURES = {
    "base:base-official-base:": "base:base-official-base:HTTP_403_TRACE",
    "base:tenderly-base:": "base:tenderly-base:HTTP_429_TRACE",
    "bsc:bnb-official-bsc:": (
        "bsc:bnb-official-bsc:HISTORICAL_TRACE_RESOURCE_OR_STATE_UNAVAILABLE"
    ),
    "ethereum:publicnode-ethereum:": (
        "ethereum:publicnode-ethereum:TRACE_METHOD_UNAVAILABLE_OR_HTTP_403"
    ),
}
_AUTHORITY = {
    "method_approved": False,
    "provider_identity_verified": False,
    "provider_registry_verified": False,
    "rpc_authorized": False,
    "denominator_admission_authorized": False,
    "selection_authorized": False,
    "qualification_authorized": False,
    "counter_authorized": False,
    "stage_promotion_authorized": False,
    "recovery3_mutation_authorized": False,
    "independent_review_established": False,
    "r5_authorized": False,
    "release_authorized": False,
    "publication_authorized": False,
}


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
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_not_ordinary"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_missing"
        ) from exc
    if not resolved.is_file():
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_not_ordinary"
        )
    return resolved


def _root(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "project_root_invalid"
        )
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "project_root_invalid"
        )
    return resolved


def _relative(path: Path, root: Path, label: str) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError as exc:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_outside_project_root"
        ) from exc


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_json_invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_root_invalid"
        )
    return payload


def _self_hash(payload: Mapping[str, object], key: str, label: str) -> None:
    material = {name: value for name, value in payload.items() if name != key}
    if payload.get(key) != _canonical_sha(material):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_self_hash_invalid"
        )


def _false_trace_authority(payload: Mapping[str, object], label: str) -> None:
    for flag in _FALSE_TRACE_FLAGS:
        if payload.get(flag) is not False:
            raise ControlProviderIdentityLegacyAliasAmendmentError(
                f"{label}_{flag}_invalid"
            )


def _canonical_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "created_at_utc_invalid"
        ) from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "created_at_utc_not_canonical"
        )
    return value


def _capability_families(report: Mapping[str, object]) -> dict[str, list[str]]:
    rows = report.get("chains")
    if not isinstance(rows, list) or len(rows) != 3:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "transport_capability_chain_scope_invalid"
        )
    result: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or row.get("complete") is not True:
            raise ControlProviderIdentityLegacyAliasAmendmentError(
                "transport_capability_chain_invalid"
            )
        chain = str(row.get("chain", "")).lower()
        providers = row.get("providers")
        if (
            chain in result
            or not isinstance(providers, list)
            or len(providers) != 2
            or not all(isinstance(provider, Mapping) for provider in providers)
        ):
            raise ControlProviderIdentityLegacyAliasAmendmentError(
                "transport_capability_provider_scope_invalid"
            )
        families = sorted(
            str(provider.get("provider_family", "")).lower()
            for provider in providers
        )
        if families != sorted(_EXPECTED_FAMILIES.get(chain, [])):
            raise ControlProviderIdentityLegacyAliasAmendmentError(
                "transport_capability_family_mismatch"
            )
        if any(provider.get("known_creation_recovered") is not True for provider in providers):
            raise ControlProviderIdentityLegacyAliasAmendmentError(
                "transport_capability_creation_recovery_invalid"
            )
        result[chain] = _EXPECTED_FAMILIES[chain]
    if set(result) != set(_EXPECTED_FAMILIES):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "transport_capability_chain_scope_invalid"
        )
    return result


def _validate_capability_verification(
    *,
    report: Mapping[str, object],
    report_path: Path,
    verification: Mapping[str, object],
    label: str,
    expected_complete: bool,
) -> None:
    if verification.get("schema_version") != (
        "stage2_control_trace_state_capability_verification.v1"
    ):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_verification_schema_invalid"
        )
    _self_hash(verification, "verification_sha256", f"{label}_verification")
    _false_trace_authority(verification, f"{label}_verification")
    if verification.get("provider_registry_verified") is not False:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_provider_registry_verified_invalid"
        )
    if (
        verification.get("complete") is not expected_complete
        or verification.get("report_sha256") != report.get("report_sha256")
        or verification.get("report_file_sha256") != _file_sha(report_path)
        or verification.get("errors") != report.get("errors")
    ):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            f"{label}_verification_binding_invalid"
        )


def build_legacy_alias_amendment_request(
    *,
    project_root: Path,
    review_kit_path: Path,
    historical_request_path: Path,
    target_identities_path: Path,
    trace_targets_path: Path,
    transport_report_path: Path,
    transport_verification_path: Path,
    fresh_report_path: Path,
    fresh_verification_path: Path,
    created_at_utc: str,
    decision_owner: str,
) -> dict[str, object]:
    """Build a non-authorizing exact-scope method-decision request."""
    root = _root(project_root)
    review_kit = _ordinary(review_kit_path, "review_kit")
    historical_path = _ordinary(historical_request_path, "historical_request")
    identities_path = _ordinary(target_identities_path, "target_identities")
    targets_path = _ordinary(trace_targets_path, "trace_targets")
    transport_path = _ordinary(transport_report_path, "transport_report")
    transport_verification_file = _ordinary(
        transport_verification_path, "transport_verification"
    )
    fresh_path = _ordinary(fresh_report_path, "fresh_report")
    fresh_verification_file = _ordinary(
        fresh_verification_path, "fresh_verification"
    )
    inputs = (
        review_kit,
        historical_path,
        identities_path,
        targets_path,
        transport_path,
        transport_verification_file,
        fresh_path,
        fresh_verification_file,
    )
    for index, path in enumerate(inputs):
        _relative(path, root, f"input_{index}")

    owner = decision_owner.strip()
    if not owner:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "decision_owner_invalid"
        )
    created = _canonical_time(created_at_utc)

    historical = _load(historical_path, "historical_request")
    if historical.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_amendment_request.v1"
    ):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "historical_request_schema_invalid"
        )
    historical_stored = str(historical.get("request_sha256", ""))
    historical_recomputed = _canonical_sha(
        {
            key: value
            for key, value in historical.items()
            if key != "request_sha256"
        }
    )
    if historical_stored == historical_recomputed:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "historical_request_not_mismatched"
        )

    identities = _load(identities_path, "target_identities")
    if identities.get("schema_version") != "stage2_control_trace_target_identities.v1":
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "target_identities_schema_invalid"
        )
    _self_hash(identities, "target_identities_sha256", "target_identities")
    _false_trace_authority(identities, "target_identities")
    identity_rows = identities.get("targets")
    if (
        not isinstance(identity_rows, list)
        or not identity_rows
        or len(identity_rows) != identities.get("target_count")
        or not all(isinstance(row, Mapping) for row in identity_rows)
    ):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "target_identities_count_invalid"
        )
    chain_counts = Counter(str(row.get("chain", "")).lower() for row in identity_rows)
    if set(chain_counts) != set(_EXPECTED_FAMILIES):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "target_identities_chain_scope_invalid"
        )
    declared_counts = identities.get("chain_target_counts")
    if declared_counts != dict(sorted(chain_counts.items())):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "target_identities_chain_count_mismatch"
        )

    transport = _load(transport_path, "transport_report")
    if (
        transport.get("schema_version")
        != "stage2_control_trace_state_capability.v1"
        or transport.get("complete") is not True
        or transport.get("errors") != []
    ):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "transport_capability_not_complete"
        )
    _self_hash(transport, "report_sha256", "transport_report")
    _false_trace_authority(transport, "transport_report")
    paired_families = _capability_families(transport)
    transport_verification = _load(
        transport_verification_file, "transport_verification"
    )
    _validate_capability_verification(
        report=transport,
        report_path=transport_path,
        verification=transport_verification,
        label="transport",
        expected_complete=True,
    )

    trace_targets = _load(targets_path, "trace_targets")
    if trace_targets.get("schema_version") != "stage2_control_trace_targets.v1":
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "trace_targets_schema_invalid"
        )
    _self_hash(trace_targets, "trace_targets_sha256", "trace_targets")
    _false_trace_authority(trace_targets, "trace_targets")
    if trace_targets.get("provider_registry_verified") is not False:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "trace_targets_provider_registry_verified_invalid"
        )
    if (
        trace_targets.get("target_identities_file_sha256")
        != _file_sha(identities_path)
        or trace_targets.get("target_identities_sha256")
        != identities.get("target_identities_sha256")
        or trace_targets.get("capability_report_file_sha256")
        != _file_sha(transport_path)
        or trace_targets.get("capability_report_sha256")
        != transport.get("report_sha256")
        or trace_targets.get("capability_verification_file_sha256")
        != _file_sha(transport_verification_file)
        or trace_targets.get("capability_verification_sha256")
        != transport_verification.get("verification_sha256")
        or trace_targets.get("target_count") != len(identity_rows)
        or trace_targets.get("rpc_call_count") != len(identity_rows) * 2
    ):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "trace_targets_binding_invalid"
        )

    fresh = _load(fresh_path, "fresh_report")
    if fresh.get("schema_version") != "stage2_control_trace_state_capability.v1":
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "fresh_capability_schema_invalid"
        )
    _self_hash(fresh, "report_sha256", "fresh_report")
    _false_trace_authority(fresh, "fresh_report")
    if fresh.get("complete") is not False or not isinstance(fresh.get("errors"), list) or not fresh.get("errors"):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "fresh_capability_not_fail_closed"
        )
    fresh_errors = [str(error) for error in fresh["errors"]]
    failure_categories: list[str] = []
    for prefix, category in _EXPECTED_FRESH_FAILURES.items():
        matches = [error for error in fresh_errors if error.startswith(prefix)]
        if len(matches) != 1:
            raise ControlProviderIdentityLegacyAliasAmendmentError(
                "fresh_capability_failure_scope_invalid"
            )
        failure_categories.append(category)
    fresh_verification = _load(fresh_verification_file, "fresh_verification")
    _validate_capability_verification(
        report=fresh,
        report_path=fresh_path,
        verification=fresh_verification,
        label="fresh",
        expected_complete=False,
    )

    request: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_amendment_request.v2"
        ),
        "created_at_utc": created,
        "decision": "AWAITING_EXPLICIT_METHOD_APPROVAL",
        "decision_owner": owner,
        "decision_requested": (
            "Choose exactly one option: "
            "PRESERVE_EXACT_PUBLICATION_REQUIRE_DOCUMENTED_RUNTIME_ENDPOINTS, or "
            "APPROVE_LEGACY_ENDPOINT_ALIAS_EVIDENCE_V2_FOR_LOCAL_TEST_ONLY."
        ),
        "supersedes": {
            "path": _relative(historical_path, root, "historical_request"),
            "file_sha256": _file_sha(historical_path),
            "status": "HISTORICAL_NON_AUTHORIZING_SELF_HASH_MISMATCH",
            "stored_request_sha256": historical_stored,
            "recomputed_request_sha256": historical_recomputed,
        },
        "current_rule": {
            "status": "FROZEN_AND_UNCHANGED",
            "summary": (
                "Each configured provider endpoint must appear exactly in a "
                "hash-bound capture fetched from an HTTPS official provider-family "
                "host; redirect, cache, DNS, TLS, runtime behavior, or third-party "
                "publication alone is insufficient."
            ),
            "review_kit_path": _relative(review_kit, root, "review_kit"),
            "review_kit_sha256": _file_sha(review_kit),
        },
        "effective_trace_scope": {
            "target_identities_path": _relative(
                identities_path, root, "target_identities"
            ),
            "target_identities_file_sha256": _file_sha(identities_path),
            "target_identities_sha256": identities["target_identities_sha256"],
            "target_count": len(identity_rows),
            "chain_target_counts": dict(sorted(chain_counts.items())),
            "trace_targets_path": _relative(targets_path, root, "trace_targets"),
            "trace_targets_file_sha256": _file_sha(targets_path),
            "trace_targets_sha256": trace_targets["trace_targets_sha256"],
            "rpc_call_count": trace_targets["rpc_call_count"],
            "provider_registry_verified": False,
            "rpc_authorized": False,
        },
        "triggering_transport_evidence": {
            "capability_report_path": _relative(
                transport_path, root, "transport_report"
            ),
            "capability_report_file_sha256": _file_sha(transport_path),
            "capability_report_sha256": transport["report_sha256"],
            "verification_path": _relative(
                transport_verification_file, root, "transport_verification"
            ),
            "verification_file_sha256": _file_sha(transport_verification_file),
            "verification_sha256": transport_verification["verification_sha256"],
            "complete_chains": sorted(paired_families),
            "paired_families": paired_families,
            "provider_registry_verified": False,
            "interpretation": (
                "Transport capability and semantic agreement are established for "
                "the frozen fixtures, but provider identity and independence are "
                "not established by this report."
            ),
        },
        "fresh_exact_registry_attempt": {
            "capability_report_path": _relative(fresh_path, root, "fresh_report"),
            "capability_report_file_sha256": _file_sha(fresh_path),
            "capability_report_sha256": fresh["report_sha256"],
            "verification_path": _relative(
                fresh_verification_file, root, "fresh_verification"
            ),
            "verification_file_sha256": _file_sha(fresh_verification_file),
            "verification_sha256": fresh_verification["verification_sha256"],
            "complete": False,
            "provider_registry_verified": False,
            "failed_provider_paths": failure_categories,
            "established_single_families": {
                "bsc": "nodereal",
                "ethereum": "quicknode",
            },
            "interpretation": (
                "The current exact-published registry does not establish two "
                "trace-capable independent families on every required chain."
            ),
        },
        "options": _options(
            target_identities_sha256=str(identities["target_identities_sha256"]),
            trace_targets_sha256=str(trace_targets["trace_targets_sha256"]),
        ),
        "authority": dict(_AUTHORITY),
        "counter_projection": {
            "control_candidates_current": 0,
            "control_candidates_required": 4170,
            "qualified_controls_current": 0,
            "qualified_controls_required": 4170,
            "changed_by_this_request": False,
        },
        "control_selection_policy_sha256": (
            "e2ec1673827d4b30245a11eb70e665e4a5ad6ad2a423283a84c8186f0d0f1e19"
        ),
    }
    request["request_sha256"] = _canonical_sha(request)
    return request


def _options(
    *, target_identities_sha256: str, trace_targets_sha256: str
) -> list[dict[str, object]]:
    return [
        {
            "option_id": "PRESERVE_EXACT_PUBLICATION_REQUIRE_DOCUMENTED_RUNTIME_ENDPOINTS",
            "method_change": False,
            "recommended_for_canonical_scientific_track": True,
            "requirements": [
                "Supply documented runtime credentials or another two-family set with current exact official endpoint publication for Base, BSC, and Ethereum.",
                "Rebuild and independently verify the provider identity revision.",
                "Rerun the frozen known-creation trace and cutoff-state capability probe before any activation.",
            ],
            "consequence": "No provider-identity exception is introduced; canonical RPC activation remains blocked until documented runtime endpoints are available.",
        },
        {
            "option_id": "APPROVE_LEGACY_ENDPOINT_ALIAS_EVIDENCE_V2_FOR_LOCAL_TEST_ONLY",
            "method_change": True,
            "recommended_for_canonical_scientific_track": False,
            "scope": {
                "environment": "LOCAL_TEST_ONLY",
                "operator_family": "merkle_blink",
                "chains": ["base", "bsc", "ethereum"],
                "exact_endpoints": [
                    "https://base.merkle.io",
                    "https://bsc.merkle.io",
                    "https://eth.merkle.io",
                ],
                "target_identities_sha256": target_identities_sha256,
                "trace_targets_sha256": trace_targets_sha256,
            },
            "required_conjunctive_evidence": [
                "A current first-party merkle.io page binds the Merkle domain to Blink Labs branding and current official Blink documentation or portal links.",
                "A current first-party Blink source establishes support for the relevant chain, even when it publishes a replacement endpoint rather than the legacy endpoint.",
                "The exact legacy endpoint remains under the merkle.io registrable domain and passes live DNS, TLS-hostname, HTTPS, and expected eth_chainId checks at freeze time.",
                "The exact legacy endpoint passes the frozen historical block, receipt, trace, EIP-1898 runtime-code, and three proxy-slot fixture checks with hash-bound raw request and response envelopes.",
                "The paired non-Merkle family has separately exact-published endpoint evidence and no identified common operator ownership with Blink Labs.",
                "The accountable human author approves this exact request hash and a separately verified provider-identity revision binds the endpoints, operator families, chains, evidence hashes, limitations, and expiry before activation.",
            ],
            "fail_closed_rules": [
                "Any failed or unavailable conjunct is INSUFFICIENT_EVIDENCE.",
                "The rule does not generalize to another hostname, chain, provider family, date, target scope, or production track.",
                "The rule does not establish archive capability beyond the exact frozen probes.",
                "The rule cannot authorize selection, qualification, counters, stage promotion, Recovery3 mutation, release eligibility, or independent review.",
                "The approval token does not itself authorize RPC; a separately signed exact-scope activation must pass after provider identity and capability verification.",
            ],
            "consequence": "If explicitly approved and implemented, the three legacy endpoints may enter only a labeled local-test provider-identity revision for this exact trace scope; canonical counters remain fail-closed.",
        },
    ]


def verify_legacy_alias_amendment_request(
    *, request_path: Path, project_root: Path
) -> dict[str, object]:
    """Rebuild the request from bound inputs and verify exact equality."""
    root = _root(project_root)
    path = _ordinary(request_path, "request")
    request = _load(path, "request")
    if request.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_amendment_request.v2"
    ):
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "request_schema_invalid"
        )
    _self_hash(request, "request_sha256", "request")
    if request.get("decision") != "AWAITING_EXPLICIT_METHOD_APPROVAL":
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "request_decision_invalid"
        )
    if request.get("authority") != _AUTHORITY:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "request_authority_invalid"
        )
    try:
        current_rule = request["current_rule"]
        supersedes = request["supersedes"]
        scope = request["effective_trace_scope"]
        transport = request["triggering_transport_evidence"]
        fresh = request["fresh_exact_registry_attempt"]
        assert isinstance(current_rule, Mapping)
        assert isinstance(supersedes, Mapping)
        assert isinstance(scope, Mapping)
        assert isinstance(transport, Mapping)
        assert isinstance(fresh, Mapping)
        bound_files = (
            (
                "target_identities",
                root / str(scope["target_identities_path"]),
                str(scope["target_identities_file_sha256"]),
            ),
            (
                "trace_targets",
                root / str(scope["trace_targets_path"]),
                str(scope["trace_targets_file_sha256"]),
            ),
            (
                "transport_report",
                root / str(transport["capability_report_path"]),
                str(transport["capability_report_file_sha256"]),
            ),
            (
                "transport_verification",
                root / str(transport["verification_path"]),
                str(transport["verification_file_sha256"]),
            ),
            (
                "fresh_report",
                root / str(fresh["capability_report_path"]),
                str(fresh["capability_report_file_sha256"]),
            ),
            (
                "fresh_verification",
                root / str(fresh["verification_path"]),
                str(fresh["verification_file_sha256"]),
            ),
        )
        for label, bound_path, expected_sha in bound_files:
            ordinary = _ordinary(bound_path, label)
            if _file_sha(ordinary) != expected_sha:
                raise ControlProviderIdentityLegacyAliasAmendmentError(
                    f"{label}_file_hash_mismatch"
                )
        rebuilt = build_legacy_alias_amendment_request(
            project_root=root,
            review_kit_path=root / str(current_rule["review_kit_path"]),
            historical_request_path=root / str(supersedes["path"]),
            target_identities_path=root / str(scope["target_identities_path"]),
            trace_targets_path=root / str(scope["trace_targets_path"]),
            transport_report_path=root / str(transport["capability_report_path"]),
            transport_verification_path=root / str(transport["verification_path"]),
            fresh_report_path=root / str(fresh["capability_report_path"]),
            fresh_verification_path=root / str(fresh["verification_path"]),
            created_at_utc=str(request["created_at_utc"]),
            decision_owner=str(request["decision_owner"]),
        )
    except (AssertionError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ControlProviderIdentityLegacyAliasAmendmentError):
            raise
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "request_binding_structure_invalid"
        ) from exc
    if request != rebuilt:
        raise ControlProviderIdentityLegacyAliasAmendmentError(
            "request_reconstruction_mismatch"
        )
    verification: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_amendment_request_verification.v1"
        ),
        "decision": "LEGACY_ALIAS_AMENDMENT_REQUEST_VERIFIED_NON_AUTHORIZING",
        "request_file_sha256": _file_sha(path),
        "request_sha256": request["request_sha256"],
        "target_count": request["effective_trace_scope"]["target_count"],
        "rpc_call_count": request["effective_trace_scope"]["rpc_call_count"],
        **dict(_AUTHORITY),
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification
