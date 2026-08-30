from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from .control_provider_identity_legacy_alias_approval import (
    verify_legacy_alias_approval_record,
)
from .control_provider_identity_legacy_alias_amendment import (
    verify_legacy_alias_amendment_request,
)


class ControlProviderIdentityLegacyAliasRevisionError(ValueError):
    """Raised when a legacy-alias identity-revision request is invalid."""


_CHAINS = ["base", "bsc", "ethereum"]
_ENDPOINTS = {
    "base": "https://base.merkle.io",
    "bsc": "https://bsc.merkle.io",
    "ethereum": "https://eth.merkle.io",
}
_CONJUNCTS = {
    "operator_domain_bridge",
    "chain_support",
    "endpoint_transport_identity",
    "frozen_runtime_capability",
    "paired_family_independence",
}
_FALSE_AUTHORITY = {
    "provider_identity_verified": False,
    "provider_registry_verified": False,
    "provider_identity_revision_authorized": False,
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
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_not_ordinary"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_missing"
        ) from exc
    if not resolved.is_file():
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_not_ordinary"
        )
    return resolved


def _directory(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_invalid"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_missing"
        ) from exc
    if not resolved.is_dir():
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_invalid"
        )
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_json_invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_root_invalid"
        )
    return payload


def _canonical_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            f"{label}_not_canonical"
        )
    return parsed


def _evidence_file(root: Path, raw_path: object) -> tuple[str, Path]:
    text = str(raw_path)
    pure = PurePosixPath(text)
    if pure.is_absolute() or ".." in pure.parts or not text:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_file_path_invalid"
        )
    path = _ordinary(root / Path(*pure.parts), "evidence_file")
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_file_outside_root"
        ) from exc
    return text, path


def _validate_evidence_packet(
    *,
    manifest_path: Path,
    evidence_root: Path,
    request_sha256: object,
    approval_record_sha256: object,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    root = _directory(evidence_root, "evidence_root")
    path = _ordinary(manifest_path, "evidence_manifest")
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_manifest_outside_root"
        ) from exc
    packet = _load(path, "evidence_manifest")
    if packet.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_evidence_packet.v1"
    ) or packet.get("decision") != "EVIDENCE_PACKET_ASSEMBLED_NON_AUTHORIZING":
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_packet_header_invalid"
        )
    material = {
        key: value
        for key, value in packet.items()
        if key != "evidence_packet_sha256"
    }
    if packet.get("evidence_packet_sha256") != _canonical_sha(material):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_packet_self_hash_invalid"
        )
    if (
        packet.get("request_sha256") != request_sha256
        or packet.get("approval_record_sha256") != approval_record_sha256
    ):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_packet_binding_invalid"
        )
    for field in (
        "provider_identity_verified",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if packet.get(field) is not False:
            raise ControlProviderIdentityLegacyAliasRevisionError(
                f"evidence_packet_{field}_invalid"
            )
    rows = packet.get("conjuncts")
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_conjuncts_invalid"
        )
    identifiers = [str(row.get("conjunct_id", "")) for row in rows]
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != _CONJUNCTS:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "evidence_conjunct_scope_invalid"
        )
    summaries: list[dict[str, object]] = []
    for row in sorted(rows, key=lambda value: str(value.get("conjunct_id"))):
        conjunct_id = str(row["conjunct_id"])
        if row.get("status") != "PRESENT_FOR_ACCOUNTABLE_REVIEW":
            raise ControlProviderIdentityLegacyAliasRevisionError(
                "evidence_conjunct_status_invalid"
            )
        chains = row.get("chains")
        endpoints = row.get("endpoints")
        expected_chains = [] if conjunct_id == "operator_domain_bridge" else _CHAINS
        expected_endpoints = (
            list(_ENDPOINTS.values())
            if conjunct_id
            in {"endpoint_transport_identity", "frozen_runtime_capability"}
            else []
        )
        if chains != expected_chains or endpoints != expected_endpoints:
            raise ControlProviderIdentityLegacyAliasRevisionError(
                "evidence_conjunct_coverage_invalid"
            )
        files = row.get("evidence_files")
        if not isinstance(files, list) or not files or not all(
            isinstance(item, Mapping) for item in files
        ):
            raise ControlProviderIdentityLegacyAliasRevisionError(
                "evidence_conjunct_files_invalid"
            )
        file_summaries = []
        seen_paths: set[str] = set()
        for item in files:
            relative, evidence_path = _evidence_file(root, item.get("path"))
            if relative in seen_paths:
                raise ControlProviderIdentityLegacyAliasRevisionError(
                    "evidence_file_duplicate"
                )
            seen_paths.add(relative)
            actual = _file_sha(evidence_path)
            if item.get("file_sha256") != actual:
                raise ControlProviderIdentityLegacyAliasRevisionError(
                    "evidence_file_hash_mismatch"
                )
            file_summaries.append({"path": relative, "file_sha256": actual})
        summaries.append(
            {
                "conjunct_id": conjunct_id,
                "status": "PRESENT_FOR_ACCOUNTABLE_REVIEW",
                "chains": chains,
                "endpoints": endpoints,
                "evidence_files": file_summaries,
            }
        )
    return packet, summaries


def build_legacy_alias_identity_revision_request(
    *,
    project_root: Path,
    request_path: Path,
    approval_path: Path,
    approval_verification_path: Path,
    evidence_manifest_path: Path,
    evidence_root: Path,
    created_at_utc: str,
    expires_at_utc: str,
    reviewer_principal: str,
) -> dict[str, object]:
    """Build a non-authorizing evidence packet awaiting identity signature."""
    root = _directory(project_root, "project_root")
    request_file = _ordinary(request_path, "request")
    verify_legacy_alias_amendment_request(
        request_path=request_file, project_root=root
    )
    request = _load(request_file, "request")
    approval_file = _ordinary(approval_path, "approval")
    approval_verification_file = _ordinary(
        approval_verification_path, "approval_verification"
    )
    computed_approval_verification = verify_legacy_alias_approval_record(
        project_root=root,
        request_path=request_file,
        approval_path=approval_file,
    )
    supplied_approval_verification = _load(
        approval_verification_file, "approval_verification"
    )
    if supplied_approval_verification != computed_approval_verification:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "approval_verification_mismatch"
        )
    approval = _load(approval_file, "approval")
    packet, conjuncts = _validate_evidence_packet(
        manifest_path=evidence_manifest_path,
        evidence_root=evidence_root,
        request_sha256=request.get("request_sha256"),
        approval_record_sha256=approval.get("record_sha256"),
    )
    created = _canonical_time(created_at_utc, "created_at_utc")
    expires = _canonical_time(expires_at_utc, "expires_at_utc")
    if expires <= created or expires - created > timedelta(days=7):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "review_window_invalid"
        )
    principal = reviewer_principal.strip()
    if not principal:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "reviewer_principal_invalid"
        )
    transport = request.get("triggering_transport_evidence")
    if not isinstance(transport, Mapping):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "request_transport_binding_invalid"
        )
    capability_path = _ordinary(
        root / str(transport.get("capability_report_path")), "capability_report"
    )
    capability = _load(capability_path, "capability_report")
    chain_rows = capability.get("chains")
    if not isinstance(chain_rows, list):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "capability_chains_invalid"
        )
    paired: list[dict[str, object]] = []
    by_chain: dict[str, Mapping[str, object]] = {}
    for raw_chain in chain_rows:
        if isinstance(raw_chain, Mapping):
            by_chain[str(raw_chain.get("chain", ""))] = raw_chain
    for chain in _CHAINS:
        raw_chain = by_chain.get(chain)
        providers = raw_chain.get("providers") if raw_chain is not None else None
        if not isinstance(providers, list):
            raise ControlProviderIdentityLegacyAliasRevisionError(
                "capability_provider_scope_invalid"
            )
        candidates = [
            provider
            for provider in providers
            if isinstance(provider, Mapping)
            and str(provider.get("provider_family", "")).lower() != "merkle"
        ]
        if len(candidates) != 1:
            raise ControlProviderIdentityLegacyAliasRevisionError(
                "paired_provider_scope_invalid"
            )
        provider = candidates[0]
        paired.append(
            {
                "chain": chain,
                "provider_id": provider["provider_id"],
                "operator_family": provider["provider_family"],
                "identity_status": "SEPARATE_EXACT_PUBLICATION_REVIEW_REQUIRED",
            }
        )
    legacy = [
        {
            "chain": chain,
            "provider_id": f"merkle-{chain}",
            "operator_family": "merkle",
            "operator_identity_family": "merkle_blink",
            "endpoint": _ENDPOINTS[chain],
            "endpoint_template_sha256": hashlib.sha256(
                _ENDPOINTS[chain].encode("utf-8")
            ).hexdigest(),
            "environment": "LOCAL_TEST_ONLY",
            "identity_status": "AWAITING_ACCOUNTABLE_REVISION_SIGNATURE",
        }
        for chain in _CHAINS
    ]
    revision: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_revision_request.v1"
        ),
        "created_at_utc": created_at_utc,
        "expires_at_utc": expires_at_utc,
        "decision": "AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_REVISION_SIGNATURE",
        "reviewer_principal": principal,
        "purpose": "LOCAL_TEST_LEGACY_ALIAS_PROVIDER_IDENTITY_REVISION_ONLY",
        "request_file_sha256": _file_sha(request_file),
        "request_sha256": request["request_sha256"],
        "approval_file_sha256": _file_sha(approval_file),
        "approval_record_sha256": approval["record_sha256"],
        "approval_verification_file_sha256": _file_sha(
            approval_verification_file
        ),
        "approval_verification_sha256": computed_approval_verification[
            "verification_sha256"
        ],
        "evidence_manifest_file_sha256": _file_sha(
            _ordinary(evidence_manifest_path, "evidence_manifest")
        ),
        "evidence_packet_sha256": packet["evidence_packet_sha256"],
        "evidence_conjuncts": conjuncts,
        "target_identities_sha256": approval["target_identities_sha256"],
        "trace_targets_sha256": approval["trace_targets_sha256"],
        "target_count": approval["target_count"],
        "rpc_call_count": approval["rpc_call_count"],
        "legacy_provider_count": len(legacy),
        "legacy_provider_bindings": legacy,
        "paired_provider_count": len(paired),
        "paired_provider_bindings": paired,
        "method_approved": True,
        **dict(_FALSE_AUTHORITY),
    }
    revision["revision_request_sha256"] = _canonical_sha(revision)
    return revision


def verify_legacy_alias_identity_revision_request(
    *,
    project_root: Path,
    request_path: Path,
    approval_path: Path,
    approval_verification_path: Path,
    evidence_manifest_path: Path,
    evidence_root: Path,
    revision_request_path: Path,
) -> dict[str, object]:
    """Reconstruct the revision request and verify exact non-authority."""
    path = _ordinary(revision_request_path, "revision_request")
    revision = _load(path, "revision_request")
    if revision.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_revision_request.v1"
    ):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "revision_schema_invalid"
        )
    material = {
        key: value
        for key, value in revision.items()
        if key != "revision_request_sha256"
    }
    if revision.get("revision_request_sha256") != _canonical_sha(material):
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "revision_self_hash_invalid"
        )
    if revision.get("method_approved") is not True:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "revision_method_approved_invalid"
        )
    for field, expected in _FALSE_AUTHORITY.items():
        if revision.get(field) is not expected:
            raise ControlProviderIdentityLegacyAliasRevisionError(
                f"revision_{field}_invalid"
            )
    rebuilt = build_legacy_alias_identity_revision_request(
        project_root=project_root,
        request_path=request_path,
        approval_path=approval_path,
        approval_verification_path=approval_verification_path,
        evidence_manifest_path=evidence_manifest_path,
        evidence_root=evidence_root,
        created_at_utc=str(revision.get("created_at_utc", "")),
        expires_at_utc=str(revision.get("expires_at_utc", "")),
        reviewer_principal=str(revision.get("reviewer_principal", "")),
    )
    if revision != rebuilt:
        raise ControlProviderIdentityLegacyAliasRevisionError(
            "revision_reconstruction_mismatch"
        )
    verification: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_revision_request_verification.v1"
        ),
        "decision": (
            "LEGACY_ALIAS_IDENTITY_REVISION_REQUEST_VERIFIED_NON_AUTHORIZING"
        ),
        "revision_request_file_sha256": _file_sha(path),
        "revision_request_sha256": revision["revision_request_sha256"],
        "request_sha256": revision["request_sha256"],
        "approval_record_sha256": revision["approval_record_sha256"],
        "evidence_packet_sha256": revision["evidence_packet_sha256"],
        "target_identities_sha256": revision["target_identities_sha256"],
        "trace_targets_sha256": revision["trace_targets_sha256"],
        "method_approved": True,
        **dict(_FALSE_AUTHORITY),
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification
