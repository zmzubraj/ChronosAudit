from __future__ import annotations

from datetime import datetime
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
import subprocess


class ControlProviderIdentityLegacyAliasRevisionApprovalError(ValueError):
    """Raised when a signed local-test legacy-alias revision is invalid."""


_SIGNATURE_NAMESPACE = (
    "chronosaudit-stage2-control-provider-identity-legacy-alias-v1"
)
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


def canonical_signed_payload(approval: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(approval)) + "\n").encode("utf-8")


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            f"{label}_not_ordinary"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            f"{label}_missing"
        ) from exc
    if not resolved.is_file():
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            f"{label}_not_ordinary"
        )
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            f"{label}_json_invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            f"{label}_root_invalid"
        )
    return payload


def _time(value: object, label: str) -> datetime:
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            f"{label}_invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.isoformat().replace("+00:00", "Z") != text:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            f"{label}_not_canonical"
        )
    return parsed


def _validate_revision(revision: Mapping[str, object]) -> None:
    if revision.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_revision_request.v1"
    ) or revision.get("decision") != (
        "AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_REVISION_SIGNATURE"
    ):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_header_invalid"
        )
    material = {
        key: value
        for key, value in revision.items()
        if key != "revision_request_sha256"
    }
    if revision.get("revision_request_sha256") != _canonical_sha(material):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_self_hash_invalid"
        )
    if revision.get("method_approved") is not True:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_method_approved_invalid"
        )
    for field, expected in {
        "provider_identity_verified": False,
        "provider_registry_verified": False,
        "provider_identity_revision_authorized": False,
        **_FALSE_AUTHORITY,
    }.items():
        if revision.get(field) is not expected:
            raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
                f"revision_{field}_invalid"
            )
    legacy = revision.get("legacy_provider_bindings")
    paired = revision.get("paired_provider_bindings")
    if (
        not isinstance(legacy, list)
        or len(legacy) != 3
        or revision.get("legacy_provider_count") != 3
        or not isinstance(paired, list)
        or len(paired) != 3
        or revision.get("paired_provider_count") != 3
    ):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_provider_scope_invalid"
        )
    chains = ["base", "bsc", "ethereum"]
    if (
        [row.get("chain") for row in legacy if isinstance(row, Mapping)] != chains
        or [row.get("chain") for row in paired if isinstance(row, Mapping)] != chains
    ):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_chain_scope_invalid"
        )


def _validate_revision_verification(
    *,
    revision: Mapping[str, object],
    revision_file: Path,
    verification: Mapping[str, object],
) -> None:
    if verification.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_revision_request_verification.v1"
    ) or verification.get("decision") != (
        "LEGACY_ALIAS_IDENTITY_REVISION_REQUEST_VERIFIED_NON_AUTHORIZING"
    ):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_verification_header_invalid"
        )
    material = {
        key: value
        for key, value in verification.items()
        if key != "verification_sha256"
    }
    if verification.get("verification_sha256") != _canonical_sha(material):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_verification_self_hash_invalid"
        )
    if (
        verification.get("revision_request_file_sha256") != _file_sha(revision_file)
        or verification.get("revision_request_sha256")
        != revision.get("revision_request_sha256")
        or verification.get("request_sha256") != revision.get("request_sha256")
        or verification.get("approval_record_sha256")
        != revision.get("approval_record_sha256")
        or verification.get("evidence_packet_sha256")
        != revision.get("evidence_packet_sha256")
        or verification.get("provider_identity_verified") is not False
        or verification.get("rpc_authorized") is not False
    ):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "revision_verification_binding_invalid"
        )


def build_legacy_alias_identity_revision_approval(
    *,
    revision_request_path: Path,
    revision_verification_path: Path,
    reviewer_principal: str,
) -> dict[str, object]:
    """Build the exact approval payload for an accountable revision signature."""
    revision_file = _ordinary(revision_request_path, "revision_request")
    verification_file = _ordinary(
        revision_verification_path, "revision_verification"
    )
    revision = _load(revision_file, "revision_request")
    verification = _load(verification_file, "revision_verification")
    _validate_revision(revision)
    _validate_revision_verification(
        revision=revision,
        revision_file=revision_file,
        verification=verification,
    )
    principal = reviewer_principal.strip()
    if not principal or principal != revision.get("reviewer_principal"):
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "reviewer_principal_mismatch"
        )
    return {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_revision_approval.v1"
        ),
        "decision": (
            "APPROVE_LOCAL_TEST_LEGACY_ALIAS_PROVIDER_IDENTITY_REVISION"
        ),
        "purpose": revision["purpose"],
        "reviewer_principal": principal,
        "review_start_utc": revision["created_at_utc"],
        "review_expires_utc": revision["expires_at_utc"],
        "revision_request_file_sha256": _file_sha(revision_file),
        "revision_request_sha256": revision["revision_request_sha256"],
        "revision_verification_file_sha256": _file_sha(verification_file),
        "revision_verification_sha256": verification["verification_sha256"],
        "method_request_sha256": revision["request_sha256"],
        "method_approval_record_sha256": revision["approval_record_sha256"],
        "evidence_packet_sha256": revision["evidence_packet_sha256"],
        "target_identities_sha256": revision["target_identities_sha256"],
        "trace_targets_sha256": revision["trace_targets_sha256"],
        "legacy_provider_bindings": revision["legacy_provider_bindings"],
        "paired_provider_bindings": revision["paired_provider_bindings"],
        "provider_identity_revision_authorized": True,
        "registry_fragment_projection_authorized": True,
        "identity_report_projection_authorized": True,
        **dict(_FALSE_AUTHORITY),
        "identity_binding_limit": (
            "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_REVIEWER_IDENTITY"
        ),
    }


def _registry_fragment(
    revision: Mapping[str, object], approval: Mapping[str, object]
) -> dict[str, object]:
    providers = []
    for binding in revision["legacy_provider_bindings"]:
        providers.append(
            {
                "provider_id": binding["provider_id"],
                "chain": binding["chain"],
                "endpoint": binding["endpoint"],
                "endpoint_template_sha256": binding["endpoint_template_sha256"],
                "operator_family": binding["operator_family"],
                "operator_identity_family": binding[
                    "operator_identity_family"
                ],
                "operator_verified": True,
                "identity_scope": "LOCAL_TEST_LEGACY_ALIAS_ONLY",
                "review_expires_utc": approval["review_expires_utc"],
                "rpc_authorized": False,
            }
        )
    fragment: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_registry_fragment.v1"
        ),
        "decision": "LEGACY_ALIAS_REGISTRY_FRAGMENT_VERIFIED_LOCAL_TEST_ONLY",
        "revision_request_sha256": revision["revision_request_sha256"],
        "reviewer_principal": approval["reviewer_principal"],
        "review_expires_utc": approval["review_expires_utc"],
        "provider_count": len(providers),
        "providers": providers,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
    }
    fragment["fragment_sha256"] = _canonical_sha(fragment)
    return fragment


def _identity_projection(revision: Mapping[str, object]) -> dict[str, object]:
    paired = {
        str(row["chain"]): row for row in revision["paired_provider_bindings"]
    }
    chains = []
    for legacy in revision["legacy_provider_bindings"]:
        chain = str(legacy["chain"])
        pair = paired[chain]
        providers = [
            {
                "provider_id": legacy["provider_id"],
                "verified_operator_family": legacy["operator_family"],
                "verified_operator_identity_family": legacy[
                    "operator_identity_family"
                ],
                "endpoint_template_sha256": legacy["endpoint_template_sha256"],
                "identity_basis": "SIGNED_LOCAL_TEST_LEGACY_ALIAS_REVISION",
                "complete": True,
            },
            {
                "provider_id": pair["provider_id"],
                "verified_operator_family": pair["operator_family"],
                "identity_basis": (
                    "SEPARATE_EXACT_PUBLICATION_EVIDENCE_BOUND_IN_REVISION"
                ),
                "complete": True,
            },
        ]
        chains.append(
            {
                "chain": chain,
                "complete": True,
                "errors": [],
                "provider_count": 2,
                "providers": providers,
                "verified_operator_families": sorted(
                    str(row["verified_operator_family"]) for row in providers
                ),
            }
        )
    report: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_verification.v1"
        ),
        "decision": "LEGACY_ALIAS_PROVIDER_IDENTITY_VERIFIED_LOCAL_TEST_ONLY",
        "revision_request_sha256": revision["revision_request_sha256"],
        "chain_count": len(chains),
        "chains": chains,
        "complete": True,
        "errors": [],
        "provider_identity_verified": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
    }
    report["report_sha256"] = _canonical_sha(report)
    return report


def verify_legacy_alias_identity_revision_approval(
    *,
    revision_request_path: Path,
    revision_verification_path: Path,
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    """Verify the signature and project identity only; never authorize RPC."""
    revision_file = _ordinary(revision_request_path, "revision_request")
    verification_file = _ordinary(
        revision_verification_path, "revision_verification"
    )
    approval_file = _ordinary(approval_path, "approval")
    signature_file = _ordinary(signature_path, "signature")
    allowed_file = _ordinary(allowed_signers_path, "allowed_signers")
    revision = _load(revision_file, "revision_request")
    approval = _load(approval_file, "approval")
    _validate_revision(revision)
    expected = build_legacy_alias_identity_revision_approval(
        revision_request_path=revision_file,
        revision_verification_path=verification_file,
        reviewer_principal=str(revision.get("reviewer_principal", "")),
    )
    if approval.get("schema_version") != expected["schema_version"]:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "approval_schema_invalid"
        )
    principal = str(approval.get("reviewer_principal", "")).strip()
    if not expected_principal or principal != expected_principal:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "reviewer_principal_mismatch"
        )
    for field, expected_value in _FALSE_AUTHORITY.items():
        if approval.get(field) is not expected_value:
            raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
                f"approval_{field}_invalid"
            )
    for field in (
        "provider_identity_revision_authorized",
        "registry_fragment_projection_authorized",
        "identity_report_projection_authorized",
    ):
        if approval.get(field) is not True:
            raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
                f"approval_{field}_invalid"
            )
    if approval != expected:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "approval_reconstruction_mismatch"
        )
    start = _time(approval["review_start_utc"], "review_start_utc")
    expires = _time(approval["review_expires_utc"], "review_expires_utc")
    now = _time(verification_time_utc, "verification_time_utc")
    if now < start:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "review_not_yet_valid"
        )
    if now > expires:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "review_expired"
        )
    signature_check = subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed_file),
            "-I",
            principal,
            "-n",
            _SIGNATURE_NAMESPACE,
            "-s",
            str(signature_file),
        ],
        input=canonical_signed_payload(approval),
        capture_output=True,
        check=False,
    )
    if signature_check.returncode != 0:
        raise ControlProviderIdentityLegacyAliasRevisionApprovalError(
            "signature_invalid"
        )
    verification: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_revision_approval_verification.v1"
        ),
        "decision": (
            "LEGACY_ALIAS_PROVIDER_IDENTITY_REVISION_VERIFIED_LOCAL_TEST_ONLY"
        ),
        "revision_request_sha256": revision["revision_request_sha256"],
        "approval_file_sha256": _file_sha(approval_file),
        "signature_file_sha256": _file_sha(signature_file),
        "allowed_signers_file_sha256": _file_sha(allowed_file),
        "signature_namespace": _SIGNATURE_NAMESPACE,
        "reviewer_principal": principal,
        "review_expires_utc": approval["review_expires_utc"],
        "target_identities_sha256": approval["target_identities_sha256"],
        "trace_targets_sha256": approval["trace_targets_sha256"],
        "provider_identity_revision_authorized": True,
        "provider_identity_verified": True,
        "provider_registry_fragment_verified": True,
        **dict(_FALSE_AUTHORITY),
        "identity_binding_limit": approval["identity_binding_limit"],
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return {
        "verification": verification,
        "provider_registry_fragment": _registry_fragment(revision, approval),
        "provider_identity_verification": _identity_projection(revision),
    }
