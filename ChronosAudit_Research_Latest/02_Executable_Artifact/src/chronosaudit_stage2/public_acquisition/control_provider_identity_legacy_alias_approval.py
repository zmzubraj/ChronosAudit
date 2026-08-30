from __future__ import annotations

from datetime import date
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from .control_provider_identity_legacy_alias_amendment import (
    verify_legacy_alias_amendment_request,
)


class ControlProviderIdentityLegacyAliasApprovalError(ValueError):
    """Raised when the exact local-test legacy-alias approval is invalid."""


APPROVAL_TOKEN = (
    "APPROVE_LEGACY_ENDPOINT_ALIAS_EVIDENCE_V2_FOR_LOCAL_TEST_ONLY"
)

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
    "independent_adjudication_authorized": False,
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
        raise ControlProviderIdentityLegacyAliasApprovalError(
            f"{label}_not_ordinary"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            f"{label}_missing"
        ) from exc
    if not resolved.is_file():
        raise ControlProviderIdentityLegacyAliasApprovalError(
            f"{label}_not_ordinary"
        )
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            f"{label}_json_invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ControlProviderIdentityLegacyAliasApprovalError(
            f"{label}_root_invalid"
        )
    return payload


def _approval_date(value: str) -> str:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approved_at_date_invalid"
        ) from exc
    if parsed.isoformat() != value:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approved_at_date_not_canonical"
        )
    return value


def _validated_request(
    *, project_root: Path, request_path: Path
) -> tuple[Path, dict[str, object]]:
    path = _ordinary(request_path, "request")
    verification = verify_legacy_alias_amendment_request(
        request_path=path,
        project_root=project_root,
    )
    if verification.get("decision") != (
        "LEGACY_ALIAS_AMENDMENT_REQUEST_VERIFIED_NON_AUTHORIZING"
    ):
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "request_not_verified"
        )
    request = _load(path, "request")
    options = request.get("options")
    if not isinstance(options, list):
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "request_options_invalid"
        )
    matches = [
        option
        for option in options
        if isinstance(option, Mapping)
        and option.get("option_id") == APPROVAL_TOKEN
    ]
    if len(matches) != 1:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "request_approval_option_invalid"
        )
    option = matches[0]
    scope = option.get("scope")
    effective = request.get("effective_trace_scope")
    if not isinstance(scope, Mapping) or not isinstance(effective, Mapping):
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "request_scope_invalid"
        )
    if (
        scope.get("environment") != "LOCAL_TEST_ONLY"
        or scope.get("chains") != ["base", "bsc", "ethereum"]
        or scope.get("target_identities_sha256")
        != effective.get("target_identities_sha256")
        or scope.get("trace_targets_sha256")
        != effective.get("trace_targets_sha256")
    ):
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "request_scope_binding_invalid"
        )
    return path, request


def build_legacy_alias_approval_record(
    *,
    project_root: Path,
    request_path: Path,
    approval_text: str,
    approved_by_principal: str,
    approved_at_date: str,
    approval_source: str,
) -> dict[str, object]:
    """Bind an exact human decision to the verified v2 request without activation."""
    if approval_text != APPROVAL_TOKEN:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approval_text_invalid"
        )
    principal = approved_by_principal.strip()
    source = approval_source.strip()
    if not principal:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approved_by_principal_invalid"
        )
    if not source:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approval_source_invalid"
        )
    approved = _approval_date(approved_at_date)
    request_file, request = _validated_request(
        project_root=project_root, request_path=request_path
    )
    effective = request["effective_trace_scope"]
    assert isinstance(effective, Mapping)
    record: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_user_approval.v2"
        ),
        "decision": APPROVAL_TOKEN,
        "approval_text": approval_text,
        "approval_source": source,
        "approved_by_principal": principal,
        "approved_at_date": approved,
        "request_path": str(request_file.relative_to(Path(project_root).resolve())),
        "request_file_sha256": _file_sha(request_file),
        "request_sha256": request["request_sha256"],
        "scope": "LOCAL_TEST_LEGACY_ALIAS_METHOD_IMPLEMENTATION_ONLY",
        "target_identities_sha256": effective["target_identities_sha256"],
        "trace_targets_sha256": effective["trace_targets_sha256"],
        "target_count": effective["target_count"],
        "rpc_call_count": effective["rpc_call_count"],
        "identity_binding_limit": (
            "USER_CHAT_AUTHORITY_IS_NOT_CRYPTOGRAPHIC_REAL_WORLD_IDENTITY_PROOF"
        ),
        "method_approved": True,
        **dict(_FALSE_AUTHORITY),
    }
    record["record_sha256"] = _canonical_sha(record)
    return record


def verify_legacy_alias_approval_record(
    *, project_root: Path, request_path: Path, approval_path: Path
) -> dict[str, object]:
    """Verify exact decision and request binding; grant no downstream authority."""
    path = _ordinary(approval_path, "approval")
    approval = _load(path, "approval")
    if approval.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_user_approval.v2"
    ):
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approval_schema_invalid"
        )
    material = {
        key: value for key, value in approval.items() if key != "record_sha256"
    }
    if approval.get("record_sha256") != _canonical_sha(material):
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approval_self_hash_invalid"
        )
    if approval.get("method_approved") is not True:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approval_method_approved_invalid"
        )
    for field, expected in _FALSE_AUTHORITY.items():
        if approval.get(field) is not expected:
            raise ControlProviderIdentityLegacyAliasApprovalError(
                f"approval_{field}_invalid"
            )
    rebuilt = build_legacy_alias_approval_record(
        project_root=project_root,
        request_path=request_path,
        approval_text=str(approval.get("approval_text", "")),
        approved_by_principal=str(approval.get("approved_by_principal", "")),
        approved_at_date=str(approval.get("approved_at_date", "")),
        approval_source=str(approval.get("approval_source", "")),
    )
    if approval != rebuilt:
        raise ControlProviderIdentityLegacyAliasApprovalError(
            "approval_reconstruction_mismatch"
        )
    verification: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_user_approval_verification.v1"
        ),
        "decision": "LEGACY_ALIAS_METHOD_APPROVAL_VERIFIED_LOCAL_TEST_ONLY",
        "approval_file_sha256": _file_sha(path),
        "approval_record_sha256": approval["record_sha256"],
        "request_file_sha256": approval["request_file_sha256"],
        "request_sha256": approval["request_sha256"],
        "target_identities_sha256": approval["target_identities_sha256"],
        "trace_targets_sha256": approval["trace_targets_sha256"],
        "target_count": approval["target_count"],
        "rpc_call_count": approval["rpc_call_count"],
        "method_approved": True,
        **dict(_FALSE_AUTHORITY),
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification
