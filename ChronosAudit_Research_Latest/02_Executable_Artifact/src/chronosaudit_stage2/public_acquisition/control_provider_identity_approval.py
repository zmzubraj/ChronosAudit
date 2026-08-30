from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
import subprocess
from typing import Mapping

import pandas as pd

from .control_provider_identity_evidence import (
    verify_control_provider_identity_evidence_review,
)


class ControlProviderIdentityApprovalError(ValueError):
    """Raised when an accountable provider-identity approval is invalid."""


_SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-provider-identity-review-v1"


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
        raise ControlProviderIdentityApprovalError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityApprovalError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlProviderIdentityApprovalError(f"{label}_not_ordinary_file")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlProviderIdentityApprovalError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlProviderIdentityApprovalError(f"{label}_root_invalid")
    return payload


def _time(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlProviderIdentityApprovalError(f"{label}_invalid")
    if str(value) != parsed.isoformat().replace("+00:00", "Z"):
        raise ControlProviderIdentityApprovalError(f"{label}_not_canonical")
    return parsed


def _request_sha(request: Mapping[str, object]) -> str:
    return _canonical_sha(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def build_control_provider_identity_approval_request(
    *,
    review_path: Path,
    provider_registry_path: Path,
    capture_index_path: Path,
    evidence_root: Path,
) -> dict[str, object]:
    """Bind an accountable review request to the verified documentation packet."""
    review_file = _ordinary(review_path, "review")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    index_file = _ordinary(capture_index_path, "capture_index")
    verification = verify_control_provider_identity_evidence_review(
        review_path=review_file,
        provider_registry_path=registry_file,
        capture_index_path=index_file,
        evidence_root=evidence_root,
    )
    if verification.get("decision") != (
        "PROVIDER_IDENTITY_EVIDENCE_REVIEW_VERIFIED_NON_AUTHORIZING"
    ):
        raise ControlProviderIdentityApprovalError("evidence_review_not_verified")
    review = _load(review_file, "review")
    captures = {
        str(item.get("source_id") or ""): item
        for item in review.get("captures", [])
        if isinstance(item, Mapping)
    }
    bindings: list[dict[str, object]] = []
    for raw_provider in review.get("providers", []):
        if not isinstance(raw_provider, Mapping):
            raise ControlProviderIdentityApprovalError("review_provider_invalid")
        source_id = str(raw_provider.get("source_id") or "")
        capture = captures.get(source_id)
        if capture is None:
            raise ControlProviderIdentityApprovalError("review_provider_capture_missing")
        bindings.append(
            {
                "provider_id": str(raw_provider.get("provider_id") or ""),
                "chain": str(raw_provider.get("chain") or ""),
                "endpoint": str(raw_provider.get("public_endpoint") or ""),
                "public_endpoint_id": str(raw_provider.get("public_endpoint_id") or ""),
                "operator_family": str(raw_provider.get("operator_family") or ""),
                "api_key_env": raw_provider.get("api_key_env"),
                "endpoint_env": raw_provider.get("endpoint_env"),
                "operator_evidence_url": str(capture.get("source_url") or ""),
                "operator_evidence_sha256": str(capture.get("content_sha256") or ""),
                "source_id": source_id,
                "capture_index_sha256": str(review.get("capture_index_sha256") or ""),
            }
        )
    if len(bindings) != int(review.get("provider_count") or -1):
        raise ControlProviderIdentityApprovalError("review_provider_count_mismatch")
    families = sorted({str(binding["operator_family"]) for binding in bindings})
    if len(families) < 2:
        raise ControlProviderIdentityApprovalError("operator_family_scope_invalid")
    chain_families: dict[str, set[str]] = defaultdict(set)
    for binding in bindings:
        chain_families[str(binding["chain"])].add(str(binding["operator_family"]))
    if any(len(values) < 2 for values in chain_families.values()):
        raise ControlProviderIdentityApprovalError("operator_family_independence_invalid")
    if families == ["1rpc", "publicnode"]:
        independence_attestation = (
            "PUBLICNODE_AND_1RPC_VERIFIED_DISTINCT_OPERATOR_FAMILIES"
        )
    else:
        independence_attestation = (
            "AT_LEAST_TWO_DISTINCT_VERIFIED_OPERATOR_FAMILIES_PER_CHAIN"
        )
    request: dict[str, object] = {
        "schema_version": "chronosaudit.control_provider_identity_approval_request.v1",
        "decision": "AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_SIGNATURE",
        "purpose": "CONTROL_RPC_PROVIDER_IDENTITY_AND_INDEPENDENCE_REVIEW_ONLY",
        "review_file_sha256": _sha(review_file),
        "review_payload_sha256": review["review_payload_sha256"],
        "provider_registry_sha256": _sha(registry_file),
        "capture_index_sha256": _sha(index_file),
        "provider_count": len(bindings),
        "operator_families": families,
        "provider_bindings": sorted(bindings, key=lambda item: str(item["provider_id"])),
        "required_operator_identity_attestation": (
            "ACCOUNTABLE_REVIEW_VERIFIED_OFFICIAL_OPERATOR_BINDING"
        ),
        "required_independence_attestation": independence_attestation,
        "archive_capability_attestation": "NOT_ASSESSED_BY_IDENTITY_REVIEW",
        "registry_projection_authorized": False,
        "identity_report_projection_authorized": False,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    request["request_sha256"] = _request_sha(request)
    return request


def build_control_provider_identity_approval(
    *,
    request: Mapping[str, object],
    reviewer_principal: str,
    review_start_utc: str,
    review_expires_utc: str,
) -> dict[str, object]:
    """Build the exact unsigned approval an accountable reviewer may sign."""
    _validate_request(request)
    principal = reviewer_principal.strip()
    if not principal:
        raise ControlProviderIdentityApprovalError("reviewer_principal_invalid")
    start = _time(review_start_utc, "review_start_utc")
    expiry = _time(review_expires_utc, "review_expires_utc")
    if expiry <= start:
        raise ControlProviderIdentityApprovalError("review_window_invalid")
    return {
        "schema_version": "chronosaudit.control_provider_identity_approval.v1",
        "request_sha256": request["request_sha256"],
        "reviewer_principal": principal,
        "decision": "APPROVE_CONTROL_PROVIDER_IDENTITY_BINDINGS",
        "purpose": request["purpose"],
        "review_start_utc": review_start_utc,
        "review_expires_utc": review_expires_utc,
        "review_file_sha256": request["review_file_sha256"],
        "review_payload_sha256": request["review_payload_sha256"],
        "provider_registry_sha256": request["provider_registry_sha256"],
        "capture_index_sha256": request["capture_index_sha256"],
        "provider_count": request["provider_count"],
        "operator_families": request["operator_families"],
        "provider_bindings": request["provider_bindings"],
        "operator_identity_attestation": request[
            "required_operator_identity_attestation"
        ],
        "independence_attestation": request["required_independence_attestation"],
        "archive_capability_attestation": "NOT_ASSESSED_BY_IDENTITY_REVIEW",
        "registry_projection_authorized": True,
        "identity_report_projection_authorized": True,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def _validate_request(request: Mapping[str, object]) -> None:
    if request.get("schema_version") != (
        "chronosaudit.control_provider_identity_approval_request.v1"
    ):
        raise ControlProviderIdentityApprovalError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_SIGNATURE":
        raise ControlProviderIdentityApprovalError("request_not_approvable")
    if request.get("request_sha256") != _request_sha(request):
        raise ControlProviderIdentityApprovalError("request_sha256_invalid")
    for field in (
        "registry_projection_authorized",
        "identity_report_projection_authorized",
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if request.get(field) is not False:
            raise ControlProviderIdentityApprovalError(f"request_{field}_invalid")


def _project_registry(request: Mapping[str, object], approval: Mapping[str, object]) -> dict[str, object]:
    providers = []
    for binding in request["provider_bindings"]:
        providers.append(
            {
                "provider_id": binding["provider_id"],
                "chain": binding["chain"],
                "endpoint": binding["endpoint"],
                "operator_family": binding["operator_family"],
                "discovery_source": binding["operator_evidence_url"],
                "tracking_enabled": True,
                "operator_evidence_url": binding["operator_evidence_url"],
                "operator_evidence_sha256": binding["operator_evidence_sha256"],
                "operator_verified": True,
                **(
                    {"api_key_env": binding["api_key_env"]}
                    if binding.get("api_key_env") is not None
                    else {}
                ),
                **(
                    {"endpoint_env": binding["endpoint_env"]}
                    if binding.get("endpoint_env") is not None
                    else {}
                ),
            }
        )
    return {
        "version": "1.2.0-accountable-provider-review-projection",
        "projection_provenance": {
            "request_sha256": request["request_sha256"],
            "review_payload_sha256": request["review_payload_sha256"],
            "reviewer_principal": approval["reviewer_principal"],
            "review_expires_utc": approval["review_expires_utc"],
            "rpc_authorized": False,
            "selection_authorized": False,
        },
        "providers": providers,
    }


def _project_identity_report(request: Mapping[str, object]) -> dict[str, object]:
    by_chain: dict[str, list[Mapping[str, object]]] = defaultdict(list)
    for binding in request["provider_bindings"]:
        by_chain[str(binding["chain"])].append(binding)
    chains = []
    for chain in sorted(by_chain):
        provider_rows = []
        for binding in sorted(by_chain[chain], key=lambda item: str(item["provider_id"])):
            identity = str(binding["public_endpoint_id"])
            family = str(binding["operator_family"])
            provider_id = str(binding["provider_id"])
            evidence = {
                "chain": chain,
                "provider_id": provider_id,
                "provider_identity_id": identity,
                "endpoint_template_sha256": identity,
                "verified_operator_family": family,
            }
            provider_rows.append(
                {
                    "chain": chain,
                    "complete": True,
                    "provider_id": provider_id,
                    "verified_operator_family": family,
                    "public_endpoint_identity_id": identity,
                    "public_endpoint_identity_sha256": _canonical_sha(identity),
                    "endpoint_template_sha256": identity,
                    "identity_evidence_sha256": _canonical_sha(evidence),
                }
            )
        chains.append(
            {
                "chain": chain,
                "complete": True,
                "errors": [],
                "provider_count": len(provider_rows),
                "providers": provider_rows,
                "verified_operator_families": sorted(
                    {str(item["verified_operator_family"]) for item in provider_rows}
                ),
            }
        )
    report: dict[str, object] = {
        "schema_version": "historical_snapshot_provider_identity_verification.v1",
        "chain_count": len(chains),
        "chains": chains,
        "complete": True,
        "errors": [],
    }
    report["report_sha256"] = _canonical_sha(report)
    return report


def verify_control_provider_identity_approval(
    *,
    request: Mapping[str, object],
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    """Verify the signature and return non-RPC registry/identity projections."""
    _validate_request(request)
    approval_file = _ordinary(approval_path, "approval")
    signature_file = _ordinary(signature_path, "signature")
    allowed_file = _ordinary(allowed_signers_path, "allowed_signers")
    approval = _load(approval_file, "approval")
    if approval.get("schema_version") != (
        "chronosaudit.control_provider_identity_approval.v1"
    ):
        raise ControlProviderIdentityApprovalError("approval_schema_invalid")
    principal = str(approval.get("reviewer_principal") or "").strip()
    if not expected_principal or principal != expected_principal:
        raise ControlProviderIdentityApprovalError("reviewer_principal_mismatch")
    expected_fields = {
        "request_sha256": request["request_sha256"],
        "decision": "APPROVE_CONTROL_PROVIDER_IDENTITY_BINDINGS",
        "purpose": request["purpose"],
        "review_file_sha256": request["review_file_sha256"],
        "review_payload_sha256": request["review_payload_sha256"],
        "provider_registry_sha256": request["provider_registry_sha256"],
        "capture_index_sha256": request["capture_index_sha256"],
        "provider_count": request["provider_count"],
        "operator_families": request["operator_families"],
        "provider_bindings": request["provider_bindings"],
        "operator_identity_attestation": request[
            "required_operator_identity_attestation"
        ],
        "independence_attestation": request["required_independence_attestation"],
        "archive_capability_attestation": "NOT_ASSESSED_BY_IDENTITY_REVIEW",
    }
    for field, expected in expected_fields.items():
        if approval.get(field) != expected:
            raise ControlProviderIdentityApprovalError(f"approval_{field}_mismatch")
    for field, expected in (
        ("registry_projection_authorized", True),
        ("identity_report_projection_authorized", True),
        ("acquisition_authorized", False),
        ("rpc_authorized", False),
        ("selection_authorized", False),
        ("stage_promotion_authorized", False),
        ("recovery3_mutation_authorized", False),
    ):
        if approval.get(field) is not expected:
            raise ControlProviderIdentityApprovalError(f"approval_{field}_invalid")
    start = _time(approval.get("review_start_utc"), "review_start_utc")
    expiry = _time(approval.get("review_expires_utc"), "review_expires_utc")
    now = _time(verification_time_utc, "verification_time_utc")
    if expiry <= start:
        raise ControlProviderIdentityApprovalError("review_window_invalid")
    if now < start:
        raise ControlProviderIdentityApprovalError("review_not_yet_valid")
    if now > expiry:
        raise ControlProviderIdentityApprovalError("review_expired")
    verification = subprocess.run(
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
    if verification.returncode != 0:
        raise ControlProviderIdentityApprovalError("signature_invalid")
    registry_projection = _project_registry(request, approval)
    identity_projection = _project_identity_report(request)
    return {
        "verification": {
            "schema_version": "chronosaudit.control_provider_identity_approval_verification.v1",
            "decision": "PROVIDER_IDENTITY_APPROVAL_VERIFIED",
            "request_sha256": request["request_sha256"],
            "approval_sha256": _sha(approval_file),
            "signature_sha256": _sha(signature_file),
            "allowed_signers_sha256": _sha(allowed_file),
            "signature_namespace": _SIGNATURE_NAMESPACE,
            "reviewer_principal": principal,
            "review_expires_utc": approval["review_expires_utc"],
            "provider_count": request["provider_count"],
            "operator_families": request["operator_families"],
            "registry_projection_authorized": True,
            "identity_report_projection_authorized": True,
            "acquisition_authorized": False,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
            "identity_binding_limit": (
                "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_REVIEWER_IDENTITY"
            ),
            "archive_capability_limit": "NOT_ASSESSED_BY_IDENTITY_REVIEW",
        },
        "provider_registry_projection": registry_projection,
        "provider_identity_verification": identity_projection,
    }
