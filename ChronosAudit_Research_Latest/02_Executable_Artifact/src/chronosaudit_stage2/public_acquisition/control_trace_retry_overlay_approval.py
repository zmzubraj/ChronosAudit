from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path


class ControlTraceRetryOverlayApprovalError(ValueError):
    """Raised when the exact written-spec approval cannot be reconstructed."""


APPROVAL_PREFIX = "APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: "
APPROVED_SPEC_SHA256 = (
    "ddc8d91165640469f3d7d5abb883c32d4ed4ac6f717e69150c8eb6c7671e5877"
)
SCHEMA_VERSION = "chronosaudit.control_trace_retry_overlay_spec_approval.v1"
DECISION = "APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256"

FALSE_DOWNSTREAM_AUTHORITY = {
    "rpc_authorized": False,
    "denominator_admission_authorized": False,
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
        raise ControlTraceRetryOverlayApprovalError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlTraceRetryOverlayApprovalError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlTraceRetryOverlayApprovalError(f"{label}_not_ordinary_file")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlTraceRetryOverlayApprovalError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlTraceRetryOverlayApprovalError(f"{label}_root_invalid")
    return payload


def _approved_digest(approval_text: str) -> str:
    if not approval_text.startswith(APPROVAL_PREFIX):
        raise ControlTraceRetryOverlayApprovalError("approval_text_invalid")
    supplied = approval_text[len(APPROVAL_PREFIX) :]
    if supplied != APPROVED_SPEC_SHA256:
        raise ControlTraceRetryOverlayApprovalError("approval_digest_invalid")
    return supplied


def build_trace_retry_overlay_spec_approval(
    *,
    specification_path: Path,
    approval_text: str,
    approved_by_principal: str,
    approved_at_date: str,
    approval_source: str,
) -> dict[str, object]:
    specification = _ordinary(specification_path, "specification")
    supplied = _approved_digest(approval_text)
    if _file_sha(specification) != supplied:
        raise ControlTraceRetryOverlayApprovalError(
            "approved_specification_mismatch"
        )
    if approved_by_principal != "zmzubraj":
        raise ControlTraceRetryOverlayApprovalError("approved_by_principal_invalid")
    if approved_at_date != "2026-08-25":
        raise ControlTraceRetryOverlayApprovalError("approved_at_date_invalid")
    if approval_source != "CODEX_CHAT_EXACT_USER_TOKEN":
        raise ControlTraceRetryOverlayApprovalError("approval_source_invalid")

    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "decision": DECISION,
        "approval_text": approval_text,
        "approved_by_principal": approved_by_principal,
        "approved_at_date": approved_at_date,
        "approval_source": approval_source,
        "specification_path": str(specification_path),
        "specification_file_sha256": supplied,
        "implementation_authorized": True,
        **FALSE_DOWNSTREAM_AUTHORITY,
    }
    record["record_sha256"] = _canonical_sha(record)
    return record


def verify_trace_retry_overlay_spec_approval(
    *, approval_path: Path, specification_path: Path
) -> dict[str, object]:
    record = _load(approval_path, "approval")
    if record.get("schema_version") != SCHEMA_VERSION:
        raise ControlTraceRetryOverlayApprovalError("approval_schema_invalid")
    supplied_hash = record.get("record_sha256")
    material = {key: value for key, value in record.items() if key != "record_sha256"}
    if supplied_hash != _canonical_sha(material):
        raise ControlTraceRetryOverlayApprovalError("approval_self_hash_invalid")
    if record.get("implementation_authorized") is not True:
        raise ControlTraceRetryOverlayApprovalError(
            "implementation_authorized_invalid"
        )
    for field in FALSE_DOWNSTREAM_AUTHORITY:
        if record.get(field) is not False:
            raise ControlTraceRetryOverlayApprovalError(f"{field}_invalid")

    rebuilt = build_trace_retry_overlay_spec_approval(
        specification_path=specification_path,
        approval_text=str(record.get("approval_text", "")),
        approved_by_principal=str(record.get("approved_by_principal", "")),
        approved_at_date=str(record.get("approved_at_date", "")),
        approval_source=str(record.get("approval_source", "")),
    )
    if not isinstance(record, Mapping) or record != rebuilt:
        raise ControlTraceRetryOverlayApprovalError(
            "approval_reconstruction_mismatch"
        )
    report: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_trace_retry_overlay_spec_approval_verification.v1"
        ),
        "decision": "TRACE_RETRY_OVERLAY_SPEC_APPROVAL_VERIFIED",
        "verified": True,
        "approval_file_sha256": _file_sha(_ordinary(approval_path, "approval")),
        "approval_record_sha256": supplied_hash,
        "specification_file_sha256": APPROVED_SPEC_SHA256,
        "implementation_authorized": True,
        **FALSE_DOWNSTREAM_AUTHORITY,
    }
    report["verification_sha256"] = _canonical_sha(report)
    return report
