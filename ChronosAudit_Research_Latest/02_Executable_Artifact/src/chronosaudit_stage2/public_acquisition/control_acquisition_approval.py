from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping

import pandas as pd


class ControlAcquisitionApprovalError(ValueError):
    """Raised when acquisition authority is missing, stale, or malformed."""


_SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-source-acquisition-v2"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_signed_payload(approval: Mapping[str, object]) -> bytes:
    """Return the exact bytes covered by the detached OpenSSH signature."""
    return (_canonical_json(dict(approval)) + "\n").encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlAcquisitionApprovalError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlAcquisitionApprovalError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlAcquisitionApprovalError(f"{label}_not_ordinary_file")
    return resolved


def _load_object(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlAcquisitionApprovalError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlAcquisitionApprovalError(f"{label}_root_invalid")
    return payload


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _bool(value: object, label: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    raise ControlAcquisitionApprovalError(f"{label}_invalid")


def _time(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlAcquisitionApprovalError(f"{label}_invalid")
    canonical = parsed.isoformat().replace("+00:00", "Z")
    if str(value) != canonical:
        raise ControlAcquisitionApprovalError(f"{label}_not_canonical")
    return parsed


def _request_sha256(request: Mapping[str, object]) -> str:
    return _canonical_sha256(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def build_control_acquisition_approval_request(
    *,
    chunk_plan_path: Path,
    chunk_manifest_path: Path,
    query_plan_sha256: str | None,
    source_object_count: int | None,
    maximum_download_bytes: int | None,
) -> dict[str, object]:
    """Bind source-download authority to an exact non-authorizing query plan."""
    chunk_plan_path = _ordinary_file(chunk_plan_path, "chunk_plan")
    chunk_manifest_path = _ordinary_file(chunk_manifest_path, "chunk_manifest")
    manifest = _load_object(chunk_manifest_path, "chunk_manifest")
    if manifest.get("schema_version") != (
        "chronosaudit.control_denominator_expansion_chunk_plan.v1"
    ):
        raise ControlAcquisitionApprovalError("chunk_manifest_schema_invalid")
    if manifest.get("decision") != (
        "BOUNDED_EXPANSION_PLAN_AWAITS_ACCOUNTABLE_ACQUISITION_APPROVAL"
    ):
        raise ControlAcquisitionApprovalError("chunk_manifest_decision_invalid")
    for field in (
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
    ):
        if manifest.get(field) is not False:
            raise ControlAcquisitionApprovalError(f"chunk_manifest_{field}_invalid")
    if int(manifest.get("case_overlap_count") or 0) != 0:
        raise ControlAcquisitionApprovalError("chunk_manifest_case_overlap")
    if int(manifest.get("requirement_overlap_count") or 0) != 0:
        raise ControlAcquisitionApprovalError("chunk_manifest_requirement_overlap")
    manifest_output = manifest.get("output")
    if not isinstance(manifest_output, Mapping):
        raise ControlAcquisitionApprovalError("chunk_manifest_output_invalid")
    plan_sha256 = _sha256_file(chunk_plan_path)
    if str(manifest_output.get("sha256") or "").lower() != plan_sha256:
        raise ControlAcquisitionApprovalError("chunk_plan_sha256_mismatch")

    plan = pd.read_csv(
        chunk_plan_path, dtype=str, keep_default_na=False, low_memory=False
    )
    required_columns = {
        "chunk_id",
        "chunk_sequence",
        "case_name",
        "chain",
        "minimum_additional_distinct_slots",
        "expansion_requirement_sha256",
        "chunk_scope_sha256",
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
    }
    missing = sorted(required_columns - set(plan.columns))
    if missing:
        raise ControlAcquisitionApprovalError(
            f"chunk_plan_missing_columns:{','.join(missing)}"
        )
    if plan.empty:
        raise ControlAcquisitionApprovalError("chunk_plan_empty")
    if plan["case_name"].duplicated().any():
        raise ControlAcquisitionApprovalError("chunk_plan_case_overlap")
    if plan["expansion_requirement_sha256"].duplicated().any():
        raise ControlAcquisitionApprovalError("chunk_plan_requirement_overlap")
    if not plan["expansion_requirement_sha256"].map(_is_sha256).all():
        raise ControlAcquisitionApprovalError("chunk_plan_requirement_hash_invalid")
    for field in (
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
    ):
        if plan[field].map(lambda value: _bool(value, field)).any():
            raise ControlAcquisitionApprovalError(f"chunk_plan_{field}_invalid")
    deficits = pd.to_numeric(
        plan["minimum_additional_distinct_slots"], errors="coerce"
    )
    if deficits.isna().any() or deficits.le(0).any():
        raise ControlAcquisitionApprovalError("chunk_plan_deficit_invalid")
    chunk_rows = (
        plan[["chunk_sequence", "chunk_id", "chunk_scope_sha256"]]
        .drop_duplicates()
        .sort_values("chunk_sequence", key=lambda series: pd.to_numeric(series))
    )
    if chunk_rows["chunk_id"].duplicated().any():
        raise ControlAcquisitionApprovalError("chunk_plan_chunk_id_duplicate")
    if not chunk_rows["chunk_scope_sha256"].map(_is_sha256).all():
        raise ControlAcquisitionApprovalError("chunk_scope_hash_invalid")
    chunk_summaries = manifest.get("chunks")
    if not isinstance(chunk_summaries, list):
        raise ControlAcquisitionApprovalError("chunk_manifest_chunks_invalid")
    expected_chunks = [
        {
            "chunk_id": str(row.chunk_id),
            "chunk_scope_sha256": str(row.chunk_scope_sha256).lower(),
        }
        for row in chunk_rows.itertuples(index=False)
    ]
    observed_chunks = [
        {
            "chunk_id": str(row.get("chunk_id") or ""),
            "chunk_scope_sha256": str(row.get("chunk_scope_sha256") or "").lower(),
        }
        for row in chunk_summaries
        if isinstance(row, Mapping)
    ]
    if expected_chunks != observed_chunks:
        raise ControlAcquisitionApprovalError("chunk_manifest_scope_mismatch")
    if int(manifest.get("chunk_count") or -1) != len(expected_chunks):
        raise ControlAcquisitionApprovalError("chunk_manifest_count_mismatch")
    if int(manifest.get("cases_requiring_expansion") or -1) != len(plan):
        raise ControlAcquisitionApprovalError("chunk_manifest_case_count_mismatch")
    total_deficit = int(deficits.sum())
    if int(manifest.get("minimum_additional_distinct_slots") or -1) != total_deficit:
        raise ControlAcquisitionApprovalError("chunk_manifest_deficit_mismatch")

    inputs = manifest.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ControlAcquisitionApprovalError("chunk_manifest_inputs_invalid")
    frozen_inputs: dict[str, str] = {}
    for field in (
        "authority_projection_sha256",
        "expansion_ledger_sha256",
        "pair_scope_manifest_sha256",
        "policy_sha256",
    ):
        value = str(inputs.get(field) or "").strip().lower()
        if not _is_sha256(value):
            raise ControlAcquisitionApprovalError(f"chunk_manifest_{field}_invalid")
        frozen_inputs[field] = value
    query_hash = (
        None if query_plan_sha256 is None else str(query_plan_sha256).strip().lower()
    )
    if query_hash is not None and not _is_sha256(query_hash):
        raise ControlAcquisitionApprovalError("query_plan_sha256_invalid")
    if query_hash is None:
        if source_object_count is not None or maximum_download_bytes is not None:
            raise ControlAcquisitionApprovalError("source_scope_without_query_plan")
        frozen_source_object_count = None
        frozen_maximum_download_bytes = None
    else:
        try:
            frozen_source_object_count = int(source_object_count or 0)
            frozen_maximum_download_bytes = int(maximum_download_bytes or 0)
        except (TypeError, ValueError) as exc:
            raise ControlAcquisitionApprovalError("source_scope_invalid") from exc
        if frozen_source_object_count <= 0 or frozen_maximum_download_bytes <= 0:
            raise ControlAcquisitionApprovalError("source_scope_invalid")
    request: dict[str, object] = {
        "schema_version": "chronosaudit.control_source_acquisition_approval_request.v2",
        "decision": (
            "AWAITING_ACCOUNTABLE_SIGNED_APPROVAL"
            if query_hash is not None
            else "AWAITING_FROZEN_QUERY_PLAN"
        ),
        "purpose": "HISTORICAL_DENOMINATOR_EXPANSION_ONLY",
        "chunk_plan_sha256": plan_sha256,
        "chunk_plan_manifest_sha256": _sha256_file(chunk_manifest_path),
        "plan_no_repeat_sha256": str(
            manifest.get("plan_no_repeat_sha256") or ""
        ).lower(),
        **frozen_inputs,
        "query_plan_sha256": query_hash,
        "source_object_count": frozen_source_object_count,
        "maximum_download_bytes": frozen_maximum_download_bytes,
        "chunk_count": len(expected_chunks),
        "case_count": len(plan),
        "minimum_additional_distinct_slots": total_deficit,
        "chunk_ids": [row["chunk_id"] for row in expected_chunks],
        "chunk_scope_sha256s": [
            row["chunk_scope_sha256"] for row in expected_chunks
        ],
        "chains": sorted(set(plan["chain"].astype(str).str.lower())),
        "raw_receipts_required": True,
        "accepted_import_ledger_required": True,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    if not _is_sha256(request["plan_no_repeat_sha256"]):
        raise ControlAcquisitionApprovalError("plan_no_repeat_sha256_invalid")
    request["request_sha256"] = _request_sha256(request)
    return request


def build_control_acquisition_approval(
    *,
    request: Mapping[str, object],
    signer_principal: str,
    approval_start_utc: str,
    approval_expires_utc: str,
) -> dict[str, object]:
    """Build the exact source-only payload an accountable owner may sign."""
    if request.get("schema_version") != (
        "chronosaudit.control_source_acquisition_approval_request.v2"
    ):
        raise ControlAcquisitionApprovalError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_SIGNED_APPROVAL":
        raise ControlAcquisitionApprovalError("request_not_approvable")
    if str(request.get("request_sha256") or "").lower() != _request_sha256(request):
        raise ControlAcquisitionApprovalError("request_sha256_invalid")
    if request.get("purpose") != "HISTORICAL_DENOMINATOR_EXPANSION_ONLY":
        raise ControlAcquisitionApprovalError("request_purpose_invalid")
    for field in (
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if request.get(field) is not False:
            raise ControlAcquisitionApprovalError(f"request_{field}_invalid")
    principal = str(signer_principal or "").strip()
    if not principal:
        raise ControlAcquisitionApprovalError("signer_principal_invalid")
    start = _time(approval_start_utc, "approval_start_utc")
    expiry = _time(approval_expires_utc, "approval_expires_utc")
    if expiry <= start:
        raise ControlAcquisitionApprovalError("approval_window_invalid")
    query_plan_sha256 = str(request.get("query_plan_sha256") or "").lower()
    if not _is_sha256(query_plan_sha256):
        raise ControlAcquisitionApprovalError("request_query_plan_invalid")
    approved_scopes = request.get("chunk_scope_sha256s")
    if not isinstance(approved_scopes, list) or not approved_scopes:
        raise ControlAcquisitionApprovalError("request_chunk_scope_invalid")
    if not all(_is_sha256(value) for value in approved_scopes):
        raise ControlAcquisitionApprovalError("request_chunk_scope_invalid")
    chains = request.get("chains")
    if not isinstance(chains, list) or not chains:
        raise ControlAcquisitionApprovalError("request_chain_scope_invalid")
    try:
        source_object_count = int(request.get("source_object_count") or 0)
        maximum_download_bytes = int(request.get("maximum_download_bytes") or 0)
    except (TypeError, ValueError) as exc:
        raise ControlAcquisitionApprovalError("request_source_scope_invalid") from exc
    if source_object_count <= 0 or maximum_download_bytes <= 0:
        raise ControlAcquisitionApprovalError("request_source_scope_invalid")
    return {
        "schema_version": "chronosaudit.control_source_acquisition_approval.v2",
        "request_sha256": request["request_sha256"],
        "signer_principal": principal,
        "decision": "APPROVE_HISTORICAL_DENOMINATOR_SOURCE_ACQUISITION",
        "purpose": "HISTORICAL_DENOMINATOR_EXPANSION_ONLY",
        "approval_start_utc": approval_start_utc,
        "approval_expires_utc": approval_expires_utc,
        "query_plan_sha256": query_plan_sha256,
        "approved_chunk_scope_sha256s": list(approved_scopes),
        "chain_allowlist": list(chains),
        "source_object_count": source_object_count,
        "maximum_download_bytes": maximum_download_bytes,
        "raw_receipts_required": True,
        "accepted_import_ledger_required": True,
        "acquisition_authorized": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def verify_control_acquisition_approval(
    *,
    request: Mapping[str, object],
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    """Verify source acquisition only; this contract can never authorize RPC."""
    if request.get("schema_version") != (
        "chronosaudit.control_source_acquisition_approval_request.v2"
    ):
        raise ControlAcquisitionApprovalError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_SIGNED_APPROVAL":
        raise ControlAcquisitionApprovalError("request_not_approvable")
    if str(request.get("request_sha256") or "").lower() != _request_sha256(request):
        raise ControlAcquisitionApprovalError("request_sha256_invalid")
    approval_path = _ordinary_file(approval_path, "approval")
    signature_path = _ordinary_file(signature_path, "signature")
    allowed_signers_path = _ordinary_file(allowed_signers_path, "allowed_signers")
    approval = _load_object(approval_path, "approval")
    if approval.get("schema_version") != (
        "chronosaudit.control_source_acquisition_approval.v2"
    ):
        raise ControlAcquisitionApprovalError("approval_schema_invalid")
    principal = str(approval.get("signer_principal") or "").strip()
    if not expected_principal or principal != expected_principal:
        raise ControlAcquisitionApprovalError("signer_principal_mismatch")
    if str(approval.get("request_sha256") or "").lower() != request["request_sha256"]:
        raise ControlAcquisitionApprovalError("approval_request_mismatch")
    if approval.get("decision") != (
        "APPROVE_HISTORICAL_DENOMINATOR_SOURCE_ACQUISITION"
    ):
        raise ControlAcquisitionApprovalError("approval_decision_invalid")
    if approval.get("purpose") != "HISTORICAL_DENOMINATOR_EXPANSION_ONLY":
        raise ControlAcquisitionApprovalError("approval_purpose_invalid")
    if str(approval.get("query_plan_sha256") or "").lower() != request[
        "query_plan_sha256"
    ]:
        raise ControlAcquisitionApprovalError("approval_query_plan_mismatch")
    approved_scopes = approval.get("approved_chunk_scope_sha256s")
    if approved_scopes != request["chunk_scope_sha256s"]:
        raise ControlAcquisitionApprovalError("approval_chunk_scope_mismatch")
    if approval.get("chain_allowlist") != request["chains"]:
        raise ControlAcquisitionApprovalError("approval_chain_scope_mismatch")
    try:
        source_object_count = int(approval.get("source_object_count") or 0)
        maximum_download_bytes = int(approval.get("maximum_download_bytes") or 0)
    except (TypeError, ValueError) as exc:
        raise ControlAcquisitionApprovalError("approval_source_scope_invalid") from exc
    if source_object_count != request["source_object_count"]:
        raise ControlAcquisitionApprovalError("approval_source_object_count_mismatch")
    if maximum_download_bytes != request["maximum_download_bytes"]:
        raise ControlAcquisitionApprovalError("approval_download_ceiling_mismatch")
    for field, expected in (
        ("raw_receipts_required", True),
        ("accepted_import_ledger_required", True),
        ("acquisition_authorized", True),
        ("rpc_authorized", False),
        ("selection_authorized", False),
        ("stage_promotion_authorized", False),
        ("recovery3_mutation_authorized", False),
    ):
        if approval.get(field) is not expected:
            raise ControlAcquisitionApprovalError(f"approval_{field}_invalid")
    start = _time(approval.get("approval_start_utc"), "approval_start_utc")
    expiry = _time(approval.get("approval_expires_utc"), "approval_expires_utc")
    verification_time = _time(verification_time_utc, "verification_time_utc")
    if expiry <= start:
        raise ControlAcquisitionApprovalError("approval_window_invalid")
    if verification_time < start:
        raise ControlAcquisitionApprovalError("approval_not_yet_valid")
    if verification_time > expiry:
        raise ControlAcquisitionApprovalError("approval_expired")

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
        raise ControlAcquisitionApprovalError("signature_invalid")
    return {
        "schema_version": (
            "chronosaudit.control_source_acquisition_approval_verification.v2"
        ),
        "decision": "SOURCE_ACQUISITION_APPROVAL_VERIFIED",
        "request_sha256": request["request_sha256"],
        "approval_sha256": _sha256_file(approval_path),
        "signature_sha256": _sha256_file(signature_path),
        "allowed_signers_sha256": _sha256_file(allowed_signers_path),
        "signature_namespace": _SIGNATURE_NAMESPACE,
        "signer_principal": principal,
        "approved_chunk_count": len(approved_scopes),
        "source_object_count": source_object_count,
        "maximum_download_bytes": maximum_download_bytes,
        "approval_expires_utc": approval["approval_expires_utc"],
        "raw_receipts_required": True,
        "accepted_import_ledger_required": True,
        "acquisition_authorized": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
    }
