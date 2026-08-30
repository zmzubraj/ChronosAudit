from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping

import pandas as pd

from .control_qualification_evidence import (
    CONTROL_QUALIFICATION_GATES,
    verify_control_qualification_evidence_batch,
)
from .qualification import (
    FROZEN_CENSORING_STATUS,
    INDEPENDENT_OUTCOME_REVIEW_COMPLETE,
    MATURE_INVESTIGATED_NEGATIVE_STATUS,
    make_control_row_sha256,
    qualify_control_rows,
    verify_control_cohort_structure,
)


class ControlQualificationApprovalError(ValueError):
    """Raised when signed control qualification authority is invalid."""


_SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-qualification-v1"
_REQUEST_SCHEMA = "chronosaudit.control_qualification_approval_request.v1"
_APPROVAL_SCHEMA = "chronosaudit.control_qualification_approval.v1"
_DISALLOWED_HUMAN_IDENTITIES = {"", "AI", "PUBLIC", "PUBLIC_LABEL", "SAME_OWNER"}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_signed_payload(approval: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(approval)) + "\n").encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _ordinary_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlQualificationApprovalError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlQualificationApprovalError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlQualificationApprovalError(f"{label}_not_ordinary_file")
    return resolved


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlQualificationApprovalError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlQualificationApprovalError(f"{label}_root_invalid")
    return payload


def _read_csv(path: Path, label: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path, keep_default_na=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        raise ControlQualificationApprovalError(f"{label}_csv_invalid") from exc


def _canonical_time(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlQualificationApprovalError(f"{label}_invalid")
    if str(value) != parsed.isoformat().replace("+00:00", "Z"):
        raise ControlQualificationApprovalError(f"{label}_not_canonical")
    return parsed


def _request_sha256(request: Mapping[str, object]) -> str:
    return _canonical_sha256(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def _candidate_identity(row: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        str(row.get("case_name") or "").strip(),
        str(row.get("chain") or "").strip().lower(),
        str(row.get("contract_address") or "").strip().lower(),
    )


def _normalized_projection_records(frame: pd.DataFrame) -> list[dict[str, object]]:
    ordered = frame.sort_values(
        ["case_name", "control_rank", "chain", "contract_address"], kind="stable"
    )
    return json.loads(ordered.to_json(orient="records", date_format="iso"))


def _validated_inputs(
    *,
    candidate_rows_path: Path,
    check_rows_path: Path,
    positive_cases_path: Path,
    evidence_root: Path,
    expected_positive_rows: int,
    controls_per_positive: int,
) -> tuple[pd.DataFrame, pd.DataFrame, list[str], dict[str, object]]:
    candidate_file = _ordinary_file(candidate_rows_path, "candidate_rows")
    check_file = _ordinary_file(check_rows_path, "check_rows")
    positive_file = _ordinary_file(positive_cases_path, "positive_cases")
    candidates = _read_csv(candidate_file, "candidate_rows")
    checks = _read_csv(check_file, "check_rows")
    positives = _read_csv(positive_file, "positive_cases")
    if "case_name" not in positives.columns:
        raise ControlQualificationApprovalError("positive_cases_missing_case_name")
    case_names = positives["case_name"].astype(str).tolist()
    if (
        len(case_names) != expected_positive_rows
        or len(set(case_names)) != expected_positive_rows
        or any(not value.strip() for value in case_names)
    ):
        raise ControlQualificationApprovalError("positive_case_scope_invalid")
    try:
        revalidated = qualify_control_rows(candidates)
    except ValueError as exc:
        raise ControlQualificationApprovalError("candidate_rows_revalidation_failed") from exc
    if not revalidated["candidate_row_valid"].map(bool).all():
        raise ControlQualificationApprovalError("candidate_rows_revalidation_failed")
    structure = verify_control_cohort_structure(
        revalidated,
        valid_column="candidate_row_valid",
        expected_case_names=case_names,
        controls_per_positive=controls_per_positive,
    )
    if not structure.get("passed"):
        blockers = ",".join(str(item) for item in structure.get("cohort_blockers", []))
        raise ControlQualificationApprovalError(f"candidate_cohort_invalid:{blockers}")
    try:
        evidence_report = verify_control_qualification_evidence_batch(
            candidate_rows=revalidated,
            check_rows=checks,
            evidence_root=evidence_root,
        )
    except ValueError as exc:
        raise ControlQualificationApprovalError("qualification_evidence_invalid") from exc
    if evidence_report.get("decision") != "QUALIFICATION_EVIDENCE_VERIFIED_NON_AUTHORIZING":
        raise ControlQualificationApprovalError("qualification_evidence_not_verified")

    horizon_by_identity = {
        _candidate_identity(row): _canonical_time(row.get("follow_up_horizon"), "follow_up_horizon")
        for row in revalidated.to_dict("records")
    }
    for row in checks.to_dict("records"):
        gate = str(row.get("gate") or "").strip().lower()
        if gate not in {"maturity", "censoring", "mechanism_separation"}:
            continue
        identity = _candidate_identity(row)
        reviewed = _canonical_time(row.get("reviewed_at_utc"), "reviewed_at_utc")
        if identity not in horizon_by_identity or reviewed < horizon_by_identity[identity]:
            raise ControlQualificationApprovalError("outcome_review_before_follow_up_horizon")
        reviewer = str(row.get("reviewer_identity") or "").strip()
        owner = str(row.get("reviewer_owner") or "").strip()
        if reviewer.upper() in _DISALLOWED_HUMAN_IDENTITIES or owner.upper() in _DISALLOWED_HUMAN_IDENTITIES:
            raise ControlQualificationApprovalError("outcome_reviewer_identity_invalid")
    return revalidated, checks, case_names, evidence_report


def build_control_qualification_approval_request(
    *,
    candidate_rows_path: Path,
    check_rows_path: Path,
    positive_cases_path: Path,
    evidence_root: Path,
    expected_positive_rows: int = 417,
    controls_per_positive: int = 10,
) -> dict[str, object]:
    """Build the exact non-authorizing request for accountable qualification."""
    if expected_positive_rows <= 0 or controls_per_positive <= 0:
        raise ControlQualificationApprovalError("cohort_target_invalid")
    candidate_file = _ordinary_file(candidate_rows_path, "candidate_rows")
    check_file = _ordinary_file(check_rows_path, "check_rows")
    positive_file = _ordinary_file(positive_cases_path, "positive_cases")
    candidates, checks, case_names, evidence_report = _validated_inputs(
        candidate_rows_path=candidate_file,
        check_rows_path=check_file,
        positive_cases_path=positive_file,
        evidence_root=evidence_root,
        expected_positive_rows=expected_positive_rows,
        controls_per_positive=controls_per_positive,
    )
    human_checks = checks.loc[
        checks["gate"].astype(str).str.lower().isin(
            {"maturity", "censoring", "mechanism_separation"}
        )
    ]
    reviewer_identities = sorted(
        set(human_checks["reviewer_identity"].astype(str).str.strip())
    )
    reviewer_owners = sorted(set(human_checks["reviewer_owner"].astype(str).str.strip()))
    request: dict[str, object] = {
        "schema_version": _REQUEST_SCHEMA,
        "decision": "AWAITING_ACCOUNTABLE_CONTROL_QUALIFICATION_SIGNATURE",
        "purpose": "CONTROL_QUALIFICATION_PROJECTION_AND_COUNTER_AUTHORITY_ONLY",
        "candidate_rows_sha256": _sha256_file(candidate_file),
        "check_rows_sha256": _sha256_file(check_file),
        "positive_cases_sha256": _sha256_file(positive_file),
        "candidate_binding_sha256": evidence_report["candidate_binding_sha256"],
        "verified_check_records_sha256": evidence_report[
            "verified_check_records_sha256"
        ],
        "positive_case_scope_sha256": _canonical_sha256(sorted(case_names)),
        "candidate_rows": len(candidates),
        "check_rows": len(checks),
        "positive_rows": len(case_names),
        "controls_per_positive": controls_per_positive,
        "required_gates": list(CONTROL_QUALIFICATION_GATES),
        "human_reviewer_identities": reviewer_identities,
        "human_reviewer_owners": reviewer_owners,
        "human_reviewer_binding_sha256": _canonical_sha256(
            {
                "identities": reviewer_identities,
                "owners": reviewer_owners,
            }
        ),
        "required_qualification_attestation": (
            "ALL_BOUND_CONTROL_CHECKS_REVIEWED_AND_APPROVED"
        ),
        "required_counter_attestation": (
            "EXACT_COHORT_AUTHORIZED_FOR_QUALIFIED_CONTROL_COUNTER"
        ),
        "qualification_projection_authorized": False,
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    request["request_sha256"] = _request_sha256(request)
    return request


def _validate_request(request: Mapping[str, object]) -> None:
    if request.get("schema_version") != _REQUEST_SCHEMA:
        raise ControlQualificationApprovalError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_CONTROL_QUALIFICATION_SIGNATURE":
        raise ControlQualificationApprovalError("request_not_approvable")
    if request.get("request_sha256") != _request_sha256(request):
        raise ControlQualificationApprovalError("request_sha256_invalid")
    for field in (
        "qualification_projection_authorized",
        "counter_authority",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if request.get(field) is not False:
            raise ControlQualificationApprovalError(f"request_{field}_invalid")


def build_control_qualification_approval(
    *,
    request: Mapping[str, object],
    authority_principal: str,
    authority_type: str = "LOCAL_TEST_MECHANICAL",
    authority_identity_binding_sha256: str = "",
    approval_start_utc: str,
    approval_expires_utc: str,
) -> dict[str, object]:
    """Build the exact unsigned approval an accountable authority may sign."""
    _validate_request(request)
    principal = authority_principal.strip()
    if not principal:
        raise ControlQualificationApprovalError("authority_principal_invalid")
    participants = {
        str(value).strip()
        for field in ("human_reviewer_identities", "human_reviewer_owners")
        for value in request.get(field, [])
    }
    if principal in participants:
        raise ControlQualificationApprovalError("authority_principal_not_independent")
    normalized_authority_type = authority_type.strip().upper()
    if normalized_authority_type not in {
        "ACCOUNTABLE_HUMAN", "LOCAL_TEST_MECHANICAL"
    }:
        raise ControlQualificationApprovalError("authority_type_invalid")
    identity_binding = authority_identity_binding_sha256.strip().lower()
    if normalized_authority_type == "ACCOUNTABLE_HUMAN" and not _is_sha256(
        identity_binding
    ):
        raise ControlQualificationApprovalError("authority_identity_binding_required")
    if normalized_authority_type == "LOCAL_TEST_MECHANICAL" and identity_binding:
        raise ControlQualificationApprovalError("local_test_identity_binding_forbidden")
    authorizing = normalized_authority_type == "ACCOUNTABLE_HUMAN"
    start = _canonical_time(approval_start_utc, "approval_start_utc")
    expiry = _canonical_time(approval_expires_utc, "approval_expires_utc")
    if expiry <= start:
        raise ControlQualificationApprovalError("approval_window_invalid")
    return {
        "schema_version": _APPROVAL_SCHEMA,
        "request_sha256": request["request_sha256"],
        "authority_principal": principal,
        "authority_type": normalized_authority_type,
        "authority_identity_binding_sha256": identity_binding,
        "decision": "APPROVE_BOUND_CONTROL_QUALIFICATION",
        "purpose": request["purpose"],
        "approval_start_utc": approval_start_utc,
        "approval_expires_utc": approval_expires_utc,
        "candidate_rows_sha256": request["candidate_rows_sha256"],
        "check_rows_sha256": request["check_rows_sha256"],
        "positive_cases_sha256": request["positive_cases_sha256"],
        "candidate_binding_sha256": request["candidate_binding_sha256"],
        "verified_check_records_sha256": request["verified_check_records_sha256"],
        "positive_case_scope_sha256": request["positive_case_scope_sha256"],
        "candidate_rows": request["candidate_rows"],
        "check_rows": request["check_rows"],
        "positive_rows": request["positive_rows"],
        "controls_per_positive": request["controls_per_positive"],
        "required_gates": request["required_gates"],
        "human_reviewer_binding_sha256": request["human_reviewer_binding_sha256"],
        "qualification_attestation": request["required_qualification_attestation"],
        "counter_attestation": request["required_counter_attestation"],
        "qualification_projection_authorized": authorizing,
        "counter_authority": authorizing,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def _qualified_projection(
    *,
    candidates: pd.DataFrame,
    checks: pd.DataFrame,
    request: Mapping[str, object],
    approval: Mapping[str, object],
    approval_sha256: str,
    signature_sha256: str,
    allowed_signers_sha256: str,
) -> pd.DataFrame:
    checks_by_identity_gate = {
        (*_candidate_identity(row), str(row.get("gate") or "").strip().lower()): row
        for row in checks.to_dict("records")
    }
    projected: list[dict[str, object]] = []
    for raw in candidates.to_dict("records"):
        row = dict(raw)
        identity = _candidate_identity(row)
        selected_sha = str(row["control_row_sha256"]).strip().lower()
        gate_rows = {
            gate: checks_by_identity_gate[(*identity, gate)]
            for gate in CONTROL_QUALIFICATION_GATES
        }
        row["selected_candidate_control_row_sha256"] = selected_sha
        for gate, check in gate_rows.items():
            row[f"{gate}_check_passed"] = True
            row[f"{gate}_check_sha256"] = str(
                check["evidence_record_sha256"]
            ).strip().lower()
        mechanism = gate_rows["mechanism_separation"]
        row["mechanism_separation_free"] = True
        row["censoring_status"] = FROZEN_CENSORING_STATUS
        row["investigated_negative_status"] = MATURE_INVESTIGATED_NEGATIVE_STATUS
        row["independent_outcome_review_status"] = INDEPENDENT_OUTCOME_REVIEW_COMPLETE
        row["independent_outcome_reviewer_identity"] = str(
            mechanism["reviewer_identity"]
        ).strip()
        row["independent_outcome_reviewer_owner"] = str(
            mechanism["reviewer_owner"]
        ).strip()
        row["independent_outcome_reviewer_conflict_clear"] = True
        row["independent_outcome_reviewer_confidence"] = str(
            mechanism["reviewer_confidence"]
        ).strip().lower()
        row["independent_outcome_decision_sha256"] = str(
            mechanism["evidence_record_sha256"]
        ).strip().lower()
        row["qualification_authority_verified"] = bool(
            approval["qualification_projection_authorized"]
        )
        row["qualification_request_sha256"] = request["request_sha256"]
        row["qualification_approval_sha256"] = approval_sha256
        row["qualification_signature_sha256"] = signature_sha256
        row["qualification_allowed_signers_sha256"] = allowed_signers_sha256
        row["qualification_authority_principal"] = approval["authority_principal"]
        row["qualification_evidence_batch_sha256"] = request[
            "verified_check_records_sha256"
        ]
        row["candidate_status"] = "QUALIFIED_CONTROL"
        row["control_row_sha256"] = make_control_row_sha256(row)
        projected.append(row)
    revalidated = qualify_control_rows(pd.DataFrame(projected))
    if not revalidated["qualified_control"].map(bool).all():
        raise ControlQualificationApprovalError("qualified_projection_revalidation_failed")
    structure = verify_control_cohort_structure(
        revalidated,
        valid_column="qualified_control",
        expected_case_names=sorted(revalidated["case_name"].astype(str).unique()),
        controls_per_positive=int(request["controls_per_positive"]),
    )
    if not structure.get("passed") or len(revalidated) != int(request["candidate_rows"]):
        raise ControlQualificationApprovalError("qualified_projection_cohort_invalid")
    return revalidated


def verify_control_qualification_approval(
    *,
    request: Mapping[str, object],
    candidate_rows_path: Path,
    check_rows_path: Path,
    positive_cases_path: Path,
    evidence_root: Path,
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
    expected_positive_rows: int = 417,
    controls_per_positive: int = 10,
) -> dict[str, object]:
    """Verify accountable authority and emit a counter-authorized projection."""
    _validate_request(request)
    rebuilt = build_control_qualification_approval_request(
        candidate_rows_path=candidate_rows_path,
        check_rows_path=check_rows_path,
        positive_cases_path=positive_cases_path,
        evidence_root=evidence_root,
        expected_positive_rows=expected_positive_rows,
        controls_per_positive=controls_per_positive,
    )
    if rebuilt != dict(request):
        raise ControlQualificationApprovalError("request_input_rebuild_mismatch")
    approval_file = _ordinary_file(approval_path, "approval")
    signature_file = _ordinary_file(signature_path, "signature")
    allowed_file = _ordinary_file(allowed_signers_path, "allowed_signers")
    approval = _load_json_object(approval_file, "approval")
    if approval.get("schema_version") != _APPROVAL_SCHEMA:
        raise ControlQualificationApprovalError("approval_schema_invalid")
    principal = str(approval.get("authority_principal") or "").strip()
    if not expected_principal or principal != expected_principal:
        raise ControlQualificationApprovalError("authority_principal_mismatch")
    expected_fields = {
        "request_sha256": request["request_sha256"],
        "decision": "APPROVE_BOUND_CONTROL_QUALIFICATION",
        "purpose": request["purpose"],
        "candidate_rows_sha256": request["candidate_rows_sha256"],
        "check_rows_sha256": request["check_rows_sha256"],
        "positive_cases_sha256": request["positive_cases_sha256"],
        "candidate_binding_sha256": request["candidate_binding_sha256"],
        "verified_check_records_sha256": request["verified_check_records_sha256"],
        "positive_case_scope_sha256": request["positive_case_scope_sha256"],
        "candidate_rows": request["candidate_rows"],
        "check_rows": request["check_rows"],
        "positive_rows": request["positive_rows"],
        "controls_per_positive": request["controls_per_positive"],
        "required_gates": request["required_gates"],
        "human_reviewer_binding_sha256": request["human_reviewer_binding_sha256"],
        "qualification_attestation": request["required_qualification_attestation"],
        "counter_attestation": request["required_counter_attestation"],
    }
    for field, expected in expected_fields.items():
        if approval.get(field) != expected:
            raise ControlQualificationApprovalError(f"approval_{field}_mismatch")
    authority_type = str(approval.get("authority_type") or "").strip().upper()
    identity_binding = str(
        approval.get("authority_identity_binding_sha256") or ""
    ).strip().lower()
    if authority_type not in {"ACCOUNTABLE_HUMAN", "LOCAL_TEST_MECHANICAL"}:
        raise ControlQualificationApprovalError("approval_authority_type_invalid")
    authorizing = authority_type == "ACCOUNTABLE_HUMAN"
    if authorizing and not _is_sha256(identity_binding):
        raise ControlQualificationApprovalError(
            "approval_authority_identity_binding_invalid"
        )
    if not authorizing and identity_binding:
        raise ControlQualificationApprovalError(
            "approval_local_test_identity_binding_invalid"
        )
    for field, expected in (
        ("qualification_projection_authorized", authorizing),
        ("counter_authority", authorizing),
        ("selection_authorized", False),
        ("stage_promotion_authorized", False),
        ("recovery3_mutation_authorized", False),
    ):
        if approval.get(field) is not expected:
            raise ControlQualificationApprovalError(f"approval_{field}_invalid")
    participants = {
        str(value).strip()
        for field in ("human_reviewer_identities", "human_reviewer_owners")
        for value in request.get(field, [])
    }
    if principal in participants:
        raise ControlQualificationApprovalError("authority_principal_not_independent")
    start = _canonical_time(approval.get("approval_start_utc"), "approval_start_utc")
    expiry = _canonical_time(approval.get("approval_expires_utc"), "approval_expires_utc")
    now = _canonical_time(verification_time_utc, "verification_time_utc")
    if expiry <= start:
        raise ControlQualificationApprovalError("approval_window_invalid")
    if now < start:
        raise ControlQualificationApprovalError("approval_not_yet_valid")
    if now > expiry:
        raise ControlQualificationApprovalError("approval_expired")
    signature_check = subprocess.run(
        [
            "/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(allowed_file),
            "-I", principal, "-n", _SIGNATURE_NAMESPACE, "-s", str(signature_file),
        ],
        input=canonical_signed_payload(approval),
        capture_output=True,
        check=False,
    )
    if signature_check.returncode != 0:
        raise ControlQualificationApprovalError("signature_invalid")

    candidates, checks, _case_names, _evidence_report = _validated_inputs(
        candidate_rows_path=candidate_rows_path,
        check_rows_path=check_rows_path,
        positive_cases_path=positive_cases_path,
        evidence_root=evidence_root,
        expected_positive_rows=expected_positive_rows,
        controls_per_positive=controls_per_positive,
    )
    approval_sha = _sha256_file(approval_file)
    signature_sha = _sha256_file(signature_file)
    allowed_sha = _sha256_file(allowed_file)
    projection = _qualified_projection(
        candidates=candidates,
        checks=checks,
        request=request,
        approval=approval,
        approval_sha256=approval_sha,
        signature_sha256=signature_sha,
        allowed_signers_sha256=allowed_sha,
    )
    verification = {
        "schema_version": "chronosaudit.control_qualification_approval_verification.v1",
        "decision": (
            "CONTROL_QUALIFICATION_APPROVAL_VERIFIED"
            if authorizing
            else "CONTROL_QUALIFICATION_MECHANICS_VERIFIED_NON_AUTHORIZING"
        ),
        "request_sha256": request["request_sha256"],
        "verified_check_records_sha256": request[
            "verified_check_records_sha256"
        ],
        "approval_sha256": approval_sha,
        "signature_sha256": signature_sha,
        "allowed_signers_sha256": allowed_sha,
        "signature_namespace": _SIGNATURE_NAMESPACE,
        "authority_principal": principal,
        "authority_type": authority_type,
        "authority_identity_binding_sha256": identity_binding,
        "authority_identity_binding_verified": authorizing,
        "approval_expires_utc": approval["approval_expires_utc"],
        "candidate_rows": len(projection),
        "qualified_rows": int(projection["qualified_control"].map(bool).sum()),
        "qualified_records_sha256": _canonical_sha256(
            _normalized_projection_records(projection)
        ),
        "qualification_projection_authorized": authorizing,
        "counter_authority": authorizing,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": (
            "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_AUTHORITY_IDENTITY"
        ),
    }
    return {
        "verification": verification,
        "qualified_control_projection": projection,
    }
