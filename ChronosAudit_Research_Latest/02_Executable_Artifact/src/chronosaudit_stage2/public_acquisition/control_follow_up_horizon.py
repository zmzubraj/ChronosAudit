from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping

import pandas as pd
import yaml


class ControlFollowUpHorizonError(ValueError):
    """Raised when the follow-up horizon decision is absent or invalid."""


_SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-horizon-v1"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_horizon_signed_payload(decision: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(decision)) + "\n").encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlFollowUpHorizonError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlFollowUpHorizonError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlFollowUpHorizonError(f"{label}_not_ordinary_file")
    return resolved


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlFollowUpHorizonError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlFollowUpHorizonError(f"{label}_root_invalid")
    return payload


def _time(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlFollowUpHorizonError(f"{label}_invalid")
    canonical = parsed.isoformat().replace("+00:00", "Z")
    if str(value) != canonical:
        raise ControlFollowUpHorizonError(f"{label}_not_canonical")
    return parsed


def _request_sha256(request: Mapping[str, object]) -> str:
    return _canonical_sha256(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )


def _validate_evidence_payloads(
    *,
    request: Mapping[str, object],
    decision: Mapping[str, object],
    evidence_paths: Mapping[str, Path],
    principal: str,
    decided_at: pd.Timestamp,
) -> dict[str, dict[str, object]]:
    request_sha256 = str(request["request_sha256"])
    outcome_plan = _load_json(
        evidence_paths["outcome_source_plan"], "outcome_source_plan"
    )
    if outcome_plan.get("schema_version") != (
        "chronosaudit.control_outcome_source_plan.v1"
    ):
        raise ControlFollowUpHorizonError("outcome_source_plan_schema_invalid")
    if outcome_plan.get("status") != "METHODS_OWNER_APPROVED":
        raise ControlFollowUpHorizonError("outcome_source_plan_status_invalid")
    if outcome_plan.get("request_sha256") != request_sha256:
        raise ControlFollowUpHorizonError("outcome_source_plan_request_mismatch")
    if not str(outcome_plan.get("source_plan_id") or "").strip():
        raise ControlFollowUpHorizonError("outcome_source_plan_id_invalid")
    sources = outcome_plan.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ControlFollowUpHorizonError("outcome_source_plan_sources_invalid")
    source_ids: set[str] = set()
    allowed_source_classes = {
        "PRIMARY_ONCHAIN",
        "INCIDENT_REGISTRY",
        "SECURITY_DISCLOSURE",
        "PROJECT_DISCLOSURE",
    }
    for source in sources:
        if not isinstance(source, Mapping):
            raise ControlFollowUpHorizonError("outcome_source_plan_sources_invalid")
        source_id = str(source.get("source_id") or "").strip()
        if not source_id or source_id in source_ids:
            raise ControlFollowUpHorizonError("outcome_source_plan_sources_invalid")
        source_ids.add(source_id)
        if source.get("source_class") not in allowed_source_classes:
            raise ControlFollowUpHorizonError("outcome_source_plan_sources_invalid")
        if source.get("event_coverage") != "QUALIFYING_CONTROL_INCIDENTS":
            raise ControlFollowUpHorizonError("outcome_source_plan_sources_invalid")
    if outcome_plan.get("post_freeze_changes_require_new_signed_decision") is not True:
        raise ControlFollowUpHorizonError("outcome_source_plan_change_rule_invalid")

    censoring = _load_json(evidence_paths["censoring_rules"], "censoring_rules")
    if censoring.get("schema_version") != (
        "chronosaudit.control_censoring_rules.v1"
    ):
        raise ControlFollowUpHorizonError("censoring_rules_schema_invalid")
    if censoring.get("status") != "FROZEN":
        raise ControlFollowUpHorizonError("censoring_rules_status_invalid")
    if censoring.get("request_sha256") != request_sha256:
        raise ControlFollowUpHorizonError("censoring_rules_request_mismatch")
    if censoring.get("right_censoring_rule") != decision.get(
        "right_censoring_rule"
    ):
        raise ControlFollowUpHorizonError("censoring_rules_rule_mismatch")
    for field in (
        "incident_free_through_horizon_required",
        "unknown_or_incomplete_follow_up_never_negative",
        "post_freeze_changes_require_new_signed_decision",
    ):
        if censoring.get(field) is not True:
            raise ControlFollowUpHorizonError(f"censoring_rules_{field}_invalid")

    attestation = _load_json(
        evidence_paths["pre_freeze_outcome_inspection_attestation"],
        "pre_freeze_outcome_inspection_attestation",
    )
    if attestation.get("schema_version") != (
        "chronosaudit.control_pre_freeze_outcome_inspection_attestation.v1"
    ):
        raise ControlFollowUpHorizonError("pre_freeze_attestation_schema_invalid")
    if attestation.get("status") != "ATTESTED":
        raise ControlFollowUpHorizonError("pre_freeze_attestation_status_invalid")
    if attestation.get("request_sha256") != request_sha256:
        raise ControlFollowUpHorizonError("pre_freeze_attestation_request_mismatch")
    if attestation.get("signer_principal") != principal:
        raise ControlFollowUpHorizonError("pre_freeze_attestation_principal_mismatch")
    if attestation.get("control_outcomes_inspected_before_freeze") is not False:
        raise ControlFollowUpHorizonError("pre_freeze_attestation_outcome_flag_invalid")
    if attestation.get("statement") != (
        "NO_CONTROL_OUTCOMES_INSPECTED_BEFORE_HORIZON_FREEZE"
    ):
        raise ControlFollowUpHorizonError("pre_freeze_attestation_statement_invalid")
    attested_at = _time(
        attestation.get("attested_at_utc"), "pre_freeze_attestation_attested_at_utc"
    )
    if attested_at > decided_at:
        raise ControlFollowUpHorizonError("pre_freeze_attestation_after_decision")
    return {
        "outcome_source_plan": outcome_plan,
        "censoring_rules": censoring,
        "pre_freeze_outcome_inspection_attestation": attestation,
    }


def build_follow_up_horizon_request(
    *, policy_path: Path, positive_projection_path: Path
) -> dict[str, object]:
    """Build a deterministic request without choosing a scientific horizon."""
    policy_path = _ordinary_file(policy_path, "policy")
    positive_projection_path = _ordinary_file(
        positive_projection_path, "positive_projection"
    )
    try:
        policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ControlFollowUpHorizonError("policy_yaml_invalid") from exc
    if not isinstance(policy, Mapping):
        raise ControlFollowUpHorizonError("policy_root_invalid")
    if policy.get("schema_version") != "chronosaudit.stage2_control_selection_policy.v1":
        raise ControlFollowUpHorizonError("policy_schema_invalid")
    unresolved = policy.get("unresolved_prespecification")
    if not isinstance(unresolved, Mapping):
        raise ControlFollowUpHorizonError("policy_unresolved_section_invalid")
    configured_horizon = unresolved.get("primary_follow_up_horizon")
    if configured_horizon is None:
        if unresolved.get("disposition") != "BLOCKED":
            raise ControlFollowUpHorizonError("policy_horizon_disposition_invalid")
        required_horizon_model = "FIXED_DURATION"
        request_decision = "AWAITING_ACCOUNTABLE_METHODS_OWNER_DECISION"
        compatibility = "HISTORICAL_FIXED_DURATION_REQUEST"
    elif configured_horizon == "DYNAMIC_HORIZON_V1":
        if unresolved.get("disposition") != (
            "USER_APPROVED_IMPLEMENTATION_AND_SIGNATURE_PENDING"
        ):
            raise ControlFollowUpHorizonError("policy_horizon_disposition_invalid")
        required_horizon_model = "DYNAMIC_HORIZON_V1"
        request_decision = "AWAITING_DYNAMIC_HORIZON_ARTIFACTS_AND_SIGNATURE"
        compatibility = "CURRENT_DYNAMIC_HORIZON_REQUEST"
    else:
        raise ControlFollowUpHorizonError("policy_horizon_model_invalid")
    population = policy.get("population")
    qualification = policy.get("qualification")
    if not isinstance(population, Mapping) or not isinstance(qualification, Mapping):
        raise ControlFollowUpHorizonError("policy_contract_invalid")
    try:
        required_cases = int(population["positive_cases_required"])
        controls_per_positive = int(population["controls_per_positive"])
        control_rows_required = int(population["control_rows_required"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlFollowUpHorizonError("policy_population_invalid") from exc
    if required_cases <= 0 or controls_per_positive <= 0:
        raise ControlFollowUpHorizonError("policy_population_invalid")
    if control_rows_required != required_cases * controls_per_positive:
        raise ControlFollowUpHorizonError("policy_control_target_invalid")
    positives = pd.read_csv(
        positive_projection_path,
        dtype=str,
        keep_default_na=False,
        low_memory=False,
    )
    required_columns = {
        "case_name",
        "prediction_cutoff_time",
        "positive_record_sha256",
        "follow_up_horizon",
    }
    missing = sorted(required_columns - set(positives.columns))
    if missing:
        raise ControlFollowUpHorizonError(
            f"positive_projection_missing_columns:{','.join(missing)}"
        )
    if len(positives) != required_cases:
        raise ControlFollowUpHorizonError("positive_case_count_mismatch")
    if positives["case_name"].duplicated().any():
        raise ControlFollowUpHorizonError("positive_case_duplicate")
    if not positives["positive_record_sha256"].map(_is_sha256).all():
        raise ControlFollowUpHorizonError("positive_record_hash_invalid")
    if positives["follow_up_horizon"].astype(str).str.strip().ne("").any():
        raise ControlFollowUpHorizonError("positive_horizon_prefilled")
    cutoffs = pd.to_datetime(
        positives["prediction_cutoff_time"], utc=True, errors="coerce"
    )
    if cutoffs.isna().any():
        raise ControlFollowUpHorizonError("positive_cutoff_invalid")
    latest_cutoff = cutoffs.max().isoformat().replace("+00:00", "Z")
    request: dict[str, object] = {
        "schema_version": "chronosaudit.control_follow_up_horizon_request.v1",
        "decision": request_decision,
        "policy_sha256": _sha256_file(policy_path),
        "positive_projection_sha256": _sha256_file(positive_projection_path),
        "positive_case_count": len(positives),
        "controls_per_positive": controls_per_positive,
        "control_rows_required": control_rows_required,
        "latest_positive_cutoff_utc": latest_cutoff,
        "required_horizon_model": required_horizon_model,
        "compatibility_classification": compatibility,
        "required_maturity_status": qualification.get(
            "investigated_negative_status"
        ),
        "required_censoring_status": qualification.get("censoring_status"),
        "outcome_inspection_before_freeze_prohibited": True,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }
    if request["required_maturity_status"] != "INVESTIGATED_NEGATIVE_MATURE":
        raise ControlFollowUpHorizonError("policy_maturity_status_invalid")
    if request["required_censoring_status"] != "FROZEN_COMPLETE":
        raise ControlFollowUpHorizonError("policy_censoring_status_invalid")
    request["request_sha256"] = _request_sha256(request)
    return request


def build_follow_up_horizon_decision(
    *,
    request: Mapping[str, object],
    signer_principal: str,
    decided_at_utc: str,
    horizon_days: int,
    administrative_censoring_cutoff_utc: str,
    outcome_source_plan_path: Path,
    censoring_rules_path: Path,
    pre_freeze_outcome_inspection_attestation_path: Path,
) -> dict[str, object]:
    """Build the exact non-authorizing payload an accountable owner may sign."""
    if request.get("schema_version") != (
        "chronosaudit.control_follow_up_horizon_request.v1"
    ):
        raise ControlFollowUpHorizonError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_METHODS_OWNER_DECISION":
        raise ControlFollowUpHorizonError("request_decision_invalid")
    if request.get("required_horizon_model") != "FIXED_DURATION":
        raise ControlFollowUpHorizonError("fixed_decision_not_current_model")
    if str(request.get("request_sha256") or "").lower() != _request_sha256(request):
        raise ControlFollowUpHorizonError("request_sha256_invalid")
    principal = str(signer_principal or "").strip()
    if not principal:
        raise ControlFollowUpHorizonError("signer_principal_invalid")
    try:
        horizon_days = int(horizon_days)
    except (TypeError, ValueError) as exc:
        raise ControlFollowUpHorizonError("horizon_days_invalid") from exc
    if horizon_days <= 0:
        raise ControlFollowUpHorizonError("horizon_days_invalid")
    decided_at = _time(decided_at_utc, "decided_at_utc")
    administrative_cutoff = _time(
        administrative_censoring_cutoff_utc,
        "administrative_censoring_cutoff_utc",
    )
    latest_cutoff = _time(
        request.get("latest_positive_cutoff_utc"), "latest_positive_cutoff_utc"
    )
    if administrative_cutoff < latest_cutoff + pd.Timedelta(days=horizon_days):
        raise ControlFollowUpHorizonError("administrative_cutoff_before_maturity")
    evidence_paths = {
        "outcome_source_plan": _ordinary_file(
            outcome_source_plan_path, "outcome_source_plan"
        ),
        "censoring_rules": _ordinary_file(censoring_rules_path, "censoring_rules"),
        "pre_freeze_outcome_inspection_attestation": _ordinary_file(
            pre_freeze_outcome_inspection_attestation_path,
            "pre_freeze_outcome_inspection_attestation",
        ),
    }
    decision: dict[str, object] = {
        "schema_version": "chronosaudit.control_follow_up_horizon_decision.v1",
        "request_sha256": request["request_sha256"],
        "signer_principal": principal,
        "decision": "FREEZE_PRIMARY_FOLLOW_UP_HORIZON",
        "decided_at_utc": decided_at_utc,
        "horizon_model": "FIXED_DURATION",
        "horizon_days": horizon_days,
        "administrative_censoring_cutoff_utc": (
            administrative_censoring_cutoff_utc
        ),
        "right_censoring_rule": (
            "CENSOR_AT_EARLIEST_OF_INCIDENT_ADMINISTRATIVE_CUTOFF_OR_"
            "LAST_VERIFIED_OBSERVATION"
        ),
        "incident_free_through_horizon_required": True,
        "outcome_source_plan_sha256": _sha256_file(
            evidence_paths["outcome_source_plan"]
        ),
        "censoring_rules_sha256": _sha256_file(evidence_paths["censoring_rules"]),
        "pre_freeze_outcome_inspection_prohibited": True,
        "pre_freeze_outcome_inspection_attestation_sha256": _sha256_file(
            evidence_paths["pre_freeze_outcome_inspection_attestation"]
        ),
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }
    _validate_evidence_payloads(
        request=request,
        decision=decision,
        evidence_paths=evidence_paths,
        principal=principal,
        decided_at=decided_at,
    )
    return decision


def verify_follow_up_horizon_decision(
    *,
    request: Mapping[str, object],
    decision_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
    outcome_source_plan_path: Path,
    censoring_rules_path: Path,
    pre_freeze_outcome_inspection_attestation_path: Path,
) -> dict[str, object]:
    """Verify the accountable horizon decision without qualifying any control."""
    if request.get("schema_version") != (
        "chronosaudit.control_follow_up_horizon_request.v1"
    ):
        raise ControlFollowUpHorizonError("request_schema_invalid")
    if request.get("decision") != "AWAITING_ACCOUNTABLE_METHODS_OWNER_DECISION":
        raise ControlFollowUpHorizonError("request_decision_invalid")
    if request.get("required_horizon_model") != "FIXED_DURATION":
        raise ControlFollowUpHorizonError("fixed_decision_not_current_model")
    if str(request.get("request_sha256") or "").lower() != _request_sha256(request):
        raise ControlFollowUpHorizonError("request_sha256_invalid")
    decision_path = _ordinary_file(decision_path, "decision")
    signature_path = _ordinary_file(signature_path, "signature")
    allowed_signers_path = _ordinary_file(allowed_signers_path, "allowed_signers")
    decision = _load_json(decision_path, "decision")
    if decision.get("schema_version") != (
        "chronosaudit.control_follow_up_horizon_decision.v1"
    ):
        raise ControlFollowUpHorizonError("decision_schema_invalid")
    principal = str(decision.get("signer_principal") or "").strip()
    if not expected_principal or principal != expected_principal:
        raise ControlFollowUpHorizonError("signer_principal_mismatch")
    if str(decision.get("request_sha256") or "").lower() != request[
        "request_sha256"
    ]:
        raise ControlFollowUpHorizonError("decision_request_mismatch")
    if decision.get("decision") != "FREEZE_PRIMARY_FOLLOW_UP_HORIZON":
        raise ControlFollowUpHorizonError("decision_value_invalid")
    if decision.get("horizon_model") != "FIXED_DURATION":
        raise ControlFollowUpHorizonError("horizon_model_invalid")
    try:
        horizon_days = int(decision.get("horizon_days") or 0)
    except (TypeError, ValueError) as exc:
        raise ControlFollowUpHorizonError("horizon_days_invalid") from exc
    if horizon_days <= 0:
        raise ControlFollowUpHorizonError("horizon_days_invalid")
    expected_rule = (
        "CENSOR_AT_EARLIEST_OF_INCIDENT_ADMINISTRATIVE_CUTOFF_OR_"
        "LAST_VERIFIED_OBSERVATION"
    )
    if decision.get("right_censoring_rule") != expected_rule:
        raise ControlFollowUpHorizonError("right_censoring_rule_invalid")
    for field, expected in (
        ("incident_free_through_horizon_required", True),
        ("pre_freeze_outcome_inspection_prohibited", True),
        ("selection_authorized", False),
        ("qualification_authorized", False),
        ("counter_authority", False),
    ):
        if decision.get(field) is not expected:
            raise ControlFollowUpHorizonError(f"decision_{field}_invalid")
    for field in (
        "outcome_source_plan_sha256",
        "censoring_rules_sha256",
        "pre_freeze_outcome_inspection_attestation_sha256",
    ):
        if not _is_sha256(decision.get(field)):
            raise ControlFollowUpHorizonError(f"{field}_invalid")
    evidence_bindings = {
        "outcome_source_plan": (
            _ordinary_file(outcome_source_plan_path, "outcome_source_plan"),
            "outcome_source_plan_sha256",
        ),
        "censoring_rules": (
            _ordinary_file(censoring_rules_path, "censoring_rules"),
            "censoring_rules_sha256",
        ),
        "pre_freeze_outcome_inspection_attestation": (
            _ordinary_file(
                pre_freeze_outcome_inspection_attestation_path,
                "pre_freeze_outcome_inspection_attestation",
            ),
            "pre_freeze_outcome_inspection_attestation_sha256",
        ),
    }
    verified_evidence: dict[str, dict[str, str]] = {}
    for label, (path, decision_field) in evidence_bindings.items():
        observed_sha256 = _sha256_file(path)
        if observed_sha256 != str(decision[decision_field]).lower():
            raise ControlFollowUpHorizonError(f"{decision_field}_mismatch")
        verified_evidence[label] = {
            "path": str(path),
            "sha256": observed_sha256,
        }
    decided_at = _time(decision.get("decided_at_utc"), "decided_at_utc")
    evidence_payloads = _validate_evidence_payloads(
        request=request,
        decision=decision,
        evidence_paths={
            label: path for label, (path, _) in evidence_bindings.items()
        },
        principal=principal,
        decided_at=decided_at,
    )
    for label, payload in evidence_payloads.items():
        verified_evidence[label]["schema_version"] = payload["schema_version"]
        verified_evidence[label]["status"] = payload["status"]
    verification_time = _time(verification_time_utc, "verification_time_utc")
    if decided_at > verification_time:
        raise ControlFollowUpHorizonError("decision_from_future")
    latest_cutoff = _time(
        request.get("latest_positive_cutoff_utc"), "latest_positive_cutoff_utc"
    )
    maturity_not_before = latest_cutoff + pd.Timedelta(days=horizon_days)
    administrative_cutoff = _time(
        decision.get("administrative_censoring_cutoff_utc"),
        "administrative_censoring_cutoff_utc",
    )
    if administrative_cutoff < maturity_not_before:
        raise ControlFollowUpHorizonError("administrative_cutoff_before_maturity")
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
        input=canonical_horizon_signed_payload(decision),
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise ControlFollowUpHorizonError("signature_invalid")
    return {
        "schema_version": "chronosaudit.control_follow_up_horizon_verification.v1",
        "decision": "FOLLOW_UP_HORIZON_DECISION_VERIFIED",
        "request_sha256": request["request_sha256"],
        "decision_sha256": _sha256_file(decision_path),
        "signature_sha256": _sha256_file(signature_path),
        "allowed_signers_sha256": _sha256_file(allowed_signers_path),
        "signature_namespace": _SIGNATURE_NAMESPACE,
        "signer_principal": principal,
        "primary_follow_up_horizon": f"P{horizon_days}D",
        "horizon_days": horizon_days,
        "administrative_censoring_cutoff_utc": decision[
            "administrative_censoring_cutoff_utc"
        ],
        "maturity_evaluation_not_before_utc": maturity_not_before.isoformat().replace(
            "+00:00", "Z"
        ),
        "required_maturity_status": request["required_maturity_status"],
        "required_censoring_status": request["required_censoring_status"],
        "verified_evidence": verified_evidence,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
    }
