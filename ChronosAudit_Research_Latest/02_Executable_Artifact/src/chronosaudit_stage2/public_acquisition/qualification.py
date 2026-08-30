from __future__ import annotations

from collections.abc import Iterable
import hashlib
import json

import pandas as pd

from ..control_matching import (
    MatchPolicy,
    deterministic_global_no_reuse_allocation,
    deterministic_matched_controls,
)

CANDIDATE_CONTROL = "CANDIDATE_CONTROL"
QUALIFIED_CONTROL = "QUALIFIED_CONTROL"
STRICT_HISTORICAL_STATUS = "HISTORICAL_SNAPSHOT_VERIFIED"
FROZEN_CENSORING_STATUS = "FROZEN_COMPLETE"
MATURE_INVESTIGATED_NEGATIVE_STATUS = "INVESTIGATED_NEGATIVE_MATURE"
INDEPENDENT_OUTCOME_REVIEW_COMPLETE = "INDEPENDENT_HUMAN_REVIEW_COMPLETE"
STRICT_HUMAN_CONFIDENCE = {"high", "very_high"}
CONTROL_POSITIVE_REQUIRED_COLUMNS = (
    "case_name", "chain", "target_contract_address", "deployment_time",
    "prediction_cutoff_time", "code_size", "proxy_status",
    "source_verified_at_cutoff", "identity_group", "clone_family",
    "proxy_family", "protocol_family", "follow_up_horizon",
    "positive_record_sha256",
)
CONTROL_DENOMINATOR_REQUIRED_COLUMNS = (
    "case_name", "chain", "contract_address", "deployment_time", "code_size", "proxy_status",
    "source_verified_at_cutoff", "identity_group", "clone_family", "proxy_family",
    "protocol_family", "source_record_sha256",
    "source_manifest_sha256", "counter_authority", "covariate_cutoff_time",
    "pair_scope_record_sha256", "runtime_code_evidence_sha256",
    "proxy_evidence_sha256", "source_verification_evidence_sha256",
    "protocol_evidence_sha256", "pair_covariate_record_sha256",
)
_CONTROL_ROW_HASH_EXCLUDED_FIELDS = {
    "control_row_sha256",
    "frozen_candidate_sha256",
    "qualified_control",
    "qualification_blockers",
    "control_row_valid",
    "candidate_row_valid",
    "matcher_provenance_valid",
}

_RELEASE_GATE_COLUMNS = (
    "historical_snapshots_ready",
    "independent_adjudications_ready",
    "deployment_denominator_ready",
    "control_candidates_ready",
    "qualified_controls_ready",
    "independent_r5_blocks_ready",
    "case_hash_bound",
    "case_schema_valid",
    "case_not_stale",
    "policy_thresholds_met",
)


def _require_columns(frame: pd.DataFrame, required: Iterable[str], name: str) -> None:
    missing = sorted(set(required) - set(frame.columns))
    if missing:
        raise ValueError(f"{name} missing columns: {missing}")


def _normalize_bool(value: object) -> bool:
    if pd.isna(value):
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def make_control_row_sha256(row: dict[str, object] | pd.Series) -> str:
    payload = {
        key: row[key]
        for key in sorted(row.keys())
        if key not in _CONTROL_ROW_HASH_EXCLUDED_FIELDS
    }
    return _canonical_hash(payload)


def _selection_check_sha256(
    *, gate: str, positive: pd.Series, control: pd.Series,
    positive_value: object, control_value: object,
) -> str:
    """Bind a mechanical selection check to both frozen source records."""
    return _canonical_hash({
        "schema_version": "chronosaudit.control_selection_check.v1",
        "gate": gate,
        "case_name": str(positive["case_name"]),
        "control_address": str(control["contract_address"]).lower(),
        "positive_record_sha256": str(positive["positive_record_sha256"]).lower(),
        "denominator_record_sha256": str(control["source_record_sha256"]).lower(),
        "source_manifest_sha256": str(control["source_manifest_sha256"]).lower(),
        "pair_covariate_record_sha256": str(
            control["pair_covariate_record_sha256"]
        ).lower(),
        "positive_value": str(positive_value),
        "control_value": str(control_value),
    })


def _positive_address_set(positives: pd.DataFrame) -> set[str]:
    addresses: set[str] = set()
    for column in ("target_contract_address", "contract_address"):
        if column in positives.columns:
            addresses.update(
                str(value).strip().lower()
                for value in positives[column].dropna().tolist()
                if str(value).strip()
            )
    return addresses


def _incomplete_counts(frame: pd.DataFrame, columns: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for column in columns:
        if column not in frame.columns:
            continue
        missing = frame[column].isna() | frame[column].astype(str).str.strip().isin({"", "nan", "none", "null"})
        counts[column] = int(missing.sum())
    return counts


def preflight_control_inputs(
    positives: pd.DataFrame,
    deployments: pd.DataFrame,
    *,
    expected_positive_rows: int = 417,
    expected_denominator_rows: int = 20_000,
    controls_per_positive: int = 10,
) -> dict[str, object]:
    """Report whether frozen inputs can enter control selection without mutating them."""
    positive_missing = sorted(set(CONTROL_POSITIVE_REQUIRED_COLUMNS) - set(positives.columns))
    denominator_missing = sorted(set(CONTROL_DENOMINATOR_REQUIRED_COLUMNS) - set(deployments.columns))
    positive_incomplete = _incomplete_counts(positives, CONTROL_POSITIVE_REQUIRED_COLUMNS)
    denominator_incomplete = _incomplete_counts(deployments, CONTROL_DENOMINATOR_REQUIRED_COLUMNS)
    positive_hash_errors = (
        int((~positives["positive_record_sha256"].map(_is_sha256)).sum())
        if "positive_record_sha256" in positives.columns else 0
    )
    denominator_hash_errors = sum(
        int((~deployments[column].map(_is_sha256)).sum())
        for column in (
            "source_record_sha256",
            "source_manifest_sha256",
            "pair_scope_record_sha256",
            "runtime_code_evidence_sha256",
            "proxy_evidence_sha256",
            "source_verification_evidence_sha256",
            "protocol_evidence_sha256",
            "pair_covariate_record_sha256",
        )
        if column in deployments.columns
    )
    unauthorized_rows = (
        int((~deployments["counter_authority"].map(_normalize_bool)).sum())
        if "counter_authority" in deployments.columns else len(deployments)
    )
    duplicate_positive_cases = (
        int(positives.duplicated(["case_name"]).sum()) if "case_name" in positives.columns else len(positives)
    )
    duplicate_denominator_identities = (
        int(deployments.duplicated(["chain", "contract_address"]).sum())
        if {"chain", "contract_address"}.issubset(deployments.columns) else len(deployments)
    )
    blockers: list[str] = []
    for condition, blocker in (
        (len(positives) != expected_positive_rows, "positive_row_count"),
        (len(deployments) != expected_denominator_rows, "denominator_row_count"),
        (bool(positive_missing), "positive_missing_columns"),
        (bool(denominator_missing), "denominator_missing_columns"),
        (any(positive_incomplete.values()), "positive_incomplete_values"),
        (any(denominator_incomplete.values()), "denominator_incomplete_values"),
        (positive_hash_errors > 0, "positive_hash_errors"),
        (denominator_hash_errors > 0, "denominator_hash_errors"),
        (unauthorized_rows > 0, "denominator_counter_authority"),
        (duplicate_positive_cases > 0, "duplicate_positive_cases"),
        (duplicate_denominator_identities > 0, "duplicate_denominator_identities"),
    ):
        if condition:
            blockers.append(blocker)
    return {
        "schema_version": "chronosaudit.control_input_preflight.v1",
        "decision": "READY_FOR_CANDIDATE_SELECTION" if not blockers else "BLOCKED_INPUT_ENRICHMENT_REQUIRED",
        "controls_per_positive": int(controls_per_positive),
        "target_control_rows": int(expected_positive_rows * controls_per_positive),
        "blockers": blockers,
        "positive_inputs": {
            "observed_rows": int(len(positives)), "required_rows": int(expected_positive_rows),
            "missing_columns": positive_missing, "incomplete_value_counts": positive_incomplete,
            "hash_errors": positive_hash_errors, "duplicate_case_names": duplicate_positive_cases,
        },
        "denominator_inputs": {
            "observed_rows": int(len(deployments)), "required_rows": int(expected_denominator_rows),
            "missing_columns": denominator_missing, "incomplete_value_counts": denominator_incomplete,
            "hash_errors": denominator_hash_errors, "unauthorized_rows": unauthorized_rows,
            "duplicate_chain_address_identities": duplicate_denominator_identities,
        },
    }


def build_control_candidates(
    positives: pd.DataFrame,
    deployments: pd.DataFrame,
    *,
    controls_per_positive: int = 10,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    _require_columns(
        positives,
        CONTROL_POSITIVE_REQUIRED_COLUMNS,
        "positives",
    )
    _require_columns(
        deployments,
        CONTROL_DENOMINATOR_REQUIRED_COLUMNS,
        "deployments",
    )
    if not deployments["counter_authority"].map(_normalize_bool).all():
        raise ValueError("deployments contain rows without counter_authority=true")

    positive_addresses = _positive_address_set(positives)
    candidate_rows: list[dict[str, object]] = []
    audit_rows: list[dict[str, object]] = []
    prepared: dict[str, tuple[pd.Series, pd.DataFrame, pd.DataFrame, dict[str, object]]] = {}
    eligible_by_case: dict[str, pd.DataFrame] = {}
    ordered_positives = positives.sort_values(["case_name", "chain"], kind="stable")
    for _, positive in ordered_positives.iterrows():
        positive_cutoff = pd.to_datetime(
            positive["prediction_cutoff_time"], utc=True, errors="coerce"
        )
        deployment_cutoffs = pd.to_datetime(
            deployments["covariate_cutoff_time"], utc=True, errors="coerce"
        )
        linkage_filtered = deployments[
            (deployments["case_name"].astype(str) == str(positive["case_name"]))
            & deployment_cutoffs.eq(positive_cutoff)
        ].copy()
        linkage_filtered["contract_address"] = linkage_filtered["contract_address"].astype(str).str.lower()
        linkage_filtered = linkage_filtered[
            ~linkage_filtered["contract_address"].isin(positive_addresses)
        ].copy()
        for linkage_column in ("identity_group", "clone_family", "proxy_family", "protocol_family"):
            if linkage_column in linkage_filtered.columns:
                linkage_filtered = linkage_filtered[
                    linkage_filtered[linkage_column].astype(str) != str(positive[linkage_column])
                ].copy()

        positive_row = pd.DataFrame([positive.to_dict()])
        matches, audit = deterministic_matched_controls(
            positives=positive_row,
            deployments=linkage_filtered,
            policy=MatchPolicy(controls_per_positive=max(1, len(linkage_filtered))),
            excluded_addresses=positive_addresses,
        )

        case_name = str(positive["case_name"])
        prepared[case_name] = (
            positive,
            linkage_filtered,
            matches,
            audit.iloc[0].to_dict() if not audit.empty else {"case_name": case_name},
        )
        eligible_by_case[case_name] = matches

    allocation = deterministic_global_no_reuse_allocation(
        eligible_by_case, controls_per_positive=controls_per_positive
    )

    for case_name in sorted(prepared):
        positive, linkage_filtered, eligible_matches, audit_row = prepared[case_name]
        selected_identities = set(allocation[case_name])
        if eligible_matches.empty:
            matches = eligible_matches.copy()
        else:
            normalized_chain = eligible_matches["chain"].astype(str).str.strip().str.lower()
            normalized_address = (
                eligible_matches["contract_address"].astype(str).str.strip().str.lower()
            )
            selected_mask = [
                (chain, address) in selected_identities
                for chain, address in zip(normalized_chain, normalized_address)
            ]
            matches = eligible_matches.loc[selected_mask].copy()
            matches = matches.sort_values(
                ["deterministic_rank_sha256", "contract_address"], kind="stable"
            )
            matches["control_rank"] = range(1, len(matches) + 1)

        follow_up_horizon = str(positive["follow_up_horizon"])
        follow_up_start = str(positive["prediction_cutoff_time"])
        if not matches.empty:
            matches = matches.copy()
            deployment_details = linkage_filtered.loc[
                linkage_filtered["contract_address"].isin(matches["contract_address"].tolist())
            ].drop_duplicates("contract_address")
            deployment_details = deployment_details.set_index("contract_address")
            matches["candidate_status"] = CANDIDATE_CONTROL
            matches["follow_up_start"] = follow_up_start
            matches["follow_up_horizon"] = follow_up_horizon
            matches["censoring_status"] = "PENDING_FROZEN_FOLLOW_UP"
            matches["investigated_negative_status"] = "PENDING_INVESTIGATED_NEGATIVE"
            matches["independent_outcome_review_status"] = "PENDING_INDEPENDENT_OUTCOME_REVIEW"
            matches["denominator_record_sha256"] = matches["contract_address"].map(
                lambda address: deployment_details.at[address, "source_record_sha256"]
            )
            matches["source_manifest_sha256"] = matches["contract_address"].map(
                lambda address: deployment_details.at[address, "source_manifest_sha256"]
            )
            for evidence_column in (
                "pair_scope_record_sha256",
                "runtime_code_evidence_sha256",
                "proxy_evidence_sha256",
                "source_verification_evidence_sha256",
                "protocol_evidence_sha256",
                "pair_covariate_record_sha256",
            ):
                matches[evidence_column] = matches["contract_address"].map(
                    lambda address, column=evidence_column: deployment_details.at[
                        address, column
                    ]
                )
            matches["identity_linkage_free"] = True
            matches["clone_linkage_free"] = True
            matches["proxy_linkage_free"] = True
            matches["protocol_linkage_free"] = True
            matches["mechanism_separation_free"] = False
            matches["positive_record_sha256"] = str(positive["positive_record_sha256"])
            matches["maturity_check_passed"] = False
            matches["maturity_check_sha256"] = ""
            matches["censoring_check_passed"] = False
            matches["censoring_check_sha256"] = ""
            selected_details = [
                {"contract_address": address, **deployment_details.loc[address].to_dict()}
                for address in matches["contract_address"].tolist()
            ]
            for gate, positive_column, control_column in (
                ("temporal", "prediction_cutoff_time", "deployment_time"),
                ("lineage", "identity_group", "identity_group"),
                ("clone", "clone_family", "clone_family"),
                ("proxy", "proxy_family", "proxy_family"),
                ("protocol", "protocol_family", "protocol_family"),
            ):
                matches[f"{gate}_check_passed"] = True
                matches[f"{gate}_check_sha256"] = [
                    _selection_check_sha256(
                        gate=gate, positive=positive, control=pd.Series(detail),
                        positive_value=positive[positive_column], control_value=detail[control_column],
                    )
                    for detail in selected_details
                ]
            # A control's mechanism is an outcome, not a cutoff-safe matching
            # covariate. It must be independently adjudicated after follow-up.
            matches["mechanism_separation_check_passed"] = False
            matches["mechanism_separation_check_sha256"] = ""
            matches["independent_outcome_reviewer_identity"] = ""
            matches["independent_outcome_reviewer_owner"] = ""
            matches["independent_outcome_reviewer_conflict_clear"] = False
            matches["independent_outcome_reviewer_confidence"] = ""
            matches["independent_outcome_decision_sha256"] = ""
            matches["qualified_control"] = False
            matches["candidate_row_valid"] = True
            matches["matcher_provenance_valid"] = True
            matches["qualification_blockers"] = (
                "maturity_check_passed,censoring_check_passed,"
                "mechanism_separation_check_passed,censoring_status,"
                "investigated_negative_status,independent_outcome_review_status"
            )
            matches["control_row_valid"] = True
            matches["control_row_sha256"] = matches.apply(
                lambda row: make_control_row_sha256(row.to_dict()),
                axis=1,
            )
            candidate_rows.extend(matches.to_dict("records"))

        audit_row["eligible_candidates"] = int(len(eligible_matches))
        audit_row["controls_selected"] = int(len(matches))
        audit_row["required"] = int(controls_per_positive)
        audit_row["complete"] = bool(len(matches) >= controls_per_positive)
        audit_rows.append(audit_row)

    candidates = pd.DataFrame(candidate_rows)
    audit_frame = pd.DataFrame(audit_rows)
    return candidates, audit_frame


def qualify_control_rows(control_rows: pd.DataFrame) -> pd.DataFrame:
    _require_columns(
        control_rows,
        (
            "case_name",
            "chain",
            "contract_address",
            "candidate_status",
            "match_set_id",
            "control_rank",
            "positive_prediction_cutoff_time",
            "deterministic_rank_sha256",
            "denominator_record_sha256",
            "source_manifest_sha256",
            "deployed_by_positive_cutoff",
            "identity_linkage_free",
            "clone_linkage_free",
            "proxy_linkage_free",
            "protocol_linkage_free",
            "mechanism_separation_free",
            "follow_up_start",
            "follow_up_horizon",
            "censoring_status",
            "investigated_negative_status",
            "independent_outcome_review_status",
            "independent_outcome_reviewer_identity",
            "independent_outcome_reviewer_owner",
            "independent_outcome_reviewer_conflict_clear",
            "independent_outcome_reviewer_confidence",
            "independent_outcome_decision_sha256",
            "control_row_sha256",
        ),
        "control_rows",
    )
    qualified = control_rows.copy()
    blockers: list[str] = []
    statuses: list[str] = []
    qualified_flags: list[bool] = []
    candidate_valid_flags: list[bool] = []

    for _, row in qualified.iterrows():
        provenance_blockers: list[str] = []
        qualification_only_blockers: list[str] = []
        if not str(row["case_name"]).strip():
            provenance_blockers.append("case_name")
        if not str(row["chain"]).strip():
            provenance_blockers.append("chain")
        if not str(row["contract_address"]).strip():
            provenance_blockers.append("contract_address")
        if str(row["candidate_status"]) not in {CANDIDATE_CONTROL, QUALIFIED_CONTROL}:
            provenance_blockers.append("candidate_status")
        if not str(row["match_set_id"]).strip():
            provenance_blockers.append("match_set_id")
        if pd.isna(row["control_rank"]) or int(row["control_rank"]) <= 0:
            provenance_blockers.append("control_rank")
        if not str(row["positive_prediction_cutoff_time"]).strip():
            provenance_blockers.append("positive_prediction_cutoff_time")
        if not _is_sha256(row["deterministic_rank_sha256"]):
            provenance_blockers.append("deterministic_rank_sha256")
        if not _is_sha256(row["denominator_record_sha256"]):
            provenance_blockers.append("denominator_record_sha256")
        if not _is_sha256(row["source_manifest_sha256"]):
            provenance_blockers.append("source_manifest_sha256")
        if not _normalize_bool(row["deployed_by_positive_cutoff"]):
            provenance_blockers.append("deployed_by_positive_cutoff")
        if not _normalize_bool(row["identity_linkage_free"]):
            provenance_blockers.append("identity_linkage_free")
        if not _normalize_bool(row["clone_linkage_free"]):
            provenance_blockers.append("clone_linkage_free")
        if not _normalize_bool(row["proxy_linkage_free"]):
            provenance_blockers.append("proxy_linkage_free")
        if not _normalize_bool(row["protocol_linkage_free"]):
            provenance_blockers.append("protocol_linkage_free")
        if not _normalize_bool(row["mechanism_separation_free"]):
            qualification_only_blockers.append("mechanism_separation_free")
        if not str(row["follow_up_start"]).strip():
            provenance_blockers.append("follow_up_start")
        if not str(row["follow_up_horizon"]).strip():
            provenance_blockers.append("follow_up_horizon")
        if str(row["control_row_sha256"]).strip().lower() != make_control_row_sha256(row.to_dict()):
            provenance_blockers.append("control_row_sha256")
        for gate in ("temporal", "lineage", "clone", "proxy", "protocol"):
            passed_column = f"{gate}_check_passed"
            hash_column = f"{gate}_check_sha256"
            if not _normalize_bool(row.get(passed_column, False)):
                provenance_blockers.append(passed_column)
            if not _is_sha256(row.get(hash_column, "")):
                provenance_blockers.append(hash_column)

        if not _normalize_bool(row.get("mechanism_separation_check_passed", False)):
            qualification_only_blockers.append("mechanism_separation_check_passed")
        if not _is_sha256(row.get("mechanism_separation_check_sha256", "")):
            qualification_only_blockers.append("mechanism_separation_check_sha256")

        if str(row["censoring_status"]) != FROZEN_CENSORING_STATUS:
            qualification_only_blockers.append("censoring_status")
        if not _normalize_bool(row.get("censoring_check_passed", False)):
            qualification_only_blockers.append("censoring_check_passed")
        if not _is_sha256(row.get("censoring_check_sha256", "")):
            qualification_only_blockers.append("censoring_check_sha256")
        if str(row["investigated_negative_status"]) != MATURE_INVESTIGATED_NEGATIVE_STATUS:
            qualification_only_blockers.append("investigated_negative_status")
        if not _normalize_bool(row.get("maturity_check_passed", False)):
            qualification_only_blockers.append("maturity_check_passed")
        if not _is_sha256(row.get("maturity_check_sha256", "")):
            qualification_only_blockers.append("maturity_check_sha256")
        if str(row["independent_outcome_review_status"]) != INDEPENDENT_OUTCOME_REVIEW_COMPLETE:
            qualification_only_blockers.append("independent_outcome_review_status")
        if str(row["independent_outcome_reviewer_identity"]).strip() in {"", "AI", "PUBLIC_LABEL", "PUBLIC", "SAME_OWNER"}:
            qualification_only_blockers.append("independent_outcome_reviewer_identity")
        if str(row["independent_outcome_reviewer_owner"]).strip() in {"", "SAME_OWNER"}:
            qualification_only_blockers.append("independent_outcome_reviewer_owner")
        if not _normalize_bool(row["independent_outcome_reviewer_conflict_clear"]):
            qualification_only_blockers.append("independent_outcome_reviewer_conflict_clear")
        if str(row["independent_outcome_reviewer_confidence"]).strip().lower() not in STRICT_HUMAN_CONFIDENCE:
            qualification_only_blockers.append("independent_outcome_reviewer_confidence")
        if not _is_sha256(row["independent_outcome_decision_sha256"]):
            qualification_only_blockers.append("independent_outcome_decision_sha256")

        candidate_valid = len(provenance_blockers) == 0
        row_blockers = provenance_blockers + qualification_only_blockers
        is_qualified = candidate_valid and len(qualification_only_blockers) == 0
        candidate_valid_flags.append(candidate_valid)
        qualified_flags.append(is_qualified)
        blockers.append(",".join(row_blockers))
        statuses.append(QUALIFIED_CONTROL if is_qualified else CANDIDATE_CONTROL)

    qualified["candidate_row_valid"] = candidate_valid_flags
    qualified["matcher_provenance_valid"] = candidate_valid_flags
    qualified["control_row_valid"] = candidate_valid_flags
    qualified["qualified_control"] = qualified_flags
    qualified["qualification_blockers"] = blockers
    qualified["candidate_status"] = statuses
    return qualified


def verify_control_cohort_structure(
    control_rows: pd.DataFrame,
    *,
    valid_column: str,
    expected_case_names: Iterable[str],
    controls_per_positive: int = 10,
) -> dict[str, object]:
    """Verify the exact cohort shape required before a counter can pass."""
    if controls_per_positive <= 0:
        raise ValueError("controls_per_positive must be positive")
    required = {
        "case_name", "chain", "contract_address", "match_set_id", "control_rank",
        valid_column,
    }
    missing = sorted(required - set(control_rows.columns))
    if missing:
        return {
            "passed": False,
            "cohort_blockers": ["missing_cohort_columns"],
            "missing_columns": missing,
        }

    expected_cases = [str(value) for value in expected_case_names]
    if len(set(expected_cases)) != len(expected_cases):
        raise ValueError("expected_case_names contains duplicates")
    expected_case_set = set(expected_cases)
    target_rows = len(expected_cases) * controls_per_positive
    valid = control_rows.loc[control_rows[valid_column].map(_normalize_bool)].copy()
    valid["_case"] = valid["case_name"].astype(str)
    valid["_chain"] = valid["chain"].astype(str).str.strip().str.lower()
    valid["_address"] = (
        valid["contract_address"].astype(str).str.strip().str.lower()
    )
    ranks = pd.to_numeric(valid["control_rank"], errors="coerce")
    observed_cases = set(valid["_case"])
    case_counts = valid["_case"].value_counts().to_dict()
    expected_ranks = set(range(1, controls_per_positive + 1))

    blockers: list[str] = []
    if len(valid) != target_rows:
        blockers.append("row_count")
    if observed_cases != expected_case_set:
        blockers.append("case_membership")
    if any(int(case_counts.get(case, 0)) != controls_per_positive for case in expected_cases):
        blockers.append("case_control_count")
    if valid.duplicated(["_chain", "_address"]).any():
        blockers.append("duplicate_chain_control_identity")
    if ranks.isna().any():
        blockers.append("control_rank")
    else:
        for case in expected_cases:
            case_ranks = set(ranks.loc[valid["_case"].eq(case)].astype(int).tolist())
            if case_ranks != expected_ranks:
                blockers.append("control_rank")
                break
    per_case_match_sets = valid.groupby("_case", sort=True)["match_set_id"].nunique()
    if any(int(per_case_match_sets.get(case, 0)) != 1 for case in expected_cases):
        blockers.append("match_set_per_case")
    match_set_case_counts = valid.groupby("match_set_id", sort=True)["_case"].nunique()
    if not match_set_case_counts.empty and match_set_case_counts.gt(1).any():
        blockers.append("match_set_reused_across_cases")

    return {
        "passed": not blockers,
        "cohort_blockers": blockers,
        "observed_valid_rows": int(len(valid)),
        "required_rows": int(target_rows),
        "observed_case_count": int(len(observed_cases)),
        "required_case_count": int(len(expected_cases)),
        "controls_per_positive": int(controls_per_positive),
        "unique_chain_control_identities": int(
            valid[["_chain", "_address"]].drop_duplicates().shape[0]
        ),
    }


def verify_release_eligibility(case_rows: pd.DataFrame) -> dict[str, object]:
    _require_columns(case_rows, _RELEASE_GATE_COLUMNS, "case_rows")
    eligible_mask = pd.Series(True, index=case_rows.index)
    for column in _RELEASE_GATE_COLUMNS:
        eligible_mask &= case_rows[column].map(_normalize_bool)

    eligible_cases = case_rows.loc[eligible_mask, "case_name"].astype(str).tolist() if "case_name" in case_rows.columns else []
    return {
        "release_eligible_cases": int(eligible_mask.sum()),
        "eligible_case_names": eligible_cases,
        "release_gate_columns": list(_RELEASE_GATE_COLUMNS),
    }
