from __future__ import annotations

import pandas as pd

from chronosaudit_stage2.public_acquisition.qualification import (
    build_control_candidates,
    make_control_row_sha256,
    preflight_control_inputs,
    qualify_control_rows,
    verify_control_cohort_structure,
    verify_release_eligibility,
)


def _positive_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "target_contract_address": "0x" + "11" * 20,
                "prediction_cutoff_time": "2024-02-01T00:00:00Z",
                "deployment_time": "2024-01-01T00:00:00Z",
                "code_size": 1200,
                "proxy_status": "none",
                "source_verified_at_cutoff": True,
                "identity_group": "id-pos-1",
                "clone_family": "clone-pos-1",
                "proxy_family": "proxy-pos-1",
                "protocol_family": "dex",
                "mechanism_family": "access_control",
                "follow_up_horizon": "2024-08-01T00:00:00Z",
                "positive_record_sha256": "0" * 64,
            }
        ]
    )


def _deployment_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "contract_address": "0x" + "aa" * 20,
                "deployment_time": "2024-01-20T00:00:00Z",
                "code_size": 1180,
                "proxy_status": "none",
                "source_verified_at_cutoff": True,
                "identity_group": "id-ctrl-good-1",
                "clone_family": "clone-ctrl-good-1",
                "proxy_family": "proxy-ctrl-good-1",
                "protocol_family": "lending",
                "mechanism_family": "oracle_manipulation",
                "source_manifest_sha256": "1" * 64,
                "source_record_sha256": "2" * 64,
                "counter_authority": True,
                "covariate_cutoff_time": "2024-02-01T00:00:00Z",
                "pair_scope_record_sha256": "d" * 64,
                "runtime_code_evidence_sha256": "e" * 64,
                "proxy_evidence_sha256": "e" * 64,
                "source_verification_evidence_sha256": "e" * 64,
                "protocol_evidence_sha256": "e" * 64,
                "pair_covariate_record_sha256": "f" * 64,
            },
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "contract_address": "0x" + "bb" * 20,
                "deployment_time": "2024-01-21T00:00:00Z",
                "code_size": 1210,
                "proxy_status": "none",
                "source_verified_at_cutoff": True,
                "identity_group": "id-pos-1",
                "clone_family": "clone-ctrl-good-2",
                "proxy_family": "proxy-ctrl-good-2",
                "protocol_family": "bridge",
                "mechanism_family": "reentrancy",
                "source_manifest_sha256": "3" * 64,
                "source_record_sha256": "4" * 64,
                "counter_authority": True,
                "covariate_cutoff_time": "2024-02-01T00:00:00Z",
                "pair_scope_record_sha256": "d" * 64,
                "runtime_code_evidence_sha256": "e" * 64,
                "proxy_evidence_sha256": "e" * 64,
                "source_verification_evidence_sha256": "e" * 64,
                "protocol_evidence_sha256": "e" * 64,
                "pair_covariate_record_sha256": "f" * 64,
            },
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "contract_address": "0x" + "cc" * 20,
                "deployment_time": "2024-01-22T00:00:00Z",
                "code_size": 1170,
                "proxy_status": "none",
                "source_verified_at_cutoff": True,
                "identity_group": "id-ctrl-good-3",
                "clone_family": "clone-pos-1",
                "proxy_family": "proxy-ctrl-good-3",
                "protocol_family": "bridge",
                "mechanism_family": "price_manipulation",
                "source_manifest_sha256": "5" * 64,
                "source_record_sha256": "6" * 64,
                "counter_authority": True,
                "covariate_cutoff_time": "2024-02-01T00:00:00Z",
                "pair_scope_record_sha256": "d" * 64,
                "runtime_code_evidence_sha256": "e" * 64,
                "proxy_evidence_sha256": "e" * 64,
                "source_verification_evidence_sha256": "e" * 64,
                "protocol_evidence_sha256": "e" * 64,
                "pair_covariate_record_sha256": "f" * 64,
            },
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "contract_address": "0x" + "dd" * 20,
                "deployment_time": "2024-01-23T00:00:00Z",
                "code_size": 1160,
                "proxy_status": "none",
                "source_verified_at_cutoff": True,
                "identity_group": "id-ctrl-good-4",
                "clone_family": "clone-ctrl-good-4",
                "proxy_family": "proxy-pos-1",
                "protocol_family": "bridge",
                "mechanism_family": "arithmetic_failure",
                "source_manifest_sha256": "7" * 64,
                "source_record_sha256": "8" * 64,
                "counter_authority": True,
                "covariate_cutoff_time": "2024-02-01T00:00:00Z",
                "pair_scope_record_sha256": "d" * 64,
                "runtime_code_evidence_sha256": "e" * 64,
                "proxy_evidence_sha256": "e" * 64,
                "source_verification_evidence_sha256": "e" * 64,
                "protocol_evidence_sha256": "e" * 64,
                "pair_covariate_record_sha256": "f" * 64,
            },
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "contract_address": "0x" + "ee" * 20,
                "deployment_time": "2024-01-24T00:00:00Z",
                "code_size": 1150,
                "proxy_status": "none",
                "source_verified_at_cutoff": True,
                "identity_group": "id-ctrl-good-5",
                "clone_family": "clone-ctrl-good-5",
                "proxy_family": "proxy-ctrl-good-5",
                "protocol_family": "dex",
                "mechanism_family": "governance_failure",
                "source_manifest_sha256": "9" * 64,
                "source_record_sha256": "a" * 64,
                "counter_authority": True,
                "covariate_cutoff_time": "2024-02-01T00:00:00Z",
                "pair_scope_record_sha256": "d" * 64,
                "runtime_code_evidence_sha256": "e" * 64,
                "proxy_evidence_sha256": "e" * 64,
                "source_verification_evidence_sha256": "e" * 64,
                "protocol_evidence_sha256": "e" * 64,
                "pair_covariate_record_sha256": "f" * 64,
            },
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "contract_address": "0x" + "ff" * 20,
                "deployment_time": "2024-01-25T00:00:00Z",
                "code_size": 1140,
                "proxy_status": "none",
                "source_verified_at_cutoff": True,
                "identity_group": "id-ctrl-good-6",
                "clone_family": "clone-ctrl-good-6",
                "proxy_family": "proxy-ctrl-good-6",
                "protocol_family": "bridge",
                "mechanism_family": "logic_failure",
                "source_manifest_sha256": "b" * 64,
                "source_record_sha256": "c" * 64,
                "counter_authority": True,
                "covariate_cutoff_time": "2024-02-01T00:00:00Z",
                "pair_scope_record_sha256": "d" * 64,
                "runtime_code_evidence_sha256": "e" * 64,
                "proxy_evidence_sha256": "e" * 64,
                "source_verification_evidence_sha256": "e" * 64,
                "protocol_evidence_sha256": "e" * 64,
                "pair_covariate_record_sha256": "f" * 64,
            },
        ]
    )


def test_build_control_candidates_excludes_positive_linkages_and_preserves_shortfall() -> None:
    candidates, audit = build_control_candidates(
        _positive_frame(),
        _deployment_frame(),
        controls_per_positive=3,
    )
    assert candidates["contract_address"].tolist() == ["0x" + "aa" * 20, "0x" + "ff" * 20]
    assert candidates["candidate_status"].tolist() == ["CANDIDATE_CONTROL", "CANDIDATE_CONTROL"]
    assert candidates["source_manifest_sha256"].tolist() == ["1" * 64, "b" * 64]
    assert candidates["pair_covariate_record_sha256"].tolist() == ["f" * 64, "f" * 64]
    assert candidates["identity_linkage_free"].tolist() == [True, True]
    assert candidates["protocol_linkage_free"].tolist() == [True, True]
    assert candidates["candidate_row_valid"].tolist() == [True, True]
    assert candidates["qualified_control"].tolist() == [False, False]
    assert candidates["follow_up_start"].tolist() == ["2024-02-01T00:00:00Z", "2024-02-01T00:00:00Z"]
    assert candidates["follow_up_horizon"].tolist() == ["2024-08-01T00:00:00Z", "2024-08-01T00:00:00Z"]
    assert audit.iloc[0]["controls_selected"] == 2
    assert not bool(audit.iloc[0]["complete"])
    assert candidates["control_row_sha256"].map(lambda value: isinstance(value, str) and len(value) == 64).all()


def test_control_preflight_reports_exact_missing_covariates_and_blocks_selection() -> None:
    positives = pd.DataFrame([{"case_name": "case-1", "chain": "ethereum"}])
    denominator = pd.DataFrame([{
        "chain": "ethereum", "contract_address": "0x" + "aa" * 20,
        "deployment_time": "2024-01-20T00:00:00Z",
        "source_record_sha256": "2" * 64, "source_manifest_sha256": "1" * 64,
        "counter_authority": True,
    }])
    report = preflight_control_inputs(
        positives, denominator, expected_positive_rows=1, expected_denominator_rows=1,
    )
    assert report["decision"] == "BLOCKED_INPUT_ENRICHMENT_REQUIRED"
    assert "prediction_cutoff_time" in report["positive_inputs"]["missing_columns"]
    assert "protocol_family" in report["denominator_inputs"]["missing_columns"]
    assert "covariate_cutoff_time" in report["denominator_inputs"]["missing_columns"]
    assert "pair_covariate_record_sha256" in report["denominator_inputs"]["missing_columns"]
    assert "mechanism_family" not in report["positive_inputs"]["missing_columns"]
    assert "mechanism_family" not in report["denominator_inputs"]["missing_columns"]
    assert report["target_control_rows"] == 10


def test_build_control_candidates_does_not_reuse_a_control_across_positive_cases() -> None:
    positives = pd.concat([
        _positive_frame(),
        _positive_frame().assign(case_name="case-2", target_contract_address="0x" + "22" * 20),
    ], ignore_index=True)
    candidates, audit = build_control_candidates(
        positives, _deployment_frame().iloc[[0]].copy(), controls_per_positive=1,
    )
    assert candidates["contract_address"].tolist() == ["0x" + "aa" * 20]
    assert candidates["contract_address"].nunique() == len(candidates)
    assert audit["controls_selected"].tolist() == [1, 0]
    assert audit["complete"].tolist() == [True, False]


def test_build_control_candidates_uses_global_allocation_instead_of_case_greedy() -> None:
    positives = pd.concat(
        [
            _positive_frame(),
            _positive_frame().assign(
                case_name="case-2",
                target_contract_address="0x" + "22" * 20,
                positive_record_sha256="9" * 64,
            ),
        ],
        ignore_index=True,
    )
    base = _deployment_frame()
    shared = base.iloc[[0]].copy()
    alternative = base.iloc[[5]].copy()
    case_two_shared = shared.assign(case_name="case-2")
    deployments = pd.concat(
        [shared, alternative, case_two_shared], ignore_index=True
    )

    candidates, audit = build_control_candidates(
        positives, deployments, controls_per_positive=1,
    )

    selected = {
        row.case_name: row.contract_address
        for row in candidates.itertuples(index=False)
    }
    assert selected == {
        "case-1": "0x" + "ff" * 20,
        "case-2": "0x" + "aa" * 20,
    }
    assert candidates[["chain", "contract_address"]].duplicated().sum() == 0
    assert audit.set_index("case_name")["complete"].map(bool).to_dict() == {
        "case-1": True,
        "case-2": True,
    }


def test_candidate_selection_defers_mechanism_separation_to_outcome_qualification() -> None:
    deployments = _deployment_frame().drop(columns=["mechanism_family"])
    report = preflight_control_inputs(
        _positive_frame(), deployments, expected_positive_rows=1,
        expected_denominator_rows=len(deployments), controls_per_positive=1,
    )
    assert "mechanism_family" not in report["denominator_inputs"]["missing_columns"]
    assert "mechanism_family" not in report["positive_inputs"]["missing_columns"]

    candidates, audit = build_control_candidates(
        _positive_frame(), deployments, controls_per_positive=1,
    )
    assert audit.iloc[0]["controls_selected"] == 1
    assert candidates.iloc[0]["mechanism_separation_check_passed"] == False
    assert candidates.iloc[0]["mechanism_separation_check_sha256"] == ""
    assert candidates.iloc[0]["mechanism_separation_free"] == False
    assert candidates.iloc[0]["qualified_control"] == False

    revalidated = qualify_control_rows(candidates)
    assert revalidated.iloc[0]["candidate_row_valid"] == True
    assert revalidated.iloc[0]["qualified_control"] == False
    assert "mechanism_separation_free" in revalidated.iloc[0]["qualification_blockers"]
    assert "mechanism_separation_check_passed" in revalidated.iloc[0]["qualification_blockers"]


def test_qualify_control_rows_requires_full_conjunction() -> None:
    rows = pd.DataFrame([_qualified_candidate_row(), _invalid_candidate_row()])
    qualified = qualify_control_rows(rows)
    assert qualified["candidate_status"].tolist() == ["QUALIFIED_CONTROL", "CANDIDATE_CONTROL"]
    assert qualified["qualified_control"].tolist() == [True, False]
    assert qualified["candidate_row_valid"].tolist() == [True, True]
    assert qualified["qualification_blockers"].tolist() == ["", "censoring_status,independent_outcome_reviewer_owner"]


def test_control_cohort_structure_requires_exact_cases_ranks_and_unique_identities() -> None:
    rows: list[dict[str, object]] = []
    for case_number in (1, 2):
        for rank in (1, 2):
            row = _qualified_candidate_row()
            row["case_name"] = f"case-{case_number}"
            row["match_set_id"] = f"match-{case_number}"
            row["control_rank"] = rank
            row["contract_address"] = "0x" + f"{case_number * 10 + rank:040x}"
            row["deterministic_rank_sha256"] = f"{case_number * 2 + rank:x}" * 64
            row["deterministic_rank_sha256"] = row["deterministic_rank_sha256"][:64]
            row["control_row_sha256"] = make_control_row_sha256(row)
            rows.append(row)
    revalidated = qualify_control_rows(pd.DataFrame(rows))

    report = verify_control_cohort_structure(
        revalidated,
        valid_column="qualified_control",
        expected_case_names=["case-1", "case-2"],
        controls_per_positive=2,
    )

    assert report["passed"] is True
    assert report["cohort_blockers"] == []
    assert report["observed_valid_rows"] == 4
    assert report["unique_chain_control_identities"] == 4


def test_qualify_control_rows_requires_all_eight_named_checks() -> None:
    row = _qualified_candidate_row()
    row["mechanism_separation_check_passed"] = False
    row["control_row_sha256"] = make_control_row_sha256(row)
    qualified = qualify_control_rows(pd.DataFrame([row]))
    assert qualified.iloc[0]["qualified_control"] == False
    assert "mechanism_separation_check_passed" in qualified.iloc[0]["qualification_blockers"]


def test_pending_but_provenance_valid_candidate_is_not_yet_qualified() -> None:
    row = _pending_candidate_row()
    qualified = qualify_control_rows(pd.DataFrame([row]))
    assert qualified.iloc[0]["candidate_row_valid"] == True
    assert qualified.iloc[0]["qualified_control"] == False
    assert qualified.iloc[0]["candidate_status"] == "CANDIDATE_CONTROL"
    assert qualified.iloc[0]["qualification_blockers"] == (
        "censoring_status,investigated_negative_status,independent_outcome_review_status,"
        "independent_outcome_reviewer_identity,independent_outcome_reviewer_owner,"
        "independent_outcome_reviewer_conflict_clear,independent_outcome_reviewer_confidence,"
        "independent_outcome_decision_sha256"
    )


def test_spoofed_prelabelled_qualified_row_fails_without_provenance_hash_and_reviewer_evidence() -> None:
    row = _qualified_candidate_row()
    row["candidate_status"] = "QUALIFIED_CONTROL"
    row["control_row_sha256"] = "0" * 64
    row["independent_outcome_reviewer_identity"] = "PUBLIC_LABEL"
    qualified = qualify_control_rows(pd.DataFrame([row]))
    assert qualified.iloc[0]["qualified_control"] == False
    assert qualified.iloc[0]["candidate_row_valid"] == False
    assert qualified.iloc[0]["candidate_status"] == "CANDIDATE_CONTROL"
    assert "control_row_sha256" in qualified.iloc[0]["qualification_blockers"]
    assert "independent_outcome_reviewer_identity" in qualified.iloc[0]["qualification_blockers"]


def test_any_missing_gate_yields_zero_release() -> None:
    release_inputs = {
        "historical_snapshots_ready": True,
        "independent_adjudications_ready": True,
        "deployment_denominator_ready": True,
        "control_candidates_ready": True,
        "qualified_controls_ready": True,
        "independent_r5_blocks_ready": True,
        "case_hash_bound": True,
        "case_schema_valid": True,
        "case_not_stale": True,
        "policy_thresholds_met": True,
    }
    for gate_name in tuple(release_inputs):
        broken = dict(release_inputs)
        broken[gate_name] = False
        result = verify_release_eligibility(
            pd.DataFrame([{"case_name": "case-1", **broken}])
        )
        assert result["release_eligible_cases"] == 0
        assert result["eligible_case_names"] == []


def _qualified_candidate_row() -> dict[str, object]:
    row = {
        "case_name": "case-1",
        "match_set_id": "match-1",
        "control_rank": 1,
        "chain": "ethereum",
        "contract_address": "0x" + "aa" * 20,
        "deployment_time": "2024-01-20T00:00:00Z",
        "positive_prediction_cutoff_time": "2024-02-01T00:00:00Z",
        "deployed_by_positive_cutoff": True,
        "code_size": 1180,
        "proxy_status": "none",
        "source_verified_at_cutoff": True,
        "deterministic_rank_sha256": "d" * 64,
        "candidate_status": "CANDIDATE_CONTROL",
        "follow_up_start": "2024-02-01T00:00:00Z",
        "follow_up_horizon": "2024-08-01T00:00:00Z",
        "censoring_status": "FROZEN_COMPLETE",
        "investigated_negative_status": "INVESTIGATED_NEGATIVE_MATURE",
        "independent_outcome_review_status": "INDEPENDENT_HUMAN_REVIEW_COMPLETE",
        "denominator_record_sha256": "2" * 64,
        "source_manifest_sha256": "1" * 64,
        "identity_linkage_free": True,
        "clone_linkage_free": True,
        "proxy_linkage_free": True,
        "protocol_linkage_free": True,
        "mechanism_separation_free": True,
        "independent_outcome_reviewer_identity": "reviewer-control-1",
        "independent_outcome_reviewer_owner": "owner-control-1",
        "independent_outcome_reviewer_conflict_clear": True,
        "independent_outcome_reviewer_confidence": "high",
        "independent_outcome_decision_sha256": "e" * 64,
        "maturity_check_passed": True,
        "maturity_check_sha256": "1" * 64,
        "censoring_check_passed": True,
        "censoring_check_sha256": "2" * 64,
        "temporal_check_passed": True,
        "temporal_check_sha256": "3" * 64,
        "lineage_check_passed": True,
        "lineage_check_sha256": "4" * 64,
        "clone_check_passed": True,
        "clone_check_sha256": "5" * 64,
        "proxy_check_passed": True,
        "proxy_check_sha256": "6" * 64,
        "protocol_check_passed": True,
        "protocol_check_sha256": "7" * 64,
        "mechanism_separation_check_passed": True,
        "mechanism_separation_check_sha256": "8" * 64,
    }
    row["control_row_sha256"] = make_control_row_sha256(row)
    return row


def _invalid_candidate_row() -> dict[str, object]:
    row = _qualified_candidate_row()
    row["contract_address"] = "0x" + "ff" * 20
    row["control_rank"] = 2
    row["deterministic_rank_sha256"] = "f" * 64
    row["censoring_status"] = "PENDING"
    row["independent_outcome_reviewer_owner"] = "SAME_OWNER"
    row["control_row_sha256"] = make_control_row_sha256(row)
    return row


def _pending_candidate_row() -> dict[str, object]:
    row = _qualified_candidate_row()
    row["censoring_status"] = "PENDING_FROZEN_FOLLOW_UP"
    row["investigated_negative_status"] = "PENDING_INVESTIGATED_NEGATIVE"
    row["independent_outcome_review_status"] = "PENDING_INDEPENDENT_OUTCOME_REVIEW"
    row["independent_outcome_reviewer_identity"] = ""
    row["independent_outcome_reviewer_owner"] = ""
    row["independent_outcome_reviewer_conflict_clear"] = False
    row["independent_outcome_reviewer_confidence"] = ""
    row["independent_outcome_decision_sha256"] = ""
    row["control_row_sha256"] = make_control_row_sha256(row)
    return row
