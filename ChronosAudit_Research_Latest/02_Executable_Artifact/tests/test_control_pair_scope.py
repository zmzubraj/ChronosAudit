from __future__ import annotations

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_pair_scope import (
    ControlPairScopeError,
    build_control_pair_acquisition_scope,
    build_denominator_expansion_requirements,
    maximum_no_reuse_allocation,
)


def _positives() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "target_contract_address": "0x" + "11" * 20,
                "deployment_time": "2024-01-15T00:00:00Z",
                "prediction_cutoff_time": "2024-02-01T00:00:00Z",
                "positive_record_sha256": "1" * 64,
            }
        ]
    )


def _denominator() -> pd.DataFrame:
    rows = [
        ("eligible", "ethereum", "22", "2024-01-20T00:00:00Z", True),
        ("future", "ethereum", "33", "2024-02-02T00:00:00Z", True),
        ("other-chain", "base", "44", "2024-01-20T00:00:00Z", True),
        ("outside-caliper", "ethereum", "55", "2023-11-01T00:00:00Z", True),
        ("positive-address", "ethereum", "11", "2024-01-15T00:00:00Z", True),
    ]
    return pd.DataFrame(
        [
            {
                "deployment_id": deployment_id,
                "chain": chain,
                "contract_address": "0x" + address_byte * 20,
                "deployment_time": deployment_time,
                "source_record_sha256": f"{index + 2:064x}",
                "source_manifest_sha256": "a" * 64,
                "row_evidence_sha256": f"{index + 20:064x}",
                "authority_projection_sha256": "b" * 64,
                "counter_authority": authorized,
            }
            for index, (
                deployment_id,
                chain,
                address_byte,
                deployment_time,
                authorized,
            ) in enumerate(rows)
        ]
    )


def test_pair_scope_uses_only_cutoff_safe_deployment_risk_set() -> None:
    scope, manifest = build_control_pair_acquisition_scope(
        positives=_positives(), denominator=_denominator(), deployment_window_days=30
    )

    assert scope[["case_name", "control_address"]].to_dict("records") == [
        {"case_name": "case-1", "control_address": "0x" + "22" * 20}
    ]
    row = scope.iloc[0]
    assert row["required_covariate_cutoff_time"] == "2024-02-01T00:00:00Z"
    assert row["denominator_record_sha256"] == f"{2:064x}"
    assert row["scope_status"] == "PAIR_COVARIATE_EVIDENCE_REQUIRED"
    assert row["selection_authorized"] == False
    assert len(row["pair_scope_record_sha256"]) == 64
    assert manifest["selection_authorized"] is False
    assert manifest["pair_count"] == 1
    assert manifest["per_case_pair_counts"] == {"case-1": 1}
    assert manifest["feasibility"]["decision"] == (
        "REDESIGN_REQUIRED_INSUFFICIENT_DEPLOYMENT_RISK_SET"
    )
    assert manifest["feasibility"]["unique_control_identities"] == 1
    assert manifest["feasibility"]["no_reuse_control_row_upper_bound"] == 1
    assert manifest["feasibility"]["cases_under_required_controls"] == 1


def test_pair_scope_is_unchanged_by_post_cutoff_or_outcome_columns() -> None:
    denominator = _denominator()
    baseline, _ = build_control_pair_acquisition_scope(
        positives=_positives(), denominator=denominator
    )
    denominator["mechanism_family"] = "outcome-derived"
    denominator["post_cutoff_activity"] = "arbitrary"
    repeated, _ = build_control_pair_acquisition_scope(
        positives=_positives(), denominator=denominator
    )

    assert repeated.to_dict("records") == baseline.to_dict("records")


def test_pair_scope_preserves_zero_for_case_with_no_eligible_denominator() -> None:
    positives = _positives().assign(chain="arbitrum")
    scope, manifest = build_control_pair_acquisition_scope(
        positives=positives, denominator=_denominator()
    )

    assert scope.empty
    assert "pair_scope_record_sha256" in scope.columns
    assert manifest["pair_count"] == 0
    assert manifest["per_case_pair_counts"] == {"case-1": 0}
    assert manifest["feasibility"]["cases_with_zero_pairs"] == 1


def test_pair_scope_rejects_unauthorized_or_hash_invalid_denominator() -> None:
    unauthorized = _denominator()
    unauthorized.loc[0, "counter_authority"] = False
    with pytest.raises(ControlPairScopeError, match="denominator_unauthorized_row"):
        build_control_pair_acquisition_scope(
            positives=_positives(), denominator=unauthorized
        )

    invalid_hash = _denominator()
    invalid_hash.loc[0, "source_record_sha256"] = "not-a-hash"
    with pytest.raises(ControlPairScopeError, match="source_record_sha256_invalid"):
        build_control_pair_acquisition_scope(
            positives=_positives(), denominator=invalid_hash
        )


def test_maximum_no_reuse_allocation_uses_augmenting_paths() -> None:
    scope = pd.DataFrame(
        [
            {"case_name": "case-1", "chain": "ethereum", "control_address": "a"},
            {"case_name": "case-1", "chain": "ethereum", "control_address": "b"},
            {"case_name": "case-2", "chain": "ethereum", "control_address": "a"},
        ]
    )

    result = maximum_no_reuse_allocation(scope, controls_per_positive=1)

    assert result["maximum_assignable_controls"] == 2
    assert result["minimum_cut_capacity"] == 2
    assert result["max_flow_min_cut_verified"] is True
    assert result["total_shortfall"] == 0
    assert result["per_case_allocated"] == {"case-1": 1, "case-2": 1}


def test_maximum_no_reuse_allocation_caps_each_case_at_required_controls() -> None:
    scope = pd.DataFrame(
        [
            {"case_name": "case-1", "chain": "ethereum", "control_address": str(i)}
            for i in range(12)
        ]
    )

    result = maximum_no_reuse_allocation(scope, controls_per_positive=10)

    assert result["maximum_assignable_controls"] == 10
    assert result["minimum_cut_capacity"] == 10
    assert result["per_case_allocated"] == {"case-1": 10}


def test_expansion_requirements_bind_case_cutoff_and_exact_shortfall() -> None:
    scope, _ = build_control_pair_acquisition_scope(
        positives=_positives(), denominator=_denominator()
    )

    requirements, manifest = build_denominator_expansion_requirements(
        positives=_positives(), scope=scope, controls_per_positive=10
    )

    row = requirements.iloc[0]
    assert row["admissible_deployment_start"] == "2023-12-16T00:00:00Z"
    assert row["admissible_deployment_end"] == "2024-02-01T00:00:00Z"
    assert row["existing_pair_count"] == 1
    assert row["maximum_flow_allocated"] == 1
    assert row["minimum_additional_distinct_slots"] == 9
    assert row["selection_authorized"] == False
    assert len(row["expansion_requirement_sha256"]) == 64
    assert manifest["minimum_additional_distinct_slots"] == 9
    assert manifest["sufficiency"] == "NECESSARY_NOT_SUFFICIENT_BEFORE_COVARIATE_FILTERS"
