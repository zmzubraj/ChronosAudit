from __future__ import annotations

import hashlib
import json

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_denominator_expansion_chunks import (
    ControlDenominatorExpansionChunkError,
    build_control_denominator_expansion_chunks,
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _requirement(case_name: str, deficit: int, index: int) -> dict[str, object]:
    record: dict[str, object] = {
        "case_name": case_name,
        "chain": "ethereum" if index % 2 else "bsc",
        "positive_deployment_time": "2024-01-15T00:00:00Z",
        "positive_prediction_cutoff_time": "2024-02-01T00:00:00Z",
        "positive_record_sha256": f"{index + 1:064x}",
        "admissible_deployment_start": "2023-12-16T00:00:00Z",
        "admissible_deployment_end": "2024-02-01T00:00:00Z",
        "existing_pair_count": 10 - deficit,
        "maximum_flow_allocated": 10 - deficit,
        "controls_required": 10,
        "minimum_additional_distinct_slots": deficit,
        "require_new_chain_address_identity": True,
        "require_deployed_by_positive_cutoff": True,
        "require_pair_specific_cutoff_covariates": True,
        "expansion_status": (
            "HISTORICAL_DENOMINATOR_EXPANSION_REQUIRED"
            if deficit
            else "NO_DEPLOYMENT_SCOPE_DEFICIT"
        ),
        "selection_authorized": False,
    }
    record["expansion_requirement_sha256"] = _canonical_sha256(record)
    return record


def _hashes() -> dict[str, str]:
    return {
        "expansion_ledger_sha256": "a" * 64,
        "pair_scope_manifest_sha256": "b" * 64,
        "authority_projection_sha256": "c" * 64,
        "policy_sha256": "d" * 64,
    }


def test_chunk_plan_is_deterministic_disjoint_and_preserves_shortfall() -> None:
    requirements = pd.DataFrame(
        [_requirement(f"case-{index:03d}", index % 10 + 1, index) for index in range(27)]
        + [_requirement("complete-case", 0, 99)]
    )

    first, first_manifest = build_control_denominator_expansion_chunks(
        requirements=requirements, max_cases_per_chunk=10, **_hashes()
    )
    second, second_manifest = build_control_denominator_expansion_chunks(
        requirements=requirements.sample(frac=1, random_state=7),
        max_cases_per_chunk=10,
        **_hashes(),
    )

    assert first.to_dict("records") == second.to_dict("records")
    assert first_manifest == second_manifest
    assert first["case_name"].is_unique
    assert len(first) == 27
    assert first["chunk_id"].nunique() == 3
    assert first.groupby("chunk_id").size().max() == 10
    assert int(first["minimum_additional_distinct_slots"].sum()) == sum(
        index % 10 + 1 for index in range(27)
    )
    assert first_manifest["cases_requiring_expansion"] == 27
    assert first_manifest["rpc_authorized"] is False
    assert first_manifest["acquisition_authorized"] is False
    assert first_manifest["selection_authorized"] is False
    assert first_manifest["case_overlap_count"] == 0
    assert first_manifest["requirement_overlap_count"] == 0


def test_chunk_plan_rejects_duplicate_case_or_requirement_hash() -> None:
    duplicate_case = pd.DataFrame(
        [_requirement("case-1", 2, 1), _requirement("case-1", 3, 2)]
    )
    with pytest.raises(
        ControlDenominatorExpansionChunkError, match="duplicate_case_name"
    ):
        build_control_denominator_expansion_chunks(
            requirements=duplicate_case, max_cases_per_chunk=10, **_hashes()
        )

    duplicate_hash = pd.DataFrame(
        [_requirement("case-1", 2, 1), _requirement("case-2", 3, 2)]
    )
    duplicate_hash.loc[1, "expansion_requirement_sha256"] = duplicate_hash.loc[
        0, "expansion_requirement_sha256"
    ]
    with pytest.raises(
        ControlDenominatorExpansionChunkError, match="duplicate_requirement_hash"
    ):
        build_control_denominator_expansion_chunks(
            requirements=duplicate_hash, max_cases_per_chunk=10, **_hashes()
        )


def test_chunk_plan_rejects_invalid_hash_or_negative_deficit() -> None:
    invalid_hash = pd.DataFrame([_requirement("case-1", 2, 1)])
    invalid_hash.loc[0, "expansion_requirement_sha256"] = "not-a-hash"
    with pytest.raises(
        ControlDenominatorExpansionChunkError, match="requirement_hash_invalid"
    ):
        build_control_denominator_expansion_chunks(
            requirements=invalid_hash, max_cases_per_chunk=10, **_hashes()
        )

    negative = pd.DataFrame([_requirement("case-1", 2, 1)])
    negative.loc[0, "minimum_additional_distinct_slots"] = -1
    with pytest.raises(
        ControlDenominatorExpansionChunkError, match="deficit_invalid"
    ):
        build_control_denominator_expansion_chunks(
            requirements=negative, max_cases_per_chunk=10, **_hashes()
        )


def test_chunk_plan_rejects_invalid_governance_hash() -> None:
    hashes = _hashes()
    hashes["policy_sha256"] = "bad"
    with pytest.raises(
        ControlDenominatorExpansionChunkError, match="policy_sha256_invalid"
    ):
        build_control_denominator_expansion_chunks(
            requirements=pd.DataFrame([_requirement("case-1", 2, 1)]),
            max_cases_per_chunk=10,
            **hashes,
        )
