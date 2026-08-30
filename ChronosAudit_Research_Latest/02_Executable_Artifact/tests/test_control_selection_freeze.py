from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_selection_freeze import (
    ControlSelectionFreezeError,
    build_frozen_control_cohort,
    replace_frozen_candidate,
    verify_frozen_control_cohort,
)
from chronosaudit_stage2.public_acquisition.qualification import qualify_control_rows


def _cases() -> pd.DataFrame:
    rows = []
    for index, case_name in enumerate(("case-1", "case-2"), start=1):
        rows.append(
            {
                "case_name": case_name,
                "chain": "ethereum",
                "target_contract_address": "0x" + f"{index:02x}" * 20,
                "prediction_cutoff_time": "2024-02-01T00:00:00Z",
                "deployment_time": "2024-01-01T00:00:00Z",
                "code_size": 1_000,
                "proxy_status": "none",
                "source_verified_at_cutoff": False,
                "identity_group": f"positive-id-{index}",
                "clone_family": f"positive-clone-{index}",
                "proxy_family": f"positive-proxy-{index}",
                "protocol_family": f"positive-protocol-{index}",
                "mechanism_family": f"positive-mechanism-{index}",
                "follow_up_horizon": "2024-08-01T00:00:00Z",
                "positive_record_sha256": f"{index:x}" * 64,
            }
        )
    return pd.DataFrame(rows)


def _candidate(case_name: str, suffix: int, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "case_name": case_name,
        "chain": "ethereum",
        "contract_address": "0x" + f"{suffix:02x}" * 20,
        "deployment_time": "2024-01-20T00:00:00Z",
        "code_size": 1_000,
        "proxy_status": "none",
        "source_verified_at_cutoff": False,
        "identity_group": f"control-id-{suffix}",
        "clone_family": f"control-clone-{suffix}",
        "proxy_family": f"control-proxy-{suffix}",
        "protocol_family": f"control-protocol-{suffix}",
        "source_record_sha256": f"{suffix % 15 + 1:x}" * 64,
        "source_manifest_sha256": "a" * 64,
        "counter_authority": True,
        "covariate_cutoff_time": "2024-02-01T00:00:00Z",
        "pair_scope_record_sha256": "b" * 64,
        "runtime_code_evidence_sha256": "c" * 64,
        "proxy_evidence_sha256": "d" * 64,
        "source_verification_evidence_sha256": "e" * 64,
        "protocol_evidence_sha256": "f" * 64,
        "pair_covariate_record_sha256": "9" * 64,
    }
    row.update(overrides)
    return row


def _candidates() -> pd.DataFrame:
    return pd.DataFrame(
        [
            _candidate("case-1", 101),
            _candidate("case-1", 102),
            _candidate("case-1", 199),
            _candidate("case-2", 103),
            _candidate("case-2", 104),
            _candidate("case-2", 199),
        ]
    )


def _horizon() -> dict[str, object]:
    return {
        "decision": "DYNAMIC_HORIZON_GATE_VERIFIED_NON_AUTHORIZING",
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "pair_feature_manifest_sha256": "7" * 64,
        "dynamic_horizon_spec_sha256": "8" * 64,
    }


def _bindings() -> dict[str, str]:
    return {
        "policy_sha256": "1" * 64,
        "queue_sha256": "2" * 64,
        "denominator_sha256": "3" * 64,
        "pair_scope_sha256": "4" * 64,
        "pair_feature_manifest_sha256": "7" * 64,
        "horizon_sha256": "8" * 64,
        "positive_authority_sha256": "6" * 64,
    }


def _admission() -> dict[str, object]:
    return {
        "schema_version": (
            "chronosaudit.denominator_expansion_admission_verification.v1"
        ),
        "decision": "DENOMINATOR_EXPANSION_ADMISSION_VERIFIED",
        "authorized_denominator_sha256": "3" * 64,
        "expected_case_count": 2,
        "controls_per_positive": 2,
        "target_control_rows": 4,
        "maximum_assignable_controls": 4,
        "denominator_qualifies": True,
        "counter_authority": True,
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def _freeze(tmp_path: Path, candidates: pd.DataFrame | None = None) -> dict[str, object]:
    return build_frozen_control_cohort(
        cases=_cases(),
        candidates=_candidates() if candidates is None else candidates,
        horizon_manifest=_horizon(),
        denominator_admission_verification=_admission(),
        output_root=tmp_path,
        authority_bindings=_bindings(),
        expected_case_count=2,
        controls_per_positive=2,
    )


def test_selection_is_exact_global_no_reuse_and_deterministic(tmp_path: Path) -> None:
    first = _freeze(tmp_path / "first")
    second = _freeze(tmp_path / "second", _candidates().sample(frac=1, random_state=11))

    assert first["status"] == "FROZEN_COMPLETE"
    cohort = pd.read_csv(first["cohort_path"], keep_default_na=False)
    assert len(cohort) == 4
    assert cohort.groupby("case_name").size().eq(2).all()
    assert not cohort.duplicated(["chain", "contract_address"]).any()
    assert cohort.groupby("case_name")["control_rank"].apply(list).tolist() == [[1, 2], [1, 2]]
    assert Path(first["cohort_path"]).read_bytes() == Path(second["cohort_path"]).read_bytes()
    assert first["allocation_min_cut_audit_sha256"] == second["allocation_min_cut_audit_sha256"]
    assert verify_frozen_control_cohort(Path(first["manifest_path"]))["complete"] is True
    assert qualify_control_rows(cohort)["candidate_row_valid"].all()


def test_positive_address_and_unknown_vs_unknown_are_excluded(tmp_path: Path) -> None:
    candidates = _candidates()
    candidates.loc[0, "contract_address"] = _cases().iloc[0]["target_contract_address"]
    candidates.loc[1, "proxy_family"] = "unknown"
    cases = _cases()
    cases.loc[0, "proxy_family"] = "unknown"

    result = build_frozen_control_cohort(
        cases=cases,
        candidates=candidates,
        horizon_manifest=_horizon(),
        denominator_admission_verification=_admission(),
        output_root=tmp_path,
        authority_bindings=_bindings(),
        expected_case_count=2,
        controls_per_positive=2,
    )

    assert result["status"] == "VERIFIED_SHORTFALL"
    assert result["max_allocated_rows"] < 4
    assert "cohort_path" not in result
    assert not (tmp_path / "frozen_control_cohort.csv").exists()


def test_insufficient_max_flow_suppresses_partial_cohort(tmp_path: Path) -> None:
    candidates = pd.DataFrame(
        [_candidate("case-1", 199), _candidate("case-2", 199)]
    )
    result = _freeze(tmp_path, candidates)

    assert result["status"] == "VERIFIED_SHORTFALL"
    assert result["max_allocated_rows"] == 1
    assert result["target_control_rows"] == 4
    assert "cohort_path" not in result
    manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
    assert manifest["counter_authority"] is False


def test_frozen_output_tampering_or_rank_gap_is_rejected(tmp_path: Path) -> None:
    frozen = _freeze(tmp_path)
    cohort_path = Path(frozen["cohort_path"])
    cohort = pd.read_csv(cohort_path)
    cohort.loc[0, "control_rank"] = 9
    cohort.to_csv(cohort_path, index=False, lineterminator="\n")

    with pytest.raises(ControlSelectionFreezeError, match="cohort_sha256_mismatch"):
        verify_frozen_control_cohort(Path(frozen["manifest_path"]))


def test_candidate_outcome_columns_are_rejected(tmp_path: Path) -> None:
    candidates = _candidates()
    candidates["exploit_outcome"] = "negative"

    with pytest.raises(ControlSelectionFreezeError, match="pre_freeze_outcome_column"):
        _freeze(tmp_path, candidates)


def test_horizon_and_binding_must_be_verified_and_consistent(tmp_path: Path) -> None:
    horizon = _horizon()
    horizon["decision"] = "UNVERIFIED"
    with pytest.raises(ControlSelectionFreezeError, match="horizon_not_verified"):
        build_frozen_control_cohort(
            cases=_cases(), candidates=_candidates(), horizon_manifest=horizon,
            denominator_admission_verification=_admission(),
            output_root=tmp_path, authority_bindings=_bindings(),
            expected_case_count=2, controls_per_positive=2,
        )


def test_selection_requires_authorizing_denominator_admission(
    tmp_path: Path,
) -> None:
    admission = _admission()
    admission["counter_authority"] = False

    with pytest.raises(
        ControlSelectionFreezeError,
        match="denominator_admission_not_authorizing",
    ):
        build_frozen_control_cohort(
            cases=_cases(),
            candidates=_candidates(),
            horizon_manifest=_horizon(),
            denominator_admission_verification=admission,
            output_root=tmp_path,
            authority_bindings=_bindings(),
            expected_case_count=2,
            controls_per_positive=2,
        )


def test_frozen_candidate_cannot_be_replaced_after_review(tmp_path: Path) -> None:
    frozen = _freeze(tmp_path)
    with pytest.raises(
        ControlSelectionFreezeError, match="post_freeze_replacement_forbidden"
    ):
        replace_frozen_candidate(frozen, failed_rank=1, replacement=_candidate("case-1", 250))
