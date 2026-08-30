from __future__ import annotations

import hashlib
import json
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pandas as pd

from chronosaudit_stage2.public_acquisition.counters import (
    HISTORICAL_SNAPSHOT_OVERLAY_FIELDS,
    build_review_bundle,
    build_counter_artifact,
    canonical_manifest_sha256,
    make_independent_adjudication_binding_sha256,
    make_control_row_sha256,
    overlay_historical_snapshot_projection,
    project_counters,
    qualify_control_rows,
)

_PRODUCTION_QUALIFICATION_PATH = Path(__file__).resolve().parents[1] / "production_qualification.py"
_PRODUCTION_QUALIFICATION_SPEC = importlib.util.spec_from_file_location("production_qualification", _PRODUCTION_QUALIFICATION_PATH)
assert _PRODUCTION_QUALIFICATION_SPEC and _PRODUCTION_QUALIFICATION_SPEC.loader
production_qualification = importlib.util.module_from_spec(_PRODUCTION_QUALIFICATION_SPEC)
_PRODUCTION_QUALIFICATION_SPEC.loader.exec_module(production_qualification)


def _counter_targets() -> dict[str, int]:
    return {
        "deployment_denominator_required": 20000,
        "deployment_denominator_per_chain": {
            "ethereum": 5000,
            "bsc": 5000,
            "base": 5000,
            "arbitrum": 5000,
        },
        "control_candidates_required": 4170,
        "qualified_controls_required": 4170,
        "independent_r5_blocks_required": 120,
    }


def _evidence_fixture() -> dict[str, object]:
    positives = pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "historical_snapshot_status": "VERIFIED",
                "historical_snapshot_source_receipt_sha256": "1" * 64,
                "historical_snapshot_identity_receipt_sha256": "2" * 64,
                "historical_snapshot_source_provider_family": "archive_rpc",
                "historical_snapshot_identity_provider_family": "block_receipts",
                "historical_snapshot_schema_valid": True,
                "historical_snapshot_hash_bound": True,
                "review_decision_status": "PENDING",
                "decision_schema_valid": False,
                "decision_hash_bound": False,
                "review_agreement_status": "",
                "final_decision_sha256": "",
                "final_decision_input_binding_sha256": "",
                "decision_case_schema_valid": False,
                "decision_case_hash_bound": False,
                "decision_case_stale": True,
                "reviewer_a_identity": "",
                "reviewer_a_owner": "",
                "reviewer_a_conflict_clear": False,
                "reviewer_a_confidence": "",
                "reviewer_a_started_at_utc": "2026-08-17T08:00:00Z",
                "reviewer_a_completed_at_utc": "2026-08-17T08:30:00Z",
                "reviewer_a_packet_sha256": "a" * 64,
                "reviewer_a_decision_sha256": "",
                "reviewer_b_identity": "",
                "reviewer_b_owner": "",
                "reviewer_b_conflict_clear": False,
                "reviewer_b_confidence": "",
                "reviewer_b_started_at_utc": "2026-08-17T08:05:00Z",
                "reviewer_b_completed_at_utc": "2026-08-17T08:40:00Z",
                "reviewer_b_packet_sha256": "b" * 64,
                "reviewer_b_decision_sha256": "",
                "final_decision_completed_at_utc": "2026-08-17T08:45:00Z",
                "third_adjudicator_identity": "",
                "third_adjudicator_owner": "",
                "third_adjudicator_conflict_clear": False,
                "third_adjudicator_confidence": "",
                "third_adjudicator_started_at_utc": "",
                "third_adjudicator_completed_at_utc": "",
                "third_adjudicator_packet_sha256": "",
                "third_adjudicator_decision_sha256": "",
                "mechanism_component_status": "PENDING",
                "lineage_component_status": "PENDING",
                "clone_leakage_free": False,
                "proxy_leakage_free": False,
                "protocol_leakage_free": False,
                "mechanism_leakage_free": False,
                "r5_component_hash_bound": False,
                "r5_component_schema_valid": False,
            }
        ]
    )
    denominator = pd.DataFrame(
        [{"deployment_id": "dep-1", "chain": "ethereum", "admissibility_status": "VERIFIED", "selection_rank_sha256": "3" * 64}]
    )
    controls = pd.DataFrame(
        [_qualified_control_row()]
    )
    positive_packets = build_review_bundle(
        positives,
        packet_type="positive_case_review_packets",
        blinding_seed="fixture-seed",
    )
    packet_sha256 = positive_packets[0]["packet_sha256"]
    positives.loc[0, "reviewer_a_packet_sha256"] = packet_sha256
    positives.loc[0, "reviewer_b_packet_sha256"] = packet_sha256
    return {
        "positive_cases": positives,
        "deployment_denominator": denominator,
        "control_rows": controls,
        "positive_case_review_packets": positive_packets,
        "control_review_packets": [],
        "finalized_positive_adjudications": [],
        "minimum_independent_r5_blocks": 120,
        "counter_targets": _counter_targets(),
    }


def test_historical_snapshot_overlay_rejects_unexpected_projection_columns() -> None:
    positives = pd.DataFrame([{"case_id": "C001", "case_name": "case-1"}])
    projection_row = {
        "case_id": "C001",
        "case_name": "case-1",
        **{field: "" for field in HISTORICAL_SNAPSHOT_OVERLAY_FIELDS},
        "unverified_extra": "must-not-enter-counter-inputs",
    }

    try:
        overlay_historical_snapshot_projection(positives, pd.DataFrame([projection_row]))
    except ValueError as exc:
        assert str(exc) == "historical_snapshot_projection_unexpected_columns:unverified_extra"
    else:
        raise AssertionError("unexpected historical projection columns must fail closed")


def test_build_review_bundle_hashes_and_blinding_are_immutable() -> None:
    rows = pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "incident_name": "Incident 1",
                "chain": "ethereum",
                "target_contract_address": "0x" + "11" * 20,
                "incident_date": "2024-02-20",
                "source_manifest_sha256": "4" * 64,
            }
        ]
    )
    bundle = build_review_bundle(rows, packet_type="positive_case_review_packets", blinding_seed="seed-1")
    assert bundle[0]["packet_type"] == "positive_case_review_packets"
    assert bundle[0]["packet_sha256"]
    assert bundle[0]["visible_fields"] == [
        "case_name",
        "incident_name",
        "chain",
        "target_contract_address",
        "incident_date",
    ]


def test_packets_do_not_increment_independent_adjudications() -> None:
    fixture = _evidence_fixture()
    fixture["positive_case_review_packets"] = [
        {"packet_id": "pos-1", "packet_sha256": "5" * 64},
        {"packet_id": "pos-2", "packet_sha256": "6" * 64},
    ]
    fixture["control_review_packets"] = [
        {"packet_id": "ctrl-1", "packet_sha256": "7" * 64},
    ]
    result = project_counters(fixture)
    assert result["independent_adjudications"]["observed"] == 0
    assert result["positive_case_review_packets"]["observed"] == 2
    assert result["control_review_packets"]["observed"] == 1


def test_candidates_do_not_increment_qualified_controls_without_revalidation() -> None:
    fixture = _evidence_fixture()
    fixture["control_rows"] = pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "contract_address": "0x" + "aa" * 20,
                "candidate_status": "CANDIDATE_CONTROL",
                "control_row_sha256": "0" * 64,
            },
            {
                "case_name": "case-1",
                "contract_address": "0x" + "bb" * 20,
                "candidate_status": "QUALIFIED_CONTROL",
                "control_row_sha256": "1" * 64,
            },
        ]
    )
    result = project_counters(fixture)
    assert result["control_candidates"]["observed"] == 0
    assert result["qualified_controls"]["observed"] == 0


def test_pending_but_provenance_valid_candidate_counts_only_as_control_candidate() -> None:
    fixture = _evidence_fixture()
    fixture["control_rows"] = pd.DataFrame([_pending_control_row()])
    result = project_counters(fixture)
    assert result["control_candidates"]["observed"] == 0
    assert result["control_candidates"]["required"] == 4170
    assert result["control_candidates"]["passed"] is False
    assert result["control_candidates"]["details"]["mechanically_valid_rows"] == 1
    assert result["control_candidates"]["details"]["selection_blocker"] == (
        "missing_control_selection_verification"
    )
    assert result["qualified_controls"]["observed"] == 0
    assert result["qualified_controls"]["passed"] is False


def test_malformed_pending_candidate_counts_as_neither_candidate_nor_qualified_control() -> None:
    fixture = _evidence_fixture()
    row = _pending_control_row()
    row["identity_linkage_free"] = False
    row["control_row_sha256"] = make_control_row_sha256(row)
    fixture["control_rows"] = pd.DataFrame([row])
    result = project_counters(fixture)
    assert result["control_candidates"]["observed"] == 0
    assert result["qualified_controls"]["observed"] == 0


def test_mature_human_reviewed_control_without_signed_authority_counts_only_as_candidate() -> None:
    fixture = _evidence_fixture()
    fixture["control_rows"] = pd.DataFrame([_qualified_control_row()])
    result = project_counters(fixture)
    assert result["control_candidates"]["observed"] == 0
    assert result["qualified_controls"]["observed"] == 0
    assert result["qualified_controls"]["details"]["authority_blocker"] == (
        "missing_control_qualification_verification"
    )


def test_signed_qualification_projection_binding_allows_qualified_counter() -> None:
    fixture = _evidence_fixture()
    row = _qualified_control_row()
    row["frozen_candidate_sha256"] = row["control_row_sha256"]
    row.update(
        {
            "candidate_status": "QUALIFIED_CONTROL",
            "selected_candidate_control_row_sha256": "9" * 64,
            "qualification_authority_verified": True,
            "qualification_request_sha256": "a" * 64,
            "qualification_approval_sha256": "b" * 64,
            "qualification_signature_sha256": "c" * 64,
            "qualification_allowed_signers_sha256": "d" * 64,
            "qualification_authority_principal": "qualification-authority@example.org",
            "qualification_evidence_batch_sha256": "e" * 64,
        }
    )
    row["control_row_sha256"] = make_control_row_sha256(row)
    controls = pd.DataFrame([row])
    revalidated = qualify_control_rows(controls)
    records = json.loads(
        revalidated.sort_values(
            ["case_name", "control_rank", "chain", "contract_address"],
            kind="stable",
        ).to_json(orient="records", date_format="iso")
    )
    fixture["control_rows"] = controls
    fixture["counter_targets"]["control_candidates_required"] = 1
    fixture["counter_targets"]["qualified_controls_required"] = 1
    fixture["control_selection_verification"] = {
        "decision": "FROZEN_CONTROL_COHORT_VERIFIED_NON_AUTHORIZING",
        "complete": True,
        "status": "FROZEN_COMPLETE",
        "target_control_rows": 1,
        "frozen_candidate_hashes_sha256": hashlib.sha256(
            json.dumps(
                [row["frozen_candidate_sha256"]],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest(),
        "counter_authority": False,
    }
    fixture["control_qualification_verification"] = {
        "schema_version": "chronosaudit.control_qualification_approval_verification.v1",
        "decision": "CONTROL_QUALIFICATION_APPROVAL_VERIFIED",
        "request_sha256": "a" * 64,
        "verified_check_records_sha256": "e" * 64,
        "approval_sha256": "b" * 64,
        "signature_sha256": "c" * 64,
        "allowed_signers_sha256": "d" * 64,
        "authority_principal": "qualification-authority@example.org",
        "authority_type": "ACCOUNTABLE_HUMAN",
        "authority_identity_binding_sha256": "f" * 64,
        "authority_identity_binding_verified": True,
        "candidate_rows": 1,
        "qualified_rows": 1,
        "qualified_records_sha256": hashlib.sha256(
            json.dumps(
                records, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest(),
        "qualification_projection_authorized": True,
        "counter_authority": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result = project_counters(fixture)
    assert result["qualified_controls"]["observed"] == 1, result["qualified_controls"]


def test_control_counter_rejects_row_count_only_duplicate_cohort() -> None:
    fixture = _evidence_fixture()
    fixture["control_rows"] = pd.DataFrame(
        [_qualified_control_row() for _ in range(4170)]
    )

    result = project_counters(fixture)

    assert result["control_candidates"]["observed"] == 0
    assert result["qualified_controls"]["observed"] == 0
    assert result["control_candidates"]["passed"] is False
    assert result["qualified_controls"]["passed"] is False
    assert result["control_candidates"]["details"]["mechanically_valid_rows"] == 4170
    assert result["control_candidates"]["details"]["selection_blocker"] == (
        "missing_control_selection_verification"
    )


def test_distinct_human_agreement_counts_as_independent_adjudication() -> None:
    fixture = _evidence_fixture()
    positives = fixture["positive_cases"].copy()
    positives.loc[0, "review_decision_status"] = "FINALIZED_INDEPENDENT_ADJUDICATION"
    positives.loc[0, "decision_schema_valid"] = True
    positives.loc[0, "decision_hash_bound"] = True
    positives.loc[0, "decision_case_schema_valid"] = True
    positives.loc[0, "decision_case_hash_bound"] = True
    positives.loc[0, "decision_case_stale"] = False
    positives.loc[0, "review_agreement_status"] = "REVIEWER_CONSENSUS"
    positives.loc[0, "reviewer_a_identity"] = "reviewer-a"
    positives.loc[0, "reviewer_a_owner"] = "owner-a"
    positives.loc[0, "reviewer_a_conflict_clear"] = True
    positives.loc[0, "reviewer_a_confidence"] = "high"
    positives.loc[0, "reviewer_a_decision_sha256"] = "4" * 64
    positives.loc[0, "reviewer_b_identity"] = "reviewer-b"
    positives.loc[0, "reviewer_b_owner"] = "owner-b"
    positives.loc[0, "reviewer_b_conflict_clear"] = True
    positives.loc[0, "reviewer_b_confidence"] = "very_high"
    positives.loc[0, "reviewer_b_decision_sha256"] = "5" * 64
    positives.loc[0, "final_decision_sha256"] = "6" * 64
    positives.loc[0, "final_decision_input_binding_sha256"] = make_independent_adjudication_binding_sha256(positives.iloc[0].to_dict())
    fixture["positive_cases"] = positives
    result = project_counters(fixture)
    assert result["independent_adjudications"]["observed"] == 1


def test_single_human_self_consensus_does_not_count_as_independent_adjudication() -> None:
    fixture = _evidence_fixture()
    positives = fixture["positive_cases"].copy()
    positives.loc[0, "review_decision_status"] = "FINALIZED_INDEPENDENT_ADJUDICATION"
    positives.loc[0, "decision_schema_valid"] = True
    positives.loc[0, "decision_hash_bound"] = True
    positives.loc[0, "decision_case_schema_valid"] = True
    positives.loc[0, "decision_case_hash_bound"] = True
    positives.loc[0, "decision_case_stale"] = False
    positives.loc[0, "review_agreement_status"] = "REVIEWER_CONSENSUS"
    positives.loc[0, "reviewer_a_identity"] = "reviewer-a"
    positives.loc[0, "reviewer_a_owner"] = "owner-a"
    positives.loc[0, "reviewer_a_conflict_clear"] = True
    positives.loc[0, "reviewer_a_confidence"] = "high"
    positives.loc[0, "reviewer_a_decision_sha256"] = "4" * 64
    positives.loc[0, "reviewer_b_identity"] = "reviewer-a"
    positives.loc[0, "reviewer_b_owner"] = "owner-a"
    positives.loc[0, "reviewer_b_conflict_clear"] = True
    positives.loc[0, "reviewer_b_confidence"] = "high"
    positives.loc[0, "reviewer_b_decision_sha256"] = "4" * 64
    positives.loc[0, "final_decision_sha256"] = "6" * 64
    positives.loc[0, "final_decision_input_binding_sha256"] = make_independent_adjudication_binding_sha256(positives.iloc[0].to_dict())
    fixture["positive_cases"] = positives
    result = project_counters(fixture)
    assert result["independent_adjudications"]["observed"] == 0


def test_missing_review_time_does_not_count_as_independent_adjudication() -> None:
    fixture = _evidence_fixture()
    positives = fixture["positive_cases"].copy()
    positives.loc[0, "review_decision_status"] = "FINALIZED_INDEPENDENT_ADJUDICATION"
    positives.loc[0, "decision_schema_valid"] = True
    positives.loc[0, "decision_hash_bound"] = True
    positives.loc[0, "decision_case_schema_valid"] = True
    positives.loc[0, "decision_case_hash_bound"] = True
    positives.loc[0, "decision_case_stale"] = False
    positives.loc[0, "review_agreement_status"] = "REVIEWER_CONSENSUS"
    positives.loc[0, "reviewer_a_identity"] = "reviewer-a"
    positives.loc[0, "reviewer_a_owner"] = "owner-a"
    positives.loc[0, "reviewer_a_conflict_clear"] = True
    positives.loc[0, "reviewer_a_confidence"] = "high"
    positives.loc[0, "reviewer_a_started_at_utc"] = ""
    positives.loc[0, "reviewer_a_decision_sha256"] = "4" * 64
    positives.loc[0, "reviewer_b_identity"] = "reviewer-b"
    positives.loc[0, "reviewer_b_owner"] = "owner-b"
    positives.loc[0, "reviewer_b_conflict_clear"] = True
    positives.loc[0, "reviewer_b_confidence"] = "high"
    positives.loc[0, "reviewer_b_decision_sha256"] = "5" * 64
    positives.loc[0, "final_decision_sha256"] = "6" * 64
    positives.loc[0, "final_decision_input_binding_sha256"] = make_independent_adjudication_binding_sha256(
        positives.iloc[0].to_dict()
    )
    fixture["positive_cases"] = positives
    result = project_counters(fixture)
    assert result["independent_adjudications"]["observed"] == 0


def test_same_owner_two_ids_do_not_count_as_independent_adjudication() -> None:
    fixture = _evidence_fixture()
    positives = fixture["positive_cases"].copy()
    positives.loc[0, "review_decision_status"] = "FINALIZED_INDEPENDENT_ADJUDICATION"
    positives.loc[0, "decision_schema_valid"] = True
    positives.loc[0, "decision_hash_bound"] = True
    positives.loc[0, "decision_case_schema_valid"] = True
    positives.loc[0, "decision_case_hash_bound"] = True
    positives.loc[0, "decision_case_stale"] = False
    positives.loc[0, "review_agreement_status"] = "REVIEWER_CONSENSUS"
    positives.loc[0, "reviewer_a_identity"] = "reviewer-a"
    positives.loc[0, "reviewer_a_owner"] = "same-owner"
    positives.loc[0, "reviewer_a_conflict_clear"] = True
    positives.loc[0, "reviewer_a_confidence"] = "high"
    positives.loc[0, "reviewer_a_decision_sha256"] = "4" * 64
    positives.loc[0, "reviewer_b_identity"] = "reviewer-b"
    positives.loc[0, "reviewer_b_owner"] = "same-owner"
    positives.loc[0, "reviewer_b_conflict_clear"] = True
    positives.loc[0, "reviewer_b_confidence"] = "high"
    positives.loc[0, "reviewer_b_decision_sha256"] = "5" * 64
    positives.loc[0, "final_decision_sha256"] = "6" * 64
    positives.loc[0, "final_decision_input_binding_sha256"] = make_independent_adjudication_binding_sha256(positives.iloc[0].to_dict())
    fixture["positive_cases"] = positives
    result = project_counters(fixture)
    assert result["independent_adjudications"]["observed"] == 0


def test_distinct_human_disagreement_requires_accountable_third_adjudicator() -> None:
    fixture = _evidence_fixture()
    positives = fixture["positive_cases"].copy()
    positives.loc[0, "review_decision_status"] = "FINALIZED_INDEPENDENT_ADJUDICATION"
    positives.loc[0, "decision_schema_valid"] = True
    positives.loc[0, "decision_hash_bound"] = True
    positives.loc[0, "decision_case_schema_valid"] = True
    positives.loc[0, "decision_case_hash_bound"] = True
    positives.loc[0, "decision_case_stale"] = False
    positives.loc[0, "review_agreement_status"] = "THIRD_ADJUDICATOR_COMPLETE"
    positives.loc[0, "reviewer_a_identity"] = "reviewer-a"
    positives.loc[0, "reviewer_a_owner"] = "owner-a"
    positives.loc[0, "reviewer_a_conflict_clear"] = True
    positives.loc[0, "reviewer_a_confidence"] = "high"
    positives.loc[0, "reviewer_a_decision_sha256"] = "4" * 64
    positives.loc[0, "reviewer_b_identity"] = "reviewer-b"
    positives.loc[0, "reviewer_b_owner"] = "owner-b"
    positives.loc[0, "reviewer_b_conflict_clear"] = True
    positives.loc[0, "reviewer_b_confidence"] = "high"
    positives.loc[0, "reviewer_b_decision_sha256"] = "5" * 64
    positives.loc[0, "third_adjudicator_identity"] = "adjudicator-c"
    positives.loc[0, "third_adjudicator_owner"] = "owner-c"
    positives.loc[0, "third_adjudicator_conflict_clear"] = True
    positives.loc[0, "third_adjudicator_confidence"] = "high"
    positives.loc[0, "third_adjudicator_started_at_utc"] = "2026-08-17T08:45:00Z"
    positives.loc[0, "third_adjudicator_completed_at_utc"] = "2026-08-17T09:10:00Z"
    positives.loc[0, "third_adjudicator_packet_sha256"] = "7" * 64
    positives.loc[0, "third_adjudicator_decision_sha256"] = "8" * 64
    positives.loc[0, "final_decision_completed_at_utc"] = "2026-08-17T09:15:00Z"
    positives.loc[0, "final_decision_sha256"] = "6" * 64
    positives.loc[0, "final_decision_input_binding_sha256"] = make_independent_adjudication_binding_sha256(positives.iloc[0].to_dict())
    fixture["positive_cases"] = positives
    result = project_counters(fixture)
    assert result["independent_adjudications"]["observed"] == 1


def test_historical_snapshots_require_strict_status_and_two_verified_operator_families() -> None:
    fixture = _evidence_fixture()
    result = project_counters(fixture)
    assert result["historical_snapshots"]["required"] == 1
    assert result["historical_snapshots"]["observed"] == 0
    assert not result["historical_snapshots"]["passed"]


def test_release_projection_stays_zero_on_missing_case_gates() -> None:
    fixture = _evidence_fixture()
    result = project_counters(fixture)
    assert result["release_eligible_cases"] == 0
    assert result["production_qualification"]["qualified"] is False


def test_project_counters_bind_required_targets_and_recompute_strict_numerators() -> None:
    fixture = _evidence_fixture()
    result = project_counters(fixture)

    assert result["historical_snapshots"] == {"required": 1, "observed": 0, "passed": False}
    assert result["independent_adjudications"] == {"required": 1, "observed": 0, "passed": False}
    assert result["deployment_denominator"]["required"] == 20000
    assert result["deployment_denominator"]["observed"] == 1
    assert result["deployment_denominator"]["passed"] is False
    assert result["deployment_denominator"]["details"]["per_chain_observed"] == {
        "arbitrum": 0,
        "base": 0,
        "bsc": 0,
        "ethereum": 1,
    }
    assert result["control_candidates"] == {
        "required": 4170,
        "observed": 0,
        "passed": False,
        "details": {
            "mechanically_valid_rows": 1,
            "selection_blocker": "missing_control_selection_verification",
        },
    }
    assert result["qualified_controls"] == {
        "required": 4170,
        "observed": 0,
        "passed": False,
        "details": {
            "scientifically_qualified_rows": 1,
            "authority_blocker": "missing_control_qualification_verification",
        },
    }
    assert result["independent_r5_blocks"] == {"required": 120, "observed": 0, "passed": False}


def test_deployment_denominator_requires_prespecified_per_chain_allocation() -> None:
    fixture = _evidence_fixture()
    fixture["deployment_denominator"] = pd.DataFrame(
        [
            {
                "deployment_id": f"dep-{index}",
                "chain": "ethereum",
                "admissibility_status": "VERIFIED",
                "selection_rank_sha256": f"{index:064x}"[-64:],
            }
            for index in range(1, 20001)
        ]
    )

    result = project_counters(fixture)

    assert result["deployment_denominator"]["required"] == 20000
    assert result["deployment_denominator"]["observed"] == 20000
    assert result["deployment_denominator"]["passed"] is False
    assert result["deployment_denominator"]["details"]["per_chain_observed"] == {
        "arbitrum": 0,
        "base": 0,
        "bsc": 0,
        "ethereum": 20000,
    }


def test_validate_production_qualification_rejects_forged_artifact_manifest_pair(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    forged = {
        "artifact_schema_version": "2026-08-08.task5",
        "input_manifest_sha256": manifest["input_manifest_sha256"],
        "counters": {
            "historical_snapshots": {"required": 1, "observed": 1, "passed": True},
            "independent_adjudications": {"required": 1, "observed": 1, "passed": True},
            "deployment_denominator": {"required": 1, "observed": 1, "passed": True},
            "control_candidates": {"required": 1, "observed": 1, "passed": True},
            "qualified_controls": {"required": 1, "observed": 1, "passed": True},
            "independent_r5_blocks": {"required": 120, "observed": 120, "passed": True},
            "release_eligible_cases": 1,
            "positive_case_review_packets": {"required": 0, "observed": 0, "passed": True},
            "control_review_packets": {"required": 0, "observed": 0, "passed": True},
            "finalized_positive_adjudications": {"required": 0, "observed": 0, "passed": True},
        },
    }
    artifact_path.write_text(json.dumps(forged, indent=2, sort_keys=True), encoding="utf-8")
    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )
    assert result["qualified"] is False
    assert "counter_projection_mismatch" in result["counter_artifact_errors"]


def test_validate_production_qualification_rejects_tampered_input_hash(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
    positive_path = fixture_dir / "positive_cases.csv"
    positives = pd.read_csv(positive_path)
    positives.loc[0, "historical_snapshot_status"] = "TAMPERED"
    positive_path.write_text(positives.to_csv(index=False), encoding="utf-8")
    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )
    assert result["qualified"] is False
    assert "input_file_sha256_mismatch:positive_cases" in result["counter_artifact_errors"]


def test_validate_production_qualification_accepts_runner_style_raw_file_sha256(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence, hash_mode="raw_bytes")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert "input_file_sha256_mismatch:positive_cases" not in result["counter_artifact_errors"]
    assert "input_file_sha256_mismatch:deployment_denominator" not in result["counter_artifact_errors"]


def test_validate_production_qualification_reports_invalid_utf8_json_input(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)

    _rewrite_manifest_input_and_artifact(
        manifest_path,
        artifact_path,
        evidence,
        "finalized_positive_adjudications",
        b"\xff\xfe\xfa",
    )

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "input_file_parse_error:finalized_positive_adjudications:UnicodeDecodeError" in result["counter_artifact_errors"]


def test_validate_production_qualification_reports_invalid_json_syntax_input(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)

    _rewrite_manifest_input_and_artifact(
        manifest_path,
        artifact_path,
        evidence,
        "finalized_positive_adjudications",
        b"{\"decision\": ]",
    )

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "input_file_parse_error:finalized_positive_adjudications:JSONDecodeError" in result["counter_artifact_errors"]


def test_validate_production_qualification_reports_malformed_csv_input(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)

    _rewrite_manifest_input_and_artifact(
        manifest_path,
        artifact_path,
        evidence,
        "control_rows",
        b"case_name,match_set_id\n\"unterminated,row\n",
    )

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "input_file_parse_error:control_rows:ParserError" in result["counter_artifact_errors"]


def test_validate_production_qualification_fail_closes_invalid_utf8_root_manifest(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    manifest_path.write_bytes(b"\xff\xfe\xfa")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert result["production_qualification_exit"] == 3
    assert result["counter_input_manifest_errors"] == [
        "counter_input_manifest_parse_error:UnicodeDecodeError"
    ]
    assert result["counter_artifact_errors"] == []


def test_validate_production_qualification_fail_closes_invalid_json_root_manifest(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    manifest_path.write_text("{\"inputs\": ]", encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert result["production_qualification_exit"] == 3
    assert result["counter_input_manifest_errors"] == [
        "counter_input_manifest_parse_error:JSONDecodeError"
    ]
    assert result["counter_artifact_errors"] == []


def test_validate_production_qualification_fail_closes_invalid_utf8_root_artifact(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    artifact_path.write_bytes(b"\xff\xfe\xfa")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert result["production_qualification_exit"] == 3
    assert result["counter_input_manifest_errors"] == []
    assert result["counter_artifact_errors"] == [
        "counter_artifact_parse_error:UnicodeDecodeError"
    ]


def test_validate_production_qualification_fail_closes_invalid_json_root_artifact(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    artifact_path.write_text("{\"counters\": ]", encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert result["production_qualification_exit"] == 3
    assert result["counter_input_manifest_errors"] == []
    assert result["counter_artifact_errors"] == [
        "counter_artifact_parse_error:JSONDecodeError"
    ]


def test_validate_production_qualification_fail_closes_non_object_root_manifest(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    manifest_path.write_text("[]", encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert result["production_qualification_exit"] == 3
    assert result["counter_input_manifest_errors"] == [
        "counter_input_manifest_parse_error:RootJsonTypeError"
    ]
    assert result["counter_artifact_errors"] == []


def test_validate_production_qualification_fail_closes_non_object_root_artifact(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    artifact_path.write_text("null", encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert result["production_qualification_exit"] == 3
    assert result["counter_input_manifest_errors"] == []
    assert result["counter_artifact_errors"] == [
        "counter_artifact_parse_error:RootJsonTypeError"
    ]


def test_validate_production_qualification_rejects_missing_counter_target_metadata(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("counter_targets")
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "missing_counter_targets" in result["counter_artifact_errors"]


def test_validate_production_qualification_rejects_missing_inputs_without_exception(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("inputs")
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "missing_manifest_inputs" in result["counter_artifact_errors"]


def test_validate_production_qualification_rejects_malformed_input_spec_without_exception(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["inputs"]["positive_cases"] = "not-a-dict"
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "invalid_manifest_input_spec:positive_cases" in result["counter_artifact_errors"]


def test_validate_production_qualification_rejects_tampered_counter_target_metadata(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["counter_targets"]["deployment_denominator_required"] = 19999
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "counter_targets_canonical_mismatch" in result["counter_artifact_errors"]


def test_validate_production_qualification_rejects_missing_per_chain_target(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["counter_targets"]["deployment_denominator_per_chain"].pop("arbitrum")
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "missing_deployment_denominator_per_chain_keys:arbitrum" in result["counter_artifact_errors"]


def test_validate_production_qualification_rejects_downgraded_canonical_targets_even_with_matching_artifact(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    lowered_targets = {
        "deployment_denominator_required": 1,
        "deployment_denominator_per_chain": {
            "ethereum": 1,
            "bsc": 0,
            "base": 0,
            "arbitrum": 0,
        },
        "control_candidates_required": 1,
        "qualified_controls_required": 1,
        "independent_r5_blocks_required": 0,
    }
    evidence["counter_targets"] = lowered_targets
    evidence["minimum_independent_r5_blocks"] = 0
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "counter_targets_canonical_mismatch" in result["counter_artifact_errors"]


def test_validate_production_qualification_rejects_malformed_counter_target_value_without_exception(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["counter_targets"]["independent_r5_blocks_required"] = "not-an-int"
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")

    result = production_qualification.evaluate_production_qualification(
        counter_artifact_path=artifact_path,
        counter_input_manifest_path=manifest_path,
    )

    assert result["qualified"] is False
    assert "invalid_counter_target_value:independent_r5_blocks_required" in result["counter_artifact_errors"]


def test_cli_rejects_forged_artifact_manifest_pair(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path = _write_manifest_inputs(fixture_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact_path = fixture_dir / "public_acquisition_counters.json"
    artifact_path.write_text(
        json.dumps(build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"]), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    positives = pd.read_csv(fixture_dir / "positive_cases.csv")
    positives.loc[0, "historical_snapshot_status"] = "TAMPERED"
    (fixture_dir / "positive_cases.csv").write_text(positives.to_csv(index=False), encoding="utf-8")
    output_path = fixture_dir / "production_qualification.json"
    env = {
        **os.environ,
        "CHRONOS_COUNTER_ARTIFACT_PATH": str(artifact_path),
        "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(manifest_path),
        "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(output_path),
    }
    completed = subprocess.run(
        [sys.executable, "production_qualification.py"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 3
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert "input_file_sha256_mismatch:positive_cases" in written["counter_artifact_errors"]


def test_cli_writes_output_json_on_invalid_utf8_manifest_input(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    _rewrite_manifest_input_and_artifact(
        manifest_path,
        artifact_path,
        evidence,
        "finalized_positive_adjudications",
        b"\xff\xfe\xfa",
    )

    output_path = fixture_dir / "production_qualification.json"
    env = {
        **os.environ,
        "CHRONOS_COUNTER_ARTIFACT_PATH": str(artifact_path),
        "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(manifest_path),
        "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(output_path),
    }

    completed = subprocess.run(
        [sys.executable, "production_qualification.py"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 3
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert "input_file_parse_error:finalized_positive_adjudications:UnicodeDecodeError" in payload["counter_artifact_errors"]


def test_cli_writes_output_json_on_invalid_json_root_manifest(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    manifest_path.write_text("{\"inputs\": ]", encoding="utf-8")

    output_path = fixture_dir / "production_qualification.json"
    env = {
        **os.environ,
        "CHRONOS_COUNTER_ARTIFACT_PATH": str(artifact_path),
        "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(manifest_path),
        "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(output_path),
    }

    completed = subprocess.run(
        [sys.executable, "production_qualification.py"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 3
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["counter_input_manifest_errors"] == [
        "counter_input_manifest_parse_error:JSONDecodeError"
    ]
    assert payload["counter_artifact_errors"] == []


def test_cli_writes_output_json_on_invalid_utf8_root_artifact(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    artifact_path.write_bytes(b"\xff\xfe\xfa")

    output_path = fixture_dir / "production_qualification.json"
    env = {
        **os.environ,
        "CHRONOS_COUNTER_ARTIFACT_PATH": str(artifact_path),
        "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(manifest_path),
        "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(output_path),
    }

    completed = subprocess.run(
        [sys.executable, "production_qualification.py"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 3
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["counter_input_manifest_errors"] == []
    assert payload["counter_artifact_errors"] == [
        "counter_artifact_parse_error:UnicodeDecodeError"
    ]


def test_cli_writes_output_json_on_non_object_root_manifest(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    manifest_path.write_text("[]", encoding="utf-8")

    output_path = fixture_dir / "production_qualification.json"
    env = {
        **os.environ,
        "CHRONOS_COUNTER_ARTIFACT_PATH": str(artifact_path),
        "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(manifest_path),
        "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(output_path),
    }

    completed = subprocess.run(
        [sys.executable, "production_qualification.py"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 3
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["counter_input_manifest_errors"] == [
        "counter_input_manifest_parse_error:RootJsonTypeError"
    ]
    assert payload["counter_artifact_errors"] == []


def test_cli_writes_output_json_on_non_object_root_artifact(tmp_path: Path) -> None:
    evidence = _evidence_fixture()
    fixture_dir = tmp_path / "fixture"
    fixture_dir.mkdir()
    manifest_path, artifact_path = _write_manifest_artifact_pair(fixture_dir, evidence)
    artifact_path.write_text("null", encoding="utf-8")

    output_path = fixture_dir / "production_qualification.json"
    env = {
        **os.environ,
        "CHRONOS_COUNTER_ARTIFACT_PATH": str(artifact_path),
        "CHRONOS_COUNTER_INPUT_MANIFEST_PATH": str(manifest_path),
        "CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH": str(output_path),
    }

    completed = subprocess.run(
        [sys.executable, "production_qualification.py"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 3
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["counter_input_manifest_errors"] == []
    assert payload["counter_artifact_errors"] == [
        "counter_artifact_parse_error:RootJsonTypeError"
    ]


def _qualified_control_row() -> dict[str, object]:
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


def _pending_control_row() -> dict[str, object]:
    row = _qualified_control_row()
    row["censoring_status"] = "PENDING_FROZEN_FOLLOW_UP"
    row["investigated_negative_status"] = "PENDING_INVESTIGATED_NEGATIVE"
    row["maturity_check_passed"] = False
    row["maturity_check_sha256"] = ""
    row["censoring_check_passed"] = False
    row["censoring_check_sha256"] = ""
    row["independent_outcome_review_status"] = "PENDING_INDEPENDENT_OUTCOME_REVIEW"
    row["independent_outcome_reviewer_identity"] = ""
    row["independent_outcome_reviewer_owner"] = ""
    row["independent_outcome_reviewer_conflict_clear"] = False
    row["independent_outcome_reviewer_confidence"] = ""
    row["independent_outcome_decision_sha256"] = ""
    row["control_row_sha256"] = make_control_row_sha256(row)
    return row


def _raw_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest_artifact_pair(base_dir: Path, evidence: dict[str, object]) -> tuple[Path, Path]:
    manifest_path = _write_manifest_inputs(base_dir, evidence)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path = base_dir / "public_acquisition_counters.json"
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path, artifact_path


def _rewrite_manifest_input_and_artifact(
    manifest_path: Path,
    artifact_path: Path,
    evidence: dict[str, object],
    input_key: str,
    raw_bytes: bytes,
) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    input_spec = manifest["inputs"][input_key]
    input_path = Path(input_spec["path"])
    input_path.write_bytes(raw_bytes)
    input_spec["sha256"] = _raw_file_sha256(input_path)
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    artifact = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")


def _write_manifest_inputs(base_dir: Path, evidence: dict[str, object], *, hash_mode: str = "raw_bytes") -> Path:
    input_specs = {}
    for key in production_qualification.REQUIRED_MANIFEST_INPUT_KEYS:
        value = evidence[key]
        path = base_dir / f"{key}.json"
        if isinstance(value, pd.DataFrame):
            path = base_dir / f"{key}.csv"
            path.write_text(value.to_csv(index=False), encoding="utf-8")
        else:
            path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
        if hash_mode == "raw_bytes":
            sha256 = _raw_file_sha256(path)
        else:
            sha256 = canonical_manifest_sha256({"content": path.read_text(encoding="utf-8")})
        input_specs[key] = {
            "path": str(path),
            "sha256": sha256,
            "format": "csv" if path.suffix == ".csv" else "json",
        }
    manifest = {
        "artifact_schema_version": "2026-08-08.task5",
        "inputs": input_specs,
        "minimum_independent_r5_blocks": int(evidence["minimum_independent_r5_blocks"]),
        "counter_targets": evidence["counter_targets"],
    }
    manifest["input_manifest_sha256"] = canonical_manifest_sha256(manifest)
    manifest_path = base_dir / "public_acquisition_counter_inputs.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path
