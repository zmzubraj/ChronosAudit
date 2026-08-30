from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pandas as pd
import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_follow_up_horizon import (
    ControlFollowUpHorizonError,
    build_follow_up_horizon_decision,
    build_follow_up_horizon_request,
    canonical_horizon_signed_payload,
    verify_follow_up_horizon_decision,
)


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    policy = {
        "schema_version": "chronosaudit.stage2_control_selection_policy.v1",
        "population": {
            "positive_cases_required": 2,
            "controls_per_positive": 10,
            "control_rows_required": 20,
        },
        "qualification": {
            "investigated_negative_status": "INVESTIGATED_NEGATIVE_MATURE",
            "censoring_status": "FROZEN_COMPLETE",
        },
        "unresolved_prespecification": {
            "primary_follow_up_horizon": None,
            "disposition": "BLOCKED",
        },
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    positives_path = tmp_path / "positives.csv"
    pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "prediction_cutoff_time": "2024-02-01T00:00:00Z",
                "positive_record_sha256": "1" * 64,
                "follow_up_horizon": "",
            },
            {
                "case_name": "case-2",
                "prediction_cutoff_time": "2024-03-01T00:00:00Z",
                "positive_record_sha256": "2" * 64,
                "follow_up_horizon": "",
            },
        ]
    ).to_csv(positives_path, index=False)
    return policy_path, positives_path


def _write_decision_evidence(
    tmp_path: Path, request: dict[str, object]
) -> dict[str, Path]:
    paths = {
        "outcome_source_plan": tmp_path / "outcome-source-plan.json",
        "censoring_rules": tmp_path / "censoring-rules.json",
        "pre_freeze_attestation": tmp_path / "pre-freeze-attestation.json",
    }
    payloads = {
        "outcome_source_plan": {
            "schema_version": "chronosaudit.control_outcome_source_plan.v1",
            "status": "METHODS_OWNER_APPROVED",
            "request_sha256": request["request_sha256"],
            "source_plan_id": "control-outcomes-v1",
            "sources": [
                {
                    "source_id": "canonical-chain-receipts",
                    "source_class": "PRIMARY_ONCHAIN",
                    "event_coverage": "QUALIFYING_CONTROL_INCIDENTS",
                }
            ],
            "post_freeze_changes_require_new_signed_decision": True,
        },
        "censoring_rules": {
            "schema_version": "chronosaudit.control_censoring_rules.v1",
            "status": "FROZEN",
            "request_sha256": request["request_sha256"],
            "right_censoring_rule": (
                "CENSOR_AT_EARLIEST_OF_INCIDENT_ADMINISTRATIVE_CUTOFF_OR_"
                "LAST_VERIFIED_OBSERVATION"
            ),
            "incident_free_through_horizon_required": True,
            "unknown_or_incomplete_follow_up_never_negative": True,
            "post_freeze_changes_require_new_signed_decision": True,
        },
        "pre_freeze_attestation": {
            "schema_version": (
                "chronosaudit.control_pre_freeze_outcome_inspection_attestation.v1"
            ),
            "status": "ATTESTED",
            "request_sha256": request["request_sha256"],
            "signer_principal": "methods-owner@example.org",
            "attested_at_utc": "2026-08-17T19:00:00Z",
            "control_outcomes_inspected_before_freeze": False,
            "statement": "NO_CONTROL_OUTCOMES_INSPECTED_BEFORE_HORIZON_FREEZE",
        },
    }
    for label, path in paths.items():
        path.write_text(json.dumps(payloads[label]) + "\n", encoding="utf-8")
    return paths


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _decision(
    request: dict[str, object], evidence_paths: dict[str, Path]
) -> dict[str, object]:
    return {
        "schema_version": "chronosaudit.control_follow_up_horizon_decision.v1",
        "request_sha256": request["request_sha256"],
        "signer_principal": "methods-owner@example.org",
        "decision": "FREEZE_PRIMARY_FOLLOW_UP_HORIZON",
        "decided_at_utc": "2026-08-17T20:00:00Z",
        "horizon_model": "FIXED_DURATION",
        "horizon_days": 365,
        "administrative_censoring_cutoff_utc": "2026-12-31T00:00:00Z",
        "right_censoring_rule": (
            "CENSOR_AT_EARLIEST_OF_INCIDENT_ADMINISTRATIVE_CUTOFF_OR_"
            "LAST_VERIFIED_OBSERVATION"
        ),
        "incident_free_through_horizon_required": True,
        "outcome_source_plan_sha256": _file_sha256(
            evidence_paths["outcome_source_plan"]
        ),
        "censoring_rules_sha256": _file_sha256(evidence_paths["censoring_rules"]),
        "pre_freeze_outcome_inspection_prohibited": True,
        "pre_freeze_outcome_inspection_attestation_sha256": _file_sha256(
            evidence_paths["pre_freeze_attestation"]
        ),
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }


def _sign(
    tmp_path: Path, decision: dict[str, object]
) -> tuple[Path, Path, Path]:
    key = tmp_path / "horizon-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    message = tmp_path / "horizon-message.json"
    message.write_bytes(canonical_horizon_signed_payload(decision))
    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-q",
            "-f",
            str(key),
            "-n",
            "chronosaudit-stage2-control-horizon-v1",
            str(message),
        ],
        check=True,
    )
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        "methods-owner@example.org "
        + Path(f"{key}.pub").read_text(encoding="utf-8").strip()
        + "\n",
        encoding="utf-8",
    )
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    return decision_path, Path(f"{message}.sig"), allowed


def test_horizon_request_is_deterministic_and_non_authorizing(tmp_path: Path) -> None:
    policy, positives = _write_inputs(tmp_path)

    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    repeated = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )

    assert request == repeated
    assert request["decision"] == "AWAITING_ACCOUNTABLE_METHODS_OWNER_DECISION"
    assert request["positive_case_count"] == 2
    assert request["latest_positive_cutoff_utc"] == "2024-03-01T00:00:00Z"
    assert request["selection_authorized"] is False
    assert request["qualification_authorized"] is False
    assert len(request["request_sha256"]) == 64


def test_current_repository_policy_routes_to_dynamic_horizon(tmp_path: Path) -> None:
    _, positives = _write_inputs(tmp_path)
    policy = Path(__file__).resolve().parents[1] / "config" / "stage2_control_selection_policy_v1.yaml"
    repository_policy = yaml.safe_load(policy.read_text(encoding="utf-8"))
    repository_policy["population"]["positive_cases_required"] = 2
    repository_policy["population"]["control_rows_required"] = 20
    repository_policy["population"]["unique_control_contracts_required"] = 20
    adjusted = tmp_path / "current-policy.yaml"
    adjusted.write_text(yaml.safe_dump(repository_policy), encoding="utf-8")

    request = build_follow_up_horizon_request(
        policy_path=adjusted, positive_projection_path=positives
    )

    assert request["required_horizon_model"] == "DYNAMIC_HORIZON_V1"
    assert request["decision"] == "AWAITING_DYNAMIC_HORIZON_ARTIFACTS_AND_SIGNATURE"
    assert request["compatibility_classification"] == "CURRENT_DYNAMIC_HORIZON_REQUEST"
    assert request["selection_authorized"] is False


def test_horizon_decision_builder_binds_evidence_and_is_non_authorizing(
    tmp_path: Path,
) -> None:
    policy, positives = _write_inputs(tmp_path)
    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    evidence_paths = _write_decision_evidence(tmp_path, request)

    decision = build_follow_up_horizon_decision(
        request=request,
        signer_principal="methods-owner@example.org",
        decided_at_utc="2026-08-17T20:00:00Z",
        horizon_days=365,
        administrative_censoring_cutoff_utc="2026-12-31T00:00:00Z",
        outcome_source_plan_path=evidence_paths["outcome_source_plan"],
        censoring_rules_path=evidence_paths["censoring_rules"],
        pre_freeze_outcome_inspection_attestation_path=evidence_paths[
            "pre_freeze_attestation"
        ],
    )
    repeated = build_follow_up_horizon_decision(
        request=request,
        signer_principal="methods-owner@example.org",
        decided_at_utc="2026-08-17T20:00:00Z",
        horizon_days=365,
        administrative_censoring_cutoff_utc="2026-12-31T00:00:00Z",
        outcome_source_plan_path=evidence_paths["outcome_source_plan"],
        censoring_rules_path=evidence_paths["censoring_rules"],
        pre_freeze_outcome_inspection_attestation_path=evidence_paths[
            "pre_freeze_attestation"
        ],
    )

    assert decision == repeated
    assert decision["outcome_source_plan_sha256"] == _file_sha256(
        evidence_paths["outcome_source_plan"]
    )
    assert decision["selection_authorized"] is False
    assert decision["qualification_authorized"] is False
    assert decision["counter_authority"] is False


def test_valid_signed_horizon_decision_is_verified(tmp_path: Path) -> None:
    policy, positives = _write_inputs(tmp_path)
    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    evidence_paths = _write_decision_evidence(tmp_path, request)
    decision = _decision(request, evidence_paths)
    decision_path, signature, allowed = _sign(tmp_path, decision)

    report = verify_follow_up_horizon_decision(
        request=request,
        decision_path=decision_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="methods-owner@example.org",
        verification_time_utc="2026-08-18T00:00:00Z",
        outcome_source_plan_path=evidence_paths["outcome_source_plan"],
        censoring_rules_path=evidence_paths["censoring_rules"],
        pre_freeze_outcome_inspection_attestation_path=evidence_paths[
            "pre_freeze_attestation"
        ],
    )

    assert report["decision"] == "FOLLOW_UP_HORIZON_DECISION_VERIFIED"
    assert report["primary_follow_up_horizon"] == "P365D"
    assert report["maturity_evaluation_not_before_utc"] == "2025-03-01T00:00:00Z"
    assert report["selection_authorized"] is False
    assert report["qualification_authorized"] is False
    assert report["counter_authority"] is False


def test_horizon_decision_rejects_too_early_admin_cutoff(tmp_path: Path) -> None:
    policy, positives = _write_inputs(tmp_path)
    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    evidence_paths = _write_decision_evidence(tmp_path, request)
    decision = _decision(request, evidence_paths)
    decision["administrative_censoring_cutoff_utc"] = "2024-12-31T00:00:00Z"
    decision_path, signature, allowed = _sign(tmp_path, decision)

    with pytest.raises(
        ControlFollowUpHorizonError, match="administrative_cutoff_before_maturity"
    ):
        verify_follow_up_horizon_decision(
            request=request,
            decision_path=decision_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="methods-owner@example.org",
            verification_time_utc="2026-08-18T00:00:00Z",
            outcome_source_plan_path=evidence_paths["outcome_source_plan"],
            censoring_rules_path=evidence_paths["censoring_rules"],
            pre_freeze_outcome_inspection_attestation_path=evidence_paths[
                "pre_freeze_attestation"
            ],
        )


def test_horizon_decision_rejects_referenced_evidence_hash_mismatch(
    tmp_path: Path,
) -> None:
    policy, positives = _write_inputs(tmp_path)
    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    evidence_paths = _write_decision_evidence(tmp_path, request)
    decision = _decision(request, evidence_paths)
    decision_path, signature, allowed = _sign(tmp_path, decision)
    evidence_paths["censoring_rules"].write_text(
        json.dumps({"artifact": "tampered"}) + "\n", encoding="utf-8"
    )

    with pytest.raises(
        ControlFollowUpHorizonError, match="censoring_rules_sha256_mismatch"
    ):
        verify_follow_up_horizon_decision(
            request=request,
            decision_path=decision_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="methods-owner@example.org",
            verification_time_utc="2026-08-18T00:00:00Z",
            outcome_source_plan_path=evidence_paths["outcome_source_plan"],
            censoring_rules_path=evidence_paths["censoring_rules"],
            pre_freeze_outcome_inspection_attestation_path=evidence_paths[
                "pre_freeze_attestation"
            ],
        )


def test_horizon_decision_rejects_semantically_invalid_evidence(
    tmp_path: Path,
) -> None:
    policy, positives = _write_inputs(tmp_path)
    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    evidence_paths = _write_decision_evidence(tmp_path, request)
    invalid_plan = json.loads(
        evidence_paths["outcome_source_plan"].read_text(encoding="utf-8")
    )
    invalid_plan["sources"] = []
    evidence_paths["outcome_source_plan"].write_text(
        json.dumps(invalid_plan) + "\n", encoding="utf-8"
    )
    decision = _decision(request, evidence_paths)
    decision_path, signature, allowed = _sign(tmp_path, decision)

    with pytest.raises(
        ControlFollowUpHorizonError, match="outcome_source_plan_sources_invalid"
    ):
        verify_follow_up_horizon_decision(
            request=request,
            decision_path=decision_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="methods-owner@example.org",
            verification_time_utc="2026-08-18T00:00:00Z",
            outcome_source_plan_path=evidence_paths["outcome_source_plan"],
            censoring_rules_path=evidence_paths["censoring_rules"],
            pre_freeze_outcome_inspection_attestation_path=evidence_paths[
                "pre_freeze_attestation"
            ],
        )


def test_horizon_decision_cli_emits_exact_canonical_signing_payload(
    tmp_path: Path,
) -> None:
    policy, positives = _write_inputs(tmp_path)
    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    evidence_paths = _write_decision_evidence(tmp_path, request)
    decision_path = tmp_path / "decision.json"
    signing_payload_path = tmp_path / "signing-payload.json"
    root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [
            sys.executable,
            str(root / "build_stage2_control_follow_up_horizon_decision.py"),
            "--policy",
            str(policy),
            "--positive-projection",
            str(positives),
            "--signer-principal",
            "methods-owner@example.org",
            "--decided-at-utc",
            "2026-08-17T20:00:00Z",
            "--horizon-days",
            "365",
            "--administrative-censoring-cutoff-utc",
            "2026-12-31T00:00:00Z",
            "--outcome-source-plan",
            str(evidence_paths["outcome_source_plan"]),
            "--censoring-rules",
            str(evidence_paths["censoring_rules"]),
            "--pre-freeze-outcome-inspection-attestation",
            str(evidence_paths["pre_freeze_attestation"]),
            "--output-decision",
            str(decision_path),
            "--output-signing-payload",
            str(signing_payload_path),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert signing_payload_path.read_bytes() == canonical_horizon_signed_payload(
        decision
    )
    stdout = json.loads(completed.stdout)
    assert stdout["signature_created"] is False
    assert stdout["selection_authorized"] is False
