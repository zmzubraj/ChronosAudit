from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pandas as pd
import pytest
import production_qualification
import run_public_evidence_acquisition as public_acquisition_runner

from chronosaudit_stage2.public_acquisition.control_qualification_approval import (
    ControlQualificationApprovalError,
    build_control_qualification_approval,
    build_control_qualification_approval_request,
    canonical_signed_payload,
    verify_control_qualification_approval,
)
from chronosaudit_stage2.public_acquisition.control_qualification_evidence import (
    CONTROL_QUALIFICATION_GATES,
)
from chronosaudit_stage2.public_acquisition.control_qualification_bundle import (
    ControlQualificationBundleError,
    assemble_control_qualification_bundle,
    build_control_qualification_bundle,
    verify_control_qualification_bundle,
)
from chronosaudit_stage2.public_acquisition.qualification import (
    make_control_row_sha256,
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _candidate() -> dict[str, object]:
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
        "censoring_status": "PENDING_FROZEN_FOLLOW_UP",
        "investigated_negative_status": "PENDING_INVESTIGATED_NEGATIVE",
        "independent_outcome_review_status": "PENDING_INDEPENDENT_OUTCOME_REVIEW",
        "denominator_record_sha256": "a2" * 32,
        "source_manifest_sha256": "b1" * 32,
        "identity_linkage_free": True,
        "clone_linkage_free": True,
        "proxy_linkage_free": True,
        "protocol_linkage_free": True,
        "mechanism_separation_free": False,
        "independent_outcome_reviewer_identity": "",
        "independent_outcome_reviewer_owner": "",
        "independent_outcome_reviewer_conflict_clear": False,
        "independent_outcome_reviewer_confidence": "",
        "independent_outcome_decision_sha256": "",
        "maturity_check_passed": False,
        "maturity_check_sha256": "",
        "censoring_check_passed": False,
        "censoring_check_sha256": "",
        "temporal_check_passed": True,
        "temporal_check_sha256": "c3" * 32,
        "lineage_check_passed": True,
        "lineage_check_sha256": "d4" * 32,
        "clone_check_passed": True,
        "clone_check_sha256": "e5" * 32,
        "proxy_check_passed": True,
        "proxy_check_sha256": "f6" * 32,
        "protocol_check_passed": True,
        "protocol_check_sha256": "a7" * 32,
        "mechanism_separation_check_passed": False,
        "mechanism_separation_check_sha256": "",
        "candidate_row_valid": True,
        "matcher_provenance_valid": True,
        "control_row_valid": True,
        "qualified_control": False,
        "qualification_blockers": "maturity,censoring,mechanism_separation",
    }
    row["control_row_sha256"] = make_control_row_sha256(row)
    return row


def _inputs(tmp_path: Path) -> dict[str, Path]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    candidate = _candidate()
    candidates = tmp_path / "candidates.csv"
    pd.DataFrame([candidate]).to_csv(candidates, index=False)
    positives = tmp_path / "positive-cases.csv"
    pd.DataFrame([{"case_name": "case-1"}]).to_csv(positives, index=False)
    rows: list[dict[str, object]] = []
    for gate in CONTROL_QUALIFICATION_GATES:
        source_relative = Path("case-1") / "sources" / f"{gate}.txt"
        source_path = evidence_root / source_relative
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(f"direct {gate} evidence", encoding="utf-8")
        evidence = {
            "schema_version": "chronosaudit.control_check_evidence.v1",
            "case_name": "case-1",
            "chain": "ethereum",
            "contract_address": candidate["contract_address"],
            "candidate_control_row_sha256": candidate["control_row_sha256"],
            "gate": gate,
            "result": "PASS",
            "decision_rule": f"frozen {gate} rule satisfied",
            "observations": [f"direct {gate} evidence reviewed"],
            "source_artifact_path": source_relative.as_posix(),
            "source_artifact_sha256": _sha(source_path),
        }
        evidence_relative = Path("case-1") / f"{gate}.json"
        evidence_path = evidence_root / evidence_relative
        evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        row = {
            "schema_version": "chronosaudit.control_qualification_check.v1",
            "case_name": "case-1",
            "chain": "ethereum",
            "contract_address": candidate["contract_address"],
            "candidate_control_row_sha256": candidate["control_row_sha256"],
            "gate": gate,
            "check_status": "PASS",
            "evidence_path": evidence_relative.as_posix(),
            "evidence_sha256": _sha(evidence_path),
            "reviewer_identity": f"reviewer-{gate}",
            "reviewer_owner": f"owner-{gate}",
            "reviewer_kind": (
                "HUMAN"
                if gate in {"maturity", "censoring", "mechanism_separation"}
                else "MECHANICAL"
            ),
            "reviewer_conflict_clear": True,
            "reviewer_confidence": "high",
            "reviewed_at_utc": "2026-08-20T00:00:00Z",
        }
        row["evidence_record_sha256"] = _canonical_sha256(row)
        rows.append(row)
    checks = tmp_path / "checks.csv"
    pd.DataFrame(rows).to_csv(checks, index=False)
    return {
        "candidates": candidates,
        "checks": checks,
        "positives": positives,
        "evidence_root": evidence_root,
    }


def _request(paths: dict[str, Path]) -> dict[str, object]:
    return build_control_qualification_approval_request(
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        expected_positive_rows=1,
        controls_per_positive=1,
    )


def _approval(request: dict[str, object]) -> dict[str, object]:
    return build_control_qualification_approval(
        request=request,
        authority_principal="qualification-authority@example.org",
        authority_type="ACCOUNTABLE_HUMAN",
        authority_identity_binding_sha256="f" * 64,
        approval_start_utc="2026-08-20T01:00:00Z",
        approval_expires_utc="2026-08-21T01:00:00Z",
    )


def _sign(
    tmp_path: Path, approval: dict[str, object]
) -> tuple[Path, Path, Path]:
    key = tmp_path / "qualification-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    message = tmp_path / "qualification-message.json"
    message.write_bytes(canonical_signed_payload(approval))
    subprocess.run(
        [
            "ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n",
            "chronosaudit-stage2-control-qualification-v1", str(message),
        ],
        check=True,
    )
    signature = Path(f"{message}.sig")
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        str(approval["authority_principal"]) + " "
        + Path(f"{key}.pub").read_text(encoding="utf-8").strip()
        + "\n",
        encoding="utf-8",
    )
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    return approval_path, signature, allowed


def test_request_is_exact_cohort_bound_and_non_authorizing(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    assert request == _request(paths)
    assert request["decision"] == "AWAITING_ACCOUNTABLE_CONTROL_QUALIFICATION_SIGNATURE"
    assert request["candidate_rows"] == 1
    assert request["check_rows"] == 8
    assert request["controls_per_positive"] == 1
    assert request["qualification_projection_authorized"] is False
    assert request["counter_authority"] is False


def test_valid_signature_projects_counter_authorized_qualified_rows(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval_path, signature, allowed = _sign(tmp_path, _approval(request))
    result = verify_control_qualification_approval(
        request=request,
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="qualification-authority@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
        expected_positive_rows=1,
        controls_per_positive=1,
    )
    verification = result["verification"]
    projection = result["qualified_control_projection"]
    assert verification["decision"] == "CONTROL_QUALIFICATION_APPROVAL_VERIFIED"
    assert verification["counter_authority"] is True
    assert len(projection) == 1
    row = projection.iloc[0]
    assert row["candidate_status"] == "QUALIFIED_CONTROL"
    assert bool(row["qualified_control"]) is True
    assert bool(row["qualification_authority_verified"]) is True
    assert row["selected_candidate_control_row_sha256"] == _candidate()["control_row_sha256"]
    assert row["control_row_sha256"] == make_control_row_sha256(row.to_dict())


def test_local_test_signature_is_mechanical_and_cannot_authorize_counter(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    local_approval = build_control_qualification_approval(
        request=request,
        authority_principal="local-test-only",
        authority_type="LOCAL_TEST_MECHANICAL",
        authority_identity_binding_sha256="",
        approval_start_utc="2026-08-20T01:00:00Z",
        approval_expires_utc="2026-08-21T01:00:00Z",
    )
    approval_path, signature, allowed = _sign(tmp_path, local_approval)
    result = verify_control_qualification_approval(
        request=request,
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="local-test-only",
        verification_time_utc="2026-08-20T12:00:00Z",
        expected_positive_rows=1,
        controls_per_positive=1,
    )
    assert result["verification"]["decision"] == (
        "CONTROL_QUALIFICATION_MECHANICS_VERIFIED_NON_AUTHORIZING"
    )
    assert result["verification"]["counter_authority"] is False
    assert result["verification"]["qualification_projection_authorized"] is False


def test_approval_authority_must_be_independent_of_evidence_reviewers(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    with pytest.raises(
        ControlQualificationApprovalError, match="authority_principal_not_independent"
    ):
        build_control_qualification_approval(
            request=request,
            authority_principal="reviewer-mechanism_separation",
            approval_start_utc="2026-08-20T01:00:00Z",
            approval_expires_utc="2026-08-21T01:00:00Z",
        )


def test_request_rejects_incomplete_candidate_cohort(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    with pytest.raises(ControlQualificationApprovalError, match="candidate_cohort_invalid"):
        build_control_qualification_approval_request(
            candidate_rows_path=paths["candidates"],
            check_rows_path=paths["checks"],
            positive_cases_path=paths["positives"],
            evidence_root=paths["evidence_root"],
            expected_positive_rows=1,
            controls_per_positive=2,
        )


def test_verifier_rejects_tampered_approval(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval = _approval(request)
    approval_path, signature, allowed = _sign(tmp_path, approval)
    approval["counter_authority"] = False
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(
        ControlQualificationApprovalError, match="approval_counter_authority_invalid"
    ):
        verify_control_qualification_approval(
            request=request,
            candidate_rows_path=paths["candidates"],
            check_rows_path=paths["checks"],
            positive_cases_path=paths["positives"],
            evidence_root=paths["evidence_root"],
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="qualification-authority@example.org",
            verification_time_utc="2026-08-20T12:00:00Z",
            expected_positive_rows=1,
            controls_per_positive=1,
        )


def test_bundle_independently_reverifies_signature_evidence_and_projection(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval_path, signature, allowed = _sign(tmp_path, _approval(request))
    built = build_control_qualification_bundle(
        bundle_root=tmp_path,
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="qualification-authority@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
        expected_positive_rows=1,
        controls_per_positive=1,
    )

    result = verify_control_qualification_bundle(
        manifest_path=built["manifest_path"]
    )

    assert result["verification"]["decision"] == (
        "CONTROL_QUALIFICATION_APPROVAL_VERIFIED"
    )
    assert result["bundle_verification"]["decision"] == (
        "CONTROL_QUALIFICATION_BUNDLE_VERIFIED"
    )
    assert result["bundle_verification"]["counter_authority"] is True
    assert len(result["qualified_control_projection"]) == 1


def test_bundle_reverification_rejects_tampered_source_evidence(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval_path, signature, allowed = _sign(tmp_path, _approval(request))
    built = build_control_qualification_bundle(
        bundle_root=tmp_path,
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="qualification-authority@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
        expected_positive_rows=1,
        controls_per_positive=1,
    )
    source = paths["evidence_root"] / "case-1" / "sources" / "maturity.txt"
    source.write_text("tampered", encoding="utf-8")

    with pytest.raises(
        ControlQualificationBundleError, match="evidence_inventory_mismatch"
    ):
        verify_control_qualification_bundle(manifest_path=built["manifest_path"])


def test_bundle_requires_every_input_to_be_contained_by_bundle_root(
    tmp_path: Path,
) -> None:
    inside = tmp_path / "inside"
    inside.mkdir()
    paths = _inputs(inside)
    request = _request(paths)
    approval_path, signature, allowed = _sign(inside, _approval(request))

    with pytest.raises(
        ControlQualificationBundleError, match="candidate_rows_outside_bundle_root"
    ):
        build_control_qualification_bundle(
            bundle_root=tmp_path / "empty-bundle",
            candidate_rows_path=paths["candidates"],
            check_rows_path=paths["checks"],
            positive_cases_path=paths["positives"],
            evidence_root=paths["evidence_root"],
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="qualification-authority@example.org",
            verification_time_utc="2026-08-20T12:00:00Z",
            expected_positive_rows=1,
            controls_per_positive=1,
        )


def test_production_loader_independently_reverifies_bundle(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval_path, signature, allowed = _sign(tmp_path, _approval(request))
    built = build_control_qualification_bundle(
        bundle_root=tmp_path,
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="qualification-authority@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
        expected_positive_rows=1,
        controls_per_positive=1,
    )
    counter_manifest_path = tmp_path / "public_acquisition_counter_inputs.json"
    counter_manifest = {
        "control_qualification_bundle": {
            "manifest": {
                "path": built["manifest_path"].name,
                "sha256": _sha(built["manifest_path"]),
                "format": "json",
            },
            "counter_authority": True,
        }
    }

    projection, verification = (
        production_qualification.load_verified_control_qualification_bundle(
            counter_manifest,
            manifest_path=counter_manifest_path,
        )
    )

    assert len(projection) == 1
    assert verification["decision"] == "CONTROL_QUALIFICATION_BUNDLE_VERIFIED"
    assert verification["counter_authority"] is True


def test_project_loader_uses_bundle_projection_and_not_a_trusted_report(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval_path, signature, allowed = _sign(tmp_path, _approval(request))
    built = build_control_qualification_bundle(
        bundle_root=tmp_path,
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="qualification-authority@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
        expected_positive_rows=1,
        controls_per_positive=1,
    )

    result = public_acquisition_runner.load_control_qualification_bundle_for_project(
        built["manifest_path"]
    )

    assert len(result["qualified_control_projection"]) == 1
    assert result["bundle_verification"]["decision"] == (
        "CONTROL_QUALIFICATION_BUNDLE_VERIFIED"
    )
    assert result["bundle_manifest_sha256"] == _sha(built["manifest_path"])


def test_assembler_copies_validated_external_inputs_into_portable_bundle(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    paths = _inputs(source_root)
    request = _request(paths)
    approval_path, signature, allowed = _sign(source_root, _approval(request))
    bundle_root = tmp_path / "portable-bundle"

    built = assemble_control_qualification_bundle(
        bundle_root=bundle_root,
        candidate_rows_path=paths["candidates"],
        check_rows_path=paths["checks"],
        positive_cases_path=paths["positives"],
        evidence_root=paths["evidence_root"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="qualification-authority@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
        expected_positive_rows=1,
        controls_per_positive=1,
    )

    assert built["manifest_path"] == (
        bundle_root / "control_qualification_bundle_manifest.json"
    )
    assert (bundle_root / "inputs" / "candidates.csv").is_file()
    assert (bundle_root / "evidence" / "case-1" / "maturity.json").is_file()
    assert verify_control_qualification_bundle(
        manifest_path=built["manifest_path"]
    )["bundle_verification"]["counter_authority"] is True
