from __future__ import annotations

import hashlib
import pandas as pd
import pytest
import json
from pathlib import Path
import subprocess
import sys

from chronosaudit_stage2.public_acquisition.control_dynamic_horizon import (
    ControlDynamicHorizonError,
    assign_dynamic_horizons,
    build_reference_latency_cohort_from_verified_snapshots,
    build_dynamic_horizon_approval_record,
    canonical_dynamic_horizon_signed_payload,
    fit_dynamic_horizon_model,
    kaplan_meier_quantile_seconds,
    make_feature_vector_sha256,
    make_reference_record_sha256,
    validate_cutoff_safe_pair_features,
    validate_reference_latency_cohort,
    verify_dynamic_horizon_artifacts,
    verify_signed_dynamic_horizon_approval,
    verify_final_pair_feature_binding,
)
from chronosaudit_stage2.public_acquisition.control_pair_feature_projection import (
    build_pair_feature,
    project_pair_features,
)


def _reference_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "reference_id": "reference-001",
        "chain": "ethereum",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "mechanism_family": "oracle-manipulation",
        "protocol_family": "lending",
        "architecture_proxy_pattern": "upgradeable-proxy",
        "code_pattern_family": "solidity-0.8",
        "code_size_bytes": 24000,
        "complexity_class": "high",
        "contract_age_days_at_risk_entry": 400,
        "source_verified_at_cutoff": True,
        "risk_entry_time_utc": "2020-01-01T00:00:00Z",
        "event_or_censoring_time_utc": "2020-04-10T00:00:00Z",
        "event_observed": True,
        "latency_seconds": 8_640_000,
        "timing_precision": "SECONDS",
        "risk_entry_source_sha256": "1" * 64,
        "event_time_source_sha256": "2" * 64,
        "provenance_record_sha256": "3" * 64,
    }
    row.update(overrides)
    row["reference_record_sha256"] = make_reference_record_sha256(row)
    return row


def _pair_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "positive_case_id": "positive-001",
        "positive_record_sha256": "4" * 64,
        "chain": "ethereum",
        "control_address": "0x2222222222222222222222222222222222222222",
        "candidate_control_row_sha256": "5" * 64,
        "prediction_cutoff_time_utc": "2021-01-01T00:00:00Z",
        "mechanism_family": "oracle-manipulation",
        "protocol_family": "lending",
        "architecture_proxy_pattern": "upgradeable-proxy",
        "code_pattern_family": "solidity-0.8",
        "code_size_bytes": 21000,
        "complexity_class": "high",
        "contract_age_days_at_cutoff": 365,
        "source_verified_at_cutoff": True,
    }
    row.update(overrides)
    row["feature_vector_sha256"] = make_feature_vector_sha256(row)
    return row


def test_reference_cohort_validation_is_deterministic_and_non_authorizing() -> None:
    frame = pd.DataFrame([_reference_row()])

    normalized, report = validate_reference_latency_cohort(frame)
    repeated, repeated_report = validate_reference_latency_cohort(frame)

    pd.testing.assert_frame_equal(normalized, repeated)
    assert report == repeated_report
    assert report["decision"] == "REFERENCE_LATENCY_COHORT_VERIFIED"
    assert report["row_count"] == 1
    assert report["selection_authorized"] is False
    assert report["qualification_authorized"] is False
    assert report["counter_authority"] is False


def test_source_verification_state_is_a_feature_not_an_eligibility_override() -> None:
    reference = _reference_row(source_verified_at_cutoff=False)
    reference["reference_record_sha256"] = make_reference_record_sha256(reference)
    pair = _pair_row(source_verified_at_cutoff=False)
    pair["feature_vector_sha256"] = make_feature_vector_sha256(pair)

    normalized_reference, _ = validate_reference_latency_cohort(pd.DataFrame([reference]))
    normalized_pair, _ = validate_cutoff_safe_pair_features(pd.DataFrame([pair]))

    assert normalized_reference.loc[0, "source_verified_at_cutoff"] is False or not normalized_reference.loc[0, "source_verified_at_cutoff"]
    assert normalized_pair.loc[0, "source_verified_at_cutoff"] is False or not normalized_pair.loc[0, "source_verified_at_cutoff"]


def test_reference_cohort_rejects_noncanonical_or_inconsistent_timing() -> None:
    noncanonical = _reference_row(
        event_or_censoring_time_utc="2020-04-10T00:00:00+00:00"
    )
    with pytest.raises(ControlDynamicHorizonError, match="not_canonical"):
        validate_reference_latency_cohort(pd.DataFrame([noncanonical]))

    inconsistent = _reference_row(latency_seconds=1)
    with pytest.raises(ControlDynamicHorizonError, match="latency_mismatch"):
        validate_reference_latency_cohort(pd.DataFrame([inconsistent]))


def test_reference_cohort_rejects_hash_tampering() -> None:
    row = _reference_row()
    row["protocol_family"] = "dex"

    with pytest.raises(ControlDynamicHorizonError, match="record_hash_mismatch"):
        validate_reference_latency_cohort(pd.DataFrame([row]))


def test_pair_features_are_cutoff_safe_and_disjoint_from_reference_cohort() -> None:
    frame = pd.DataFrame([_pair_row()])

    normalized, report = validate_cutoff_safe_pair_features(
        frame,
        reference_identities={
            ("ethereum", "0x1111111111111111111111111111111111111111")
        },
    )

    assert len(normalized) == 1
    assert report["decision"] == "CUTOFF_SAFE_PAIR_FEATURES_VERIFIED"
    assert report["prohibited_field_count"] == 0
    assert report["selection_authorized"] is False
    assert report["qualification_authorized"] is False
    assert report["counter_authority"] is False


def test_pair_features_reject_outcomes_overlap_and_hash_tampering() -> None:
    prohibited = _pair_row(control_future_exploit_status="NO_INCIDENT")
    with pytest.raises(ControlDynamicHorizonError, match="prohibited_fields"):
        validate_cutoff_safe_pair_features(pd.DataFrame([prohibited]))

    overlap = _pair_row(
        control_address="0x1111111111111111111111111111111111111111"
    )
    overlap["feature_vector_sha256"] = make_feature_vector_sha256(overlap)
    with pytest.raises(ControlDynamicHorizonError, match="reference_overlap"):
        validate_cutoff_safe_pair_features(
            pd.DataFrame([overlap]),
            reference_identities={
                ("ethereum", "0x1111111111111111111111111111111111111111")
            },
        )

    tampered = _pair_row()
    tampered["code_size_bytes"] = 1
    with pytest.raises(ControlDynamicHorizonError, match="feature_hash_mismatch"):
        validate_cutoff_safe_pair_features(pd.DataFrame([tampered]))


def _reference_cohort(count: int = 40) -> pd.DataFrame:
    rows = []
    start = pd.Timestamp("2020-01-01T00:00:00Z")
    for index in range(count):
        latency_days = index + 1
        end = start + pd.Timedelta(days=latency_days)
        rows.append(
            _reference_row(
                reference_id=f"reference-{index:03d}",
                contract_address=f"0x{index + 100:040x}",
                event_or_censoring_time_utc=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                latency_seconds=latency_days * 86_400,
            )
        )
    return validate_reference_latency_cohort(pd.DataFrame(rows))[0]


def test_kaplan_meier_quantile_handles_events_and_unreached_tail() -> None:
    assert kaplan_meier_quantile_seconds([10, 20, 30, 40], [True] * 4, 0.5) == 20
    assert kaplan_meier_quantile_seconds([10, 20, 30, 40], [True, False, False, False], 0.95) is None


def test_dynamic_model_is_deterministic_and_non_authorizing() -> None:
    cohort = _reference_cohort()

    model = fit_dynamic_horizon_model(cohort)
    repeated = fit_dynamic_horizon_model(cohort)

    assert model == repeated
    assert model["decision"] == "DYNAMIC_HORIZON_MODEL_FITTED"
    assert model["quantile_probability"] == 0.95
    assert model["bootstrap_replicates"] == 1000
    assert model["global_lower_bound_seconds"] > 0
    assert model["global_upper_bound_seconds"] >= model["global_lower_bound_seconds"]
    assert model["selection_authorized"] is False
    assert model["qualification_authorized"] is False
    assert model["counter_authority"] is False


def test_assignment_uses_hierarchy_and_fails_closed_when_no_stratum_qualifies() -> None:
    cohort = _reference_cohort()
    model = fit_dynamic_horizon_model(cohort)
    pair = validate_cutoff_safe_pair_features(pd.DataFrame([_pair_row()]))[0]

    assigned, report = assign_dynamic_horizons(pair, model)

    assert assigned.loc[0, "dynamic_horizon_status"] == "ASSIGNED"
    assert assigned.loc[0, "selected_stratum_level"] == "EXACT"
    assert assigned.loc[0, "dynamic_horizon_days"] > 0
    assert report["assigned_count"] == 1
    assert report["selection_authorized"] is False
    assert report["qualification_authorized"] is False
    assert report["counter_authority"] is False

    sparse = _reference_cohort(19)
    sparse_model = fit_dynamic_horizon_model(sparse)
    sparse_assigned, sparse_report = assign_dynamic_horizons(pair, sparse_model)
    assert sparse_assigned.loc[0, "dynamic_horizon_status"] == "INSUFFICIENT_REFERENCE_EVIDENCE"
    assert sparse_assigned.loc[0, "dynamic_horizon_days"] == ""
    assert sparse_report["insufficient_reference_evidence_count"] == 1


def test_assignment_binds_maturity_counts_hashes_and_reconstructs() -> None:
    cohort = _reference_cohort()
    model = fit_dynamic_horizon_model(cohort)
    pair = validate_cutoff_safe_pair_features(pd.DataFrame([_pair_row()]))[0]

    assigned, assignment_report = assign_dynamic_horizons(pair, model)
    row = assigned.iloc[0]

    expected_maturity = pd.Timestamp("2021-01-01T00:00:00Z") + pd.Timedelta(
        days=int(row["dynamic_horizon_days"])
    )
    assert row["maturity_time_utc"] == expected_maturity.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert row["selected_stratum_row_count"] == 40
    assert row["selected_stratum_event_count"] == 40
    assert row["reference_records_sha256"] == model["reference_records_sha256"]
    assert len(row["assignment_record_sha256"]) == 64

    verification = verify_dynamic_horizon_artifacts(
        reference_frame=cohort,
        pair_frame=pair,
        model=model,
        assignments=assigned,
        assignment_report=assignment_report,
    )
    assert verification["decision"] == "DYNAMIC_HORIZON_ARTIFACTS_VERIFIED"
    assert verification["deterministic_reconstruction_verified"] is True
    assert verification["selection_authorized"] is False
    assert verification["qualification_authorized"] is False
    assert verification["counter_authority"] is False


def test_reconstruction_rejects_assignment_tampering() -> None:
    cohort = _reference_cohort()
    model = fit_dynamic_horizon_model(cohort)
    pair = validate_cutoff_safe_pair_features(pd.DataFrame([_pair_row()]))[0]
    assigned, assignment_report = assign_dynamic_horizons(pair, model)
    assigned.loc[0, "dynamic_horizon_days"] = 1

    with pytest.raises(ControlDynamicHorizonError, match="assignments_mismatch"):
        verify_dynamic_horizon_artifacts(
            reference_frame=cohort,
            pair_frame=pair,
            model=model,
            assignments=assigned,
            assignment_report=assignment_report,
        )


def test_signed_approval_binds_principal_hashes_namespace_and_authority(tmp_path: Path) -> None:
    record = build_dynamic_horizon_approval_record(
        principal="zmzubraj",
        approved_at_utc="2026-08-20T12:00:00Z",
        design_spec_sha256="6" * 64,
        dynamic_horizon_spec_sha256="7" * 64,
        reference_cohort_sha256="8" * 64,
        model_sha256="9" * 64,
    )
    key = tmp_path / "fixture-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    payload = tmp_path / "approval.json"
    payload.write_bytes(canonical_dynamic_horizon_signed_payload(record))
    subprocess.run(
        [
            "ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n",
            "chronosaudit-stage2-control-dynamic-horizon-v1", str(payload),
        ],
        check=True,
    )
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        "zmzubraj " + Path(f"{key}.pub").read_text(encoding="utf-8").strip() + "\n",
        encoding="utf-8",
    )
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = verify_signed_dynamic_horizon_approval(
        approval_record_path=record_path,
        signature_path=Path(f"{payload}.sig"),
        allowed_signers_path=allowed,
        expected_principal="zmzubraj",
        expected_design_spec_sha256="6" * 64,
        expected_dynamic_horizon_spec_sha256="7" * 64,
        expected_reference_cohort_sha256="8" * 64,
        expected_model_sha256="9" * 64,
    )

    assert report["decision"] == "DYNAMIC_HORIZON_USER_APPROVAL_VERIFIED"
    assert report["signature_namespace"] == "chronosaudit-stage2-control-dynamic-horizon-v1"
    assert report["independent_human_review"] is False
    assert report["selection_authorized"] is False
    assert report["qualification_authorized"] is False
    assert report["counter_authority"] is False


def test_signed_approval_rejects_hash_mismatch(tmp_path: Path) -> None:
    record = build_dynamic_horizon_approval_record(
        principal="zmzubraj",
        approved_at_utc="2026-08-20T12:00:00Z",
        design_spec_sha256="6" * 64,
        dynamic_horizon_spec_sha256="7" * 64,
        reference_cohort_sha256="8" * 64,
        model_sha256="9" * 64,
    )
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    signature = tmp_path / "unused.sig"
    signature.write_text("not-a-signature", encoding="utf-8")
    allowed = tmp_path / "allowed"
    allowed.write_text("zmzubraj ssh-ed25519 invalid\n", encoding="utf-8")

    with pytest.raises(ControlDynamicHorizonError, match="model_hash_mismatch"):
        verify_signed_dynamic_horizon_approval(
            approval_record_path=record_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="zmzubraj",
            expected_design_spec_sha256="6" * 64,
            expected_dynamic_horizon_spec_sha256="7" * 64,
            expected_reference_cohort_sha256="8" * 64,
            expected_model_sha256="a" * 64,
        )


def _final_pair_projection(tmp_path: Path) -> dict[str, object]:
    address = "0x" + "22" * 20
    rich = build_pair_feature(
        pair_scope={
            "case_name": "positive-001", "positive_record_sha256": "4" * 64,
            "chain": "ethereum", "control_address": address,
            "control_deployment_time": "2020-01-01T00:00:00Z",
            "required_covariate_cutoff_time": "2021-01-01T00:00:00Z",
            "denominator_record_sha256": "5" * 64,
            "pair_scope_record_sha256": "6" * 64,
        },
        denominator={
            "chain": "ethereum", "contract_address": address,
            "denominator_record_sha256": "5" * 64, "counter_authority": True,
        },
        trace={
            "disposition": "complete", "chain_address": f"ethereum:{address}",
            "record_sha256": "7" * 64, "creation_set_sha256": "8" * 64,
        },
        state={
            "status": "complete", "chain_address": f"ethereum:{address}",
            "cutoff_timestamp": 1609459200, "runtime_code_size": 100,
            "clone_family": "9" * 64, "proxy_status": "unknown",
            "proxy_family": "unknown", "result_sha256": "a" * 64,
            "raw_evidence_hashes": ["b" * 64],
            "field_statuses": {"proxy_classification": "unavailable"},
        },
        source=None, protocol=None, dynamic_horizon_spec_sha256="c" * 64,
    )
    labels = (
        "pair_scope", "denominator", "trace_results", "trace_checkpoint",
        "state_results", "state_checkpoint", "dynamic_horizon_spec",
    )
    artifacts = {}
    for label in labels:
        path = tmp_path / f"{label}.json"
        path.write_text(json.dumps({"label": label}) + "\n", encoding="utf-8")
        artifacts[label] = path
    return project_pair_features(
        rows=[rich], output_root=tmp_path / "projection", upstream_artifacts=artifacts
    )


def test_cli_flow_produces_all_eight_non_authorizing_artifacts(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    reference_path = tmp_path / "reference.csv"
    projection = _final_pair_projection(tmp_path)
    pair_path = Path(projection["csv_path"])
    design_path = tmp_path / "design.md"
    _reference_cohort().to_csv(reference_path, index=False)
    design_path.write_text("approved design\n", encoding="utf-8")
    output = tmp_path / "artifacts"

    build = subprocess.run(
        [
            sys.executable,
            str(root / "build_stage2_control_dynamic_horizon.py"),
            "--reference-cohort", str(reference_path),
            "--pair-features", str(pair_path),
            "--pair-feature-manifest", str(projection["manifest_path"]),
            "--design-spec", str(design_path),
            "--output-dir", str(output),
        ],
        text=True, capture_output=True, check=False,
    )
    assert build.returncode == 0, build.stderr

    approval = subprocess.run(
        [
            sys.executable,
            str(root / "build_stage2_control_dynamic_horizon_approval.py"),
            "--artifact-dir", str(output),
            "--design-spec", str(design_path),
            "--principal", "zmzubraj",
            "--approved-at-utc", "2026-08-20T12:00:00Z",
        ],
        text=True, capture_output=True, check=False,
    )
    assert approval.returncode == 0, approval.stderr

    key = tmp_path / "cli-fixture-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    approval_record = output / "user_approval_record.json"
    subprocess.run(
        [
            "ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n",
            "chronosaudit-stage2-control-dynamic-horizon-v1", str(approval_record),
        ],
        check=True,
    )
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        "zmzubraj " + Path(f"{key}.pub").read_text(encoding="utf-8").strip() + "\n",
        encoding="utf-8",
    )
    verify = subprocess.run(
        [
            sys.executable,
            str(root / "verify_stage2_control_dynamic_horizon.py"),
            "--artifact-dir", str(output),
            "--design-spec", str(design_path),
            "--signature", str(Path(f"{approval_record}.sig")),
            "--allowed-signers", str(allowed),
            "--expected-principal", "zmzubraj",
        ],
        text=True, capture_output=True, check=False,
    )
    assert verify.returncode == 0, verify.stderr

    required = {
        "dynamic_horizon_spec.json",
        "reference_latency_cohort.csv",
        "reference_cohort_manifest.json",
        "cutoff_safe_feature_manifest.json",
        "dynamic_horizon_model.json",
        "dynamic_horizon_assignments.csv",
        "dynamic_horizon_verification.json",
        "user_approval_record.json",
    }
    assert required == {path.name for path in output.iterdir() if path.suffix in {".json", ".csv"}}
    verification = json.loads(
        (output / "dynamic_horizon_verification.json").read_text(encoding="utf-8")
    )
    assert verification["decision"] == "DYNAMIC_HORIZON_GATE_VERIFIED_NON_AUTHORIZING"
    assert verification["selection_authorized"] is False
    assert verification["qualification_authorized"] is False
    assert verification["counter_authority"] is False


def test_final_horizon_input_binds_verified_pair_feature_manifest(tmp_path: Path) -> None:
    projection = _final_pair_projection(tmp_path)
    report = verify_final_pair_feature_binding(
        pair_features_path=Path(projection["csv_path"]),
        pair_feature_manifest_path=Path(projection["manifest_path"]),
    )
    assert report["complete"] is True
    assert report["pair_feature_manifest_sha256"] == hashlib.sha256(
        Path(projection["manifest_path"]).read_bytes()
    ).hexdigest()


def test_current_verified_snapshots_apply_approved_reference_identity_dedup_v1() -> None:
    root = Path(__file__).resolve().parents[1]
    cohort, report = build_reference_latency_cohort_from_verified_snapshots(
        positive_projection_path=(
            root / "processed/stage2_controls/2026-08-17/covariate-inventory/positive_control_covariate_projection.csv"
        ),
        verified_projection_path=(
            root / "reports/historical-snapshots-417-revised-v4-verification/historical_snapshot_verified_projection.csv"
        ),
        snapshot_root=(
            root / "raw/historical_snapshots/2026-08-11/historical-snapshots-417-revised-v4"
        ),
    )

    assert len(cohort) == 410
    assert not cohort.duplicated(["chain", "contract_address"]).any()
    assert report["deduplication_policy"] == "REFERENCE_IDENTITY_DEDUP_V1"
    assert report["source_row_count"] == 417
    assert report["duplicate_identity_group_count"] == 7
    assert report["deduplicated_source_row_count"] == 7
    assert len(report["assembly_lineage"]) == 410
    assert set(cohort["protocol_family"]) == {"unknown"}
    assert "unknown" in set(cohort["architecture_proxy_pattern"])
    assert set(cohort["complexity_class"]) == {"unknown"}
    assert not cohort["source_verified_at_cutoff"].any()
    assert all(
        entry["event_time_utc"] > entry["risk_entry_time_utc"]
        for entry in report["assembly_lineage"]
    )


def test_reference_side_package_cli_is_deterministic_and_non_authorizing(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    common = [
        sys.executable,
        str(root / "build_stage2_control_dynamic_horizon_reference.py"),
        "--positive-projection",
        str(root / "processed/stage2_controls/2026-08-17/covariate-inventory/positive_control_covariate_projection.csv"),
        "--verified-projection",
        str(root / "reports/historical-snapshots-417-revised-v4-verification/historical_snapshot_verified_projection.csv"),
        "--snapshot-root",
        str(root / "raw/historical_snapshots/2026-08-11/historical-snapshots-417-revised-v4"),
    ]
    outputs = [tmp_path / "first", tmp_path / "second"]
    for output in outputs:
        run = subprocess.run(
            [*common, "--output-dir", str(output)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert run.returncode == 0, run.stderr

    expected = {
        "reference_latency_cohort.csv",
        "reference_cohort_manifest.json",
        "dynamic_horizon_model.json",
        "reference_package_manifest.json",
    }
    assert expected == {path.name for path in outputs[0].iterdir()}
    assert all(
        (outputs[0] / name).read_bytes() == (outputs[1] / name).read_bytes()
        for name in expected
    )
    model = json.loads((outputs[0] / "dynamic_horizon_model.json").read_text())
    package = json.loads((outputs[0] / "reference_package_manifest.json").read_text())
    assert model["global_lower_bound_seconds"] is not None
    assert model["global_upper_bound_seconds"] is not None
    assert package["decision"] == "DYNAMIC_HORIZON_REFERENCE_PACKAGE_VERIFIED_NON_AUTHORIZING"
    assert package["reference_row_count"] == 410
    assert package["selection_authorized"] is False
    assert package["qualification_authorized"] is False
    assert package["counter_authority"] is False
