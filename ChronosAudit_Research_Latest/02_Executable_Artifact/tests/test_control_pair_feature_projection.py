from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_pair_feature_projection import (
    ControlPairFeatureProjectionError,
    build_pair_feature,
    project_pair_features,
    verify_pair_feature_projection,
)
from chronosaudit_stage2.public_acquisition.control_dynamic_horizon import (
    validate_cutoff_safe_pair_features,
)
from chronosaudit_stage2.public_acquisition.control_pair_covariate_import import (
    PairCovariateImportError,
    verify_cutoff_safe_pair_feature_manifest,
)


ADDRESS = "0x" + "22" * 20


def pair_scope() -> dict[str, object]:
    return {
        "case_name": "case-1",
        "positive_record_sha256": "1" * 64,
        "chain": "ethereum",
        "control_address": ADDRESS,
        "control_deployment_time": "2020-01-01T00:00:00Z",
        "required_covariate_cutoff_time": "2021-01-01T00:00:00Z",
        "denominator_record_sha256": "2" * 64,
        "pair_scope_record_sha256": "3" * 64,
    }


def denominator() -> dict[str, object]:
    return {
        "chain": "ethereum",
        "contract_address": ADDRESS,
        "denominator_record_sha256": "2" * 64,
        "counter_authority": True,
    }


def trace_result() -> dict[str, object]:
    return {
        "disposition": "complete",
        "chain": "ethereum",
        "chain_address": f"ethereum:{ADDRESS}",
        "record_sha256": "4" * 64,
        "creation_set_sha256": "5" * 64,
    }


def state_result(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "status": "complete",
        "chain": "ethereum",
        "chain_address": f"ethereum:{ADDRESS}",
        "cutoff_timestamp": 1609459200,
        "runtime_code_size": 100,
        "clone_family": "6" * 64,
        "proxy_status": "unknown",
        "proxy_family": "unknown",
        "result_sha256": "7" * 64,
        "raw_evidence_hashes": ["8" * 64],
        "field_statuses": {"proxy_classification": "unavailable"},
    }
    row.update(overrides)
    return row


def test_unavailable_fields_use_explicit_categories():
    row = build_pair_feature(
        pair_scope=pair_scope(),
        denominator=denominator(),
        trace=trace_result(),
        state=state_result(),
        source=None,
        protocol=None,
        dynamic_horizon_spec_sha256="9" * 64,
    )
    assert row["proxy_status"] == "unknown"
    assert row["protocol_family"] == "unknown"
    assert row["complexity_class"] == "unknown"
    assert row["source_verified_at_cutoff"] is False
    assert row["separation_eligible"] is False


def test_post_cutoff_source_record_is_rejected():
    with pytest.raises(ControlPairFeatureProjectionError, match="source_after_cutoff"):
        build_pair_feature(
            pair_scope=pair_scope(),
            denominator=denominator(),
            trace=trace_result(),
            state=state_result(),
            source={
                "status": "observed",
                "verified": True,
                "verified_at_utc": "2021-01-02T00:00:00Z",
                "historical_cutoff_proven": True,
                "evidence_sha256": "a" * 64,
            },
            protocol=None,
            dynamic_horizon_spec_sha256="9" * 64,
        )


def test_current_only_source_state_cannot_be_relabelled_historical():
    with pytest.raises(ControlPairFeatureProjectionError, match="source_cutoff_not_proven"):
        build_pair_feature(
            pair_scope=pair_scope(), denominator=denominator(), trace=trace_result(),
            state=state_result(),
            source={
                "status": "observed", "verified": True,
                "verified_at_utc": "2020-12-01T00:00:00Z",
                "historical_cutoff_proven": False,
                "evidence_sha256": "a" * 64,
            },
            protocol=None, dynamic_horizon_spec_sha256="9" * 64,
        )


def test_acquisition_error_is_not_normalized_to_unknown():
    with pytest.raises(
        ControlPairFeatureProjectionError, match="acquisition_error_not_category"
    ):
        build_pair_feature(
            pair_scope=pair_scope(), denominator=denominator(), trace=trace_result(),
            state=state_result(status="partial_or_disputed"), source=None, protocol=None,
            dynamic_horizon_spec_sha256="9" * 64,
        )


def test_projection_is_stable_and_accepted_by_dynamic_horizon_validator(tmp_path: Path):
    row = build_pair_feature(
        pair_scope=pair_scope(), denominator=denominator(), trace=trace_result(),
        state=state_result(), source=None, protocol=None,
        dynamic_horizon_spec_sha256="9" * 64,
    )
    first = project_pair_features(rows=[row], output_root=tmp_path / "first")
    second = project_pair_features(rows=[row], output_root=tmp_path / "second")
    assert Path(first["csv_path"]).read_bytes() == Path(second["csv_path"]).read_bytes()
    assert first["csv_sha256"] == second["csv_sha256"]
    frame = pd.read_csv(first["csv_path"], keep_default_na=False)
    normalized, report = validate_cutoff_safe_pair_features(frame)
    assert len(normalized) == 1
    assert report["decision"] == "CUTOFF_SAFE_PAIR_FEATURES_VERIFIED"
    manifest = json.loads(Path(first["manifest_path"]).read_text())
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    expected = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    assert manifest["manifest_sha256"] == expected


def test_projection_rejects_duplicate_pair(tmp_path: Path):
    row = build_pair_feature(
        pair_scope=pair_scope(), denominator=denominator(), trace=trace_result(),
        state=state_result(), source=None, protocol=None,
        dynamic_horizon_spec_sha256="9" * 64,
    )
    with pytest.raises(ControlPairFeatureProjectionError, match="duplicate_pair"):
        project_pair_features(rows=[row, row], output_root=tmp_path)


def test_projection_verifier_rehashes_copied_upstream_artifacts(tmp_path: Path):
    row = build_pair_feature(
        pair_scope=pair_scope(), denominator=denominator(), trace=trace_result(),
        state=state_result(), source=None, protocol=None,
        dynamic_horizon_spec_sha256="9" * 64,
    )
    upstream = tmp_path / "trace-checkpoint.json"
    upstream.write_text('{"checkpoint":"bound"}\n', encoding="utf-8")
    result = project_pair_features(
        rows=[row],
        output_root=tmp_path / "projection",
        upstream_artifacts={"trace_checkpoint": upstream},
    )
    report = verify_pair_feature_projection(Path(result["manifest_path"]))
    assert report["complete"] is True
    copied = Path(result["manifest_path"]).parent / "input-evidence" / upstream.name
    copied.write_text('{"checkpoint":"substituted"}\n', encoding="utf-8")
    with pytest.raises(ControlPairFeatureProjectionError, match="upstream_hash_mismatch"):
        verify_pair_feature_projection(Path(result["manifest_path"]))


def test_import_boundary_requires_trace_and_state_checkpoint_manifests(tmp_path: Path):
    row = build_pair_feature(
        pair_scope=pair_scope(), denominator=denominator(), trace=trace_result(),
        state=state_result(), source=None, protocol=None,
        dynamic_horizon_spec_sha256="9" * 64,
    )
    required_labels = (
        "pair_scope", "denominator", "trace_results", "trace_checkpoint",
        "state_results", "state_checkpoint", "dynamic_horizon_spec",
    )
    artifacts = {}
    for label in required_labels:
        path = tmp_path / f"{label}.json"
        path.write_text(json.dumps({"label": label}) + "\n", encoding="utf-8")
        artifacts[label] = path
    result = project_pair_features(
        rows=[row], output_root=tmp_path / "complete", upstream_artifacts=artifacts
    )
    report = verify_cutoff_safe_pair_feature_manifest(Path(result["manifest_path"]))
    assert report["complete"] is True

    incomplete = dict(artifacts)
    incomplete.pop("state_checkpoint")
    missing = project_pair_features(
        rows=[row], output_root=tmp_path / "missing", upstream_artifacts=incomplete
    )
    with pytest.raises(PairCovariateImportError, match="required_upstream_missing"):
        verify_cutoff_safe_pair_feature_manifest(Path(missing["manifest_path"]))
