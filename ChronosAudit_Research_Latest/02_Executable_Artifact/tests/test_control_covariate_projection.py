from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_covariate_projection import (
    CovariateProjectionError,
    build_denominator_covariate_projection,
    build_positive_covariate_projection,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _positive_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    snapshot_root = tmp_path / "snapshots"
    case_path = snapshot_root / "cases" / "case-1.json"
    case_path.parent.mkdir(parents=True)
    case = {
        "strict_snapshot_sha256": "a" * 64,
        "strict_snapshot_closed": True,
        "strict_snapshot": {
            "strict_snapshot_closed": True,
            "deployment_timestamp": 1_704_067_200,
            "prediction_cutoff_timestamp": 1_704_153_600,
            "snapshot": {
                "status": "complete",
                "code": {"status": "consensus", "value": "0x60016002"},
                "metadata_stripped_bytecode_sha256": "b" * 64,
                "implementation": {"status": "consensus", "value": "0x" + "22" * 20},
                "beacon": {"status": "consensus", "value": None},
                "beacon_implementation": {"status": "not_applicable", "value": None},
                "eip1167_target": None,
                "diamond_resolution_status": "requires_loupe_or_historical_event_resolver",
            },
        },
    }
    case_path.write_text(json.dumps(case), encoding="utf-8")

    positives_path = tmp_path / "positives.csv"
    pd.DataFrame(
        [{
            "case_name": "case-1",
            "chain": "ethereum",
            "target_contract_address": "0x" + "11" * 20,
        }]
    ).to_csv(positives_path, index=False)
    verified_path = tmp_path / "verified.csv"
    pd.DataFrame(
        [{
            "case_name": "case-1",
            "case_artifact_path": "cases/case-1.json",
            "case_artifact_sha256": _sha256_file(case_path),
            "counter_authority": True,
        }]
    ).to_csv(verified_path, index=False)
    return positives_path, verified_path, snapshot_root


def test_positive_projection_derives_only_cutoff_safe_evidence(tmp_path: Path) -> None:
    positives_path, verified_path, snapshot_root = _positive_fixture(tmp_path)
    projection, manifest = build_positive_covariate_projection(
        positives_path=positives_path,
        verified_projection_path=verified_path,
        snapshot_root=snapshot_root,
    )

    row = projection.iloc[0]
    assert row["deployment_time"] == "2024-01-01T00:00:00Z"
    assert row["prediction_cutoff_time"] == "2024-01-02T00:00:00Z"
    assert row["code_size"] == 4
    assert row["identity_group"] == "1:0x" + "11" * 20
    assert row["clone_family"] == "b" * 64
    assert row["proxy_status"] == "EIP1967_PROXY"
    assert row["proxy_family"] == "eip1967:0x" + "22" * 20
    assert row["source_verified_at_cutoff"] == ""
    assert row["protocol_family"] == ""
    assert row["mechanism_family"] == ""
    assert row["follow_up_horizon"] == ""
    assert len(row["positive_record_sha256"]) == 64
    assert manifest["selection_authorized"] is False
    assert manifest["coverage"]["deployment_time"] == 1
    assert manifest["coverage"]["source_verified_at_cutoff"] == 0


def test_positive_projection_rejects_case_artifact_hash_mismatch(tmp_path: Path) -> None:
    positives_path, verified_path, snapshot_root = _positive_fixture(tmp_path)
    verified = pd.read_csv(verified_path)
    verified.loc[0, "case_artifact_sha256"] = "0" * 64
    verified.to_csv(verified_path, index=False)

    with pytest.raises(CovariateProjectionError, match="case_artifact_sha256_mismatch"):
        build_positive_covariate_projection(
            positives_path=positives_path,
            verified_projection_path=verified_path,
            snapshot_root=snapshot_root,
        )


def test_denominator_projection_adds_only_evidence_supported_identity(tmp_path: Path) -> None:
    authority_path = tmp_path / "authority.csv"
    pd.DataFrame(
        [{
            "chain": "base",
            "chain_id": "8453",
            "contract_address": "0x" + "33" * 20,
            "deployment_time": "2024-01-03T00:00:00Z",
            "source_record_sha256": "c" * 64,
            "source_manifest_sha256": "d" * 64,
            "row_evidence_sha256": "e" * 64,
            "counter_authority": True,
        }]
    ).to_csv(authority_path, index=False)

    projection, manifest = build_denominator_covariate_projection(
        authority_projection_path=authority_path
    )

    row = projection.iloc[0]
    assert row["identity_group"] == "8453:0x" + "33" * 20
    for field in (
        "code_size", "proxy_status", "source_verified_at_cutoff", "clone_family",
        "proxy_family", "protocol_family",
    ):
        assert row[field] == ""
        assert manifest["coverage"][field] == 0
    assert row["identity_group_resolution"] == "DERIVED_EXACT_CHAIN_ADDRESS"
    assert manifest["selection_authorized"] is False
