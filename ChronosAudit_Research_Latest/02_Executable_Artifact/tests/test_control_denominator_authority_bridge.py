from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_denominator_authority_bridge import (
    AuthorityBridgeError,
    build_control_denominator_authority_bridge,
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_authoritative_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    rows = [
        {
            "deployment_id": "dep-1",
            "chain": "ethereum",
            "chain_id": 1,
            "contract_address": "0x" + "11" * 20,
            "deployment_time": "2024-01-01T00:00:00Z",
            "selection_rank_sha256": "1" * 64,
            "source_record_sha256": "2" * 64,
            "row_evidence_sha256": "3" * 64,
            "qualification_status": "VERIFIED",
            "counter_authority": True,
        },
        {
            "deployment_id": "dep-2",
            "chain": "base",
            "chain_id": 8453,
            "contract_address": "0x" + "22" * 20,
            "deployment_time": "2024-01-02T00:00:00Z",
            "selection_rank_sha256": "4" * 64,
            "source_record_sha256": "5" * 64,
            "row_evidence_sha256": "6" * 64,
            "qualification_status": "VERIFIED",
            "counter_authority": True,
        },
    ]
    projection_path = tmp_path / "qualified_denominator_verified_projection.csv"
    pd.DataFrame(rows).to_csv(projection_path, index=False)
    projection_sha256 = _sha256_file(projection_path)

    report = {
        "schema_version": "qualified_denominator_verification.v1",
        "counter_authority": True,
        "global_integrity_valid": True,
        "exact_plan_targets_met": True,
        "production_targets_met": True,
        "plan_authority": True,
        "plan_valid": True,
        "plan_sha256": "7" * 64,
        "selected_row_count": 2,
        "projection_row_count": 2,
        "integrity_errors": [],
        "row_blockers": [],
        "observed_counts": {
            "total": 2,
            "per_chain": {"base": 1, "ethereum": 1},
        },
        "artifacts": {"verified_projection_sha256": projection_sha256},
    }
    report_path = tmp_path / "qualified_denominator_verification_report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    sorted_rows = sorted(
        rows,
        key=lambda row: (
            row["chain"], row["selection_rank_sha256"], row["deployment_id"]
        ),
    )
    seal = {
        "schema_version": "qualified_denominator_final_seal.v1",
        "plan_sha256": "7" * 64,
        "manifest": {
            "schema_version": "qualified_denominator_manifest.v1",
            "row_count": 2,
            "rows": rows,
            "rows_sha256": _canonical_sha256(sorted_rows),
        },
    }
    seal_path = tmp_path / "final_seal.json"
    seal_path.write_text(json.dumps(seal), encoding="utf-8")
    return projection_path, report_path, seal_path


def test_authority_bridge_binds_sealed_projection_without_rewriting_source(
    tmp_path: Path,
) -> None:
    projection_path, report_path, seal_path = _write_authoritative_fixture(tmp_path)
    source_before = projection_path.read_bytes()

    bridged, manifest = build_control_denominator_authority_bridge(
        projection_path=projection_path,
        verification_report_path=report_path,
        final_seal_path=seal_path,
    )

    assert projection_path.read_bytes() == source_before
    assert bridged["deployment_id"].tolist() == ["dep-1", "dep-2"]
    assert bridged["authority_projection_sha256"].nunique() == 1
    assert bridged.iloc[0]["authority_projection_sha256"] == _sha256_file(projection_path)
    assert bridged.iloc[0]["authority_verification_report_sha256"] == _sha256_file(report_path)
    assert bridged.iloc[0]["authority_final_seal_sha256"] == _sha256_file(seal_path)
    assert bridged["source_manifest_sha256"].tolist() == [_sha256_file(seal_path)] * 2
    assert manifest["decision"] == "AUTHORITY_BRIDGE_VERIFIED"
    assert manifest["selection_authorized"] is False
    assert manifest["row_count"] == 2
    assert manifest["per_chain_rows"] == {"base": 1, "ethereum": 1}


def test_authority_bridge_rejects_projection_hash_mismatch(tmp_path: Path) -> None:
    projection_path, report_path, seal_path = _write_authoritative_fixture(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["artifacts"]["verified_projection_sha256"] = "0" * 64
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(AuthorityBridgeError, match="verified_projection_sha256_mismatch"):
        build_control_denominator_authority_bridge(
            projection_path=projection_path,
            verification_report_path=report_path,
            final_seal_path=seal_path,
        )


def test_authority_bridge_rejects_unauthorized_projection_row(tmp_path: Path) -> None:
    projection_path, report_path, seal_path = _write_authoritative_fixture(tmp_path)
    frame = pd.read_csv(projection_path)
    frame.loc[0, "counter_authority"] = False
    frame.to_csv(projection_path, index=False)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["artifacts"]["verified_projection_sha256"] = _sha256_file(projection_path)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(AuthorityBridgeError, match="projection_rows_not_counter_authorized"):
        build_control_denominator_authority_bridge(
            projection_path=projection_path,
            verification_report_path=report_path,
            final_seal_path=seal_path,
        )


def test_control_preflight_script_runs_without_external_pythonpath(tmp_path: Path) -> None:
    positives = tmp_path / "positives.csv"
    denominator = tmp_path / "denominator.csv"
    output = tmp_path / "preflight.json"
    pd.DataFrame([{"case_name": "case-1", "chain": "ethereum"}]).to_csv(
        positives, index=False
    )
    pd.DataFrame(
        [{"chain": "ethereum", "contract_address": "0x" + "11" * 20}]
    ).to_csv(denominator, index=False)
    executable_root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [
            sys.executable,
            str(executable_root / "preflight_stage2_controls.py"),
            "--positives",
            str(positives),
            "--denominator",
            str(denominator),
            "--output",
            str(output),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 3
    assert json.loads(output.read_text(encoding="utf-8"))["decision"] == (
        "BLOCKED_INPUT_ENRICHMENT_REQUIRED"
    )
