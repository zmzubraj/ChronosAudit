from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_pair_covariate_import import (
    PairCovariateImportError,
    build_updated_import_ledger,
    make_import_ledger_entry_sha256,
    make_no_repeat_scope_sha256,
    make_pair_covariate_record_sha256,
    verify_control_pair_covariate_batch,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_batch(tmp_path: Path) -> dict[str, Path]:
    scope_path = tmp_path / "scope.csv"
    pair_hash = "1" * 64
    pd.DataFrame(
        [
            {
                "case_name": "case-1",
                "chain": "ethereum",
                "positive_prediction_cutoff_time": "2024-02-01T00:00:00Z",
                "positive_record_sha256": "2" * 64,
                "deployment_id": "dep-1",
                "control_address": "0x" + "33" * 20,
                "control_deployment_time": "2024-01-20T00:00:00Z",
                "denominator_record_sha256": "4" * 64,
                "source_manifest_sha256": "5" * 64,
                "row_evidence_sha256": "6" * 64,
                "authority_projection_sha256": "7" * 64,
                "required_covariate_cutoff_time": "2024-02-01T00:00:00Z",
                "pair_scope_record_sha256": pair_hash,
            }
        ]
    ).to_csv(scope_path, index=False)

    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    receipt_paths: dict[str, Path] = {}
    for name in ("query-plan", "runtime", "proxy", "source", "protocol"):
        path = raw_root / f"{name}.json"
        path.write_text(json.dumps({"name": name}), encoding="utf-8")
        receipt_paths[name] = path
    raw_manifest = {
        "schema_version": "chronosaudit.control_pair_raw_evidence_manifest.v1",
        "receipts": [
            {"path": path.name, "sha256": _sha256_file(path)}
            for path in receipt_paths.values()
        ],
    }
    raw_manifest_path = raw_root / "raw-manifest.json"
    raw_manifest_path.write_text(json.dumps(raw_manifest), encoding="utf-8")

    evidence_path = tmp_path / "evidence.csv"
    row = {
        "pair_scope_record_sha256": pair_hash,
        "case_name": "case-1",
        "chain": "ethereum",
        "control_address": "0x" + "33" * 20,
        "denominator_record_sha256": "4" * 64,
        "covariate_cutoff_time": "2024-02-01T00:00:00Z",
        "evidence_block_number": 100,
        "evidence_block_timestamp": "2024-01-31T23:59:59Z",
        "code_size": 1234,
        "proxy_status": "DIRECT",
        "source_verified_at_cutoff": True,
        "source_verification_basis": "PUBLISHED_BY_CUTOFF",
        "identity_group": "1:0x" + "33" * 20,
        "clone_family": "8" * 64,
        "proxy_family": "direct",
        "protocol_family": "lending",
        "runtime_code_evidence_sha256": _sha256_file(receipt_paths["runtime"]),
        "proxy_evidence_sha256": _sha256_file(receipt_paths["proxy"]),
        "source_verification_evidence_sha256": _sha256_file(receipt_paths["source"]),
        "protocol_evidence_sha256": _sha256_file(receipt_paths["protocol"]),
        "pair_covariate_record_sha256": "",
    }
    row["pair_covariate_record_sha256"] = make_pair_covariate_record_sha256(row)
    pd.DataFrame([row]).to_csv(evidence_path, index=False)

    batch_manifest = {
        "schema_version": "chronosaudit.control_pair_covariate_batch.v1",
        "batch_id": "batch-1",
        "pair_scope_sha256": _sha256_file(scope_path),
        "evidence_csv_sha256": _sha256_file(evidence_path),
        "raw_evidence_manifest_path": "raw-manifest.json",
        "raw_evidence_manifest_sha256": _sha256_file(raw_manifest_path),
        "query_plan_sha256": _sha256_file(receipt_paths["query-plan"]),
        "no_repeat_scope_sha256": make_no_repeat_scope_sha256([pair_hash]),
        "row_count": 1,
        "selection_authorized": False,
    }
    batch_manifest_path = tmp_path / "batch-manifest.json"
    batch_manifest_path.write_text(json.dumps(batch_manifest), encoding="utf-8")
    return {
        "scope": scope_path,
        "evidence": evidence_path,
        "batch_manifest": batch_manifest_path,
        "raw_root": raw_root,
        "runtime_receipt": receipt_paths["runtime"],
    }


def _write_verification_report(paths: dict[str, Path], destination: Path) -> Path:
    _, report = verify_control_pair_covariate_batch(
        pair_scope_path=paths["scope"],
        evidence_csv_path=paths["evidence"],
        batch_manifest_path=paths["batch_manifest"],
        raw_evidence_root=paths["raw_root"],
    )
    destination.write_text(json.dumps(report), encoding="utf-8")
    return destination


def test_pair_covariate_batch_verifies_scope_cutoff_receipts_and_hashes(
    tmp_path: Path,
) -> None:
    paths = _write_batch(tmp_path)
    verified, report = verify_control_pair_covariate_batch(
        pair_scope_path=paths["scope"],
        evidence_csv_path=paths["evidence"],
        batch_manifest_path=paths["batch_manifest"],
        raw_evidence_root=paths["raw_root"],
    )

    assert len(verified) == 1
    assert report["decision"] == "PAIR_COVARIATE_IMPORT_VERIFIED"
    assert report["selection_authorized"] is False
    assert report["verified_rows"] == 1
    assert report["replayed_pair_records"] == 0


def test_pair_covariate_batch_rejects_cutoff_mismatch(tmp_path: Path) -> None:
    paths = _write_batch(tmp_path)
    evidence = pd.read_csv(paths["evidence"])
    evidence.loc[0, "covariate_cutoff_time"] = "2024-02-02T00:00:00Z"
    evidence.loc[0, "pair_covariate_record_sha256"] = make_pair_covariate_record_sha256(
        evidence.loc[0].to_dict()
    )
    evidence.to_csv(paths["evidence"], index=False)
    manifest = json.loads(paths["batch_manifest"].read_text(encoding="utf-8"))
    manifest["evidence_csv_sha256"] = _sha256_file(paths["evidence"])
    paths["batch_manifest"].write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(PairCovariateImportError, match="covariate_cutoff_mismatch"):
        verify_control_pair_covariate_batch(
            pair_scope_path=paths["scope"],
            evidence_csv_path=paths["evidence"],
            batch_manifest_path=paths["batch_manifest"],
            raw_evidence_root=paths["raw_root"],
        )


def test_pair_covariate_batch_rejects_tampered_raw_receipt(tmp_path: Path) -> None:
    paths = _write_batch(tmp_path)
    paths["runtime_receipt"].write_text("tampered", encoding="utf-8")

    with pytest.raises(PairCovariateImportError, match="raw_receipt_sha256_mismatch"):
        verify_control_pair_covariate_batch(
            pair_scope_path=paths["scope"],
            evidence_csv_path=paths["evidence"],
            batch_manifest_path=paths["batch_manifest"],
            raw_evidence_root=paths["raw_root"],
        )


def test_pair_covariate_batch_rejects_symlinked_raw_receipt(tmp_path: Path) -> None:
    paths = _write_batch(tmp_path)
    link = paths["raw_root"] / "runtime-link.json"
    link.symlink_to(paths["runtime_receipt"])
    raw_manifest_path = paths["raw_root"] / "raw-manifest.json"
    raw_manifest = json.loads(raw_manifest_path.read_text(encoding="utf-8"))
    for receipt in raw_manifest["receipts"]:
        if receipt["path"] == "runtime.json":
            receipt["path"] = link.name
    raw_manifest_path.write_text(json.dumps(raw_manifest), encoding="utf-8")
    batch_manifest = json.loads(paths["batch_manifest"].read_text(encoding="utf-8"))
    batch_manifest["raw_evidence_manifest_sha256"] = _sha256_file(raw_manifest_path)
    paths["batch_manifest"].write_text(json.dumps(batch_manifest), encoding="utf-8")

    with pytest.raises(PairCovariateImportError, match="raw_receipt_not_ordinary_file"):
        verify_control_pair_covariate_batch(
            pair_scope_path=paths["scope"],
            evidence_csv_path=paths["evidence"],
            batch_manifest_path=paths["batch_manifest"],
            raw_evidence_root=paths["raw_root"],
        )


def test_pair_covariate_batch_rejects_accepted_pair_replay(tmp_path: Path) -> None:
    paths = _write_batch(tmp_path)
    report_path = _write_verification_report(paths, tmp_path / "verification.json")
    ledger = build_updated_import_ledger(
        verification_report_path=report_path,
        batch_manifest_path=paths["batch_manifest"],
        evidence_csv_path=paths["evidence"],
        accepted_at_utc="2026-08-17T20:00:00Z",
    )
    entry = ledger["accepted_batches"][0]
    entry["batch_id"] = "older-batch"
    entry["evidence_csv_sha256"] = "a" * 64
    entry["entry_sha256"] = make_import_ledger_entry_sha256(entry)
    ledger["head_entry_sha256"] = entry["entry_sha256"]
    ledger_path = tmp_path / "accepted-ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(PairCovariateImportError, match="pair_scope_replay"):
        verify_control_pair_covariate_batch(
            pair_scope_path=paths["scope"],
            evidence_csv_path=paths["evidence"],
            batch_manifest_path=paths["batch_manifest"],
            raw_evidence_root=paths["raw_root"],
            accepted_ledger_path=ledger_path,
        )


def test_verified_batch_builds_first_hash_chained_ledger_entry(tmp_path: Path) -> None:
    paths = _write_batch(tmp_path)
    report_path = _write_verification_report(paths, tmp_path / "verification.json")

    ledger = build_updated_import_ledger(
        verification_report_path=report_path,
        batch_manifest_path=paths["batch_manifest"],
        evidence_csv_path=paths["evidence"],
        accepted_at_utc="2026-08-17T20:00:00Z",
    )

    assert ledger["accepted_batch_count"] == 1
    assert ledger["accepted_pair_count"] == 1
    assert ledger["selection_authorized"] is False
    entry = ledger["accepted_batches"][0]
    assert entry["sequence"] == 1
    assert entry["previous_entry_sha256"] == "0" * 64
    assert entry["entry_sha256"] == make_import_ledger_entry_sha256(entry)
    assert ledger["head_entry_sha256"] == entry["entry_sha256"]


def test_import_ledger_rejects_tampered_existing_hash_chain(tmp_path: Path) -> None:
    paths = _write_batch(tmp_path)
    report_path = _write_verification_report(paths, tmp_path / "verification.json")
    ledger = build_updated_import_ledger(
        verification_report_path=report_path,
        batch_manifest_path=paths["batch_manifest"],
        evidence_csv_path=paths["evidence"],
        accepted_at_utc="2026-08-17T20:00:00Z",
    )
    ledger["accepted_batches"][0]["batch_id"] = "tampered"
    ledger_path = tmp_path / "accepted-ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(PairCovariateImportError, match="accepted_ledger_entry_hash_mismatch"):
        build_updated_import_ledger(
            verification_report_path=report_path,
            batch_manifest_path=paths["batch_manifest"],
            evidence_csv_path=paths["evidence"],
            accepted_at_utc="2026-08-17T21:00:00Z",
            existing_ledger_path=ledger_path,
        )
