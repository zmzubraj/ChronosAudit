from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.control_historical_source_import import (
    HistoricalSourceImportError,
    verify_historical_source_import,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    source_root = tmp_path / "sources"
    receipt_root = tmp_path / "receipts"
    source_root.mkdir()
    receipt_root.mkdir()
    objects = []
    receipts = []
    for index, size in enumerate((10, 12)):
        start = index * 1_000_000
        key = f"v2/contract_deployments/contract_deployments_{start}_{start + 1_000_000}.parquet"
        source = source_root / f"{index}.parquet"
        source.write_bytes(bytes([index + 1]) * size)
        headers = receipt_root / f"{index}.headers.json"
        headers.write_text(json.dumps({"etag": f"etag-{index}"}), encoding="utf-8")
        objects.append(
            {
                "start": start,
                "end": start + 1_000_000,
                "key": key,
                "etag": f"etag-{index}",
                "size": size,
                "last_modified": "2026-01-01T00:00:00Z",
                "inventory_page_sha256": "a" * 64,
            }
        )
        receipts.append(
            {
                "key": key,
                "etag": f"etag-{index}",
                "path": str(source),
                "size": size,
                "sha256": _sha(source),
                "headers_path": str(headers),
                "headers_sha256": _sha(headers),
            }
        )
    plan = {
        "schema_version": "chronosaudit.control_historical_expansion_query_plan.v1",
        "decision": "FROZEN_QUERY_PLAN_AWAITS_ACCOUNTABLE_SIGNED_APPROVAL",
        "purpose": "HISTORICAL_DENOMINATOR_EXPANSION_ONLY",
        "source_object_count": 2,
        "source_total_bytes": 22,
        "source_objects": objects,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    manifest = {
        "schema_version": "chronosaudit.control_historical_source_import.v1",
        "query_plan_file_sha256": _sha(plan_path),
        "objects": receipts,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
    }
    manifest_path = receipt_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return plan_path, manifest_path, source_root, receipt_root


def test_source_import_verifies_exact_receipts_and_is_non_authorizing(tmp_path: Path) -> None:
    plan, manifest, source_root, receipt_root = _fixture(tmp_path)
    report = verify_historical_source_import(
        query_plan_path=plan,
        import_manifest_path=manifest,
        source_root=source_root,
        receipt_root=receipt_root,
    )
    assert report["decision"] == "SOURCE_BATCH_VERIFIED_FOR_LOCAL_TRANSFORM"
    assert report["verified_object_count"] == 2
    assert report["verified_total_bytes"] == 22
    assert report["rpc_authorized"] is False
    assert report["selection_authorized"] is False


def test_source_import_rejects_tamper_and_path_escape(tmp_path: Path) -> None:
    plan, manifest, source_root, receipt_root = _fixture(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["objects"][0]["etag"] = "wrong"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(HistoricalSourceImportError, match="source_etag_mismatch"):
        verify_historical_source_import(
            query_plan_path=plan,
            import_manifest_path=manifest,
            source_root=source_root,
            receipt_root=receipt_root,
        )

    payload["objects"][0]["etag"] = "etag-0"
    outside = tmp_path / "outside.parquet"
    outside.write_bytes(b"x" * 10)
    payload["objects"][0]["path"] = str(outside)
    payload["objects"][0]["sha256"] = _sha(outside)
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(HistoricalSourceImportError, match="source_path_escape"):
        verify_historical_source_import(
            query_plan_path=plan,
            import_manifest_path=manifest,
            source_root=source_root,
            receipt_root=receipt_root,
        )
