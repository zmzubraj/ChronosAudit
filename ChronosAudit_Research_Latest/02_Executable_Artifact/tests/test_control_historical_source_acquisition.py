from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.control_historical_source_acquisition import (
    HistoricalSourceAcquisitionError,
    acquire_historical_source_batch,
)


def _plan() -> dict[str, object]:
    return {
        "schema_version": "chronosaudit.control_historical_expansion_query_plan.v1",
        "purpose": "HISTORICAL_DENOMINATOR_EXPANSION_ONLY",
        "source_object_count": 2,
        "source_total_bytes": 7,
        "source_objects": [
            {"key": "v2/contract_deployments/a.parquet", "etag": "etag-a", "size": 3},
            {"key": "v2/contract_deployments/b.parquet", "etag": "etag-b", "size": 4},
        ],
    }


def _approval() -> dict[str, object]:
    return {
        "schema_version": "chronosaudit.control_source_acquisition_approval_verification.v2",
        "decision": "SOURCE_ACQUISITION_APPROVAL_VERIFIED",
        "source_object_count": 2,
        "maximum_download_bytes": 7,
        "acquisition_authorized": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def test_acquisition_writes_exact_sources_receipts_and_non_authorizing_manifest(
    tmp_path: Path,
) -> None:
    bodies = {"a.parquet": b"abc", "b.parquet": b"defg"}

    def fetch(url: str, offset: int, write: object) -> tuple[int, dict[str, str]]:
        name = url.rsplit("/", 1)[-1]
        body = bodies[name]
        etag = "etag-a" if name == "a.parquet" else "etag-b"
        write(body)
        return 200, {"etag": f'"{etag}"', "content-length": str(len(body))}

    source_root = tmp_path / "sources"
    receipt_root = tmp_path / "receipts"
    manifest = acquire_historical_source_batch(
        query_plan=_plan(),
        approval_verification=_approval(),
        query_plan_file_sha256="a" * 64,
        source_root=source_root,
        receipt_root=receipt_root,
        fetch=fetch,
    )

    assert manifest["schema_version"] == "chronosaudit.control_historical_source_import.v1"
    assert manifest["decision"] == "SOURCE_BATCH_CAPTURED_AWAITING_IMPORT_VERIFICATION"
    assert manifest["captured_object_count"] == 2
    assert manifest["captured_total_bytes"] == 7
    assert manifest["acquisition_authorized"] is False
    assert manifest["rpc_authorized"] is False
    assert manifest["selection_authorized"] is False
    assert (source_root / "v2/contract_deployments/a.parquet").read_bytes() == b"abc"
    assert (source_root / "v2/contract_deployments/b.parquet").read_bytes() == b"defg"
    for row in manifest["objects"]:
        source = Path(row["path"])
        headers = Path(row["headers_path"])
        assert hashlib.sha256(source.read_bytes()).hexdigest() == row["sha256"]
        assert hashlib.sha256(headers.read_bytes()).hexdigest() == row["headers_sha256"]
        assert json.loads(headers.read_text())["normalized_etag"] == row["etag"]


def test_acquisition_rejects_etag_mismatch_and_preserves_no_final_file(
    tmp_path: Path,
) -> None:
    plan = _plan()
    plan["source_object_count"] = 1
    plan["source_total_bytes"] = 3
    plan["source_objects"] = plan["source_objects"][:1]
    approval = _approval()
    approval["source_object_count"] = 1
    approval["maximum_download_bytes"] = 3

    def fetch(url: str, offset: int, write: object) -> tuple[int, dict[str, str]]:
        write(b"abc")
        return 200, {"etag": '"wrong"', "content-length": "3"}

    source_root = tmp_path / "sources"
    with pytest.raises(HistoricalSourceAcquisitionError, match="source_etag_mismatch"):
        acquire_historical_source_batch(
            query_plan=plan,
            approval_verification=approval,
            query_plan_file_sha256="a" * 64,
            source_root=source_root,
            receipt_root=tmp_path / "receipts",
            fetch=fetch,
        )
    assert not (source_root / "v2/contract_deployments/a.parquet").exists()


def test_acquisition_rejects_scope_or_authority_drift(tmp_path: Path) -> None:
    approval = _approval()
    approval["rpc_authorized"] = True
    with pytest.raises(HistoricalSourceAcquisitionError, match="approval_rpc_authorized_invalid"):
        acquire_historical_source_batch(
            query_plan=_plan(),
            approval_verification=approval,
            query_plan_file_sha256="a" * 64,
            source_root=tmp_path / "sources",
            receipt_root=tmp_path / "receipts",
            fetch=lambda *_: (200, {}),
        )
