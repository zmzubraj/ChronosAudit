import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.inventory import (
    capture_chainlist_inventory,
    capture_s3_inventory,
    capture_sourcify_inventory,
)


def test_chainlist_inventory_excludes_secret_and_tracking_endpoints(tmp_path: Path):
    payload = {
        "chains": [
            {
                "name": "Ethereum Mainnet",
                "chainId": 1,
                "rpc": [
                    "https://rpc.publicnode.com/eth",
                    "https://rpc.service.example/${API_KEY}",
                    "https://rpc.tracker.example/eth?utm_source=chainlist",
                ],
            }
        ]
    }

    result = capture_chainlist_inventory(json.dumps(payload).encode("utf-8"), tmp_path)

    assert result["raw_sha256"]
    assert Path(result["raw_artifact_path"]).exists()
    assert Path(result["manifest_path"]).exists()
    assert all("${" not in row["endpoint"] for row in result["eligible_endpoints"])
    assert all(row["tracking"] is False for row in result["eligible_endpoints"])
    assert [row["endpoint"] for row in result["eligible_endpoints"]] == ["https://rpc.publicnode.com/eth"]

    normalized = pd.read_csv(result["normalized_path"])
    assert normalized["eligible"].tolist() == [True, False, False]
    assert set(normalized.loc[~normalized["eligible"], "exclusion_reason"]) == {
        "secret_template_endpoint",
        "tracking_endpoint",
    }


def test_s3_inventory_preserves_pagination_tokens_and_object_metadata(tmp_path: Path):
    page = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>ethereum/</Prefix>
  <NextContinuationToken>token-2</NextContinuationToken>
  <Contents>
    <Key>ethereum/contracts/part-0001.parquet</Key>
    <Size>123</Size>
    <ETag>&quot;etag-1&quot;</ETag>
    <LastModified>2026-08-08T00:00:00.000Z</LastModified>
  </Contents>
</ListBucketResult>
"""

    result = capture_s3_inventory(
        [page],
        tmp_path,
        provider="aws_public_dataset",
        chain="ethereum",
        prefix="ethereum/",
    )

    assert result["next_tokens"] == ["token-2"]
    assert result["errors"] == []
    assert result["row_count"] == 1
    assert Path(result["raw_artifact_paths"][0]).exists()

    normalized = pd.read_csv(result["normalized_path"])
    assert normalized.loc[0, "key"] == "ethereum/contracts/part-0001.parquet"
    assert normalized.loc[0, "etag"] == "etag-1"
    assert normalized.loc[0, "size"] == 123


def test_sourcify_inventory_tracks_dataset_name(tmp_path: Path):
    page = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>sourcify</Name>
  <Prefix>verified_contracts/ethereum/</Prefix>
  <Contents>
    <Key>verified_contracts/ethereum/part-0001.parquet</Key>
    <Size>456</Size>
    <ETag>&quot;etag-2&quot;</ETag>
    <LastModified>2026-08-08T01:00:00.000Z</LastModified>
  </Contents>
</ListBucketResult>
"""

    result = capture_sourcify_inventory(
        {"verified_contracts": [page]},
        tmp_path,
        chain="ethereum",
    )

    normalized = pd.read_csv(result["normalized_path"])
    assert normalized["dataset"].tolist() == ["verified_contracts"]
    assert normalized["chain"].tolist() == ["ethereum"]
    assert result["row_count"] == 1


def test_s3_inventory_stops_on_page_limit_breach(tmp_path: Path):
    page = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>ethereum/</Prefix>
</ListBucketResult>
"""

    result = capture_s3_inventory(
        [page, page],
        tmp_path,
        provider="aws_public_dataset",
        chain="ethereum",
        prefix="ethereum/",
        max_pages=1,
    )

    manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
    assert result["completed"] is False
    assert manifest["outcome"] == "LIMIT_BREACH"
    assert "max_pages_exceeded" in manifest["errors"]
    assert manifest["limits"]["max_pages"] == 1


def test_s3_inventory_stops_on_object_limit_breach(tmp_path: Path):
    page = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>ethereum/</Prefix>
  <Contents><Key>a.parquet</Key><Size>1</Size><ETag>&quot;a&quot;</ETag></Contents>
  <Contents><Key>b.parquet</Key><Size>1</Size><ETag>&quot;b&quot;</ETag></Contents>
</ListBucketResult>
"""

    result = capture_sourcify_inventory(
        {"verified_contracts": [page]},
        tmp_path,
        chain="ethereum",
        max_objects=1,
    )

    manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
    assert result["completed"] is False
    assert manifest["outcome"] == "LIMIT_BREACH"
    assert "max_objects_exceeded" in manifest["errors"]
    assert manifest["limits"]["max_objects"] == 1


def test_s3_inventory_stops_on_response_byte_limit_breach(tmp_path: Path):
    page = b"x" * 20

    result = capture_s3_inventory(
        [page],
        tmp_path,
        provider="aws_public_dataset",
        chain="ethereum",
        prefix="ethereum/",
        max_response_bytes=10,
    )

    manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
    assert result["completed"] is False
    assert manifest["outcome"] == "LIMIT_BREACH"
    assert "max_response_bytes_exceeded" in manifest["errors"]
    assert manifest["limits"]["max_response_bytes"] == 10


def test_chainlist_inventory_stops_on_elapsed_limit_breach(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    payload = {
        "chains": [
            {
                "name": "Ethereum Mainnet",
                "chainId": 1,
                "rpc": ["https://rpc.publicnode.com/eth"],
            }
        ]
    }
    ticks = iter([0.0, 0.5])
    monkeypatch.setattr("chronosaudit_stage2.public_acquisition.inventory.time.monotonic", lambda: next(ticks))

    result = capture_chainlist_inventory(
        json.dumps(payload).encode("utf-8"),
        tmp_path,
        max_elapsed_seconds=0.1,
    )

    manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
    assert result["completed"] is False
    assert manifest["outcome"] == "LIMIT_BREACH"
    assert "max_elapsed_seconds_exceeded" in manifest["errors"]
