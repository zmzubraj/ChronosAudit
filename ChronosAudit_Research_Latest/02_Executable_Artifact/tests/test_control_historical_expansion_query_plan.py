from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_historical_expansion_query_plan import (
    HistoricalExpansionQueryPlanError,
    build_historical_expansion_query_plan,
    verify_historical_expansion_query_plan,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixtures(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    inventory = tmp_path / "inventory.csv"
    pd.DataFrame(
        [
            {
                "provider": "sourcify_bucket",
                "dataset": "v2/contract_deployments",
                "chain": "all",
                "prefix": "v2/contract_deployments/all/",
                "key": f"v2/contract_deployments/contract_deployments_{start}_{start + 1000000}.parquet",
                "etag": str(start),
                "size": 100 + start,
                "last_modified": "2026-01-01T00:00:00Z",
                "page_index": 0,
                "raw_page_sha256": "a" * 64,
            }
            for start in (0, 1_000_000, 2_000_000)
        ]
    ).to_csv(inventory, index=False)
    inventory_manifest = tmp_path / "inventory-manifest.json"
    inventory_manifest.write_text(
        json.dumps(
            {
                "provider": "sourcify_bucket",
                "dataset": "v2/contract_deployments",
                "chain": "all",
                "outcome": "COMPLETE",
                "row_count": 3,
                "objects_processed": 3,
                "errors": [],
            }
        ),
        encoding="utf-8",
    )
    chunks = tmp_path / "chunks.csv"
    pd.DataFrame(
        [
            {
                "chunk_id": "chunk-1",
                "chunk_sequence": 1,
                "case_name": "case-a",
                "chain": "ethereum",
                "admissible_deployment_start": "2020-01-01T00:00:00Z",
                "admissible_deployment_end": "2020-02-01T00:00:00Z",
                "positive_prediction_cutoff_time": "2020-02-01T00:00:00Z",
                "minimum_additional_distinct_slots": 9,
                "expansion_requirement_sha256": "b" * 64,
                "chunk_scope_sha256": "c" * 64,
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            }
        ]
    ).to_csv(chunks, index=False)
    chunk_manifest = tmp_path / "chunk-manifest.json"
    chunk_manifest.write_text(
        json.dumps(
            {
                "schema_version": "chronosaudit.control_denominator_expansion_chunk_plan.v1",
                "decision": "BOUNDED_EXPANSION_PLAN_AWAITS_ACCOUNTABLE_ACQUISITION_APPROVAL",
                "chunk_count": 1,
                "cases_requiring_expansion": 1,
                "minimum_additional_distinct_slots": 9,
                "output": {"sha256": _sha(chunks)},
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            }
        ),
        encoding="utf-8",
    )
    return inventory, inventory_manifest, chunks, chunk_manifest


def test_plan_is_deterministic_bounded_and_non_authorizing(tmp_path: Path) -> None:
    inventory, inventory_manifest, chunks, chunk_manifest = _fixtures(tmp_path)
    kwargs = dict(
        inventory_path=inventory,
        inventory_manifest_path=inventory_manifest,
        chunk_plan_path=chunks,
        chunk_manifest_path=chunk_manifest,
        historical_end_exclusive=2_000_000,
    )
    plan = build_historical_expansion_query_plan(**kwargs)
    assert plan == build_historical_expansion_query_plan(**kwargs)
    assert plan["decision"] == "FROZEN_QUERY_PLAN_AWAITS_ACCOUNTABLE_SIGNED_APPROVAL"
    assert plan["source_object_count"] == 2
    assert plan["source_total_bytes"] == 1_000_200
    assert [row["start"] for row in plan["source_objects"]] == [0, 1_000_000]
    assert plan["rpc_methods"] == [
        "eth_chainId",
        "eth_getTransactionReceipt",
        "eth_getBlockByHash",
    ]
    assert plan["candidate_queue_rules"] == {
        "allocation_algorithm": "deterministic_capacity_dinic_v1",
        "candidate_identity": "chain_id:lower(address)",
        "candidate_identity_capacity": 1,
        "overflow_disposition": "REPLAN_REQUIRED",
        "per_case_edge_scan_ceiling": 1000,
        "queue_hash_required_before_rpc": True,
        "reserve_multiplier": 10,
        "reserve_target_rule": "minimum_additional_distinct_slots*reserve_multiplier",
    }
    assert plan["acquisition_authorized"] is False
    assert plan["rpc_authorized"] is False
    assert plan["selection_authorized"] is False
    assert len(plan["query_plan_sha256"]) == 64


def test_plan_rejects_incomplete_or_noncontiguous_inventory(tmp_path: Path) -> None:
    inventory, inventory_manifest, chunks, chunk_manifest = _fixtures(tmp_path)
    payload = json.loads(inventory_manifest.read_text(encoding="utf-8"))
    payload["outcome"] = "PARTIAL"
    inventory_manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(HistoricalExpansionQueryPlanError, match="inventory_not_complete"):
        build_historical_expansion_query_plan(
            inventory_path=inventory,
            inventory_manifest_path=inventory_manifest,
            chunk_plan_path=chunks,
            chunk_manifest_path=chunk_manifest,
            historical_end_exclusive=2_000_000,
        )

    payload["outcome"] = "COMPLETE"
    inventory_manifest.write_text(json.dumps(payload), encoding="utf-8")
    frame = pd.read_csv(inventory)
    frame.loc[1, "key"] = "v2/contract_deployments/contract_deployments_1500000_2500000.parquet"
    frame.to_csv(inventory, index=False)
    with pytest.raises(HistoricalExpansionQueryPlanError, match="source_object_range_noncontiguous"):
        build_historical_expansion_query_plan(
            inventory_path=inventory,
            inventory_manifest_path=inventory_manifest,
            chunk_plan_path=chunks,
            chunk_manifest_path=chunk_manifest,
            historical_end_exclusive=2_000_000,
        )


def test_persisted_plan_verifier_rejects_tamper(tmp_path: Path) -> None:
    inventory, inventory_manifest, chunks, chunk_manifest = _fixtures(tmp_path)
    plan = build_historical_expansion_query_plan(
        inventory_path=inventory,
        inventory_manifest_path=inventory_manifest,
        chunk_plan_path=chunks,
        chunk_manifest_path=chunk_manifest,
        historical_end_exclusive=2_000_000,
    )
    plan_path = tmp_path / "query-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    report = verify_historical_expansion_query_plan(
        query_plan_path=plan_path,
        chunk_plan_path=chunks,
        chunk_manifest_path=chunk_manifest,
    )
    assert report["decision"] == "QUERY_PLAN_VERIFIED_NON_AUTHORIZING"
    assert report["query_plan_file_sha256"] == _sha(plan_path)
    assert report["rpc_authorized"] is False

    plan["rpc_authorized"] = True
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(HistoricalExpansionQueryPlanError, match="query_plan_rpc_authorized_invalid"):
        verify_historical_expansion_query_plan(
            query_plan_path=plan_path,
            chunk_plan_path=chunks,
            chunk_manifest_path=chunk_manifest,
        )
