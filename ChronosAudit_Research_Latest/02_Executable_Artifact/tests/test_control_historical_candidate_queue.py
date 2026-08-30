from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_historical_candidate_queue import (
    HistoricalCandidateQueueError,
    build_historical_candidate_queue,
    verify_historical_candidate_queue,
)
from chronosaudit_stage2.public_acquisition.control_historical_expansion_query_plan import (
    build_historical_expansion_query_plan,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _address(value: int) -> str:
    return f"0x{value:040x}"


def _tx(value: int) -> str:
    return f"0x{value:064x}"


def _fixture(tmp_path: Path, valid_candidates: int = 27) -> dict[str, Path]:
    source_root = tmp_path / "sources"
    receipt_root = tmp_path / "receipts"
    source_root.mkdir()
    receipt_root.mkdir()
    positive_a, positive_b = _address(90_001), _address(90_002)
    authority_address = _address(1)
    rows = [
        {
            "chain_id": 1,
            "address": _address(index),
            "transaction_hash": _tx(index),
            "block_number": 1_000 + index,
            "created_at": f"2021-01-01T{index % 24:02d}:00:00Z",
            "creation_type": "transaction",
            "trace_proof": False,
        }
        for index in range(1, valid_candidates + 1)
    ]
    rows.extend(
        [
            {**rows[0], "address": positive_a, "transaction_hash": _tx(90_001)},
            {**rows[0], "chain_id": 56, "address": _address(80_001)},
            {
                **rows[0],
                "address": _address(80_002),
                "transaction_hash": _tx(80_002),
                "created_at": "2021-02-01T00:00:00Z",
            },
        ]
    )
    source = source_root / "0.csv"
    pd.DataFrame(rows).to_csv(source, index=False)
    headers = receipt_root / "0.headers.json"
    headers.write_text(json.dumps({"etag": "etag-0"}), encoding="utf-8")

    inventory = tmp_path / "inventory.csv"
    pd.DataFrame(
        [
            {
                "provider": "sourcify_bucket",
                "dataset": "v2/contract_deployments",
                "chain": "all",
                "prefix": "v2/contract_deployments/all/",
                "key": "v2/contract_deployments/contract_deployments_0_1000000.parquet",
                "etag": "etag-0",
                "size": source.stat().st_size,
                "last_modified": "2026-01-01T00:00:00Z",
                "page_index": 0,
                "raw_page_sha256": "a" * 64,
            }
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
                "row_count": 1,
                "objects_processed": 1,
                "errors": [],
            }
        ),
        encoding="utf-8",
    )
    chunks = tmp_path / "chunks.csv"
    chunk_rows = [
        {
            "chunk_id": "chunk-1",
            "chunk_sequence": 1,
            "case_name": case,
            "chain": "ethereum",
            "admissible_deployment_start": start,
            "admissible_deployment_end": end,
            "positive_prediction_cutoff_time": end,
            "minimum_additional_distinct_slots": 1,
            "expansion_requirement_sha256": requirement,
            "chunk_scope_sha256": "c" * 64,
            "acquisition_authorized": False,
            "rpc_authorized": False,
            "selection_authorized": False,
        }
        for case, start, end, requirement in (
            ("case-a", "2020-12-16T00:00:00Z", "2021-01-16T00:00:00Z", "b" * 64),
            ("case-b", "2020-12-21T00:00:00Z", "2021-01-21T00:00:00Z", "d" * 64),
        )
    ]
    pd.DataFrame(chunk_rows).to_csv(chunks, index=False)
    chunk_manifest = tmp_path / "chunk-manifest.json"
    chunk_manifest.write_text(
        json.dumps(
            {
                "schema_version": "chronosaudit.control_denominator_expansion_chunk_plan.v1",
                "decision": "BOUNDED_EXPANSION_PLAN_AWAITS_ACCOUNTABLE_ACQUISITION_APPROVAL",
                "chunk_count": 1,
                "cases_requiring_expansion": 2,
                "minimum_additional_distinct_slots": 2,
                "output": {"sha256": _sha(chunks)},
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            }
        ),
        encoding="utf-8",
    )
    plan = build_historical_expansion_query_plan(
        inventory_path=inventory,
        inventory_manifest_path=inventory_manifest,
        chunk_plan_path=chunks,
        chunk_manifest_path=chunk_manifest,
        historical_end_exclusive=1_000_000,
    )
    plan_path = tmp_path / "query-plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    import_manifest = receipt_root / "import-manifest.json"
    import_manifest.write_text(
        json.dumps(
            {
                "schema_version": "chronosaudit.control_historical_source_import.v1",
                "query_plan_file_sha256": _sha(plan_path),
                "objects": [
                    {
                        "key": "v2/contract_deployments/contract_deployments_0_1000000.parquet",
                        "etag": "etag-0",
                        "path": str(source),
                        "size": source.stat().st_size,
                        "sha256": _sha(source),
                        "headers_path": str(headers),
                        "headers_sha256": _sha(headers),
                    }
                ],
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    positives = tmp_path / "positives.csv"
    pd.DataFrame(
        [
            {
                "case_name": "case-a",
                "chain": "ethereum",
                "target_contract_address": positive_a,
                "deployment_time": "2021-01-15T00:00:00Z",
                "prediction_cutoff_time": "2021-01-16T00:00:00Z",
            },
            {
                "case_name": "case-b",
                "chain": "ethereum",
                "target_contract_address": positive_b,
                "deployment_time": "2021-01-20T00:00:00Z",
                "prediction_cutoff_time": "2021-01-21T00:00:00Z",
            },
        ]
    ).to_csv(positives, index=False)
    authority = tmp_path / "authority.csv"
    pd.DataFrame(
        [{"chain": "ethereum", "chain_id": 1, "contract_address": authority_address}]
    ).to_csv(authority, index=False)
    return {
        "query_plan": plan_path,
        "inventory": inventory,
        "inventory_manifest": inventory_manifest,
        "chunk_plan": chunks,
        "chunk_manifest": chunk_manifest,
        "import_manifest": import_manifest,
        "source_root": source_root,
        "receipt_root": receipt_root,
        "positives": positives,
        "authority": authority,
    }


def _build(paths: dict[str, Path], output: Path, manifest: Path) -> dict[str, object]:
    return build_historical_candidate_queue(
        query_plan_path=paths["query_plan"],
        inventory_path=paths["inventory"],
        inventory_manifest_path=paths["inventory_manifest"],
        chunk_plan_path=paths["chunk_plan"],
        chunk_manifest_path=paths["chunk_manifest"],
        import_manifest_path=paths["import_manifest"],
        source_root=paths["source_root"],
        receipt_root=paths["receipt_root"],
        positive_projection_path=paths["positives"],
        authority_projection_path=paths["authority"],
        output_queue_path=output,
        output_manifest_path=manifest,
        block_window_path=paths.get("block_windows"),
    )


def test_queue_is_deterministic_outcome_blind_and_globally_no_reuse(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    output = tmp_path / "queue.csv"
    manifest_path = tmp_path / "queue-manifest.json"
    report = _build(paths, output, manifest_path)
    queue = pd.read_csv(output, dtype=str, keep_default_na=False)
    assert report["decision"] == "RESERVE_QUEUE_FROZEN_REQUIRES_HASH_BOUND_RPC_ACTIVATION"
    assert report["reserve_target"] == 20
    assert report["reserve_allocated"] == 20
    assert report["reserve_shortfall"] == 0
    assert queue.groupby("case_name").size().to_dict() == {"case-a": 10, "case-b": 10}
    assert not queue[["chain", "control_address"]].duplicated().any()
    assert _address(1) not in set(queue["control_address"])
    assert _address(90_001) not in set(queue["control_address"])
    assert queue["rpc_authorized"].eq("False").all()
    assert queue["selection_authorized"].eq("False").all()

    repeat_output = tmp_path / "repeat.csv"
    repeat_manifest = tmp_path / "repeat-manifest.json"
    repeated = _build(paths, repeat_output, repeat_manifest)
    assert output.read_bytes() == repeat_output.read_bytes()
    assert report["queue_sha256"] == repeated["queue_sha256"]
    verification = verify_historical_candidate_queue(
        queue_path=output,
        manifest_path=manifest_path,
        query_plan_path=paths["query_plan"],
        chunk_plan_path=paths["chunk_plan"],
        positive_projection_path=paths["positives"],
        authority_projection_path=paths["authority"],
        import_manifest_path=paths["import_manifest"],
    )
    assert verification["decision"] == "RESERVE_QUEUE_VERIFIED_NON_AUTHORIZING"
    assert verification["queue_row_count"] == 20


def test_queue_preserves_insufficient_reserve_as_replan(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, valid_candidates=4)
    report = _build(paths, tmp_path / "queue.csv", tmp_path / "manifest.json")
    assert report["decision"] == "RESERVE_QUEUE_INSUFFICIENT_REPLAN_REQUIRED"
    assert report["reserve_allocated"] < report["reserve_target"]
    assert report["rpc_authorized"] is False
    assert report["selection_authorized"] is False


def test_queue_accepts_real_sourcify_schema_only_with_verified_block_windows(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    source = next(paths["source_root"].glob("*.csv"))
    frame = pd.read_csv(source)
    frame["address"] = frame["address"].map(lambda value: bytes.fromhex(value[2:]))
    frame["transaction_hash"] = frame["transaction_hash"].map(lambda value: bytes.fromhex(value[2:]))
    frame["transaction_index"] = 0
    frame["deployer"] = bytes.fromhex(_address(777)[2:])
    frame["contract_id"] = "fixture"
    frame["created_by"] = "sourcify"
    frame["updated_by"] = "sourcify"
    frame["updated_at"] = frame["created_at"]
    frame["created_at"] = "2026-01-01T00:00:00Z"
    frame = frame.drop(columns=["creation_type", "trace_proof"])
    irrelevant = frame.iloc[0].copy()
    irrelevant["chain_id"] = 1
    irrelevant["transaction_hash"] = None
    irrelevant["block_number"] = None
    unusable_in_window = frame.iloc[0].copy()
    unusable_in_window["address"] = bytes.fromhex(_address(778)[2:])
    unusable_in_window["transaction_hash"] = None
    unusable_in_window["block_number"] = 1050
    redeployment = frame.iloc[1].copy()
    redeployment["transaction_hash"] = bytes.fromhex(_tx(999_998)[2:])
    redeployment["block_number"] = int(frame.iloc[1]["block_number"]) + 10
    frame = pd.concat(
        [
            frame,
            irrelevant.to_frame().T,
            unusable_in_window.to_frame().T,
            redeployment.to_frame().T,
        ],
        ignore_index=True,
    )
    parquet = paths["source_root"] / "0.parquet"
    frame.to_parquet(parquet, index=False)
    source.unlink()
    payload = json.loads(paths["import_manifest"].read_text(encoding="utf-8"))
    payload["objects"][0]["path"] = str(parquet)
    payload["objects"][0]["size"] = parquet.stat().st_size
    payload["objects"][0]["sha256"] = _sha(parquet)
    paths["import_manifest"].write_text(json.dumps(payload), encoding="utf-8")
    plan = json.loads(paths["query_plan"].read_text(encoding="utf-8"))
    plan["source_objects"][0]["size"] = parquet.stat().st_size
    plan["source_total_bytes"] = parquet.stat().st_size
    plan["download_rules"]["maximum_download_bytes"] = parquet.stat().st_size
    plan["query_plan_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in plan.items() if key != "query_plan_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    paths["query_plan"].write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    payload["query_plan_file_sha256"] = _sha(paths["query_plan"])
    paths["import_manifest"].write_text(json.dumps(payload), encoding="utf-8")
    windows = tmp_path / "block-windows.csv"
    pd.DataFrame(
        [
            {
                "case_name": case,
                "chain": "ethereum",
                "chain_id": 1,
                "admissible_deployment_start": start,
                "admissible_deployment_end": end,
                "start_block": 1000,
                "end_block": 1100,
                "boundary_status": "LOCAL_TEST_SINGLE_PROVIDER_EXACT_BLOCK_BRACKET",
            }
            for case, start, end in (
                ("case-a", "2020-12-16T00:00:00Z", "2021-01-16T00:00:00Z"),
                ("case-b", "2020-12-21T00:00:00Z", "2021-01-21T00:00:00Z"),
            )
        ]
    ).to_csv(windows, index=False)
    paths["block_windows"] = windows

    report = _build(paths, tmp_path / "queue.csv", tmp_path / "manifest.json")
    queue = pd.read_csv(tmp_path / "queue.csv", dtype=str, keep_default_na=False)
    assert report["reserve_allocated"] == 20
    assert report["source_created_at_used_as_deployment_time"] is False
    assert report["unusable_in_window_rows_excluded"] == 1
    assert report["lifecycle_conflict_identities"] == 1
    first_identity = "1:" + _address(2)
    selected = queue[queue["control_identity"] == first_identity]
    if not selected.empty:
        assert int(selected.iloc[0]["deployment_block"]) == int(frame.iloc[1]["block_number"])
    assert queue["control_deployment_time"].eq("UNKNOWN_REQUIRES_RPC").all()
    assert queue["creation_type"].eq("UNKNOWN_REQUIRES_RPC").all()
    verification = verify_historical_candidate_queue(
        queue_path=tmp_path / "queue.csv",
        manifest_path=tmp_path / "manifest.json",
        query_plan_path=paths["query_plan"],
        chunk_plan_path=paths["chunk_plan"],
        positive_projection_path=paths["positives"],
        authority_projection_path=paths["authority"],
        import_manifest_path=paths["import_manifest"],
        block_window_path=windows,
    )
    assert verification["decision"] == "RESERVE_QUEUE_VERIFIED_NON_AUTHORIZING"


def test_queue_rejects_positive_cutoff_drift(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    positives = pd.read_csv(paths["positives"])
    positives.loc[0, "prediction_cutoff_time"] = "2021-01-16T00:00:01Z"
    positives.to_csv(paths["positives"], index=False)
    with pytest.raises(HistoricalCandidateQueueError, match="positive_cutoff_mismatch"):
        _build(paths, tmp_path / "queue.csv", tmp_path / "manifest.json")


def test_queue_rejects_conflicting_duplicate_identity(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    source = next(paths["source_root"].glob("*.csv"))
    frame = pd.read_csv(source)
    conflict = frame.iloc[1].copy()
    conflict["transaction_hash"] = _tx(999_999)
    frame = pd.concat([frame, conflict.to_frame().T], ignore_index=True)
    frame.to_csv(source, index=False)
    payload = json.loads(paths["import_manifest"].read_text(encoding="utf-8"))
    payload["objects"][0]["size"] = source.stat().st_size
    payload["objects"][0]["sha256"] = _sha(source)
    paths["import_manifest"].write_text(json.dumps(payload), encoding="utf-8")
    plan = json.loads(paths["query_plan"].read_text(encoding="utf-8"))
    plan["source_objects"][0]["size"] = source.stat().st_size
    plan["source_total_bytes"] = source.stat().st_size
    plan["download_rules"]["maximum_download_bytes"] = source.stat().st_size
    plan["query_plan_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in plan.items() if key != "query_plan_sha256"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    paths["query_plan"].write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    payload["query_plan_file_sha256"] = _sha(paths["query_plan"])
    paths["import_manifest"].write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(HistoricalCandidateQueueError, match="source_identity_conflict"):
        _build(paths, tmp_path / "queue.csv", tmp_path / "manifest.json")


def test_queue_verifier_rejects_row_tamper(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    output = tmp_path / "queue.csv"
    manifest = tmp_path / "manifest.json"
    _build(paths, output, manifest)
    queue = pd.read_csv(output)
    queue.loc[0, "control_address"] = _address(777_777)
    queue.to_csv(output, index=False)
    with pytest.raises(HistoricalCandidateQueueError, match="queue_sha256_mismatch"):
        verify_historical_candidate_queue(
            queue_path=output,
            manifest_path=manifest,
            query_plan_path=paths["query_plan"],
            chunk_plan_path=paths["chunk_plan"],
            positive_projection_path=paths["positives"],
            authority_projection_path=paths["authority"],
            import_manifest_path=paths["import_manifest"],
        )
