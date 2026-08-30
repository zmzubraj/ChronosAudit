from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from chronosaudit_stage2.public_acquisition.denominator import (
    normalize_deployment_batch,
    select_denominator,
    validate_denominator,
)
from chronosaudit_stage2.source_history import ingest_sourcify_deployments_export

SEED = "chronosaudit-public-pilot-v1-20260808"


def test_denominator_requires_creation_proof_and_deduplicates():
    rows = [
        {
            "chain": "ethereum",
            "chain_id": 1,
            "contract_address": "0x" + "11" * 20,
            "creation_tx_hash": "0x" + "aa" * 32,
            "creation_type": "create",
            "deployment_block": 100,
            "deployment_block_hash": "0x" + "bb" * 32,
            "deployment_time": "2026-01-01T00:00:00Z",
            "creator_address": "0x" + "22" * 20,
            "runtime_code_sha256": "c" * 64,
            "source_provider": "aws_public_dataset",
            "source_object_key": "ethereum/contracts/part-0001.parquet",
            "source_object_etag": "etag-1",
            "source_record_sha256": "d" * 64,
            "creation_proof_type": "transaction",
        },
        {
            "chain": "ethereum",
            "chain_id": 1,
            "contract_address": "0x" + "11" * 20,
            "creation_tx_hash": "0x" + "aa" * 32,
            "creation_type": "create",
            "deployment_block": 100,
            "deployment_block_hash": "0x" + "bb" * 32,
            "deployment_time": "2026-01-01T00:00:00Z",
            "creator_address": "0x" + "22" * 20,
            "runtime_code_sha256": "c" * 64,
            "source_provider": "aws_public_dataset",
            "source_object_key": "ethereum/contracts/part-0001.parquet",
            "source_object_etag": "etag-2",
            "source_record_sha256": "e" * 64,
            "creation_proof_type": "transaction",
        },
        {
            "chain": "ethereum",
            "chain_id": 1,
            "contract_address": "0x" + "33" * 20,
            "creation_tx_hash": None,
            "creation_type": "current_code_only",
            "deployment_block": 101,
            "deployment_block_hash": "0x" + "cc" * 32,
            "deployment_time": "2026-01-02T00:00:00Z",
            "creator_address": "0x" + "44" * 20,
            "runtime_code_sha256": "f" * 64,
            "source_provider": "aws_public_dataset",
            "source_object_key": "ethereum/contracts/part-0002.parquet",
            "source_object_etag": "etag-3",
            "source_record_sha256": "1" * 64,
            "creation_proof_type": None,
        },
    ]

    normalized = normalize_deployment_batch(rows)

    assert normalized["admissibility_status"].tolist().count("VERIFIED") == 1
    assert "missing_creation_proof" in set(normalized["exclusion_reason"].fillna(""))
    assert "duplicate_record" in set(normalized["exclusion_reason"].fillna(""))


def test_denominator_excludes_top_level_creation_without_explicit_proof():
    normalized = normalize_deployment_batch(
        [
            {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + "55" * 20,
                "creation_tx_hash": "0x" + "aa" * 32,
                "creation_type": "create",
                "deployment_block": 100,
                "deployment_block_hash": "0x" + "bb" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "22" * 20,
                "runtime_code_sha256": "c" * 64,
                "source_provider": "aws_public_dataset",
                "source_object_key": "ethereum/contracts/part-0001.parquet",
                "source_object_etag": "etag-1",
                "source_record_sha256": "d" * 64,
                "creation_proof_type": None,
            }
        ]
    )

    assert normalized.loc[0, "admissibility_status"] == "EXCLUDED"
    assert normalized.loc[0, "exclusion_reason"] == "missing_creation_proof"


def test_denominator_canonicalizes_bytes_and_stringified_bytes_fields():
    address_hex = "11" * 20
    tx_hash_hex = "aa" * 32
    normalized = normalize_deployment_batch(
        [
            {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": bytes.fromhex(address_hex),
                "creation_tx_hash": repr(bytes.fromhex(tx_hash_hex)),
                "creation_type": "create",
                "deployment_block": 100,
                "deployment_block_hash": "0x" + "bb" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": bytes.fromhex("22" * 20),
                "runtime_code_sha256": "c" * 64,
                "source_provider": "aws_public_dataset",
                "source_object_key": "ethereum/contracts/part-0001.parquet",
                "source_object_etag": "etag-1",
                "source_record_sha256": "d" * 64,
                "creation_proof_type": "transaction",
            }
        ]
    )

    assert normalized.loc[0, "contract_address"] == "0x" + address_hex
    assert normalized.loc[0, "creation_tx_hash"] == "0x" + tx_hash_hex
    assert normalized.loc[0, "creator_address"] == "0x" + "22" * 20
    assert normalized.loc[0, "admissibility_status"] == "VERIFIED"


def test_denominator_excludes_missing_deployment_block_and_timestamp():
    normalized = normalize_deployment_batch(
        [
            {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + "99" * 20,
                "creation_tx_hash": "0x" + "aa" * 32,
                "creation_type": "create",
                "deployment_block": None,
                "deployment_block_hash": "0x" + "bb" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "22" * 20,
                "runtime_code_sha256": "c" * 64,
                "source_provider": "aws_public_dataset",
                "source_object_key": "ethereum/contracts/part-0001.parquet",
                "source_object_etag": "etag-1",
                "source_record_sha256": "d" * 64,
                "creation_proof_type": "transaction",
            },
            {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + "98" * 20,
                "creation_tx_hash": "0x" + "ab" * 32,
                "creation_type": "create",
                "deployment_block": 101,
                "deployment_block_hash": "0x" + "bc" * 32,
                "deployment_time": None,
                "creator_address": "0x" + "23" * 20,
                "runtime_code_sha256": "e" * 64,
                "source_provider": "aws_public_dataset",
                "source_object_key": "ethereum/contracts/part-0002.parquet",
                "source_object_etag": "etag-2",
                "source_record_sha256": "f" * 64,
                "creation_proof_type": "transaction",
            },
        ]
    )

    reasons = normalized.set_index("contract_address")["exclusion_reason"].to_dict()
    assert reasons["0x" + "99" * 20] == "missing_deployment_block"
    assert reasons["0x" + "98" * 20] == "missing_deployment_timestamp"


def test_denominator_excludes_invalid_creation_proof_value():
    normalized = normalize_deployment_batch(
        [
            {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + "66" * 20,
                "creation_tx_hash": "0x" + "aa" * 32,
                "creation_type": "create2",
                "deployment_block": 100,
                "deployment_block_hash": "0x" + "bb" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "22" * 20,
                "runtime_code_sha256": "c" * 64,
                "source_provider": "aws_public_dataset",
                "source_object_key": "ethereum/contracts/part-0001.parquet",
                "source_object_etag": "etag-1",
                "source_record_sha256": "d" * 64,
                "creation_proof_type": "guessed",
            }
        ]
    )

    assert normalized.loc[0, "admissibility_status"] == "EXCLUDED"
    assert normalized.loc[0, "exclusion_reason"] == "invalid_creation_proof_type"


def test_denominator_internal_creation_requires_trace_proof():
    normalized = normalize_deployment_batch(
        [
            {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + "77" * 20,
                "creation_tx_hash": "0x" + "aa" * 32,
                "creation_type": "internal_create",
                "deployment_block": 100,
                "deployment_block_hash": "0x" + "bb" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "22" * 20,
                "runtime_code_sha256": "c" * 64,
                "source_provider": "aws_public_dataset",
                "source_object_key": "ethereum/contracts/part-0001.parquet",
                "source_object_etag": "etag-1",
                "source_record_sha256": "d" * 64,
                "creation_proof_type": "transaction",
                "trace_proof": False,
            }
        ]
    )

    assert normalized.loc[0, "admissibility_status"] == "EXCLUDED"
    assert normalized.loc[0, "exclusion_reason"] == "invalid_creation_proof_type"


def test_denominator_internal_creation_accepts_trace_proof():
    normalized = normalize_deployment_batch(
        [
            {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + "88" * 20,
                "creation_tx_hash": "0x" + "aa" * 32,
                "creation_type": "internal_create2",
                "deployment_block": 100,
                "deployment_block_hash": "0x" + "bb" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "22" * 20,
                "runtime_code_sha256": "c" * 64,
                "source_provider": "aws_public_dataset",
                "source_object_key": "ethereum/contracts/part-0001.parquet",
                "source_object_etag": "etag-1",
                "source_record_sha256": "d" * 64,
                "creation_proof_type": "trace",
                "trace_proof": True,
            }
        ]
    )

    assert normalized.loc[0, "admissibility_status"] == "VERIFIED"
    assert pd.isna(normalized.loc[0, "exclusion_reason"])


def test_sourcify_deployments_export_uses_validated_field_mapping_and_batches(tmp_path: Path):
    table = pa.table(
        {
            "chain_id": [1, 8453],
            "contract_address": pa.array([bytes.fromhex("11" * 20), bytes.fromhex("22" * 20)], type=pa.binary()),
            "tx_hash": pa.array([bytes.fromhex("aa" * 32), bytes.fromhex("bb" * 32)], type=pa.binary()),
            "block_number": [10, 20],
            "created_at": ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"],
            "creation_type": ["create", "create2"],
            "trace_proof": [True, True],
        }
    )
    target = tmp_path / "deployments.parquet"
    pq.write_table(table, target)

    rows = ingest_sourcify_deployments_export(
        target,
        field_mapping={
            "address": ["contract_address"],
            "chain": ["chain_id"],
            "deployment_block": ["block_number"],
            "deployment_tx_hash": ["tx_hash"],
            "deployment_time": ["created_at"],
            "creation_type": ["creation_type"],
            "trace_proof": ["trace_proof"],
        },
        batch_size=1,
    )

    assert len(rows) == 2
    assert rows[0]["chain"] == "ethereum"
    assert rows[1]["chain"] == "base"
    assert rows[0]["address"] == "0x" + "11" * 20
    assert rows[0]["deployment_tx_hash"] == "0x" + "aa" * 32
    assert rows[0]["record_sha256"]


def test_no_chain_shortfall_reallocation():
    rows: list[dict[str, object]] = []
    for i in range(5002):
        rows.append(
            {
                "deployment_id": f"eth-{i}",
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + f"{i:040x}"[-40:],
                "creation_tx_hash": "0x" + f"{i:064x}"[-64:],
                "creation_type": "create",
                "deployment_block": i + 1,
                "deployment_block_hash": "0x" + "ab" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "12" * 20,
                "runtime_code_sha256": f"{i:064x}"[-64:],
                "source_provider": "aws_public_dataset",
                "source_object_key": f"ethereum/part-{i}.parquet",
                "source_object_etag": f"etag-{i}",
                "source_record_sha256": f"{i + 1:064x}"[-64:],
                "duplicate_group_id": f"group-eth-{i}",
                "admissibility_status": "VERIFIED",
                "exclusion_reason": None,
            }
        )
    for i in range(7):
        rows.append(
            {
                "deployment_id": f"base-{i}",
                "chain": "base",
                "chain_id": 8453,
                "contract_address": "0x" + f"{i + 6000:040x}"[-40:],
                "creation_tx_hash": "0x" + f"{i + 7000:064x}"[-64:],
                "creation_type": "create",
                "deployment_block": i + 1,
                "deployment_block_hash": "0x" + "cd" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "34" * 20,
                "runtime_code_sha256": f"{i + 8000:064x}"[-64:],
                "source_provider": "aws_public_dataset",
                "source_object_key": f"base/part-{i}.parquet",
                "source_object_etag": f"etag-base-{i}",
                "source_record_sha256": f"{i + 9000:064x}"[-64:],
                "duplicate_group_id": f"group-base-{i}",
                "admissibility_status": "VERIFIED",
                "exclusion_reason": None,
            }
        )

    selected, audit = select_denominator(pd.DataFrame(rows), per_chain=5000, seed=SEED)

    indexed = audit.set_index("chain")
    assert indexed.loc["base", "selected"] == indexed.loc["base", "available"]
    assert len(selected[selected.chain == "ethereum"]) == 5000
    assert indexed.loc["base", "shortfall"] > 0
    assert "base" in set(indexed.index)


def test_select_denominator_includes_zero_row_supported_chains():
    rows = [
        {
            "deployment_id": "eth-0",
            "chain": "ethereum",
            "chain_id": 1,
            "contract_address": "0x" + "11" * 20,
            "creation_tx_hash": "0x" + "aa" * 32,
            "creation_type": "create",
            "deployment_block": 1,
            "deployment_block_hash": "0x" + "ab" * 32,
            "deployment_time": "2026-01-01T00:00:00Z",
            "creator_address": "0x" + "12" * 20,
            "runtime_code_sha256": "1" * 64,
            "source_provider": "aws_public_dataset",
            "source_object_key": "ethereum/part-0.parquet",
            "source_object_etag": "etag-0",
            "source_record_sha256": "2" * 64,
            "duplicate_group_id": "group-eth-0",
            "admissibility_status": "VERIFIED",
            "exclusion_reason": None,
        }
    ]

    _, audit = select_denominator(pd.DataFrame(rows), per_chain=5000, seed=SEED)

    indexed = audit.set_index("chain")
    assert set(indexed.index) == {"ethereum", "bsc", "base", "arbitrum"}
    assert indexed.loc["bsc", "selected"] == 0
    assert indexed.loc["bsc", "shortfall"] == 5000


def _candidate_row(index: int, *, chain: str = "ethereum") -> dict[str, object]:
    chain_id = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}[chain]
    return {
        "deployment_id": f"{chain}-{index}",
        "chain": chain,
        "chain_id": chain_id,
        "contract_address": "0x" + f"{index + chain_id:040x}"[-40:],
        "creation_tx_hash": "0x" + f"{index + chain_id + 1:064x}"[-64:],
        "creation_type": "create",
        "deployment_block": index + 1,
        "deployment_block_hash": "0x" + "ab" * 32,
        "deployment_time": "2026-01-01T00:00:00Z",
        "creator_address": "0x" + "12" * 20,
        "runtime_code_sha256": f"{index + 2:064x}"[-64:],
        "source_provider": "aws_public_dataset",
        "source_object_key": f"{chain}/part-{index}.parquet",
        "source_object_etag": f"etag-{chain}-{index}",
        "source_record_sha256": f"{index + 3:064x}"[-64:],
        "duplicate_group_id": f"group-{chain}-{index}",
        "admissibility_status": "VERIFIED",
        "exclusion_reason": None,
        "selection_rank_sha256": f"{index + 4:064x}"[-64:],
    }


def test_representative_four_chain_fixture_selects_full_quota():
    raw_rows: list[dict[str, object]] = []
    for chain, chain_id in (("ethereum", 1), ("bsc", 56), ("base", 8453), ("arbitrum", 42161)):
        for index in range(5001):
            offset = chain_id * 100_000 + index
            raw_rows.append(
                {
                    "chain": chain,
                    "chain_id": chain_id,
                    "contract_address": "0x" + f"{offset:040x}"[-40:],
                    "creation_tx_hash": "0x" + f"{offset + 1:064x}"[-64:],
                    "creation_type": "create",
                    "deployment_block": offset + 2,
                    "deployment_block_hash": None,
                    "deployment_time": "2026-01-01T00:00:00Z",
                    "creator_address": None,
                    "runtime_code_sha256": None,
                    "source_provider": "sourcify_pinned_deployments_export",
                    "source_object_key": f"{chain}/contract_deployments.csv",
                    "source_object_etag": "",
                    "source_record_sha256": f"{offset + 3:064x}"[-64:],
                    "creation_proof_type": "transaction",
                }
            )

    normalized = normalize_deployment_batch(raw_rows)
    selected, audit = select_denominator(normalized, per_chain=5000, seed=SEED)

    assert len(selected) == 20_000
    assert set(selected["chain"]) == {"ethereum", "bsc", "base", "arbitrum"}
    indexed = audit.set_index("chain")
    assert all(int(indexed.loc[chain, "selected"]) == 5000 for chain in ("ethereum", "bsc", "base", "arbitrum"))
    assert all(int(indexed.loc[chain, "shortfall"]) == 0 for chain in ("ethereum", "bsc", "base", "arbitrum"))


def test_validate_denominator_replaces_failed_crosscheck_before_freeze():
    candidates = pd.DataFrame([_candidate_row(i) for i in range(4)])
    selected = candidates.iloc[:2].copy()
    audit = pd.DataFrame(
        [
            {"chain": "ethereum", "available": 4, "selected": 2, "shortfall": 0},
        ]
    )
    crosschecks = pd.DataFrame(
        [
            {"deployment_id": "ethereum-0", "adjudication_status": "PARTIAL", "reason": "rpc_mismatch"},
        ]
    )

    result = validate_denominator(
        selected,
        audit,
        per_chain=2,
        crosscheck_per_chain=2,
        seed=SEED,
        expected_chains=("ethereum",),
        candidate_pool=candidates,
        crosscheck_results=crosschecks,
        frozen=False,
    )

    assert result["valid"] is True
    assert set(result["selected"]["deployment_id"]) == {"ethereum-1", "ethereum-2"}
    assert result["replacement_log"][0]["failed_deployment_id"] == "ethereum-0"
    assert result["replacement_log"][0]["replacement_deployment_id"] == "ethereum-2"
    assert result["replacement_log"][0]["crosscheck_status"] == "PARTIAL"


def test_validate_denominator_logs_disputed_replacement_before_freeze():
    candidates = pd.DataFrame([_candidate_row(i) for i in range(4)])
    selected = candidates.iloc[:2].copy()
    audit = pd.DataFrame([{"chain": "ethereum", "available": 4, "selected": 2, "shortfall": 0}])
    crosschecks = pd.DataFrame(
        [
            {"deployment_id": "ethereum-1", "adjudication_status": "DISPUTED", "reason": "source_conflict"},
        ]
    )

    result = validate_denominator(
        selected,
        audit,
        per_chain=2,
        crosscheck_per_chain=2,
        seed=SEED,
        expected_chains=("ethereum",),
        candidate_pool=candidates,
        crosscheck_results=crosschecks,
        frozen=False,
    )

    assert result["valid"] is True
    assert result["replacement_log"][0]["crosscheck_status"] == "DISPUTED"
    assert result["adjudication_log"][0]["admissibility_status"] == "DISPUTED"


def test_validate_denominator_quarantines_failed_rows_across_multiple_replacements():
    candidates = pd.DataFrame([_candidate_row(i) for i in range(5)])
    selected = candidates.iloc[:2].copy()
    audit = pd.DataFrame([{"chain": "ethereum", "available": 5, "selected": 2, "shortfall": 0}])
    crosschecks = pd.DataFrame(
        [
            {"deployment_id": "ethereum-0", "adjudication_status": "PARTIAL", "reason": "rpc_mismatch"},
            {"deployment_id": "ethereum-1", "adjudication_status": "DISPUTED", "reason": "source_conflict"},
        ]
    )

    result = validate_denominator(
        selected,
        audit,
        per_chain=2,
        crosscheck_per_chain=2,
        seed=SEED,
        expected_chains=("ethereum",),
        candidate_pool=candidates,
        crosscheck_results=crosschecks,
        frozen=False,
    )

    assert result["valid"] is True
    assert set(result["selected"]["deployment_id"]) == {"ethereum-2", "ethereum-3"}
    assert [entry["replacement_deployment_id"] for entry in result["replacement_log"]] == ["ethereum-2", "ethereum-3"]
    assert all(entry["failed_deployment_id"] != "ethereum-0" or entry["replacement_deployment_id"] != "ethereum-0" for entry in result["replacement_log"])


def test_validate_denominator_blocks_replacement_after_freeze():
    candidates = pd.DataFrame([_candidate_row(i) for i in range(4)])
    selected = candidates.iloc[:2].copy()
    audit = pd.DataFrame([{"chain": "ethereum", "available": 4, "selected": 2, "shortfall": 0}])
    crosschecks = pd.DataFrame(
        [
            {"deployment_id": "ethereum-0", "adjudication_status": "PARTIAL", "reason": "rpc_mismatch"},
        ]
    )

    result = validate_denominator(
        selected,
        audit,
        per_chain=2,
        crosscheck_per_chain=2,
        seed=SEED,
        expected_chains=("ethereum",),
        candidate_pool=candidates,
        crosscheck_results=crosschecks,
        frozen=True,
    )

    assert result["valid"] is False
    assert any("frozen_denominator_crosscheck_failure" in error for error in result["errors"])
    assert result["replacement_log"] == []
    assert set(result["selected"]["deployment_id"]) == {"ethereum-0", "ethereum-1"}


def test_validate_denominator_reports_no_eligible_replacement():
    candidates = pd.DataFrame([_candidate_row(i) for i in range(2)])
    selected = candidates.iloc[:2].copy()
    audit = pd.DataFrame([{"chain": "ethereum", "available": 2, "selected": 2, "shortfall": 0}])
    crosschecks = pd.DataFrame(
        [
            {"deployment_id": "ethereum-0", "adjudication_status": "PARTIAL", "reason": "rpc_mismatch"},
        ]
    )

    result = validate_denominator(
        selected,
        audit,
        per_chain=2,
        crosscheck_per_chain=2,
        seed=SEED,
        expected_chains=("ethereum",),
        candidate_pool=candidates,
        crosscheck_results=crosschecks,
        frozen=False,
    )

    assert result["valid"] is False
    assert "no_replacement_available:ethereum-0" in result["errors"]
    assert result["replacement_log"] == []


def test_validate_denominator_emits_crosscheck_manifest():
    selected = pd.DataFrame(
        [
            {
                "deployment_id": f"eth-{i}",
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0x" + f"{i:040x}"[-40:],
                "creation_tx_hash": "0x" + f"{i + 1:064x}"[-64:],
                "creation_type": "create",
                "deployment_block": i + 1,
                "deployment_block_hash": "0x" + "ab" * 32,
                "deployment_time": "2026-01-01T00:00:00Z",
                "creator_address": "0x" + "12" * 20,
                "runtime_code_sha256": f"{i + 2:064x}"[-64:],
                "source_provider": "aws_public_dataset",
                "source_object_key": f"ethereum/part-{i}.parquet",
                "source_object_etag": f"etag-{i}",
                "source_record_sha256": f"{i + 3:064x}"[-64:],
                "duplicate_group_id": f"group-eth-{i}",
                "admissibility_status": "VERIFIED",
                "exclusion_reason": None,
                "selection_rank_sha256": f"{i + 4:064x}"[-64:],
            }
            for i in range(5)
        ]
    )
    audit = pd.DataFrame([{"chain": "ethereum", "available": 5, "selected": 5, "shortfall": 0}])

    result = validate_denominator(
        selected,
        audit,
        per_chain=5,
        crosscheck_per_chain=2,
        seed=SEED,
        expected_chains=("ethereum",),
    )

    assert result["valid"] is True
    assert len(result["crosscheck_manifest"]) == 2
    assert set(result["crosscheck_manifest"]["chain"]) == {"ethereum"}


def test_validate_denominator_enforces_expected_chain_set():
    selected = pd.DataFrame([_candidate_row(0, chain="ethereum")])
    audit = pd.DataFrame([{"chain": "ethereum", "available": 1, "selected": 1, "shortfall": 0}])

    result = validate_denominator(
        selected,
        audit,
        per_chain=1,
        crosscheck_per_chain=1,
        seed=SEED,
        expected_chains=("ethereum", "bsc"),
    )

    assert result["valid"] is False
    assert any("missing_expected_chain:bsc" == error for error in result["errors"])
