from __future__ import annotations

import csv
import hashlib
import heapq
import json
import os
from collections import deque
from collections.abc import Iterator, Mapping
from pathlib import Path
import sqlite3
import tempfile

import pandas as pd

from .control_historical_expansion_query_plan import (
    verify_historical_expansion_query_plan,
)
from .control_historical_source_import import verify_historical_source_import


class HistoricalCandidateQueueError(ValueError):
    """Raised when an outcome-blind historical candidate queue cannot be frozen."""


_CHAIN_IDS = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}
_CHAIN_NAMES = {value: key for key, value in _CHAIN_IDS.items()}
_QUEUE_COLUMNS = (
    "case_name",
    "chain",
    "chain_id",
    "positive_prediction_cutoff_time",
    "minimum_additional_distinct_slots",
    "reserve_target",
    "control_address",
    "control_identity",
    "control_deployment_time",
    "deployment_distance_seconds",
    "creation_tx_hash",
    "deployment_block",
    "creation_type",
    "trace_proof",
    "source_object_key",
    "source_object_sha256",
    "source_record_sha256",
    "edge_rank_sha256",
    "reserve_assignment_sha256",
    "queue_status",
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ).hexdigest()


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HistoricalCandidateQueueError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise HistoricalCandidateQueueError(f"{label}_root_invalid")
    return value


def _address(value: object, label: str) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        text = "0x" + bytes(value).hex()
    else:
        text = str(value or "").strip().lower()
    if len(text) != 42 or not text.startswith("0x"):
        raise HistoricalCandidateQueueError(f"{label}_invalid")
    try:
        int(text[2:], 16)
    except ValueError as exc:
        raise HistoricalCandidateQueueError(f"{label}_invalid") from exc
    return text


def _tx(value: object) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        text = "0x" + bytes(value).hex()
    else:
        text = str(value or "").strip().lower()
    if len(text) != 66 or not text.startswith("0x"):
        raise HistoricalCandidateQueueError("source_transaction_hash_invalid")
    try:
        int(text[2:], 16)
    except ValueError as exc:
        raise HistoricalCandidateQueueError("source_transaction_hash_invalid") from exc
    return text


def _boolean(value: object) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no", ""}:
        return False
    raise HistoricalCandidateQueueError("source_trace_proof_invalid")


def _utc(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise HistoricalCandidateQueueError(f"{label}_invalid")
    return parsed


def _iso(value: pd.Timestamp) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _source_batches(path: Path, batch_size: int = 100_000) -> Iterator[pd.DataFrame]:
    if path.suffix.lower() in {".parquet", ".pq"}:
        import pyarrow.parquet as pq

        parquet = pq.ParquetFile(path)
        for batch in parquet.iter_batches(batch_size=batch_size):
            yield batch.to_pandas()
        return
    for frame in pd.read_csv(
        path, dtype=str, keep_default_na=False, chunksize=batch_size, low_memory=False
    ):
        yield frame


def _capacity_allocation(
    edges: list[dict[str, object]], targets: Mapping[str, int]
) -> tuple[list[dict[str, object]], dict[str, int], int]:
    source = ("source", "")
    sink = ("sink", "")
    adjacency: dict[tuple[str, str], list[list[object]]] = {}

    def add(start: tuple[str, str], end: tuple[str, str], capacity: int) -> list[object]:
        adjacency.setdefault(start, [])
        adjacency.setdefault(end, [])
        forward: list[object] = [end, len(adjacency[end]), capacity, capacity]
        reverse: list[object] = [start, len(adjacency[start]), 0, 0]
        adjacency[start].append(forward)
        adjacency[end].append(reverse)
        return forward

    references: dict[tuple[str, str], list[object]] = {}
    for case in sorted(targets):
        add(source, ("case", case), int(targets[case]))
    identities = sorted({str(edge["control_identity"]) for edge in edges})
    for identity in identities:
        add(("control", identity), sink, 1)
    by_pair = sorted(
        edges,
        key=lambda row: (
            str(row["case_name"]),
            str(row["edge_rank_sha256"]),
            str(row["control_identity"]),
        ),
    )
    for edge in by_pair:
        pair = (str(edge["case_name"]), str(edge["control_identity"]))
        references[pair] = add(("case", pair[0]), ("control", pair[1]), 1)

    flow = 0
    while True:
        level = {source: 0}
        queue: deque[tuple[str, str]] = deque([source])
        while queue:
            node = queue.popleft()
            for edge in adjacency[node]:
                target = edge[0]
                if int(edge[2]) > 0 and target not in level:
                    level[target] = level[node] + 1
                    queue.append(target)
        if sink not in level:
            break
        cursor = {node: 0 for node in adjacency}

        def send(node: tuple[str, str], amount: int) -> int:
            if node == sink:
                return amount
            while cursor[node] < len(adjacency[node]):
                edge = adjacency[node][cursor[node]]
                target = edge[0]
                if int(edge[2]) > 0 and level.get(target) == level[node] + 1:
                    pushed = send(target, min(amount, int(edge[2])))
                    if pushed:
                        edge[2] = int(edge[2]) - pushed
                        reverse = adjacency[target][int(edge[1])]
                        reverse[2] = int(reverse[2]) + pushed
                        return pushed
                cursor[node] += 1
            return 0

        while pushed := send(source, 10**9):
            flow += pushed

    selected = [
        edge
        for edge in by_pair
        if int(references[(str(edge["case_name"]), str(edge["control_identity"]))][2])
        == 0
    ]
    per_case = {case: 0 for case in targets}
    for edge in selected:
        per_case[str(edge["case_name"])] += 1
    return selected, per_case, flow


def build_historical_candidate_queue(
    *,
    query_plan_path: Path,
    inventory_path: Path,
    inventory_manifest_path: Path,
    chunk_plan_path: Path,
    chunk_manifest_path: Path,
    import_manifest_path: Path,
    source_root: Path,
    receipt_root: Path,
    positive_projection_path: Path,
    authority_projection_path: Path,
    output_queue_path: Path,
    output_manifest_path: Path,
    block_window_path: Path | None = None,
) -> dict[str, object]:
    """Build a frozen reserve queue; this never selects or qualifies controls."""
    plan_verification = verify_historical_expansion_query_plan(
        query_plan_path=query_plan_path,
        chunk_plan_path=chunk_plan_path,
        chunk_manifest_path=chunk_manifest_path,
    )
    source_verification = verify_historical_source_import(
        query_plan_path=query_plan_path,
        import_manifest_path=import_manifest_path,
        source_root=source_root,
        receipt_root=receipt_root,
    )
    plan = _load(query_plan_path, "query_plan")
    if plan.get("inventory_sha256") != _sha(inventory_path):
        raise HistoricalCandidateQueueError("inventory_sha256_mismatch")
    if plan.get("inventory_manifest_sha256") != _sha(inventory_manifest_path):
        raise HistoricalCandidateQueueError("inventory_manifest_sha256_mismatch")
    rules = plan.get("candidate_queue_rules")
    if not isinstance(rules, Mapping):
        raise HistoricalCandidateQueueError("candidate_queue_rules_missing")
    reserve_multiplier = int(rules.get("reserve_multiplier") or 0)
    edge_ceiling = int(rules.get("per_case_edge_scan_ceiling") or 0)
    if reserve_multiplier <= 0 or edge_ceiling <= 0:
        raise HistoricalCandidateQueueError("candidate_queue_rules_invalid")

    chunks = pd.read_csv(chunk_plan_path, dtype=str, keep_default_na=False)
    required_chunk = {
        "case_name",
        "chain",
        "admissible_deployment_start",
        "admissible_deployment_end",
        "positive_prediction_cutoff_time",
        "minimum_additional_distinct_slots",
        "expansion_requirement_sha256",
    }
    if missing := sorted(required_chunk - set(chunks.columns)):
        raise HistoricalCandidateQueueError(
            f"chunk_plan_missing_columns:{','.join(missing)}"
        )
    if chunks["case_name"].duplicated().any():
        raise HistoricalCandidateQueueError("chunk_plan_duplicate_case")
    windows: dict[str, dict[str, object]] = {}
    buckets: dict[tuple[int, str], list[str]] = {}
    block_buckets: dict[tuple[int, int], list[str]] = {}
    targets: dict[str, int] = {}
    for row in chunks.to_dict("records"):
        case = str(row["case_name"])
        chain = str(row["chain"]).lower()
        if chain not in _CHAIN_IDS:
            raise HistoricalCandidateQueueError("chunk_chain_invalid")
        start = _utc(row["admissible_deployment_start"], "admissible_start")
        end = _utc(row["admissible_deployment_end"], "admissible_end")
        cutoff = _utc(row["positive_prediction_cutoff_time"], "positive_cutoff")
        if end > cutoff or start > end:
            raise HistoricalCandidateQueueError("chunk_window_invalid")
        deficit = int(row["minimum_additional_distinct_slots"])
        if deficit <= 0:
            raise HistoricalCandidateQueueError("chunk_deficit_invalid")
        windows[case] = {
            "case_name": case,
            "chain": chain,
            "chain_id": _CHAIN_IDS[chain],
            "start": start,
            "end": end,
            "cutoff": cutoff,
            "deficit": deficit,
            "requirement": str(row["expansion_requirement_sha256"]).lower(),
        }
        targets[case] = deficit * reserve_multiplier
        if block_window_path is None:
            for day in pd.date_range(start.normalize(), end.normalize(), freq="D"):
                buckets.setdefault((_CHAIN_IDS[chain], day.date().isoformat()), []).append(case)

    block_window_sha256: str | None = None
    if block_window_path is not None:
        block_windows = pd.read_csv(block_window_path, dtype=str, keep_default_na=False)
        required_block_windows = {
            "case_name",
            "chain",
            "chain_id",
            "admissible_deployment_start",
            "admissible_deployment_end",
            "start_block",
            "end_block",
            "boundary_status",
        }
        if missing := sorted(required_block_windows - set(block_windows.columns)):
            raise HistoricalCandidateQueueError(
                f"block_window_missing_columns:{','.join(missing)}"
            )
        if block_windows["case_name"].duplicated().any():
            raise HistoricalCandidateQueueError("block_window_duplicate_case")
        block_by_case = {
            str(row["case_name"]): row for row in block_windows.to_dict("records")
        }
        if set(block_by_case) != set(windows):
            raise HistoricalCandidateQueueError("block_window_case_coverage_mismatch")
        for case, window in windows.items():
            block_row = block_by_case[case]
            if (
                str(block_row["chain"]).lower() != window["chain"]
                or int(block_row["chain_id"]) != window["chain_id"]
                or str(block_row["admissible_deployment_start"]) != _iso(window["start"])
                or str(block_row["admissible_deployment_end"]) != _iso(window["end"])
                or str(block_row["boundary_status"])
                != "LOCAL_TEST_SINGLE_PROVIDER_EXACT_BLOCK_BRACKET"
            ):
                raise HistoricalCandidateQueueError("block_window_binding_mismatch")
            start_block = int(block_row["start_block"])
            end_block = int(block_row["end_block"])
            if start_block < 0 or end_block < start_block:
                raise HistoricalCandidateQueueError("block_window_range_invalid")
            window["start_block"] = start_block
            window["end_block"] = end_block
            for block_bucket in range(start_block // 100_000, end_block // 100_000 + 1):
                block_buckets.setdefault((int(window["chain_id"]), block_bucket), []).append(case)
        block_window_sha256 = _sha(block_window_path)

    positives = pd.read_csv(positive_projection_path, dtype=str, keep_default_na=False)
    positive_address_column = (
        "target_contract_address"
        if "target_contract_address" in positives.columns
        else "positive_address"
    )
    positive_required = {
        "case_name",
        "chain",
        positive_address_column,
        "deployment_time",
        "prediction_cutoff_time",
    }
    if not positive_required.issubset(positives.columns):
        raise HistoricalCandidateQueueError("positive_projection_columns_invalid")
    if positives["case_name"].duplicated().any():
        raise HistoricalCandidateQueueError("positive_projection_duplicate_case")
    positive_by_case = {
        str(row["case_name"]): row for row in positives.to_dict("records")
    }
    for case, window in windows.items():
        if case not in positive_by_case:
            raise HistoricalCandidateQueueError("positive_case_missing")
        positive = positive_by_case[case]
        if str(positive["chain"]).lower() != window["chain"]:
            raise HistoricalCandidateQueueError("positive_chain_mismatch")
        deployment = _utc(positive["deployment_time"], "positive_deployment_time")
        cutoff = _utc(positive["prediction_cutoff_time"], "positive_cutoff_time")
        if cutoff != window["cutoff"]:
            raise HistoricalCandidateQueueError("positive_cutoff_mismatch")
        if not window["start"] <= deployment <= window["end"]:
            raise HistoricalCandidateQueueError("positive_deployment_window_mismatch")
        window["positive_deployment"] = deployment
    excluded: set[str] = set()
    for row in positives.to_dict("records"):
        chain = str(row["chain"]).lower()
        if chain not in _CHAIN_IDS:
            raise HistoricalCandidateQueueError("positive_chain_invalid")
        excluded.add(
            f"{_CHAIN_IDS[chain]}:{_address(row[positive_address_column], 'positive_address')}"
        )
    authority = pd.read_csv(authority_projection_path, dtype=str, keep_default_na=False)
    if "contract_address" not in authority.columns:
        raise HistoricalCandidateQueueError("authority_projection_columns_invalid")
    for row in authority.to_dict("records"):
        chain_id = int(row.get("chain_id") or _CHAIN_IDS.get(str(row.get("chain", "")).lower(), 0))
        if chain_id not in _CHAIN_NAMES:
            raise HistoricalCandidateQueueError("authority_chain_invalid")
        excluded.add(
            f"{chain_id}:{_address(row['contract_address'], 'authority_address')}"
        )

    import_manifest = _load(import_manifest_path, "import_manifest")
    receipts = import_manifest.get("objects")
    if not isinstance(receipts, list):
        raise HistoricalCandidateQueueError("import_manifest_objects_invalid")
    temporary_db = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
    temporary_db.close()
    database_path = Path(temporary_db.name)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            """
            CREATE TABLE candidates (
              identity TEXT NOT NULL,
              record_sha256 TEXT NOT NULL,
              chain_id INTEGER NOT NULL,
              address TEXT NOT NULL,
              transaction_hash TEXT NOT NULL,
              block_number INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              creation_type TEXT NOT NULL,
              trace_proof INTEGER NOT NULL,
              source_object_key TEXT NOT NULL,
              source_object_sha256 TEXT NOT NULL,
              PRIMARY KEY(identity, record_sha256)
            )
            """
        )
        source_rows_seen = 0
        candidate_rows_seen = 0
        unusable_in_window_rows_excluded = 0
        for receipt in receipts:
            if not isinstance(receipt, Mapping):
                raise HistoricalCandidateQueueError("import_receipt_invalid")
            path = Path(str(receipt.get("path") or ""))
            source_key = str(receipt.get("key") or "")
            source_sha = str(receipt.get("sha256") or "").lower()
            for frame in _source_batches(path):
                required_source = {
                    "chain_id",
                    "address",
                    "transaction_hash",
                    "block_number",
                }
                if block_window_path is None:
                    required_source.update({"created_at", "creation_type", "trace_proof"})
                if missing := sorted(required_source - set(frame.columns)):
                    raise HistoricalCandidateQueueError(
                        f"source_missing_columns:{','.join(missing)}"
                    )
                inserts: list[tuple[object, ...]] = []
                for row in frame.to_dict("records"):
                    source_rows_seen += 1
                    try:
                        chain_id = int(row["chain_id"])
                    except (TypeError, ValueError) as exc:
                        raise HistoricalCandidateQueueError("source_chain_id_invalid") from exc
                    if chain_id not in _CHAIN_NAMES:
                        continue
                    try:
                        block_number = int(row["block_number"])
                    except (TypeError, ValueError) as exc:
                        if block_window_path is not None:
                            continue
                        raise HistoricalCandidateQueueError("source_block_number_invalid") from exc
                    if block_number < 0:
                        if block_window_path is not None:
                            continue
                        raise HistoricalCandidateQueueError("source_block_number_invalid")
                    if block_window_path is not None:
                        possible_cases = block_buckets.get((chain_id, block_number // 100_000), [])
                        if not any(
                            int(windows[case]["start_block"])
                            <= block_number
                            <= int(windows[case]["end_block"])
                            for case in possible_cases
                        ):
                            continue
                    try:
                        address = _address(row["address"], "source_address")
                        transaction_hash = _tx(row["transaction_hash"])
                    except HistoricalCandidateQueueError:
                        if block_window_path is not None:
                            unusable_in_window_rows_excluded += 1
                            continue
                        raise
                    identity = f"{chain_id}:{address}"
                    if identity in excluded:
                        continue
                    if block_window_path is None:
                        created = _utc(row["created_at"], "source_created_at")
                        possible_cases = buckets.get((chain_id, created.date().isoformat()), [])
                        if not any(
                            windows[case]["start"] <= created <= windows[case]["end"]
                            and created <= windows[case]["cutoff"]
                            for case in possible_cases
                        ):
                            continue
                        creation_type = str(row["creation_type"] or "").strip().lower()
                        if not creation_type:
                            raise HistoricalCandidateQueueError("source_creation_type_invalid")
                        trace_proof = _boolean(row["trace_proof"])
                        created_iso = _iso(created)
                    else:
                        creation_type = "UNKNOWN_REQUIRES_RPC"
                        trace_proof = False
                        created_iso = "UNKNOWN_REQUIRES_RPC"
                    record_material = {
                        "chain_id": chain_id,
                        "address": address,
                        "transaction_hash": transaction_hash,
                        "block_number": block_number,
                        "created_at": created_iso,
                        "creation_type": creation_type,
                        "trace_proof": trace_proof,
                    }
                    record_sha = _canonical_sha(record_material)
                    inserts.append(
                        (
                            identity,
                            record_sha,
                            chain_id,
                            address,
                            transaction_hash,
                            block_number,
                            created_iso,
                            creation_type,
                            int(trace_proof),
                            source_key,
                            source_sha,
                        )
                    )
                    candidate_rows_seen += 1
                connection.executemany(
                    "INSERT OR IGNORE INTO candidates VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    inserts,
                )
                connection.commit()
        conflict = connection.execute(
            "SELECT identity FROM candidates GROUP BY identity HAVING COUNT(*) > 1 LIMIT 1"
        ).fetchone()
        if conflict and block_window_path is None:
            raise HistoricalCandidateQueueError(
                f"source_identity_conflict:{conflict[0]}"
            )
        lifecycle_conflict_identities = int(
            connection.execute(
                "SELECT COUNT(*) FROM (SELECT identity FROM candidates GROUP BY identity HAVING COUNT(*) > 1)"
            ).fetchone()[0]
        )
        candidate_count = int(
            connection.execute("SELECT COUNT(DISTINCT identity) FROM candidates").fetchone()[0]
        )
        heaps: dict[str, list[tuple[int, str, dict[str, object]]]] = {
            case: [] for case in windows
        }
        block_best_edges: dict[tuple[str, str], dict[str, object]] = {}
        cursor = connection.execute(
            """
            SELECT identity, record_sha256, chain_id, address, transaction_hash,
                   block_number, created_at, creation_type, trace_proof,
                   source_object_key, source_object_sha256
            FROM candidates ORDER BY identity
            """
        )
        for row in cursor:
            (
                identity,
                record_sha,
                chain_id,
                address,
                transaction_hash,
                block_number,
                created_at,
                creation_type,
                trace_proof,
                source_key,
                source_sha,
            ) = row
            if block_window_path is None:
                created = _utc(created_at, "candidate_created_at")
                possible_cases = buckets.get((int(chain_id), created.date().isoformat()), [])
            else:
                created = None
                possible_cases = block_buckets.get((int(chain_id), int(block_number) // 100_000), [])
            for case in possible_cases:
                window = windows[case]
                if block_window_path is None:
                    if not (
                        window["start"] <= created <= window["end"]
                        and created <= window["cutoff"]
                    ):
                        continue
                elif not (
                    int(window["start_block"])
                    <= int(block_number)
                    <= int(window["end_block"])
                ):
                    continue
                edge_rank = _canonical_sha(
                    {
                        "case_name": case,
                        "control_identity": identity,
                        "source_record_sha256": record_sha,
                        "expansion_requirement_sha256": window["requirement"],
                    }
                )
                edge = {
                    "case_name": case,
                    "chain": window["chain"],
                    "chain_id": int(chain_id),
                    "positive_prediction_cutoff_time": _iso(window["cutoff"]),
                    "minimum_additional_distinct_slots": int(window["deficit"]),
                    "reserve_target": int(targets[case]),
                    "control_address": address,
                    "control_identity": identity,
                    "control_deployment_time": (
                        _iso(created) if created is not None else "UNKNOWN_REQUIRES_RPC"
                    ),
                    "deployment_distance_seconds": (
                        int(abs((window["positive_deployment"] - created).total_seconds()))
                        if created is not None
                        else -1
                    ),
                    "creation_tx_hash": transaction_hash,
                    "deployment_block": int(block_number),
                    "creation_type": creation_type,
                    "trace_proof": bool(trace_proof),
                    "source_object_key": source_key,
                    "source_object_sha256": source_sha,
                    "source_record_sha256": record_sha,
                    "edge_rank_sha256": edge_rank,
                }
                if block_window_path is not None:
                    key = (case, identity)
                    current = block_best_edges.get(key)
                    ordering = (
                        int(edge["deployment_block"]),
                        str(edge["creation_tx_hash"]),
                        str(edge["source_record_sha256"]),
                    )
                    if current is None or ordering < (
                        int(current["deployment_block"]),
                        str(current["creation_tx_hash"]),
                        str(current["source_record_sha256"]),
                    ):
                        block_best_edges[key] = edge
                    continue
                score = int(edge_rank, 16)
                heap = heaps[case]
                entry = (-score, identity, edge)
                if len(heap) < edge_ceiling:
                    heapq.heappush(heap, entry)
                elif score < -heap[0][0]:
                    heapq.heapreplace(heap, entry)
        if block_window_path is not None:
            for edge in block_best_edges.values():
                case = str(edge["case_name"])
                identity = str(edge["control_identity"])
                score = int(str(edge["edge_rank_sha256"]), 16)
                heap = heaps[case]
                entry = (-score, identity, edge)
                if len(heap) < edge_ceiling:
                    heapq.heappush(heap, entry)
                elif score < -heap[0][0]:
                    heapq.heapreplace(heap, entry)
        capped_edges = [entry[2] for heap in heaps.values() for entry in heap]
        selected, per_case_allocated, flow = _capacity_allocation(capped_edges, targets)
    finally:
        connection.close()
        try:
            database_path.unlink()
        except FileNotFoundError:
            pass

    queue_records: list[dict[str, object]] = []
    for edge in sorted(
        selected,
        key=lambda row: (
            str(row["case_name"]),
            str(row["edge_rank_sha256"]),
            str(row["control_identity"]),
        ),
    ):
        record = dict(edge)
        record["queue_status"] = "RESERVE_CANDIDATE_REQUIRES_RPC_AND_PAIR_EVIDENCE"
        record["rpc_authorized"] = False
        record["selection_authorized"] = False
        record["stage_promotion_authorized"] = False
        record["recovery3_mutation_authorized"] = False
        record["reserve_assignment_sha256"] = _canonical_sha(record)
        queue_records.append(record)
    output_queue_path = output_queue_path.expanduser().resolve(strict=False)
    output_manifest_path = output_manifest_path.expanduser().resolve(strict=False)
    input_paths = {
        path.expanduser().resolve(strict=True)
        for path in (
            query_plan_path,
            inventory_path,
            inventory_manifest_path,
            chunk_plan_path,
            chunk_manifest_path,
            import_manifest_path,
            positive_projection_path,
            authority_projection_path,
        )
    }
    if output_queue_path in input_paths or output_manifest_path in input_paths:
        raise HistoricalCandidateQueueError("output_overwrites_input")
    output_queue_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=output_queue_path.parent, delete=False
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=_QUEUE_COLUMNS)
        writer.writeheader()
        writer.writerows(queue_records)
        queue_temporary = Path(handle.name)
    os.replace(queue_temporary, output_queue_path)
    reserve_target = sum(targets.values())
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_historical_candidate_reserve_queue.v1",
        "decision": (
            "RESERVE_QUEUE_FROZEN_REQUIRES_HASH_BOUND_RPC_ACTIVATION"
            if flow == reserve_target
            else "RESERVE_QUEUE_INSUFFICIENT_REPLAN_REQUIRED"
        ),
        "query_plan_file_sha256": plan_verification["query_plan_file_sha256"],
        "source_import_manifest_sha256": source_verification["import_manifest_sha256"],
        "positive_projection_sha256": _sha(positive_projection_path),
        "authority_projection_sha256": _sha(authority_projection_path),
        "chunk_plan_sha256": _sha(chunk_plan_path),
        "block_window_sha256": block_window_sha256,
        "source_created_at_used_as_deployment_time": block_window_path is None,
        "source_rows_seen": source_rows_seen,
        "candidate_rows_seen_before_deduplication": candidate_rows_seen,
        "unusable_in_window_rows_excluded": unusable_in_window_rows_excluded,
        "unique_candidate_identities": candidate_count,
        "lifecycle_conflict_identities": lifecycle_conflict_identities,
        "lifecycle_tie_break_rule": (
            "EARLIEST_QUALIFYING_BLOCK_THEN_TRANSACTION_HASH_THEN_SOURCE_RECORD_SHA256"
            if block_window_path is not None
            else None
        ),
        "capped_edge_count": len(capped_edges),
        "per_case_edge_scan_ceiling": edge_ceiling,
        "reserve_multiplier": reserve_multiplier,
        "reserve_target": reserve_target,
        "reserve_allocated": flow,
        "reserve_shortfall": reserve_target - flow,
        "per_case_reserve_target": targets,
        "per_case_reserve_allocated": per_case_allocated,
        "global_no_reuse_verified": len(
            {str(row["control_identity"]) for row in queue_records}
        )
        == len(queue_records),
        "queue_path": str(output_queue_path),
        "queue_sha256": _sha(output_queue_path),
        "queue_row_count": len(queue_records),
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output_manifest_path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        manifest_temporary = Path(handle.name)
    os.replace(manifest_temporary, output_manifest_path)
    return manifest


def verify_historical_candidate_queue(
    *,
    queue_path: Path,
    manifest_path: Path,
    query_plan_path: Path,
    chunk_plan_path: Path,
    positive_projection_path: Path,
    authority_projection_path: Path,
    import_manifest_path: Path,
    block_window_path: Path | None = None,
) -> dict[str, object]:
    """Verify a frozen reserve queue without granting RPC or selection authority."""
    queue_path = queue_path.expanduser().resolve(strict=True)
    manifest_path = manifest_path.expanduser().resolve(strict=True)
    manifest = _load(manifest_path, "queue_manifest")
    if manifest.get("schema_version") != (
        "chronosaudit.control_historical_candidate_reserve_queue.v1"
    ):
        raise HistoricalCandidateQueueError("queue_manifest_schema_invalid")
    if manifest.get("decision") not in {
        "RESERVE_QUEUE_FROZEN_REQUIRES_HASH_BOUND_RPC_ACTIVATION",
        "RESERVE_QUEUE_INSUFFICIENT_REPLAN_REQUIRED",
    }:
        raise HistoricalCandidateQueueError("queue_manifest_decision_invalid")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if manifest.get(field) is not False:
            raise HistoricalCandidateQueueError(f"queue_manifest_{field}_invalid")
    if manifest.get("query_plan_file_sha256") != _sha(query_plan_path):
        raise HistoricalCandidateQueueError("queue_query_plan_sha256_mismatch")
    if manifest.get("source_import_manifest_sha256") != _sha(import_manifest_path):
        raise HistoricalCandidateQueueError("queue_source_import_sha256_mismatch")
    if manifest.get("positive_projection_sha256") != _sha(positive_projection_path):
        raise HistoricalCandidateQueueError("queue_positive_sha256_mismatch")
    if manifest.get("authority_projection_sha256") != _sha(authority_projection_path):
        raise HistoricalCandidateQueueError("queue_authority_sha256_mismatch")
    if manifest.get("chunk_plan_sha256") != _sha(chunk_plan_path):
        raise HistoricalCandidateQueueError("queue_chunk_plan_sha256_mismatch")
    if block_window_path is None:
        if manifest.get("block_window_sha256") is not None:
            raise HistoricalCandidateQueueError("queue_unexpected_block_window_binding")
    elif manifest.get("block_window_sha256") != _sha(block_window_path):
        raise HistoricalCandidateQueueError("queue_block_window_sha256_mismatch")
    if manifest.get("source_created_at_used_as_deployment_time") is not (
        block_window_path is None
    ):
        raise HistoricalCandidateQueueError("queue_source_time_semantics_mismatch")
    if manifest.get("queue_sha256") != _sha(queue_path):
        raise HistoricalCandidateQueueError("queue_sha256_mismatch")
    if int(manifest.get("unusable_in_window_rows_excluded") or 0) < 0:
        raise HistoricalCandidateQueueError("queue_unusable_row_count_invalid")
    if block_window_path is not None:
        if int(manifest.get("lifecycle_conflict_identities") or 0) < 0:
            raise HistoricalCandidateQueueError("queue_lifecycle_conflict_count_invalid")
        if manifest.get("lifecycle_tie_break_rule") != (
            "EARLIEST_QUALIFYING_BLOCK_THEN_TRANSACTION_HASH_THEN_SOURCE_RECORD_SHA256"
        ):
            raise HistoricalCandidateQueueError("queue_lifecycle_tie_break_invalid")

    queue = pd.read_csv(queue_path, dtype=str, keep_default_na=False)
    if missing := sorted(set(_QUEUE_COLUMNS) - set(queue.columns)):
        raise HistoricalCandidateQueueError(
            f"queue_missing_columns:{','.join(missing)}"
        )
    if len(queue) != int(manifest.get("queue_row_count") or -1):
        raise HistoricalCandidateQueueError("queue_row_count_mismatch")
    if queue[["case_name", "control_identity"]].duplicated().any():
        raise HistoricalCandidateQueueError("queue_pair_duplicate")
    if queue["control_identity"].duplicated().any():
        raise HistoricalCandidateQueueError("queue_global_identity_reuse")
    if not bool(manifest.get("global_no_reuse_verified")):
        raise HistoricalCandidateQueueError("queue_manifest_no_reuse_invalid")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if not queue[field].str.lower().eq("false").all():
            raise HistoricalCandidateQueueError(f"queue_{field}_invalid")
    if not queue["queue_status"].eq(
        "RESERVE_CANDIDATE_REQUIRES_RPC_AND_PAIR_EVIDENCE"
    ).all():
        raise HistoricalCandidateQueueError("queue_status_invalid")

    chunks = pd.read_csv(chunk_plan_path, dtype=str, keep_default_na=False)
    chunk_by_case = {
        str(row["case_name"]): row for row in chunks.to_dict("records")
    }
    block_by_case: dict[str, dict[str, str]] = {}
    if block_window_path is not None:
        block_windows = pd.read_csv(block_window_path, dtype=str, keep_default_na=False)
        block_by_case = {
            str(row["case_name"]): row for row in block_windows.to_dict("records")
        }
        if set(block_by_case) != set(chunk_by_case):
            raise HistoricalCandidateQueueError("queue_block_window_case_coverage_mismatch")
    plan = _load(query_plan_path, "query_plan")
    rules = plan.get("candidate_queue_rules")
    if not isinstance(rules, Mapping):
        raise HistoricalCandidateQueueError("candidate_queue_rules_missing")
    multiplier = int(rules.get("reserve_multiplier") or 0)
    observed_counts = queue.groupby("case_name").size().to_dict()
    expected_targets: dict[str, int] = {}
    for case, chunk in chunk_by_case.items():
        expected_targets[case] = int(chunk["minimum_additional_distinct_slots"]) * multiplier
    manifest_targets = {
        str(key): int(value)
        for key, value in dict(manifest.get("per_case_reserve_target") or {}).items()
    }
    if manifest_targets != expected_targets:
        raise HistoricalCandidateQueueError("queue_case_targets_mismatch")
    manifest_allocated = {
        str(key): int(value)
        for key, value in dict(manifest.get("per_case_reserve_allocated") or {}).items()
    }
    expected_allocated = {
        case: int(observed_counts.get(case, 0)) for case in expected_targets
    }
    if manifest_allocated != expected_allocated:
        raise HistoricalCandidateQueueError("queue_case_allocations_mismatch")
    for row in queue.to_dict("records"):
        case = str(row["case_name"])
        if case not in chunk_by_case:
            raise HistoricalCandidateQueueError("queue_unknown_case")
        chunk = chunk_by_case[case]
        chain = str(chunk["chain"]).lower()
        identity = f"{_CHAIN_IDS[chain]}:{_address(row['control_address'], 'queue_address')}"
        if row["control_identity"] != identity:
            raise HistoricalCandidateQueueError("queue_identity_mismatch")
        if row["positive_prediction_cutoff_time"] != chunk[
            "positive_prediction_cutoff_time"
        ]:
            raise HistoricalCandidateQueueError("queue_cutoff_mismatch")
        if int(row["minimum_additional_distinct_slots"]) != int(
            chunk["minimum_additional_distinct_slots"]
        ):
            raise HistoricalCandidateQueueError("queue_deficit_mismatch")
        if int(row["reserve_target"]) != expected_targets[case]:
            raise HistoricalCandidateQueueError("queue_reserve_target_mismatch")
        if block_window_path is not None:
            boundary = block_by_case[case]
            if not (
                int(boundary["start_block"])
                <= int(row["deployment_block"])
                <= int(boundary["end_block"])
            ):
                raise HistoricalCandidateQueueError("queue_block_outside_verified_window")
            if (
                row["control_deployment_time"] != "UNKNOWN_REQUIRES_RPC"
                or int(row["deployment_distance_seconds"]) != -1
                or row["creation_type"] != "UNKNOWN_REQUIRES_RPC"
                or str(row["trace_proof"]).lower() != "false"
            ):
                raise HistoricalCandidateQueueError("queue_unresolved_rpc_fields_invalid")
        expected_edge = _canonical_sha(
            {
                "case_name": case,
                "control_identity": identity,
                "source_record_sha256": row["source_record_sha256"],
                "expansion_requirement_sha256": chunk[
                    "expansion_requirement_sha256"
                ],
            }
        )
        if row["edge_rank_sha256"] != expected_edge:
            raise HistoricalCandidateQueueError("queue_edge_rank_mismatch")
        assignment = {
            key: value
            for key, value in row.items()
            if key != "reserve_assignment_sha256"
        }
        for key in (
            "chain_id",
            "minimum_additional_distinct_slots",
            "reserve_target",
            "deployment_distance_seconds",
            "deployment_block",
        ):
            assignment[key] = int(assignment[key])
        assignment["trace_proof"] = str(assignment["trace_proof"]).lower() == "true"
        for key in (
            "rpc_authorized",
            "selection_authorized",
            "stage_promotion_authorized",
            "recovery3_mutation_authorized",
        ):
            assignment[key] = False
        if row["reserve_assignment_sha256"] != _canonical_sha(assignment):
            raise HistoricalCandidateQueueError("queue_assignment_hash_mismatch")

    reserve_target = sum(expected_targets.values())
    allocated = len(queue)
    if int(manifest.get("reserve_target") or -1) != reserve_target:
        raise HistoricalCandidateQueueError("queue_manifest_target_mismatch")
    if int(manifest.get("reserve_allocated") or -1) != allocated:
        raise HistoricalCandidateQueueError("queue_manifest_allocated_mismatch")
    if int(manifest.get("reserve_shortfall", -1)) != reserve_target - allocated:
        raise HistoricalCandidateQueueError("queue_manifest_shortfall_mismatch")
    expected_decision = (
        "RESERVE_QUEUE_FROZEN_REQUIRES_HASH_BOUND_RPC_ACTIVATION"
        if allocated == reserve_target
        else "RESERVE_QUEUE_INSUFFICIENT_REPLAN_REQUIRED"
    )
    if manifest.get("decision") != expected_decision:
        raise HistoricalCandidateQueueError("queue_manifest_decision_mismatch")
    return {
        "schema_version": "chronosaudit.control_historical_candidate_reserve_queue_verification.v1",
        "decision": (
            "RESERVE_QUEUE_VERIFIED_NON_AUTHORIZING"
            if allocated == reserve_target
            else "RESERVE_QUEUE_VERIFIED_INSUFFICIENT_REPLAN_REQUIRED"
        ),
        "queue_sha256": _sha(queue_path),
        "manifest_sha256": _sha(manifest_path),
        "queue_row_count": allocated,
        "reserve_target": reserve_target,
        "reserve_shortfall": reserve_target - allocated,
        "global_no_reuse_verified": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
