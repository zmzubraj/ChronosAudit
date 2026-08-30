from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

import pandas as pd


class HistoricalExpansionQueryPlanError(ValueError):
    """Raised when the frozen historical expansion scope is not fail-closed."""


_KEY = re.compile(
    r"^v2/contract_deployments/contract_deployments_(\d+)_(\d+)\.parquet$"
)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise HistoricalExpansionQueryPlanError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HistoricalExpansionQueryPlanError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise HistoricalExpansionQueryPlanError(f"{label}_not_ordinary_file")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HistoricalExpansionQueryPlanError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise HistoricalExpansionQueryPlanError(f"{label}_root_invalid")
    return value


def build_historical_expansion_query_plan(
    *,
    inventory_path: Path,
    inventory_manifest_path: Path,
    chunk_plan_path: Path,
    chunk_manifest_path: Path,
    historical_end_exclusive: int,
) -> dict[str, object]:
    """Freeze source acquisition and deployment-verification rules without authority."""
    inventory_path = _ordinary(inventory_path, "inventory")
    inventory_manifest_path = _ordinary(inventory_manifest_path, "inventory_manifest")
    chunk_plan_path = _ordinary(chunk_plan_path, "chunk_plan")
    chunk_manifest_path = _ordinary(chunk_manifest_path, "chunk_manifest")
    inventory_manifest = _load_json(inventory_manifest_path, "inventory_manifest")
    if inventory_manifest.get("outcome") != "COMPLETE" or inventory_manifest.get("errors") != []:
        raise HistoricalExpansionQueryPlanError("inventory_not_complete")
    if inventory_manifest.get("provider") != "sourcify_bucket":
        raise HistoricalExpansionQueryPlanError("inventory_provider_invalid")
    if inventory_manifest.get("dataset") != "v2/contract_deployments":
        raise HistoricalExpansionQueryPlanError("inventory_dataset_invalid")

    inventory = pd.read_csv(inventory_path, dtype=str, keep_default_na=False)
    required = {
        "provider", "dataset", "chain", "prefix", "key", "etag", "size",
        "last_modified", "raw_page_sha256",
    }
    if missing := sorted(required - set(inventory.columns)):
        raise HistoricalExpansionQueryPlanError(
            f"inventory_missing_columns:{','.join(missing)}"
        )
    expected_rows = int(inventory_manifest.get("row_count") or -1)
    if expected_rows != len(inventory) or int(
        inventory_manifest.get("objects_processed") or -1
    ) != len(inventory):
        raise HistoricalExpansionQueryPlanError("inventory_count_mismatch")
    if inventory["key"].duplicated().any():
        raise HistoricalExpansionQueryPlanError("source_object_duplicate")
    if not (
        inventory["provider"].eq("sourcify_bucket").all()
        and inventory["dataset"].eq("v2/contract_deployments").all()
        and inventory["chain"].eq("all").all()
    ):
        raise HistoricalExpansionQueryPlanError("inventory_scope_invalid")

    objects: list[dict[str, object]] = []
    for row in inventory.itertuples(index=False):
        match = _KEY.fullmatch(str(row.key))
        if not match:
            raise HistoricalExpansionQueryPlanError("source_object_key_invalid")
        start, end = map(int, match.groups())
        if end <= historical_end_exclusive:
            if end - start != 1_000_000:
                raise HistoricalExpansionQueryPlanError("source_object_range_invalid")
            try:
                size = int(row.size)
            except ValueError as exc:
                raise HistoricalExpansionQueryPlanError("source_object_size_invalid") from exc
            if size <= 0 or not str(row.etag).strip():
                raise HistoricalExpansionQueryPlanError("source_object_identity_invalid")
            objects.append(
                {
                    "start": start,
                    "end": end,
                    "key": str(row.key),
                    "etag": str(row.etag),
                    "size": size,
                    "last_modified": str(row.last_modified),
                    "inventory_page_sha256": str(row.raw_page_sha256).lower(),
                }
            )
    objects.sort(key=lambda item: int(item["start"]))
    if not objects or int(objects[0]["start"]) != 0:
        raise HistoricalExpansionQueryPlanError("source_object_range_noncontiguous")
    expected_start = 0
    for item in objects:
        if int(item["start"]) != expected_start:
            raise HistoricalExpansionQueryPlanError("source_object_range_noncontiguous")
        expected_start = int(item["end"])
    if expected_start != historical_end_exclusive:
        raise HistoricalExpansionQueryPlanError("source_object_range_noncontiguous")

    chunk_manifest = _load_json(chunk_manifest_path, "chunk_manifest")
    if chunk_manifest.get("schema_version") != "chronosaudit.control_denominator_expansion_chunk_plan.v1":
        raise HistoricalExpansionQueryPlanError("chunk_manifest_schema_invalid")
    if chunk_manifest.get("decision") != "BOUNDED_EXPANSION_PLAN_AWAITS_ACCOUNTABLE_ACQUISITION_APPROVAL":
        raise HistoricalExpansionQueryPlanError("chunk_manifest_decision_invalid")
    for field in ("acquisition_authorized", "rpc_authorized", "selection_authorized"):
        if chunk_manifest.get(field) is not False:
            raise HistoricalExpansionQueryPlanError(f"chunk_manifest_{field}_invalid")
    output = chunk_manifest.get("output")
    if not isinstance(output, Mapping) or output.get("sha256") != _sha(chunk_plan_path):
        raise HistoricalExpansionQueryPlanError("chunk_plan_sha256_mismatch")
    chunks = pd.read_csv(chunk_plan_path, dtype=str, keep_default_na=False)
    if len(chunks) != int(chunk_manifest.get("cases_requiring_expansion") or -1):
        raise HistoricalExpansionQueryPlanError("chunk_case_count_mismatch")
    if chunks["case_name"].duplicated().any():
        raise HistoricalExpansionQueryPlanError("chunk_case_overlap")
    for field in ("acquisition_authorized", "rpc_authorized", "selection_authorized"):
        if not chunks[field].str.lower().eq("false").all():
            raise HistoricalExpansionQueryPlanError(f"chunk_{field}_invalid")

    plan: dict[str, object] = {
        "schema_version": "chronosaudit.control_historical_expansion_query_plan.v1",
        "decision": "FROZEN_QUERY_PLAN_AWAITS_ACCOUNTABLE_SIGNED_APPROVAL",
        "purpose": "HISTORICAL_DENOMINATOR_EXPANSION_ONLY",
        "inventory_sha256": _sha(inventory_path),
        "inventory_manifest_sha256": _sha(inventory_manifest_path),
        "chunk_plan_sha256": _sha(chunk_plan_path),
        "chunk_manifest_sha256": _sha(chunk_manifest_path),
        "historical_object_range": [0, historical_end_exclusive],
        "source_object_count": len(objects),
        "source_total_bytes": sum(int(row["size"]) for row in objects),
        "source_objects": objects,
        "download_rules": {
            "exact_object_allowlist_only": True,
            "capture_response_headers_and_sha256": True,
            "ordinary_files_only": True,
            "maximum_download_bytes": sum(int(row["size"]) for row in objects),
            "adaptive_object_discovery": False,
        },
        "local_transform_rules": {
            "target_chain_ids": [1, 56, 8453, 42161],
            "case_bound_window_filter": True,
            "exclude_positive_chain_address": True,
            "exclude_recovery3_chain_address": True,
            "deduplicate_chain_address": True,
            "require_deployed_by_positive_cutoff": True,
            "deterministic_rank": "sha256(chain_id,address,transaction_hash,block_number,created_at)",
            "outcome_blind": True,
        },
        "candidate_queue_rules": {
            "allocation_algorithm": "deterministic_capacity_dinic_v1",
            "candidate_identity": "chain_id:lower(address)",
            "candidate_identity_capacity": 1,
            "overflow_disposition": "REPLAN_REQUIRED",
            "per_case_edge_scan_ceiling": 1000,
            "queue_hash_required_before_rpc": True,
            "reserve_multiplier": 10,
            "reserve_target_rule": (
                "minimum_additional_distinct_slots*reserve_multiplier"
            ),
        },
        "rpc_methods": [
            "eth_chainId",
            "eth_getTransactionReceipt",
            "eth_getBlockByHash",
        ],
        "rpc_rules": {
            "candidate_queue_must_be_hash_frozen_before_rpc": True,
            "raw_request_and_response_receipts_required": True,
            "provider_registry_binding_required": True,
            "creation_receipt_contract_address_match_required": True,
            "block_hash_and_timestamp_match_required": True,
            "internal_or_create2_requires_separate_creation_evidence": True,
        },
        "case_count": len(chunks),
        "minimum_additional_distinct_slots": int(
            pd.to_numeric(chunks["minimum_additional_distinct_slots"]).sum()
        ),
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    plan["query_plan_sha256"] = _canonical_sha(plan)
    return plan


def verify_historical_expansion_query_plan(
    *,
    query_plan_path: Path,
    chunk_plan_path: Path,
    chunk_manifest_path: Path,
) -> dict[str, object]:
    """Verify a persisted plan before it may be bound into an approval request."""
    query_plan_path = _ordinary(query_plan_path, "query_plan")
    chunk_plan_path = _ordinary(chunk_plan_path, "chunk_plan")
    chunk_manifest_path = _ordinary(chunk_manifest_path, "chunk_manifest")
    plan = _load_json(query_plan_path, "query_plan")
    if plan.get("schema_version") != (
        "chronosaudit.control_historical_expansion_query_plan.v1"
    ):
        raise HistoricalExpansionQueryPlanError("query_plan_schema_invalid")
    if plan.get("decision") != (
        "FROZEN_QUERY_PLAN_AWAITS_ACCOUNTABLE_SIGNED_APPROVAL"
    ):
        raise HistoricalExpansionQueryPlanError("query_plan_decision_invalid")
    if plan.get("purpose") != "HISTORICAL_DENOMINATOR_EXPANSION_ONLY":
        raise HistoricalExpansionQueryPlanError("query_plan_purpose_invalid")
    for field in (
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if plan.get(field) is not False:
            raise HistoricalExpansionQueryPlanError(f"query_plan_{field}_invalid")
    if plan.get("chunk_plan_sha256") != _sha(chunk_plan_path):
        raise HistoricalExpansionQueryPlanError("query_plan_chunk_plan_mismatch")
    if plan.get("chunk_manifest_sha256") != _sha(chunk_manifest_path):
        raise HistoricalExpansionQueryPlanError("query_plan_chunk_manifest_mismatch")

    manifest = _load_json(chunk_manifest_path, "chunk_manifest")
    output = manifest.get("output")
    if not isinstance(output, Mapping) or output.get("sha256") != _sha(chunk_plan_path):
        raise HistoricalExpansionQueryPlanError("chunk_plan_sha256_mismatch")
    chunks = pd.read_csv(chunk_plan_path, dtype=str, keep_default_na=False)
    if int(plan.get("case_count") or -1) != len(chunks):
        raise HistoricalExpansionQueryPlanError("query_plan_case_count_mismatch")
    expected_slots = int(
        pd.to_numeric(chunks["minimum_additional_distinct_slots"], errors="raise").sum()
    )
    if int(plan.get("minimum_additional_distinct_slots") or -1) != expected_slots:
        raise HistoricalExpansionQueryPlanError("query_plan_slot_count_mismatch")

    source_objects = plan.get("source_objects")
    object_range = plan.get("historical_object_range")
    if (
        not isinstance(source_objects, list)
        or not source_objects
        or not isinstance(object_range, list)
        or len(object_range) != 2
    ):
        raise HistoricalExpansionQueryPlanError("query_plan_source_scope_invalid")
    start_expected, end_expected = map(int, object_range)
    if start_expected != 0:
        raise HistoricalExpansionQueryPlanError("query_plan_source_range_invalid")
    total_bytes = 0
    observed = start_expected
    for item in source_objects:
        if not isinstance(item, Mapping):
            raise HistoricalExpansionQueryPlanError("query_plan_source_object_invalid")
        start = int(item.get("start", -1))
        end = int(item.get("end", -1))
        size = int(item.get("size", -1))
        if start != observed or end - start != 1_000_000 or size <= 0:
            raise HistoricalExpansionQueryPlanError("query_plan_source_range_invalid")
        match = _KEY.fullmatch(str(item.get("key") or ""))
        if not match or tuple(map(int, match.groups())) != (start, end):
            raise HistoricalExpansionQueryPlanError("query_plan_source_key_invalid")
        if not str(item.get("etag") or "").strip():
            raise HistoricalExpansionQueryPlanError("query_plan_source_etag_invalid")
        page_hash = str(item.get("inventory_page_sha256") or "").lower()
        if len(page_hash) != 64 or any(char not in "0123456789abcdef" for char in page_hash):
            raise HistoricalExpansionQueryPlanError("query_plan_inventory_page_hash_invalid")
        total_bytes += size
        observed = end
    if observed != end_expected:
        raise HistoricalExpansionQueryPlanError("query_plan_source_range_invalid")
    if int(plan.get("source_object_count") or -1) != len(source_objects):
        raise HistoricalExpansionQueryPlanError("query_plan_source_count_mismatch")
    if int(plan.get("source_total_bytes") or -1) != total_bytes:
        raise HistoricalExpansionQueryPlanError("query_plan_source_bytes_mismatch")

    downloads = plan.get("download_rules")
    if not isinstance(downloads, Mapping):
        raise HistoricalExpansionQueryPlanError("query_plan_download_rules_invalid")
    for field in (
        "exact_object_allowlist_only",
        "capture_response_headers_and_sha256",
        "ordinary_files_only",
    ):
        if downloads.get(field) is not True:
            raise HistoricalExpansionQueryPlanError(f"query_plan_{field}_invalid")
    if downloads.get("adaptive_object_discovery") is not False:
        raise HistoricalExpansionQueryPlanError("query_plan_adaptive_discovery_invalid")
    if int(downloads.get("maximum_download_bytes") or -1) != total_bytes:
        raise HistoricalExpansionQueryPlanError("query_plan_download_ceiling_mismatch")

    transform = plan.get("local_transform_rules")
    if not isinstance(transform, Mapping):
        raise HistoricalExpansionQueryPlanError("query_plan_transform_rules_invalid")
    for field in (
        "case_bound_window_filter",
        "deduplicate_chain_address",
        "exclude_positive_chain_address",
        "exclude_recovery3_chain_address",
        "outcome_blind",
        "require_deployed_by_positive_cutoff",
    ):
        if transform.get(field) is not True:
            raise HistoricalExpansionQueryPlanError(f"query_plan_{field}_invalid")
    if transform.get("target_chain_ids") != [1, 56, 8453, 42161]:
        raise HistoricalExpansionQueryPlanError("query_plan_chain_scope_invalid")
    queue_rules = plan.get("candidate_queue_rules")
    if queue_rules != {
        "allocation_algorithm": "deterministic_capacity_dinic_v1",
        "candidate_identity": "chain_id:lower(address)",
        "candidate_identity_capacity": 1,
        "overflow_disposition": "REPLAN_REQUIRED",
        "per_case_edge_scan_ceiling": 1000,
        "queue_hash_required_before_rpc": True,
        "reserve_multiplier": 10,
        "reserve_target_rule": (
            "minimum_additional_distinct_slots*reserve_multiplier"
        ),
    }:
        raise HistoricalExpansionQueryPlanError("query_plan_candidate_queue_rules_invalid")
    if plan.get("rpc_methods") != [
        "eth_chainId",
        "eth_getTransactionReceipt",
        "eth_getBlockByHash",
    ]:
        raise HistoricalExpansionQueryPlanError("query_plan_rpc_methods_invalid")
    rpc_rules = plan.get("rpc_rules")
    if not isinstance(rpc_rules, Mapping) or not all(
        rpc_rules.get(field) is True
        for field in (
            "candidate_queue_must_be_hash_frozen_before_rpc",
            "raw_request_and_response_receipts_required",
            "provider_registry_binding_required",
            "creation_receipt_contract_address_match_required",
            "block_hash_and_timestamp_match_required",
            "internal_or_create2_requires_separate_creation_evidence",
        )
    ):
        raise HistoricalExpansionQueryPlanError("query_plan_rpc_rules_invalid")

    internal_hash = str(plan.get("query_plan_sha256") or "").lower()
    material = {key: value for key, value in plan.items() if key != "query_plan_sha256"}
    if internal_hash != _canonical_sha(material):
        raise HistoricalExpansionQueryPlanError("query_plan_internal_hash_invalid")
    return {
        "schema_version": "chronosaudit.control_historical_expansion_query_plan_verification.v1",
        "decision": "QUERY_PLAN_VERIFIED_NON_AUTHORIZING",
        "query_plan_file_sha256": _sha(query_plan_path),
        "query_plan_internal_sha256": internal_hash,
        "source_object_count": len(source_objects),
        "source_total_bytes": total_bytes,
        "case_count": len(chunks),
        "minimum_additional_distinct_slots": expected_slots,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
    }
