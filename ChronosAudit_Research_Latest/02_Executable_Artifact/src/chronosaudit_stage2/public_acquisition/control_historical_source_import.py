from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping


class HistoricalSourceImportError(ValueError):
    """Raised when a downloaded historical source batch is not exact or auditable."""


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise HistoricalSourceImportError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HistoricalSourceImportError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise HistoricalSourceImportError(f"{label}_not_ordinary_file")
    return resolved


def _inside(path: Path, root: Path, label: str) -> Path:
    resolved = _ordinary(path, label)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise HistoricalSourceImportError(f"{label}_path_escape") from exc
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HistoricalSourceImportError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise HistoricalSourceImportError(f"{label}_root_invalid")
    return value


def verify_historical_source_import(
    *,
    query_plan_path: Path,
    import_manifest_path: Path,
    source_root: Path,
    receipt_root: Path,
) -> dict[str, object]:
    """Verify exact downloaded objects before any local transform or RPC queue."""
    query_plan_path = _ordinary(query_plan_path, "query_plan")
    import_manifest_path = _inside(import_manifest_path, receipt_root, "import_manifest")
    plan = _load(query_plan_path, "query_plan")
    manifest = _load(import_manifest_path, "import_manifest")
    if plan.get("schema_version") != "chronosaudit.control_historical_expansion_query_plan.v1":
        raise HistoricalSourceImportError("query_plan_schema_invalid")
    if plan.get("decision") != "FROZEN_QUERY_PLAN_AWAITS_ACCOUNTABLE_SIGNED_APPROVAL":
        raise HistoricalSourceImportError("query_plan_decision_invalid")
    if plan.get("purpose") != "HISTORICAL_DENOMINATOR_EXPANSION_ONLY":
        raise HistoricalSourceImportError("query_plan_purpose_invalid")
    for field in (
        "acquisition_authorized",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if plan.get(field) is not False:
            raise HistoricalSourceImportError(f"query_plan_{field}_invalid")
    if manifest.get("schema_version") != "chronosaudit.control_historical_source_import.v1":
        raise HistoricalSourceImportError("import_manifest_schema_invalid")
    if manifest.get("query_plan_file_sha256") != _sha(query_plan_path):
        raise HistoricalSourceImportError("query_plan_file_sha256_mismatch")
    for field in ("acquisition_authorized", "rpc_authorized", "selection_authorized"):
        if manifest.get(field) is not False:
            raise HistoricalSourceImportError(f"import_manifest_{field}_invalid")

    expected = plan.get("source_objects")
    observed = manifest.get("objects")
    if not isinstance(expected, list) or not isinstance(observed, list):
        raise HistoricalSourceImportError("source_objects_invalid")
    if len(expected) != int(plan.get("source_object_count") or -1):
        raise HistoricalSourceImportError("query_plan_source_count_mismatch")
    if len(observed) != len(expected):
        raise HistoricalSourceImportError("source_object_count_mismatch")
    if len({str(row.get("key")) for row in observed if isinstance(row, Mapping)}) != len(observed):
        raise HistoricalSourceImportError("source_object_duplicate")

    verified: list[dict[str, object]] = []
    total_bytes = 0
    for planned, receipt in zip(expected, observed, strict=True):
        if not isinstance(planned, Mapping) or not isinstance(receipt, Mapping):
            raise HistoricalSourceImportError("source_object_invalid")
        key = str(planned.get("key") or "")
        if str(receipt.get("key") or "") != key:
            raise HistoricalSourceImportError("source_key_mismatch")
        if str(receipt.get("etag") or "") != str(planned.get("etag") or ""):
            raise HistoricalSourceImportError("source_etag_mismatch")
        source = _inside(Path(str(receipt.get("path") or "")), source_root, "source")
        headers = _inside(
            Path(str(receipt.get("headers_path") or "")), receipt_root, "headers"
        )
        expected_size = int(planned.get("size") or -1)
        if (
            int(receipt.get("size") or -1) != expected_size
            or source.stat().st_size != expected_size
        ):
            raise HistoricalSourceImportError("source_size_mismatch")
        source_sha = _sha(source)
        if str(receipt.get("sha256") or "").lower() != source_sha:
            raise HistoricalSourceImportError("source_sha256_mismatch")
        headers_sha = _sha(headers)
        if str(receipt.get("headers_sha256") or "").lower() != headers_sha:
            raise HistoricalSourceImportError("headers_sha256_mismatch")
        total_bytes += expected_size
        verified.append(
            {
                "key": key,
                "etag": str(planned.get("etag") or ""),
                "size": expected_size,
                "sha256": source_sha,
                "headers_sha256": headers_sha,
            }
        )
    if total_bytes != int(plan.get("source_total_bytes") or -1):
        raise HistoricalSourceImportError("source_total_bytes_mismatch")
    return {
        "schema_version": "chronosaudit.control_historical_source_import_verification.v1",
        "decision": "SOURCE_BATCH_VERIFIED_FOR_LOCAL_TRANSFORM",
        "query_plan_file_sha256": _sha(query_plan_path),
        "import_manifest_sha256": _sha(import_manifest_path),
        "verified_object_count": len(verified),
        "verified_total_bytes": total_bytes,
        "verified_objects_sha256": hashlib.sha256(
            json.dumps(verified, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
