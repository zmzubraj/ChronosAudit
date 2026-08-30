from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import time
from typing import Callable, Mapping
from urllib.parse import quote
from urllib.request import Request, urlopen


class HistoricalSourceAcquisitionError(ValueError):
    """Raised when bounded historical-source acquisition violates its authority."""


OFFICIAL_SOURCE_BASE_URL = (
    "https://storage.googleapis.com/sourcify-production-parquet-export/"
)

Fetch = Callable[[str, int, Callable[[bytes], object]], tuple[int, dict[str, str]]]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _normalized_etag(value: object) -> str:
    return str(value or "").strip().strip('"').lower()


def _official_fetch(
    url: str,
    offset: int,
    write: Callable[[bytes], object],
) -> tuple[int, dict[str, str]]:
    if offset != 0:
        raise HistoricalSourceAcquisitionError("partial_resume_not_supported")
    request = Request(url, method="GET", headers={"User-Agent": "ChronosAudit/1.0"})
    with urlopen(request, timeout=120) as response:  # noqa: S310 - exact frozen HTTPS origin
        status = int(getattr(response, "status", 200))
        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            write(chunk)
    return status, headers


def _safe_object_path(root: Path, key: str, label: str) -> Path:
    pure = PurePosixPath(key)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise HistoricalSourceAcquisitionError(f"{label}_path_invalid")
    candidate = root.joinpath(*pure.parts)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    resolved_parent = candidate.parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise HistoricalSourceAcquisitionError(f"{label}_path_escape") from exc
    if candidate.is_symlink():
        raise HistoricalSourceAcquisitionError(f"{label}_not_ordinary_file")
    return candidate


def acquire_historical_source_batch(
    *,
    query_plan: Mapping[str, object],
    approval_verification: Mapping[str, object],
    query_plan_file_sha256: str,
    source_root: Path,
    receipt_root: Path,
    fetch: Fetch = _official_fetch,
) -> dict[str, object]:
    """Download only the signed plan's exact objects and emit import receipts."""
    if query_plan.get("schema_version") != "chronosaudit.control_historical_expansion_query_plan.v1":
        raise HistoricalSourceAcquisitionError("query_plan_schema_invalid")
    if query_plan.get("purpose") != "HISTORICAL_DENOMINATOR_EXPANSION_ONLY":
        raise HistoricalSourceAcquisitionError("query_plan_purpose_invalid")
    if approval_verification.get("schema_version") != (
        "chronosaudit.control_source_acquisition_approval_verification.v2"
    ):
        raise HistoricalSourceAcquisitionError("approval_schema_invalid")
    if approval_verification.get("decision") != "SOURCE_ACQUISITION_APPROVAL_VERIFIED":
        raise HistoricalSourceAcquisitionError("approval_decision_invalid")
    for field, expected in (
        ("acquisition_authorized", True),
        ("rpc_authorized", False),
        ("selection_authorized", False),
        ("stage_promotion_authorized", False),
        ("recovery3_mutation_authorized", False),
    ):
        if approval_verification.get(field) is not expected:
            raise HistoricalSourceAcquisitionError(f"approval_{field}_invalid")

    objects = query_plan.get("source_objects")
    if not isinstance(objects, list) or not objects:
        raise HistoricalSourceAcquisitionError("source_objects_invalid")
    planned_count = int(query_plan.get("source_object_count") or -1)
    planned_bytes = int(query_plan.get("source_total_bytes") or -1)
    if planned_count != len(objects) or planned_count != int(
        approval_verification.get("source_object_count") or -1
    ):
        raise HistoricalSourceAcquisitionError("source_object_count_mismatch")
    if planned_bytes != int(approval_verification.get("maximum_download_bytes") or -1):
        raise HistoricalSourceAcquisitionError("source_byte_ceiling_mismatch")
    if sum(int(row.get("size") or -1) for row in objects if isinstance(row, Mapping)) != planned_bytes:
        raise HistoricalSourceAcquisitionError("source_total_bytes_mismatch")
    if len(query_plan_file_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in query_plan_file_sha256.lower()
    ):
        raise HistoricalSourceAcquisitionError("query_plan_file_sha256_invalid")

    source_root = source_root.expanduser().resolve(strict=False)
    receipt_root = receipt_root.expanduser().resolve(strict=False)
    source_root.mkdir(parents=True, exist_ok=True)
    receipt_root.mkdir(parents=True, exist_ok=True)
    if source_root.is_symlink() or receipt_root.is_symlink():
        raise HistoricalSourceAcquisitionError("acquisition_root_not_ordinary_directory")

    receipts: list[dict[str, object]] = []
    captured_bytes = 0
    for index, planned in enumerate(objects):
        if not isinstance(planned, Mapping):
            raise HistoricalSourceAcquisitionError("source_object_invalid")
        key = str(planned.get("key") or "")
        expected_etag = _normalized_etag(planned.get("etag"))
        expected_size = int(planned.get("size") or -1)
        if not key or not expected_etag or expected_size <= 0:
            raise HistoricalSourceAcquisitionError("source_object_invalid")
        captured_bytes += expected_size
        if captured_bytes > planned_bytes:
            raise HistoricalSourceAcquisitionError("source_byte_ceiling_exceeded")
        source = _safe_object_path(source_root, key, "source")
        headers_path = _safe_object_path(receipt_root, f"{key}.headers.json", "headers")
        url = OFFICIAL_SOURCE_BASE_URL + quote(key, safe="/")

        reuse = source.exists() and headers_path.exists()
        if reuse:
            if not source.is_file() or source.stat().st_size != expected_size:
                raise HistoricalSourceAcquisitionError("existing_source_size_mismatch")
            try:
                headers_record = json.loads(headers_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise HistoricalSourceAcquisitionError("existing_headers_invalid") from exc
            if headers_record.get("normalized_etag") != expected_etag:
                raise HistoricalSourceAcquisitionError("existing_source_etag_mismatch")
        else:
            if source.exists() or headers_path.exists():
                raise HistoricalSourceAcquisitionError("partial_final_artifact_present")
            part = source.with_name(f".{source.name}.part")
            if part.is_symlink():
                raise HistoricalSourceAcquisitionError("source_part_not_ordinary_file")
            last_error: Exception | None = None
            for attempt in range(1, 4):
                try:
                    with part.open("wb") as handle:
                        status, response_headers = fetch(url, 0, handle.write)
                    break
                except Exception as exc:  # network failures retain a bounded retry record
                    last_error = exc
                    if attempt == 3:
                        raise HistoricalSourceAcquisitionError(
                            f"source_download_failed:{index}:{type(exc).__name__}"
                        ) from exc
                    time.sleep(float(attempt))
            else:  # pragma: no cover - loop always breaks or raises
                raise HistoricalSourceAcquisitionError("source_download_failed") from last_error
            if status != 200:
                raise HistoricalSourceAcquisitionError("source_http_status_invalid")
            observed_etag = _normalized_etag(response_headers.get("etag"))
            if observed_etag != expected_etag:
                raise HistoricalSourceAcquisitionError("source_etag_mismatch")
            if part.stat().st_size != expected_size:
                raise HistoricalSourceAcquisitionError("source_size_mismatch")
            content_length = response_headers.get("content-length")
            if content_length is not None and int(content_length) != expected_size:
                raise HistoricalSourceAcquisitionError("source_content_length_mismatch")
            headers_record = {
                "schema_version": "chronosaudit.control_historical_source_headers.v1",
                "key": key,
                "request_url": url,
                "http_status": status,
                "normalized_etag": observed_etag,
                "expected_size": expected_size,
                "response_headers": dict(sorted(response_headers.items())),
            }
            _atomic_json(headers_path, headers_record)
            os.replace(part, source)

        receipts.append(
            {
                "key": key,
                "etag": expected_etag,
                "path": str(source.resolve(strict=True)),
                "size": expected_size,
                "sha256": _sha256_file(source),
                "headers_path": str(headers_path.resolve(strict=True)),
                "headers_sha256": _sha256_file(headers_path),
            }
        )
        print(
            json.dumps(
                {
                    "event": "SOURCE_OBJECT_CAPTURED",
                    "index": index + 1,
                    "total": planned_count,
                    "key": key,
                    "size": expected_size,
                    "reused": reuse,
                },
                sort_keys=True,
            ),
            flush=True,
        )

    return {
        "schema_version": "chronosaudit.control_historical_source_import.v1",
        "decision": "SOURCE_BATCH_CAPTURED_AWAITING_IMPORT_VERIFICATION",
        "query_plan_file_sha256": query_plan_file_sha256.lower(),
        "official_source_base_url": OFFICIAL_SOURCE_BASE_URL,
        "captured_object_count": len(receipts),
        "captured_total_bytes": captured_bytes,
        "objects": receipts,
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
