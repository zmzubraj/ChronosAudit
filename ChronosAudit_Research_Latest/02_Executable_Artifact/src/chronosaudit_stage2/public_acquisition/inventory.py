from __future__ import annotations

import csv
import hashlib
import json
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .providers import endpoint_id

_TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "source",
}
_TRACKING_QUERY_PREFIXES = ("utm_",)


def _ensure_output_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _store_raw_artifact(
    output_dir: str | Path,
    *,
    provider: str,
    payload: bytes,
    response_metadata: dict[str, Any] | None = None,
) -> tuple[str, str]:
    root = _ensure_output_dir(output_dir)
    raw_sha256 = _sha256_bytes(payload)
    raw_dir = root / "raw" / raw_sha256[:2]
    raw_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = raw_dir / f"{raw_sha256}.bin"
    if not artifact_path.exists():
        artifact_path.write_bytes(payload)
    sidecar_path = raw_dir / f"{raw_sha256}.json"
    if not sidecar_path.exists():
        _write_json(
            sidecar_path,
            {
                "provider": provider,
                "sha256": raw_sha256,
                "bytes": len(payload),
                "response_metadata": response_metadata or {},
            },
        )
    return raw_sha256, str(artifact_path)


def bounded_url_download(
    url: str,
    *,
    timeout_seconds: int = 20,
    max_response_bytes: int = 10 * 1024 * 1024,
    user_agent: str = "ChronosAudit-Stage2/0.5",
) -> tuple[bytes, dict[str, Any]]:
    started = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = response.read(max_response_bytes + 1)
        if len(payload) > max_response_bytes:
            raise ValueError(f"response exceeded max_response_bytes={max_response_bytes}")
        elapsed = time.monotonic() - started
        metadata = {
            "url": url,
            "status": getattr(response, "status", None),
            "headers": dict(response.headers.items()),
            "elapsed_seconds": round(elapsed, 6),
        }
        return payload, metadata


def _tracking_endpoint(endpoint: str) -> bool:
    query = urllib.parse.urlsplit(endpoint).query
    for key, _value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in _TRACKING_QUERY_KEYS:
            return True
        if any(lowered.startswith(prefix) for prefix in _TRACKING_QUERY_PREFIXES):
            return True
    return False


def _secret_template_endpoint(endpoint: str) -> bool:
    return any(token in endpoint for token in ("${", "{{", "<api-key>", "<apikey>", "{api_key}", "{apikey}"))


def _inventory_outcome(errors: list[str]) -> tuple[bool, str]:
    if not errors:
        return True, "COMPLETE"
    if any("exceeded" in error for error in errors):
        return False, "LIMIT_BREACH"
    return False, "ERROR"


def _limit_state(
    *,
    max_pages: int | None,
    max_objects: int | None,
    max_response_bytes: int | None,
    max_elapsed_seconds: float | None,
) -> dict[str, Any]:
    return {
        "max_pages": max_pages,
        "max_objects": max_objects,
        "max_response_bytes": max_response_bytes,
        "max_elapsed_seconds": max_elapsed_seconds,
    }


def _chainlist_rows(payload: bytes) -> list[dict[str, Any]]:
    parsed = json.loads(payload.decode("utf-8"))
    if isinstance(parsed, list):
        chains = parsed
    elif isinstance(parsed, dict) and "chains" in parsed:
        chains = parsed["chains"]
    else:
        raise ValueError("unsupported Chainlist payload shape")

    rows: list[dict[str, Any]] = []
    for item in chains:
        if not isinstance(item, dict):
            continue
        chain = str(item.get("name") or item.get("chain") or "").strip() or "unknown"
        chain_id = item.get("chainId") or item.get("chain_id")
        for endpoint in item.get("rpc", []) or []:
            endpoint_text = str(endpoint).strip()
            if not endpoint_text:
                continue
            tracking = _tracking_endpoint(endpoint_text)
            secret_template = _secret_template_endpoint(endpoint_text)
            exclusion_reason = None
            eligible = True
            if secret_template:
                eligible = False
                exclusion_reason = "secret_template_endpoint"
            elif tracking:
                eligible = False
                exclusion_reason = "tracking_endpoint"
            rows.append(
                {
                    "chain": chain,
                    "chain_id": chain_id,
                    "endpoint": endpoint_text,
                    "endpoint_id": endpoint_id(endpoint_text),
                    "tracking": tracking,
                    "secret_template": secret_template,
                    "eligible": eligible,
                    "exclusion_reason": exclusion_reason,
                }
            )
    return rows


def capture_chainlist_inventory(
    source: bytes | str | dict[str, Any] | list[Any],
    output_dir: str | Path,
    *,
    max_pages: int | None = 1,
    max_objects: int | None = None,
    max_response_bytes: int | None = None,
    max_elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    payload = source if isinstance(source, bytes) else (source.encode("utf-8") if isinstance(source, str) else json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    raw_sha256, raw_artifact_path = _store_raw_artifact(output_dir, provider="chainlist", payload=payload)

    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    if max_pages is not None and max_pages < 1:
        errors.append("max_pages_exceeded")
    if max_response_bytes is not None and len(payload) > max_response_bytes:
        errors.append("max_response_bytes_exceeded")
    if not errors:
        rows = _chainlist_rows(payload)
    if max_objects is not None and len(rows) > max_objects:
        errors.append("max_objects_exceeded")

    elapsed_seconds = round(time.monotonic() - started, 6)
    if max_elapsed_seconds is not None and elapsed_seconds > max_elapsed_seconds:
        errors.append("max_elapsed_seconds_exceeded")

    completed, outcome = _inventory_outcome(errors)
    output_root = _ensure_output_dir(output_dir)
    normalized_path = output_root / "chainlist_inventory.csv"
    manifest_path = output_root / "chainlist_inventory_manifest.json"
    _write_csv(normalized_path, rows)
    _write_json(
        manifest_path,
        {
            "provider": "chainlist",
            "raw_sha256": raw_sha256,
            "raw_artifact_path": raw_artifact_path,
            "row_count": len(rows),
            "eligible_count": sum(1 for row in rows if row["eligible"]),
            "pages_processed": 1,
            "objects_processed": len(rows),
            "elapsed_seconds": elapsed_seconds,
            "limits": _limit_state(
                max_pages=max_pages,
                max_objects=max_objects,
                max_response_bytes=max_response_bytes,
                max_elapsed_seconds=max_elapsed_seconds,
            ),
            "errors": errors,
            "outcome": outcome,
        },
    )
    eligible_endpoints = [
        {
            "chain": row["chain"],
            "chain_id": row["chain_id"],
            "endpoint": row["endpoint"],
            "endpoint_id": row["endpoint_id"],
            "tracking": row["tracking"],
        }
        for row in rows
        if row["eligible"]
    ]
    return {
        "raw_sha256": raw_sha256,
        "raw_artifact_path": raw_artifact_path,
        "normalized_path": str(normalized_path),
        "manifest_path": str(manifest_path),
        "eligible_endpoints": eligible_endpoints,
        "completed": completed,
        "errors": errors,
    }


def _s3_namespace(root: ET.Element) -> str:
    if root.tag.startswith("{") and "}" in root.tag:
        return root.tag[1:].split("}", 1)[0]
    return ""


def _s3_child_text(element: ET.Element, namespace: str, name: str) -> str | None:
    query = f"{{{namespace}}}{name}" if namespace else name
    child = element.find(query)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def _parse_s3_inventory_page(
    payload: bytes,
    *,
    provider: str,
    chain: str,
    prefix: str,
    dataset: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    root = ET.fromstring(payload)
    namespace = _s3_namespace(root)
    next_token = _s3_child_text(root, namespace, "NextContinuationToken")
    rows: list[dict[str, Any]] = []
    contents_query = f"{{{namespace}}}Contents" if namespace else "Contents"
    for entry in root.findall(contents_query):
        key = _s3_child_text(entry, namespace, "Key")
        if not key:
            continue
        etag = (_s3_child_text(entry, namespace, "ETag") or "").strip('"')
        size_text = _s3_child_text(entry, namespace, "Size") or "0"
        last_modified = _s3_child_text(entry, namespace, "LastModified")
        rows.append(
            {
                "provider": provider,
                "dataset": dataset or "",
                "chain": chain,
                "prefix": prefix,
                "key": key,
                "etag": etag,
                "size": int(size_text),
                "last_modified": last_modified,
            }
        )
    return rows, next_token


def _capture_s3_pages(
    pages: Iterable[bytes | str],
    output_dir: str | Path,
    *,
    provider: str,
    chain: str,
    prefix: str,
    dataset: str | None = None,
    normalized_filename: str,
    manifest_filename: str,
    max_pages: int | None = None,
    max_objects: int | None = None,
    max_response_bytes: int | None = None,
    max_elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    rows: list[dict[str, Any]] = []
    next_tokens: list[str] = []
    raw_paths: list[str] = []
    errors: list[str] = []
    output_root = _ensure_output_dir(output_dir)

    for index, page in enumerate(pages):
        if max_pages is not None and index >= max_pages:
            errors.append("max_pages_exceeded")
            break
        payload = page if isinstance(page, bytes) else str(page).encode("utf-8")
        raw_sha256, raw_path = _store_raw_artifact(
            output_root,
            provider=provider,
            payload=payload,
            response_metadata={"page_index": index, "prefix": prefix, "dataset": dataset},
        )
        raw_paths.append(raw_path)
        if max_response_bytes is not None and len(payload) > max_response_bytes:
            errors.append("max_response_bytes_exceeded")
            break
        try:
            page_rows, next_token = _parse_s3_inventory_page(
                payload,
                provider=provider,
                chain=chain,
                prefix=prefix,
                dataset=dataset,
            )
        except ET.ParseError as exc:
            errors.append(f"page_{index}:{type(exc).__name__}")
            break
        if max_objects is not None and len(rows) + len(page_rows) > max_objects:
            errors.append("max_objects_exceeded")
            break
        for row in page_rows:
            row["page_index"] = index
            row["raw_page_sha256"] = raw_sha256
            rows.append(row)
        if next_token:
            next_tokens.append(next_token)
        if max_elapsed_seconds is not None and (time.monotonic() - started) > max_elapsed_seconds:
            errors.append("max_elapsed_seconds_exceeded")
            break

    elapsed_seconds = round(time.monotonic() - started, 6)
    completed, outcome = _inventory_outcome(errors)
    normalized_path = output_root / normalized_filename
    manifest_path = output_root / manifest_filename
    _write_csv(normalized_path, rows)
    _write_json(
        manifest_path,
        {
            "provider": provider,
            "dataset": dataset,
            "chain": chain,
            "prefix": prefix,
            "row_count": len(rows),
            "page_count": len(raw_paths),
            "pages_processed": len(raw_paths),
            "objects_processed": len(rows),
            "elapsed_seconds": elapsed_seconds,
            "limits": _limit_state(
                max_pages=max_pages,
                max_objects=max_objects,
                max_response_bytes=max_response_bytes,
                max_elapsed_seconds=max_elapsed_seconds,
            ),
            "next_tokens": next_tokens,
            "errors": errors,
            "outcome": outcome,
        },
    )
    return {
        "row_count": len(rows),
        "rows": rows,
        "raw_artifact_paths": raw_paths,
        "normalized_path": str(normalized_path),
        "manifest_path": str(manifest_path),
        "next_tokens": next_tokens,
        "errors": errors,
        "completed": completed,
        "outcome": outcome,
        "pages_processed": len(raw_paths),
        "objects_processed": len(rows),
        "elapsed_seconds": elapsed_seconds,
    }


def capture_s3_inventory(
    pages: Iterable[bytes | str],
    output_dir: str | Path,
    *,
    provider: str,
    chain: str,
    prefix: str,
    max_pages: int | None = None,
    max_objects: int | None = None,
    max_response_bytes: int | None = None,
    max_elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    return _capture_s3_pages(
        pages,
        output_dir,
        provider=provider,
        chain=chain,
        prefix=prefix,
        normalized_filename=f"{provider}_{chain}_inventory.csv",
        manifest_filename=f"{provider}_{chain}_inventory_manifest.json",
        max_pages=max_pages,
        max_objects=max_objects,
        max_response_bytes=max_response_bytes,
        max_elapsed_seconds=max_elapsed_seconds,
    )


def capture_sourcify_inventory(
    dataset_pages: dict[str, Iterable[bytes | str]],
    output_dir: str | Path,
    *,
    chain: str,
    max_pages: int | None = None,
    max_objects: int | None = None,
    max_response_bytes: int | None = None,
    max_elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    aggregate_rows: list[dict[str, Any]] = []
    raw_paths: list[str] = []
    errors: list[str] = []
    next_tokens: list[str] = []
    output_root = _ensure_output_dir(output_dir)
    total_pages = 0
    total_objects = 0
    started = time.monotonic()

    for dataset, pages in dataset_pages.items():
        remaining_pages = None if max_pages is None else max_pages - total_pages
        remaining_objects = None if max_objects is None else max_objects - total_objects
        remaining_elapsed = None
        if max_elapsed_seconds is not None:
            remaining_elapsed = max_elapsed_seconds - (time.monotonic() - started)
        if remaining_pages is not None and remaining_pages <= 0:
            errors.append("max_pages_exceeded")
            break
        if remaining_objects is not None and remaining_objects <= 0:
            errors.append("max_objects_exceeded")
            break
        if remaining_elapsed is not None and remaining_elapsed <= 0:
            errors.append("max_elapsed_seconds_exceeded")
            break

        result = _capture_s3_pages(
            pages,
            output_root,
            provider="sourcify_bucket",
            chain=chain,
            prefix=f"{dataset}/{chain}/",
            dataset=dataset,
            normalized_filename=f"sourcify_{dataset}_{chain}_inventory.csv",
            manifest_filename=f"sourcify_{dataset}_{chain}_manifest.json",
            max_pages=remaining_pages,
            max_objects=remaining_objects,
            max_response_bytes=max_response_bytes,
            max_elapsed_seconds=remaining_elapsed,
        )
        total_pages += result["pages_processed"]
        total_objects += result["objects_processed"]
        raw_paths.extend(result["raw_artifact_paths"])
        next_tokens.extend(result["next_tokens"])
        aggregate_rows.extend(result["rows"])
        if result["errors"]:
            errors.extend(result["errors"])
            break

    elapsed_seconds = round(time.monotonic() - started, 6)
    completed, outcome = _inventory_outcome(errors)
    normalized_path = output_root / f"sourcify_{chain}_inventory.csv"
    manifest_path = output_root / f"sourcify_{chain}_inventory_manifest.json"
    _write_csv(normalized_path, aggregate_rows)
    _write_json(
        manifest_path,
        {
            "provider": "sourcify_bucket",
            "chain": chain,
            "datasets": sorted(dataset_pages.keys()),
            "row_count": len(aggregate_rows),
            "page_count": total_pages,
            "pages_processed": total_pages,
            "objects_processed": total_objects,
            "elapsed_seconds": elapsed_seconds,
            "limits": _limit_state(
                max_pages=max_pages,
                max_objects=max_objects,
                max_response_bytes=max_response_bytes,
                max_elapsed_seconds=max_elapsed_seconds,
            ),
            "next_tokens": next_tokens,
            "errors": errors,
            "outcome": outcome,
        },
    )
    return {
        "row_count": len(aggregate_rows),
        "raw_artifact_paths": raw_paths,
        "normalized_path": str(normalized_path),
        "manifest_path": str(manifest_path),
        "next_tokens": next_tokens,
        "errors": errors,
        "completed": completed,
        "outcome": outcome,
    }
