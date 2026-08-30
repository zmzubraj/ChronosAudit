from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path


class ControlBaseStateRetryTargetsError(ValueError):
    """A retry subset could not be derived from immutable batch evidence."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> tuple[Path, dict[str, object]]:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlBaseStateRetryTargetsError(f"{label}_not_ordinary_file")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ControlBaseStateRetryTargetsError(f"{label}_not_ordinary_file")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ControlBaseStateRetryTargetsError(f"{label}_root_invalid")
    return resolved, payload


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlBaseStateRetryTargetsError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_canonical_json(dict(payload)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_base_state_retry_targets(
    *,
    original_targets_path: Path,
    checkpoint_path: Path,
    output_path: Path,
) -> dict[str, object]:
    targets_file, original = _load(original_targets_path, "original_targets")
    checkpoint_file, checkpoint = _load(checkpoint_path, "checkpoint")
    if original.get("schema_version") != "stage2_control_base_state_targets.v1":
        raise ControlBaseStateRetryTargetsError("original_targets_schema_invalid")
    original_material = {
        key: value for key, value in original.items() if key != "targets_sha256"
    }
    if original.get("targets_sha256") != _canonical_sha(original_material):
        raise ControlBaseStateRetryTargetsError("original_targets_self_hash_invalid")
    checkpoint_material = {
        key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"
    }
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(checkpoint_material):
        raise ControlBaseStateRetryTargetsError("checkpoint_self_hash_invalid")
    if checkpoint.get("status") != "PARTIAL_NON_AUTHORIZING":
        raise ControlBaseStateRetryTargetsError("checkpoint_not_partial")
    if checkpoint.get("state_targets_sha256") != _file_sha(targets_file):
        raise ControlBaseStateRetryTargetsError("checkpoint_targets_hash_mismatch")

    root = checkpoint_file.parent
    results_file = (root / str(checkpoint.get("normalized_results_path", ""))).resolve(
        strict=True
    )
    ledger_file = (root / str(checkpoint.get("event_ledger_path", ""))).resolve(
        strict=True
    )
    if root.resolve() not in results_file.parents or root.resolve() not in ledger_file.parents:
        raise ControlBaseStateRetryTargetsError("checkpoint_path_escape")
    if (
        _file_sha(results_file) != checkpoint.get("normalized_results_sha256")
        or _file_sha(ledger_file) != checkpoint.get("event_ledger_sha256")
    ):
        raise ControlBaseStateRetryTargetsError("checkpoint_evidence_hash_mismatch")
    results = json.loads(results_file.read_text(encoding="utf-8"))
    rows = results.get("targets") if isinstance(results, dict) else None
    if not isinstance(rows, list):
        raise ControlBaseStateRetryTargetsError("normalized_results_invalid")
    failed_ids = {
        str(row.get("target_id", ""))
        for row in rows
        if isinstance(row, dict) and row.get("disposition") != "complete"
    }
    provider_error_ids: set[str] = set()
    for line in ledger_file.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("disposition") == "provider_error":
            provider_error_ids.add(str(event.get("target_id", "")))
    retry_ids = failed_ids & provider_error_ids
    if not retry_ids:
        raise ControlBaseStateRetryTargetsError("no_provider_error_retry_targets")
    original_rows = original.get("targets")
    if not isinstance(original_rows, list):
        raise ControlBaseStateRetryTargetsError("original_targets_invalid")
    retry_rows = sorted(
        [dict(row) for row in original_rows if str(row.get("target_id", "")) in retry_ids],
        key=lambda row: str(row["target_id"]),
    )
    if len(retry_rows) != len(retry_ids):
        raise ControlBaseStateRetryTargetsError("retry_target_missing")
    payload = {
        **{key: value for key, value in original.items() if key not in {
            "targets", "target_count", "call_count", "targets_sha256"
        }},
        "target_count": len(retry_rows),
        "call_count": sum(len(row.get("calls", [])) for row in retry_rows),
        "targets": retry_rows,
        "retry_source_checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "retry_source_results_file_sha256": _file_sha(results_file),
        "retry_reason": "HASH_CHAINED_PROVIDER_ERROR_ONLY",
    }
    payload["targets_sha256"] = _canonical_sha(payload)
    _atomic_write(output_path.expanduser(), payload)
    return payload
