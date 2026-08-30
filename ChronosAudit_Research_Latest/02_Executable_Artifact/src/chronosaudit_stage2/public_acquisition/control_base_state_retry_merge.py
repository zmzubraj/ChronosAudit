from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from chronosaudit_stage2.public_acquisition.control_cutoff_state_acquisition import (
    verify_cutoff_state_checkpoint_signature,
)


class ControlBaseStateRetryMergeError(ValueError):
    """Original and retry batches could not be merged without weakening evidence."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> tuple[Path, dict[str, object]]:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlBaseStateRetryMergeError(f"{label}_not_ordinary_file")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ControlBaseStateRetryMergeError(f"{label}_not_ordinary_file")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlBaseStateRetryMergeError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlBaseStateRetryMergeError(f"{label}_root_invalid")
    return resolved, payload


def _results_from_checkpoint(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    checkpoint_file, checkpoint = _load(path, "checkpoint")
    material = {key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"}
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(material):
        raise ControlBaseStateRetryMergeError("checkpoint_self_hash_invalid")
    relative = Path(str(checkpoint.get("normalized_results_path", "")))
    if relative.is_absolute() or ".." in relative.parts:
        raise ControlBaseStateRetryMergeError("results_path_escape")
    results_file, results = _load(checkpoint_file.parent / relative, "results")
    if _file_sha(results_file) != checkpoint.get("normalized_results_sha256"):
        raise ControlBaseStateRetryMergeError("results_hash_mismatch")
    return checkpoint, results


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlBaseStateRetryMergeError("output_symlink")
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


def merge_base_state_retry_results(
    *,
    original_checkpoint_path: Path,
    original_signature_path: Path,
    retry_checkpoint_path: Path,
    retry_signature_path: Path,
    retry_targets_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    output_path: Path,
) -> dict[str, object]:
    for checkpoint, signature in (
        (original_checkpoint_path, original_signature_path),
        (retry_checkpoint_path, retry_signature_path),
    ):
        verification = verify_cutoff_state_checkpoint_signature(
            checkpoint_path=checkpoint,
            signature_path=signature,
            allowed_signers_path=allowed_signers_path,
            expected_principal=expected_principal,
        )
        if verification.get("complete") is not True:
            raise ControlBaseStateRetryMergeError("checkpoint_signature_invalid")
    original_checkpoint, original = _results_from_checkpoint(original_checkpoint_path)
    retry_checkpoint, retry = _results_from_checkpoint(retry_checkpoint_path)
    _, retry_targets = _load(retry_targets_path, "retry_targets")
    retry_target_rows = retry_targets.get("targets")
    if not isinstance(retry_target_rows, list):
        raise ControlBaseStateRetryMergeError("retry_targets_invalid")
    retry_ids = {str(row.get("target_id", "")) for row in retry_target_rows if isinstance(row, Mapping)}
    original_rows = original.get("targets")
    retry_rows = retry.get("targets")
    if not isinstance(original_rows, list) or not isinstance(retry_rows, list):
        raise ControlBaseStateRetryMergeError("results_targets_invalid")
    failed_ids = {
        str(row.get("target_id", ""))
        for row in original_rows
        if isinstance(row, Mapping) and row.get("disposition") != "complete"
    }
    if not retry_ids or retry_ids != failed_ids:
        raise ControlBaseStateRetryMergeError("retry_identity_mismatch")
    retry_by_id = {
        str(row.get("target_id", "")): dict(row)
        for row in retry_rows
        if isinstance(row, Mapping) and row.get("disposition") == "complete"
    }
    if set(retry_by_id) != retry_ids:
        raise ControlBaseStateRetryMergeError("retry_results_incomplete")
    merged_rows = sorted(
        [
            retry_by_id.get(str(row.get("target_id", "")), dict(row))
            for row in original_rows
            if isinstance(row, Mapping)
        ],
        key=lambda row: str(row["target_id"]),
    )
    if len(merged_rows) != int(original.get("target_count", -1)):
        raise ControlBaseStateRetryMergeError("merged_target_count_invalid")
    dispositions = dict(sorted(Counter(str(row.get("disposition")) for row in merged_rows).items()))
    if dispositions != {"complete": len(merged_rows)}:
        raise ControlBaseStateRetryMergeError("merged_results_incomplete")
    payload: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_state_results.v1",
        "target_count": len(merged_rows),
        "processed_target_count": len(merged_rows),
        "completed_target_count": len(merged_rows),
        "dispositions": dispositions,
        "targets": merged_rows,
        "original_checkpoint_sha256": original_checkpoint["checkpoint_sha256"],
        "retry_checkpoint_sha256": retry_checkpoint["checkpoint_sha256"],
        "retry_targets_file_sha256": _file_sha(retry_targets_path.resolve(strict=True)),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    payload["results_sha256"] = _canonical_sha(payload)
    _atomic_write(output_path.expanduser(), payload)
    return payload
