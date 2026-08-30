from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.onchain import JsonRpcProvider  # noqa: E402
from chronosaudit_stage2.ai_adjudication import (  # noqa: E402
    build_ai_evidence_packets,
    build_ai_track_package,
)
from chronosaudit_stage2.public_acquisition.counters import (  # noqa: E402
    COUNTER_ARTIFACT_VERSION,
    DEFAULT_COUNTER_TARGETS,
    build_counter_artifact,
    build_review_bundle,
    canonical_manifest_sha256,
    HISTORICAL_SNAPSHOT_OVERLAY_FIELDS,
    overlay_historical_snapshot_projection,
    project_counters,
)
from chronosaudit_stage2.public_acquisition.denominator import SUPPORTED_CHAINS, normalize_deployment_batch, select_denominator  # noqa: E402
from chronosaudit_stage2.public_acquisition.inventory import (  # noqa: E402
    capture_chainlist_inventory,
    capture_s3_inventory,
    capture_sourcify_inventory,
)
from chronosaudit_stage2.public_acquisition.ledger import AppendOnlyLedger  # noqa: E402
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry  # noqa: E402
from chronosaudit_stage2.public_acquisition.qualification import (  # noqa: E402
    build_control_candidates,
    preflight_control_inputs,
    qualify_control_rows,
)
from chronosaudit_stage2.public_acquisition.queue import build_case_queue  # noqa: E402
from chronosaudit_stage2.public_acquisition.rpc import acquire_case_snapshot, acquire_queue  # noqa: E402
from chronosaudit_stage2.public_acquisition.historical_snapshot_verifier import (  # noqa: E402
    PROJECTION_FIELDS as HISTORICAL_PROJECTION_FIELDS,
    PROJECTION_FILENAME as HISTORICAL_PROJECTION_FILENAME,
    REPORT_FILENAME as HISTORICAL_REPORT_FILENAME,
    verify_historical_snapshot_run,
)
from chronosaudit_stage2.public_acquisition.control_qualification_bundle import (  # noqa: E402
    ControlQualificationBundleError,
    verify_control_qualification_bundle,
)
from chronosaudit_stage2.source_history import ingest_sourcify_deployments_export  # noqa: E402

CANONICAL_QUEUE_PATH = ROOT / "processed" / "stage2b_onchain_query_queue.csv"
POSITIVE_CASES_PATH = ROOT / "processed" / "stage2a_temporal_provenance.csv"
POLICY_PATH = ROOT / "config" / "public_acquisition_policy.yaml"
PROVIDER_REGISTRY_PATH = ROOT / "config" / "public_provider_registry.yaml"
AI_ADJUDICATION_AMENDMENT_PATH = ROOT / "config" / "ai_adjudication_protocol_amendment_v1.yaml"
DEFAULT_REVISION = "2026-08-08"
RUN_ID_PREFIX = "public-acquisition"
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
COUNTER_SCHEMA_VERSION = COUNTER_ARTIFACT_VERSION
FIXED_UTC_COMPACT_ENV = "CHRONOSAUDIT_PUBLIC_ACQ_FIXED_UTC_COMPACT"
RPC_REQUIRED_CELLS = (
    "block_capability",
    "runtime_code",
    "eip1967_implementation_slot",
    "eip1967_beacon_slot",
    "eip1967_admin_slot",
    "beacon_implementation_call",
    "implementation_runtime_code",
    "source_locator",
    "creation_locator",
)


@dataclass(frozen=True)
class RunPaths:
    output_root: Path
    revision: str
    run_id: str
    raw_dir: Path
    processed_dir: Path
    report_dir: Path

    @property
    def run_root(self) -> Path:
        return self.report_dir.parent.parent.parent / self.revision / self.run_id


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_compact() -> str:
    fixed_value = os.environ.get(FIXED_UTC_COMPACT_ENV, "").strip()
    if fixed_value:
        return _validate_slug("fixed_utc_compact", fixed_value)
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _json_dumps(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_request_bytes(method: str, params: list[Any]) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _sha256_json(payload: Any) -> str:
    return _sha256_text(_canonical_json(payload))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_policy() -> dict[str, Any]:
    return _load_yaml(POLICY_PATH)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(content)
        temp_path = Path(handle.name)
    os.replace(temp_path, path)


def _atomic_write_json(path: Path, payload: Any) -> None:
    _atomic_write_text(path, _json_dumps(payload))


def _write_csv(path: Path, frame: pd.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)


def _load_queue_source(path: Path | None = None) -> tuple[pd.DataFrame, str]:
    source = Path(path or CANONICAL_QUEUE_PATH).resolve()
    return pd.read_csv(source), _sha256_file(source)


def _load_positive_cases() -> pd.DataFrame:
    return pd.read_csv(POSITIVE_CASES_PATH)


def _validate_slug(name: str, value: str) -> str:
    normalized = str(value).strip()
    if not normalized or not SLUG_RE.fullmatch(normalized):
        raise ValueError(f"{name} must match {SLUG_RE.pattern}")
    if "/" in normalized or "\\" in normalized or ".." in normalized:
        raise ValueError(f"{name} must not contain path separators or traversal")
    if Path(normalized).is_absolute():
        raise ValueError(f"{name} must not be absolute")
    return normalized


def _make_run_id(input_sha256: str) -> str:
    return _validate_slug("run_id", f"{RUN_ID_PREFIX}-{_utc_compact()}-{input_sha256[:12]}")


def _run_paths(output_root: Path, revision: str, run_id: str) -> RunPaths:
    safe_revision = _validate_slug("revision", revision)
    safe_run_id = _validate_slug("run_id", run_id)
    return RunPaths(
        output_root=output_root,
        revision=safe_revision,
        run_id=safe_run_id,
        raw_dir=output_root / "raw" / "public_acquisition" / safe_revision / safe_run_id,
        processed_dir=output_root / "processed" / "public_acquisition" / safe_revision / safe_run_id,
        report_dir=output_root / "reports" / "public_acquisition" / safe_revision / safe_run_id,
    )


def _portable_run_path(paths: RunPaths, path: Path | str) -> str:
    resolved = Path(path).resolve(strict=False)
    try:
        relative = resolved.relative_to(paths.output_root.resolve())
    except ValueError as exc:
        raise ValueError(f"run artifact path escapes output root: {path}") from exc
    allowed_roots = (paths.raw_dir.resolve(), paths.processed_dir.resolve(), paths.report_dir.resolve())
    if not any(root == resolved or root in resolved.parents for root in allowed_roots):
        raise ValueError(f"path outside run root: {path}")
    return relative.as_posix()


def _portable_output_path(paths: RunPaths, path: Path | str) -> str:
    resolved = Path(path).resolve(strict=False)
    try:
        return resolved.relative_to(paths.output_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError("historical_snapshot_run_root_outside_output_root") from exc


def _portable_run_references(paths: RunPaths, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _portable_run_references(paths, nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_portable_run_references(paths, nested) for nested in value]
    if isinstance(value, str) and Path(value).is_absolute():
        try:
            return _portable_run_path(paths, value)
        except ValueError:
            return value
    return value


def _latest_pointer_path(output_root: Path, revision: str) -> Path:
    return output_root / "reports" / "public_acquisition" / revision / "latest_run.json"


def _write_latest_pointer(paths: RunPaths) -> None:
    _atomic_write_json(
        _latest_pointer_path(paths.output_root, paths.revision),
        {"revision": paths.revision, "run_id": paths.run_id, "updated_at_utc": _utc_now()},
    )


def _discover_latest_run(output_root: Path, revision: str | None = None) -> RunPaths | None:
    base = output_root / "reports" / "public_acquisition"
    if not base.exists():
        return None
    revisions = [_validate_slug("revision", revision)] if revision else sorted(path.name for path in base.glob("*") if path.is_dir())
    for revision_name in reversed(revisions):
        pointer = _latest_pointer_path(output_root, revision_name)
        if pointer.exists():
            payload = _read_json(pointer)
            run_id = str(payload.get("run_id") or "").strip()
            if run_id:
                return _run_paths(output_root, revision_name, run_id)
        candidates = sorted(path.name for path in (base / revision_name).glob("*") if path.is_dir())
        if candidates:
            return _run_paths(output_root, revision_name, candidates[-1])
    return None


def _input_snapshot_path(paths: RunPaths, label: str, source: Path) -> Path:
    suffix = source.suffix or ".csv"
    return paths.report_dir / "inputs" / f"{label}{suffix}"


def _copy_snapshot(paths: RunPaths, label: str, source: Path) -> tuple[Path, str]:
    destination = _input_snapshot_path(paths, label, source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination, _sha256_file(destination)


def _initial_run_state(paths: RunPaths, *, input_sha256: str) -> dict[str, Any]:
    return {
        "run_id": paths.run_id,
        "revision": paths.revision,
        "created_at_utc": _utc_now(),
        "updated_at_utc": _utc_now(),
        "input_sha256": input_sha256,
        "scientific_ledger_path": _portable_run_path(paths, paths.raw_dir / "acquisition_events.jsonl"),
        "cells": {},
    }


def _load_run_state(paths: RunPaths, *, input_sha256: str) -> dict[str, Any]:
    state_path = paths.report_dir / "run_state.json"
    if state_path.exists():
        return _read_json(state_path)
    return _initial_run_state(paths, input_sha256=input_sha256)


def _update_run_state(paths: RunPaths, *, input_sha256: str, cell: str, status: str, details: dict[str, Any]) -> dict[str, Any]:
    state = _load_run_state(paths, input_sha256=input_sha256)
    state["updated_at_utc"] = _utc_now()
    state["cells"][cell] = {
        "status": status,
        "updated_at_utc": _utc_now(),
        "details": _portable_run_references(paths, details),
    }
    _atomic_write_json(paths.report_dir / "run_state.json", state)
    return state


def _deadline_at(seconds: int | None) -> float | None:
    if seconds is None:
        return None
    if seconds <= 0:
        return None
    return time.monotonic() + float(seconds)


def _deadline_expired(deadline_at: float | None) -> bool:
    return deadline_at is not None and time.monotonic() >= deadline_at


def _resolve_paths(
    args: argparse.Namespace,
    *,
    allow_create_new: bool = False,
    require_explicit_identity: bool = False,
    reuse_explicit_run: bool = False,
) -> RunPaths:
    output_root = Path(args.output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    revision = _validate_slug("revision", getattr(args, "revision", None) or DEFAULT_REVISION)
    run_id = getattr(args, "run_id", None)
    latest = bool(getattr(args, "latest", False))
    if run_id:
        paths = _run_paths(output_root, revision, run_id)
        exists = paths.report_dir.exists() or paths.processed_dir.exists() or paths.raw_dir.exists()
        if exists or reuse_explicit_run:
            return paths
        raise FileNotFoundError(f"run_id not found: {run_id}")
    if latest:
        discovered = _discover_latest_run(output_root, revision=revision)
        if discovered is None:
            raise FileNotFoundError(f"no public acquisition run found for revision {revision}")
        return discovered
    if require_explicit_identity:
        raise FileNotFoundError("explicit --run-id or --latest is required for this subcommand")
    if not allow_create_new:
        raise FileNotFoundError("no prior public acquisition run exists")
    _queue_frame, input_sha256 = _load_queue_source()
    return _run_paths(output_root, revision, _make_run_id(input_sha256))


def _ensure_plan_artifacts(paths: RunPaths) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any], str]:
    queue_path = paths.processed_dir / "case_queue.csv"
    pilot_path = paths.processed_dir / "pilot_case_queue.csv"
    manifest_path = paths.report_dir / "case_queue_manifest.json"
    if queue_path.exists() and pilot_path.exists() and manifest_path.exists():
        manifest = _read_json(manifest_path)
        return pd.read_csv(queue_path), pd.read_csv(pilot_path), manifest, str(manifest["input_sha256"])
    result = run_plan(paths.output_root, revision=paths.revision, run_id=paths.run_id)
    manifest = _read_json(paths.report_dir / "case_queue_manifest.json")
    return pd.read_csv(queue_path), pd.read_csv(pilot_path), manifest, result["input_sha256"]


def run_plan(
    output_root: Path,
    *,
    revision: str,
    run_id: str | None = None,
    queue_source_path: Path | None = None,
    positive_cases_path: Path | None = None,
) -> dict[str, Any]:
    output_root = Path(output_root).resolve()
    resolved_queue_source = Path(queue_source_path or CANONICAL_QUEUE_PATH).resolve()
    resolved_positive_cases = Path(positive_cases_path or POSITIVE_CASES_PATH).resolve()
    queue_source, input_sha256 = _load_queue_source(resolved_queue_source)
    policy = _load_policy()
    paths = _run_paths(output_root, revision, run_id or _make_run_id(input_sha256))
    if paths.report_dir.exists() or paths.processed_dir.exists() or paths.raw_dir.exists():
        if run_id:
            raise FileExistsError(f"run already exists: {paths.run_id}")
        raise FileExistsError(f"auto-generated run_id collision: {paths.run_id}")
    for directory in (paths.raw_dir, paths.processed_dir, paths.report_dir):
        directory.mkdir(parents=True, exist_ok=True)
    source_snapshot_path, source_snapshot_sha = _copy_snapshot(paths, "case_queue_source_snapshot", resolved_queue_source)
    positive_snapshot_path, positive_snapshot_sha = _copy_snapshot(paths, "positive_cases_snapshot", resolved_positive_cases)
    policy_snapshot = paths.report_dir / "inputs" / "public_acquisition_policy.yaml"
    shutil.copy2(POLICY_PATH, policy_snapshot)
    policy_snapshot_sha = _sha256_file(policy_snapshot)

    full_queue, pilot_queue = build_case_queue(queue_source, policy, input_sha256=input_sha256)
    queue_path = paths.processed_dir / "case_queue.csv"
    pilot_path = paths.processed_dir / "pilot_case_queue.csv"
    _write_csv(queue_path, full_queue)
    _write_csv(pilot_path, pilot_queue)

    queue_manifest = {
        "run_id": paths.run_id,
        "revision": paths.revision,
        "created_at_utc": _utc_now(),
        "input_sha256": input_sha256,
        "policy_sha256": _sha256_text(_canonical_json(policy)),
        "queue_sha256": full_queue["queue_sha256"].iat[0],
        "full_case_target": int(policy["full_case_target"]),
        "queue_rows": int(len(full_queue)),
        "pilot_rows": int(len(pilot_queue)),
        "expected_pilot_rows": int(sum(policy["pilot_allocation"].values())),
        "queue_csv_path": _portable_run_path(paths, queue_path),
        "queue_csv_sha256": _sha256_file(queue_path),
        "pilot_csv_path": _portable_run_path(paths, pilot_path),
        "pilot_csv_sha256": _sha256_file(pilot_path),
        "source_snapshot_path": _portable_run_path(paths, source_snapshot_path),
        "source_snapshot_sha256": source_snapshot_sha,
        "positive_snapshot_path": _portable_run_path(paths, positive_snapshot_path),
        "positive_snapshot_sha256": positive_snapshot_sha,
        "policy_snapshot_path": _portable_run_path(paths, policy_snapshot),
        "policy_snapshot_sha256": policy_snapshot_sha,
    }
    _atomic_write_json(paths.report_dir / "case_queue_manifest.json", queue_manifest)

    chain_audit: dict[str, Any] = {}
    for chain, expected in policy["pilot_allocation"].items():
        chain_rows = full_queue.loc[full_queue["chain"] == chain]
        selected = int(chain_rows["pilot_member"].sum())
        chain_audit[chain] = {
            "pilot_allocation_expected": int(expected),
            "pilot_allocation_selected": selected,
            "allocation_satisfied": bool(chain_rows["allocation_satisfied"].all()) if not chain_rows.empty else False,
            "queue_rows": int(len(chain_rows)),
        }
    shortfall = {
        "run_id": paths.run_id,
        "revision": paths.revision,
        "full_case_target": int(policy["full_case_target"]),
        "queue_rows": int(len(full_queue)),
        "pilot_expected": int(sum(policy["pilot_allocation"].values())),
        "pilot_selected": int(len(pilot_queue)),
        "pilot_shortfall": int(sum(policy["pilot_allocation"].values()) - len(pilot_queue)),
        "chains": chain_audit,
    }
    _atomic_write_json(paths.report_dir / "pilot_shortfall_audit.json", shortfall)
    _update_run_state(
        paths,
        input_sha256=input_sha256,
        cell="plan",
        status="complete",
        details={
            "offline": True,
            "queue_rows": int(len(full_queue)),
            "pilot_rows": int(len(pilot_queue)),
            "queue_manifest_path": str(paths.report_dir / "case_queue_manifest.json"),
            "pilot_shortfall_audit_path": str(paths.report_dir / "pilot_shortfall_audit.json"),
        },
    )
    _write_latest_pointer(paths)
    return {
        "command": "plan",
        "status": "complete",
        "offline": True,
        "run_id": paths.run_id,
        "revision": paths.revision,
        "input_sha256": input_sha256,
        "queue_rows": int(len(full_queue)),
        "pilot_rows": int(len(pilot_queue)),
        "queue_path": str(queue_path),
        "pilot_shortfall_audit_path": str(paths.report_dir / "pilot_shortfall_audit.json"),
    }


def _load_structured_rows(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".json":
        payload = _read_json(path)
        if isinstance(payload, dict):
            payload = payload.get("rows", [])
        return pd.DataFrame(payload)
    if path.suffix.lower() in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    return pd.read_csv(path)


def _safe_read_csv(path: Path) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def _copy_input_file(paths: RunPaths, path: Path, *, category: str, index: int) -> tuple[Path, str]:
    destination = paths.raw_dir / category / f"{index:03d}-{path.name}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, destination)
    return destination, _sha256_file(destination)


def _load_inventory_spec(path: Path) -> dict[str, Any]:
    spec = _read_json(path)
    if not isinstance(spec, dict):
        raise ValueError("inventory spec must be a JSON object")
    return spec


def _command_status(completed: bool, *, errors: list[str] | None = None) -> str:
    if completed and not errors:
        return "complete"
    return "partial"


def _command_plan_only(paths: RunPaths, *, input_sha256: str, cell: str, details: dict[str, Any]) -> dict[str, Any]:
    _update_run_state(paths, input_sha256=input_sha256, cell=cell, status="plan_only", details=details)
    return details


def _fixture_snapshot_provider_factory(case: dict[str, Any]) -> list[JsonRpcProvider]:
    chain = str(case["chain"])
    return [
        JsonRpcProvider(provider_id=f"fixture-a-{chain}", url="fixture://a", provider_family="fixture-a"),
        JsonRpcProvider(provider_id=f"fixture-b-{chain}", url="fixture://b", provider_family="fixture-b"),
    ]


def _write_receipt_artifact(paths: RunPaths, *, case_id: str, receipt_index: int, request: Any, response: Any) -> dict[str, Any]:
    request_bytes = _canonical_json(request).encode("utf-8")
    response_bytes = _canonical_json(response).encode("utf-8")
    request_sha256 = _sha256_bytes(request_bytes)
    response_sha256 = _sha256_bytes(response_bytes)
    raw_path = paths.raw_dir / "responses" / response_sha256[:2] / f"{response_sha256}.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    if not raw_path.exists():
        raw_path.write_bytes(response_bytes)
    request_path = paths.raw_dir / "requests" / request_sha256[:2] / f"{request_sha256}.json"
    request_path.parent.mkdir(parents=True, exist_ok=True)
    if not request_path.exists():
        request_path.write_bytes(request_bytes)
    return {
        "case_id": case_id,
        "receipt_index": receipt_index,
        "request_sha256": request_sha256,
        "request_path": _portable_run_path(paths, request_path),
        "response_sha256": response_sha256,
        "raw_response_path": _portable_run_path(paths, raw_path),
    }


def _safe_run_artifact_path(paths: RunPaths, candidate: str) -> Path:
    path = Path(candidate)
    resolved = (paths.output_root / path).resolve(strict=False) if not path.is_absolute() else path.resolve(strict=False)
    run_root = paths.output_root.resolve()
    try:
        resolved.relative_to(run_root)
    except ValueError as exc:
        raise ValueError(f"path escapes output root containment: {candidate}") from exc
    allowed_roots = (paths.raw_dir.resolve(), paths.processed_dir.resolve(), paths.report_dir.resolve())
    if not any(root == resolved or root in resolved.parents for root in allowed_roots):
        raise ValueError(f"path outside run root: {candidate}")
    if resolved.exists() and resolved.is_symlink():
        raise ValueError(f"symlinked artifact rejected: {candidate}")
    if not resolved.exists():
        raise FileNotFoundError(candidate)
    return resolved


def _iter_provider_observations(node: Any) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []

    def _walk(value: Any) -> None:
        if isinstance(value, dict):
            if {
                "provider_family",
                "provider_id",
                "method",
                "params",
                "request_sha256",
                "attempt",
            }.issubset(value.keys()):
                observations.append(value)
            for nested in value.values():
                _walk(nested)
        elif isinstance(value, list):
            for nested in value:
                _walk(nested)

    _walk(node)
    return observations


def _recover_receipts_from_rpc_results(paths: RunPaths, queue: pd.DataFrame) -> dict[str, Any] | None:
    rpc_results_path = paths.report_dir / "rpc_case_results.json"
    rpc_receipts_path = paths.report_dir / "rpc_receipts.json"
    if not rpc_results_path.exists():
        return None
    rpc_results = _read_json(rpc_results_path)
    existing_receipts = []
    if rpc_receipts_path.exists():
        existing_receipts = list(_read_json(rpc_receipts_path).get("receipts", []))
    if existing_receipts:
        return None

    results_rows = list(rpc_results.get("results", []))
    if not results_rows:
        return None

    queue_case_ids = {str(case_id) for case_id in queue.get("case_id", pd.Series(dtype=str)).astype(str).tolist()}
    recovered_receipts: list[dict[str, Any]] = []
    nested_observation_count = 0
    bindable_response_receipt_count = 0
    request_only_error_receipt_count = 0
    staging_parent = paths.raw_dir / ".rpc_receipt_recovery_staging"
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix="rpc-recovery-", dir=staging_parent))
    try:
        staged_request_targets: list[tuple[Path, Path]] = []
        for row in results_rows:
            case_id = str(row.get("case_id", ""))
            if queue_case_ids and case_id not in queue_case_ids:
                raise ValueError(f"rpc recovery encountered unknown case_id: {case_id}")
            row_receipts: list[dict[str, Any]] = []
            seen: set[tuple[str, str, str, str, str, str, int]] = set()
            observations = _iter_provider_observations(
                {
                    "capability_snapshot": row.get("capability_snapshot"),
                    "prediction_snapshot": row.get("prediction_snapshot"),
                }
            )
            nested_observation_count += len(observations)
            for observation in observations:
                provider_family = str(observation.get("provider_family", ""))
                provider_id = str(observation.get("provider_id", ""))
                method = str(observation.get("method", ""))
                params = list(observation.get("params", []))
                request_sha256 = str(observation.get("request_sha256", ""))
                response_sha256_value = observation.get("response_sha256")
                response_sha256 = None if response_sha256_value in (None, "") else str(response_sha256_value)
                raw_response_path_value = observation.get("raw_response_path")
                raw_response_path_text = None if raw_response_path_value in (None, "") else str(raw_response_path_value)
                http_status_value = observation.get("http_status")
                http_status = None if http_status_value in (None, "") else int(http_status_value)
                error_value = observation.get("error")
                error_text = "" if error_value in (None, "") else str(error_value).strip()
                attempt = int(observation.get("attempt", 0) or 0)
                identity = (
                    case_id,
                    provider_family,
                    provider_id,
                    method,
                    _canonical_json(params),
                    request_sha256,
                    response_sha256 or "",
                    attempt,
                )
                if identity in seen:
                    continue
                seen.add(identity)
                raw_response_path: Path | None = None
                if raw_response_path_text is None and response_sha256 is None:
                    if not error_text and (http_status is None or 200 <= http_status <= 299):
                        raise ValueError(f"successful request-only observation lacks response evidence for {case_id}:{provider_id}:{method}")
                    request_only_error_receipt_count += 1
                elif raw_response_path_text is None or response_sha256 is None:
                    raise ValueError(f"response evidence pair mismatch for {case_id}:{provider_id}:{method}")
                else:
                    raw_response_path = _safe_run_artifact_path(paths, raw_response_path_text)
                    if _sha256_file(raw_response_path) != response_sha256:
                        raise ValueError(f"response artifact hash mismatch for {raw_response_path.name}")
                    bindable_response_receipt_count += 1

                request_bytes = _canonical_request_bytes(method, params)
                if _sha256_bytes(request_bytes) != request_sha256:
                    raise ValueError(f"request reconstruction hash mismatch for {case_id}:{provider_id}:{method}")
                request_path = paths.raw_dir / "requests" / request_sha256[:2] / f"{request_sha256}.json"
                if request_path.exists():
                    if _sha256_file(request_path) != request_sha256:
                        raise ValueError(f"request artifact hash mismatch for {request_path.name}")
                else:
                    staged_request_path = staging_root / "requests" / request_sha256[:2] / f"{request_sha256}.json"
                    staged_request_path.parent.mkdir(parents=True, exist_ok=True)
                    if staged_request_path.exists():
                        if _sha256_file(staged_request_path) != request_sha256:
                            raise ValueError(f"staged request artifact hash mismatch for {staged_request_path.name}")
                    else:
                        staged_request_path.write_bytes(request_bytes)
                    staged_request_targets.append((staged_request_path, request_path))

                receipt = {
                    "case_id": case_id,
                    "receipt_index": len(row_receipts) + 1,
                    "provider_family": provider_family,
                    "provider_id": provider_id,
                    "method": method,
                    "params": params,
                    "request_sha256": request_sha256,
                    "request_path": _portable_run_path(paths, request_path),
                    "response_sha256": response_sha256,
                    "raw_response_path": _portable_run_path(paths, raw_response_path) if raw_response_path is not None else None,
                    "http_status": http_status,
                    "attempt": attempt,
                    "observed_at_utc": observation.get("observed_at_utc"),
                    "observed_at_unix": observation.get("observed_at_unix"),
                    "error": error_value,
                }
                row_receipts.append(receipt)
                recovered_receipts.append(receipt)
            row["receipts"] = [
                {
                    "case_id": receipt["case_id"],
                    "receipt_index": receipt["receipt_index"],
                    "request_sha256": receipt["request_sha256"],
                    "response_sha256": receipt["response_sha256"],
                }
                for receipt in row_receipts
            ]

        if nested_observation_count == 0:
            return None

        pre_recovery_rpc_case_results_sha256 = _sha256_file(rpc_results_path)
        summary = dict(rpc_results.get("summary", {}))
        summary.update(
            {
                "command": "rpc",
                "status": "partial",
                "execute": True,
                "run_id": paths.run_id,
                "revision": paths.revision,
                "cases_processed": int(summary.get("cases_processed") or len(results_rows)),
                "cases_planned": int(summary.get("cases_planned") or len(results_rows)),
                "receipt_count": int(len(recovered_receipts)),
                "receipt_recovery": {
                    "performed": True,
                    "recovered_at_utc": _utc_now(),
                    "pre_recovery_rpc_case_results_sha256": pre_recovery_rpc_case_results_sha256,
                    "nested_observation_count": int(nested_observation_count),
                    "bindable_response_receipt_count": int(bindable_response_receipt_count),
                    "request_only_error_receipt_count": int(request_only_error_receipt_count),
                    "recovered_receipt_count": int(len(recovered_receipts)),
                },
            }
        )
        rpc_results["summary"] = summary
        receipts_payload = {"summary": summary, "receipts": recovered_receipts}
        post_recovery_rpc_case_results_sha256 = _sha256_text(_json_dumps(rpc_results))
        post_recovery_rpc_receipts_sha256 = _sha256_text(_json_dumps(receipts_payload))
        audit = {
            "command": "rpc_receipt_recovery",
            "status": "complete",
            "run_id": paths.run_id,
            "revision": paths.revision,
            "recovered_at_utc": summary["receipt_recovery"]["recovered_at_utc"],
            "pre_recovery_rpc_case_results_sha256": pre_recovery_rpc_case_results_sha256,
            "post_recovery_rpc_case_results_sha256": post_recovery_rpc_case_results_sha256,
            "post_recovery_rpc_receipts_sha256": post_recovery_rpc_receipts_sha256,
            "nested_observation_count": int(nested_observation_count),
            "bindable_response_receipt_count": int(bindable_response_receipt_count),
            "request_only_error_receipt_count": int(request_only_error_receipt_count),
            "recovered_receipt_count": int(len(recovered_receipts)),
        }

        for staged_request_path, request_path in staged_request_targets:
            request_path.parent.mkdir(parents=True, exist_ok=True)
            if request_path.exists():
                if _sha256_file(request_path) != _sha256_file(staged_request_path):
                    raise ValueError(f"request artifact changed during staged publish for {request_path.name}")
                continue
            os.replace(staged_request_path, request_path)
        _atomic_write_json(rpc_results_path, rpc_results)
        _atomic_write_json(rpc_receipts_path, receipts_payload)
        _atomic_write_json(paths.report_dir / "rpc_receipt_recovery_audit.json", audit)
        return summary
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
        if staging_parent.exists() and not any(staging_parent.iterdir()):
            staging_parent.rmdir()


def _not_attempted_rpc_result(case: dict[str, Any], *, reason: str) -> dict[str, Any]:
    incident_block = int(case["incident_block"])
    return {
        "case_id": case["case_id"],
        "case_name": case["case_name"],
        "chain": case["chain"],
        "address": case["address"],
        "incident_block": incident_block,
        "status": "NOT_ATTEMPTED",
        "blocked_reason": reason,
        "prediction_snapshot": None,
        "provider_families": [],
        "cell_results": {
            cell_name: {
                "status": "NOT_ATTEMPTED",
                "block_selector": f"incident:{incident_block}" if cell_name == "block_capability" else "not_attempted",
                "error_detail": reason,
            }
            for cell_name in RPC_REQUIRED_CELLS
        },
        "receipts": [],
    }
def _derive_run_public_status(
    *,
    execute: bool,
    stage_payloads: dict[str, dict[str, Any]],
    verification: dict[str, Any],
) -> str:
    if execute and verification["structure_valid"] and verification["scientifically_complete"] and verification["release_ready"]:
        if all(str(payload.get("status")) in {"complete", "resume"} for payload in stage_payloads.values()):
            return "complete"
    if not execute:
        return "incomplete"

    prereq_statuses = {
        stage: str(stage_payloads.get(stage, {}).get("status", ""))
        for stage in ("inventory", "rpc", "denominator")
    }
    if any(status == "waiting_external" for status in prereq_statuses.values()):
        if not any(status in {"complete", "partial"} for status in prereq_statuses.values()):
            return "waiting_external"

    attempted_statuses = {"complete", "partial", "scientifically_incomplete", "skipped_deadline", "resume"}
    if any(str(payload.get("status")) in attempted_statuses for payload in stage_payloads.values()):
        return "partial"
    return "incomplete"


def _load_rpc_fixture(path: Path) -> dict[str, Any]:
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ValueError("rpc fixture must be a JSON object")
    return payload


def _fixture_snapshot_acquirer(fixture: dict[str, Any], paths: RunPaths, max_bytes: int | None, deadline_at: float | None) -> Callable[..., dict[str, Any]]:
    def _snapshot(case: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        if _deadline_expired(deadline_at):
            return {
                "case_id": case["case_id"],
                "case_name": case["case_name"],
                "chain": case["chain"],
                "address": case["address"],
                "incident_block": int(case["incident_block"]),
                "status": "PARTIAL",
                "blocked_reason": "deadline_exceeded",
                "prediction_snapshot": None,
                "provider_families": ["fixture-a", "fixture-b"],
                "cell_results": {
                    "block_capability": {"status": "PARTIAL", "block_selector": f"incident:{int(case['incident_block'])}", "error_detail": "deadline_exceeded"}
                },
                "receipts": [],
            }
        fixture_case = fixture.get(str(case["case_id"])) or fixture.get(str(case["case_name"])) or fixture.get("default") or {}
        result = dict(fixture_case)
        result.setdefault("case_id", case["case_id"])
        result.setdefault("case_name", case["case_name"])
        result.setdefault("chain", case["chain"])
        result.setdefault("address", case["address"])
        result.setdefault("incident_block", int(case["incident_block"]))
        result.setdefault("status", "PARTIAL")
        result.setdefault("provider_families", ["fixture-a", "fixture-b"])
        default_cell_results = {
            cell_name: {
                "status": "WAITING_EXTERNAL",
                "block_selector": f"incident:{int(case['incident_block'])}" if cell_name == "block_capability" else "prediction:unresolved",
                "error_detail": result.get("blocked_reason", "fixture_missing"),
            }
            for cell_name in RPC_REQUIRED_CELLS
        }
        default_cell_results["block_capability"] = {
            "status": "PARTIAL",
            "block_selector": f"incident:{int(case['incident_block'])}",
            "error_detail": result.get("blocked_reason", "fixture_missing"),
        }
        merged_cell_results = dict(default_cell_results)
        merged_cell_results.update(dict(result.get("cell_results", {})))
        result.setdefault(
            "cell_results",
            merged_cell_results,
        )
        if "cell_results" in fixture_case:
            result["cell_results"] = merged_cell_results
        normalized_receipts: list[dict[str, Any]] = []
        for index, receipt in enumerate(result.get("receipts", []), start=1):
            artifact = _write_receipt_artifact(
                paths,
                case_id=str(case["case_id"]),
                receipt_index=index,
                request=receipt.get("request", {}),
                response=receipt.get("response", {}),
            )
            response_bytes = _canonical_json(receipt.get("response", {})).encode("utf-8")
            if max_bytes is not None and len(response_bytes) > max_bytes:
                result["status"] = "PARTIAL"
                result["blocked_reason"] = "max_bytes_exceeded"
            normalized_receipts.append(
                {
                    "method": receipt.get("method", ""),
                    "block_selector": receipt.get("block_selector", ""),
                    **artifact,
                }
            )
        result["receipts"] = normalized_receipts
        return result

    return _snapshot


def _normalize_deployment_export_frame(frame: pd.DataFrame, *, source_provider: str, source_object_key: str) -> pd.DataFrame:
    required = {
        "deployment_id",
        "chain",
        "chain_id",
        "contract_address",
        "creation_tx_hash",
        "creation_type",
        "deployment_block",
        "deployment_block_hash",
        "deployment_time",
        "creator_address",
        "runtime_code_sha256",
        "source_provider",
        "source_object_key",
        "source_object_etag",
        "source_record_sha256",
        "duplicate_group_id",
        "admissibility_status",
        "exclusion_reason",
        "selection_rank_sha256",
    }
    if required.issubset(frame.columns):
        normalized_input = frame.loc[:, list(required)].copy()
        if "creation_proof_type" in frame.columns:
            normalized_input["creation_proof_type"] = frame["creation_proof_type"]
        else:
            normalized_input["creation_proof_type"] = normalized_input.apply(
                lambda row: (
                    None
                    if pd.isna(row["creation_tx_hash"]) or not str(row["creation_tx_hash"]).strip()
                    else ("trace" if str(row["creation_type"]).strip().lower().startswith("internal") else "transaction")
                ),
                axis=1,
            )
        if "trace_proof" in frame.columns:
            normalized_input["trace_proof"] = frame["trace_proof"]
        return normalize_deployment_batch(normalized_input)

    normalized_rows = []
    for row in ingest_sourcify_deployments_export(source_object_key):
        normalized_rows.append(
            {
                "chain": row["chain"],
                "chain_id": SUPPORTED_CHAINS[row["chain"]],
                "contract_address": row["address"],
                "creation_tx_hash": row["deployment_tx_hash"],
                "creation_type": row["creation_type"] or ("transaction_and_trace" if row.get("trace_proof") else "transaction"),
                "creation_proof_type": "transaction" if row["deployment_tx_hash"] else None,
                "deployment_block": row["deployment_block"],
                "deployment_block_hash": None,
                "deployment_time": row["deployment_time"],
                "creator_address": None,
                "runtime_code_sha256": None,
                "source_provider": str(row.get("provider") or source_provider),
                "source_object_key": Path(source_object_key).name,
                "source_object_etag": "",
                "source_record_sha256": row["record_sha256"],
            }
        )
    return normalize_deployment_batch(normalized_rows)


def _projectable_positive_cases(frame: pd.DataFrame) -> pd.DataFrame:
    prepared = frame.copy()
    default_columns: dict[str, Any] = {
        "historical_snapshot_status": "",
        "historical_snapshot_source_receipt_sha256": "",
        "historical_snapshot_identity_receipt_sha256": "",
        "historical_snapshot_source_provider_family": "",
        "historical_snapshot_identity_provider_family": "",
        "historical_snapshot_schema_valid": False,
        "historical_snapshot_hash_bound": False,
        "review_decision_status": "",
        "decision_schema_valid": False,
        "decision_hash_bound": False,
        "reviewer_a_identity": "",
        "reviewer_a_owner": "",
        "reviewer_a_conflict_clear": False,
        "reviewer_a_confidence": "",
        "reviewer_a_started_at_utc": "",
        "reviewer_a_completed_at_utc": "",
        "reviewer_a_packet_sha256": "",
        "reviewer_a_decision_sha256": "",
        "reviewer_b_identity": "",
        "reviewer_b_owner": "",
        "reviewer_b_conflict_clear": False,
        "reviewer_b_confidence": "",
        "reviewer_b_started_at_utc": "",
        "reviewer_b_completed_at_utc": "",
        "reviewer_b_packet_sha256": "",
        "reviewer_b_decision_sha256": "",
        "review_agreement_status": "",
        "final_decision_sha256": "",
        "final_decision_completed_at_utc": "",
        "final_decision_input_binding_sha256": "",
        "decision_case_schema_valid": False,
        "decision_case_hash_bound": False,
        "decision_case_stale": True,
        "third_adjudicator_identity": "",
        "third_adjudicator_owner": "",
        "third_adjudicator_conflict_clear": False,
        "third_adjudicator_confidence": "",
        "third_adjudicator_started_at_utc": "",
        "third_adjudicator_completed_at_utc": "",
        "third_adjudicator_packet_sha256": "",
        "third_adjudicator_decision_sha256": "",
        "mechanism_component_status": "",
        "lineage_component_status": "",
        "clone_leakage_free": False,
        "proxy_leakage_free": False,
        "protocol_leakage_free": False,
        "mechanism_leakage_free": False,
        "r5_component_hash_bound": False,
        "r5_component_schema_valid": False,
    }
    for column, default in default_columns.items():
        if column not in prepared.columns:
            prepared[column] = default
    return prepared


def command_plan(args: argparse.Namespace) -> dict[str, Any]:
    return run_plan(
        Path(args.output_root),
        revision=args.revision,
        run_id=args.run_id,
        queue_source_path=getattr(args, "queue_source_path", None),
        positive_cases_path=getattr(args, "positive_cases_path", None),
    )


def command_inventory(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    _queue, _pilot, _manifest, input_sha256 = _ensure_plan_artifacts(paths)
    if not args.execute:
        return _command_plan_only(
            paths,
            input_sha256=input_sha256,
            cell="inventory",
            details={"command": "inventory", "status": "plan_only", "execute": False, "run_id": paths.run_id, "revision": paths.revision},
        )
    if not args.inventory_spec_file:
        summary = {
            "command": "inventory",
            "status": "waiting_external",
            "execute": True,
            "run_id": paths.run_id,
            "revision": paths.revision,
            "reason": "inventory_spec_file_required_for_bounded_public_capture",
        }
        _atomic_write_json(paths.report_dir / "inventory_manifest.json", summary)
        _update_run_state(paths, input_sha256=input_sha256, cell="inventory", status="waiting_external", details=summary)
        return summary

    deadline_at = _deadline_at(args.deadline_seconds)
    inventory_spec_path = Path(args.inventory_spec_file).resolve()
    spec = _load_inventory_spec(inventory_spec_path)
    copied_spec, copied_spec_sha = _copy_input_file(paths, inventory_spec_path, category="inventory_specs", index=1)
    inventory_root = paths.raw_dir / "inventory"
    inventory_root.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {"sections": {}, "deployment_exports": []}
    all_errors: list[str] = []

    chainlist_spec = spec.get("chainlist")
    if chainlist_spec is not None and not _deadline_expired(deadline_at):
        source_path = Path(chainlist_spec["source_file"]).resolve()
        payload = _read_json(source_path)
        results["sections"]["chainlist"] = capture_chainlist_inventory(
            payload,
            inventory_root / "chainlist",
            max_pages=args.max_pages,
            max_response_bytes=args.max_bytes,
            max_elapsed_seconds=max(0.0, deadline_at - time.monotonic()) if deadline_at is not None else None,
        )
        all_errors.extend(results["sections"]["chainlist"]["errors"])
    elif chainlist_spec is not None:
        all_errors.append("deadline_exceeded")

    s3_results = []
    for item in spec.get("s3", []) or []:
        if _deadline_expired(deadline_at):
            all_errors.append("deadline_exceeded")
            break
        pages = [Path(page_file).read_text(encoding="utf-8") for page_file in item.get("page_files", [])]
        result = capture_s3_inventory(
            pages,
            inventory_root / "s3" / str(item["provider"]) / str(item["chain"]),
            provider=str(item["provider"]),
            chain=str(item["chain"]),
            prefix=str(item["prefix"]),
            max_pages=args.max_pages,
            max_response_bytes=args.max_bytes,
            max_elapsed_seconds=max(0.0, deadline_at - time.monotonic()) if deadline_at is not None else None,
        )
        s3_results.append(result)
        all_errors.extend(result["errors"])
    if s3_results:
        results["sections"]["s3"] = s3_results

    sourcify_results = []
    for item in spec.get("sourcify", []) or []:
        if _deadline_expired(deadline_at):
            all_errors.append("deadline_exceeded")
            break
        dataset_pages = {
            str(dataset): [Path(page_file).read_text(encoding="utf-8") for page_file in page_files]
            for dataset, page_files in dict(item.get("datasets", {})).items()
        }
        result = capture_sourcify_inventory(
            dataset_pages,
            inventory_root / "sourcify" / str(item["chain"]),
            chain=str(item["chain"]),
            max_pages=args.max_pages,
            max_response_bytes=args.max_bytes,
            max_elapsed_seconds=max(0.0, deadline_at - time.monotonic()) if deadline_at is not None else None,
        )
        sourcify_results.append(result)
        all_errors.extend(result["errors"])
    if sourcify_results:
        results["sections"]["sourcify"] = sourcify_results

    for index, export_spec in enumerate(spec.get("deployment_exports", []) or [], start=1):
        export_path = Path(export_spec["path"]).resolve()
        copied_path, copied_sha = _copy_input_file(paths, export_path, category="deployment_exports", index=index)
        results["deployment_exports"].append(
            {
                "chain": export_spec.get("chain", "all"),
                "path": _portable_run_path(paths, copied_path),
                "sha256": copied_sha,
                "format": export_spec.get("format", copied_path.suffix.lstrip(".") or "csv"),
            }
        )

    status = _command_status("deadline_exceeded" not in all_errors and not any(error.endswith("_exceeded") for error in all_errors), errors=all_errors)
    manifest = {
        "command": "inventory",
        "status": status,
        "execute": True,
        "run_id": paths.run_id,
        "revision": paths.revision,
        "inventory_spec_path": _portable_run_path(paths, copied_spec),
        "inventory_spec_sha256": copied_spec_sha,
        "max_pages": args.max_pages,
        "max_bytes": args.max_bytes,
        "deadline_seconds": args.deadline_seconds,
        "completed": status == "complete",
        "errors": all_errors,
        **_portable_run_references(paths, results),
    }
    _atomic_write_json(paths.report_dir / "inventory_manifest.json", manifest)
    _update_run_state(paths, input_sha256=input_sha256, cell="inventory", status=status, details=manifest)
    return manifest


def command_rpc(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    queue, _pilot, _manifest, input_sha256 = _ensure_plan_artifacts(paths)
    if args.max_cases and args.max_cases > 0:
        queue = queue.head(args.max_cases).reset_index(drop=True)
    if not args.execute:
        return _command_plan_only(
            paths,
            input_sha256=input_sha256,
            cell="rpc",
            details={"command": "rpc", "status": "plan_only", "execute": False, "run_id": paths.run_id, "revision": paths.revision, "planned_cases": int(len(queue))},
        )

    if args.deadline_seconds is not None and int(args.deadline_seconds) < 0:
        planned_rows = [_not_attempted_rpc_result(case, reason="deadline_exceeded_before_attempt") for case in queue.to_dict("records")]
        summary = {
            "command": "rpc",
            "status": "skipped_deadline",
            "execute": True,
            "run_id": paths.run_id,
            "revision": paths.revision,
            "cases_planned": int(len(queue)),
        }
        _atomic_write_json(paths.report_dir / "rpc_case_results.json", {"results": planned_rows, "summary": summary})
        _atomic_write_json(paths.report_dir / "rpc_receipts.json", {"receipts": [], "summary": summary})
        _update_run_state(paths, input_sha256=input_sha256, cell="rpc", status="skipped_deadline", details=summary)
        return summary

    deadline_at = _deadline_at(args.deadline_seconds)
    if _deadline_expired(deadline_at):
        planned_rows = [_not_attempted_rpc_result(case, reason="deadline_exceeded_before_attempt") for case in queue.to_dict("records")]
        summary = {
            "command": "rpc",
            "status": "skipped_deadline",
            "execute": True,
            "run_id": paths.run_id,
            "revision": paths.revision,
            "cases_planned": int(len(queue)),
        }
        _atomic_write_json(paths.report_dir / "rpc_case_results.json", {"results": planned_rows, "summary": summary})
        _atomic_write_json(paths.report_dir / "rpc_receipts.json", {"receipts": [], "summary": summary})
        _update_run_state(paths, input_sha256=input_sha256, cell="rpc", status="skipped_deadline", details=summary)
        return summary

    recovered_summary = _recover_receipts_from_rpc_results(paths, queue)
    if recovered_summary is not None:
        _update_run_state(paths, input_sha256=input_sha256, cell="rpc", status="partial", details=recovered_summary)
        return recovered_summary

    registry = ProviderRegistry.from_path(PROVIDER_REGISTRY_PATH)
    ledger = AppendOnlyLedger(paths.raw_dir / "acquisition_events.jsonl")
    policy = {**_load_policy(), "global_concurrency": 1}
    provider_factory: Callable[[dict[str, Any]], list[JsonRpcProvider]] | None = None
    snapshot_acquirer: Callable[..., dict[str, Any]] | None = None
    if args.rpc_fixture_file:
        fixture = _load_rpc_fixture(Path(args.rpc_fixture_file).resolve())
        provider_factory = _fixture_snapshot_provider_factory
        snapshot_acquirer = _fixture_snapshot_acquirer(fixture, paths, args.max_bytes, deadline_at)

    result = acquire_queue(
        queue,
        policy,
        registry=registry,
        ledger=ledger,
        execute=True,
        artifact_root=paths.raw_dir / "responses",
        provider_factory=provider_factory,
        snapshot_acquirer=snapshot_acquirer or acquire_case_snapshot,
    )
    case_results = _portable_run_references(paths, result["results"])
    receipts = [receipt for case_result in case_results for receipt in case_result.get("receipts", [])]
    status = "complete" if all(str(case_result.get("status")) == "VERIFIED" for case_result in case_results) else "partial"
    summary = {
        "command": "rpc",
        "status": status,
        "execute": True,
        "run_id": paths.run_id,
        "revision": paths.revision,
        "cases_processed": int(len(queue)),
        "cases_planned": int(len(queue)),
        "receipt_count": int(len(receipts)),
        "deadline_seconds": args.deadline_seconds,
        "ledger_path": _portable_run_path(paths, paths.raw_dir / "acquisition_events.jsonl"),
    }
    _atomic_write_json(paths.report_dir / "rpc_case_results.json", {"summary": summary, "results": case_results})
    _atomic_write_json(paths.report_dir / "rpc_receipts.json", {"summary": summary, "receipts": receipts})
    _update_run_state(paths, input_sha256=input_sha256, cell="rpc", status=status, details=summary)
    return summary


def command_denominator(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    _queue, _pilot, _manifest, input_sha256 = _ensure_plan_artifacts(paths)
    if not args.execute:
        return _command_plan_only(
            paths,
            input_sha256=input_sha256,
            cell="denominator",
            details={"command": "denominator", "status": "plan_only", "execute": False, "run_id": paths.run_id, "revision": paths.revision},
        )

    deadline_at = _deadline_at(args.deadline_seconds)
    source_specs: list[dict[str, Any]] = []
    if args.source_file:
        source_path = Path(args.source_file).resolve()
        copied_path, copied_sha = _copy_input_file(paths, source_path, category="denominator_sources", index=1)
        source_specs.append(
            {
                "chain": "all",
                "path": _portable_run_path(paths, copied_path),
                "sha256": copied_sha,
                "format": copied_path.suffix.lstrip(".") or "csv",
            }
        )
    else:
        inventory_manifest_path = paths.report_dir / "inventory_manifest.json"
        if inventory_manifest_path.exists():
            inventory_manifest = _read_json(inventory_manifest_path)
            source_specs.extend(list(inventory_manifest.get("deployment_exports", [])))
    if not source_specs:
        denominator_path = paths.processed_dir / "deployment_denominator.csv"
        audit_path = paths.report_dir / "denominator_audit.csv"
        _write_csv(denominator_path, pd.DataFrame())
        _write_csv(audit_path, pd.DataFrame())
        manifest = {
            "command": "denominator",
            "status": "waiting_external",
            "execute": True,
            "run_id": paths.run_id,
            "revision": paths.revision,
            "sources": [],
            "source_errors": [],
            "reason": "denominator_source_required",
            "denominator_rows": 0,
            "denominator_csv_path": _portable_run_path(paths, denominator_path),
            "denominator_csv_sha256": _sha256_file(denominator_path),
            "audit_csv_path": _portable_run_path(paths, audit_path),
            "audit_csv_sha256": _sha256_file(audit_path),
        }
        _atomic_write_json(paths.report_dir / "denominator_manifest.json", manifest)
        _update_run_state(paths, input_sha256=input_sha256, cell="denominator", status="waiting_external", details=manifest)
        return manifest

    normalized_frames: list[pd.DataFrame] = []
    source_errors: list[dict[str, Any]] = []
    for spec in source_specs:
        if _deadline_expired(deadline_at):
            source_errors.append({"path": spec.get("path", ""), "error": "deadline_exceeded"})
            break
        source_path = _safe_run_artifact_path(paths, str(spec["path"]))
        try:
            if args.max_bytes and args.max_bytes > 0 and source_path.stat().st_size > args.max_bytes:
                raise ValueError("max_bytes_exceeded")
            frame = _load_structured_rows(source_path)
            normalized = _normalize_deployment_export_frame(
                frame,
                source_provider=str(frame["source_provider"].iloc[0]) if "source_provider" in frame.columns and not frame.empty else "fixture",
                source_object_key=str(source_path),
            )
            normalized_frames.append(normalized)
        except Exception as exc:  # noqa: BLE001
            source_errors.append({"path": str(source_path), "error": str(exc)})

    combined = pd.concat(normalized_frames, ignore_index=True) if normalized_frames else pd.DataFrame()
    policy = _load_policy()
    if not combined.empty:
        denominator, audit = select_denominator(
            combined,
            per_chain=int(policy["denominator_per_chain"]),
            seed=str(policy["seed"]),
        )
    else:
        denominator = pd.DataFrame()
        audit = pd.DataFrame(
            [
                {
                    "chain": chain,
                    "inventory_rows": 0,
                    "parsed_rows": 0,
                    "verified_rows": 0,
                    "duplicates": 0,
                    "exclusions": 0,
                    "available": 0,
                    "selected": 0,
                    "shortfall": int(policy["denominator_per_chain"]),
                }
                for chain in SUPPORTED_CHAINS
            ]
        )
    denominator_path = paths.processed_dir / "deployment_denominator.csv"
    audit_path = paths.report_dir / "denominator_audit.csv"
    _write_csv(denominator_path, denominator)
    _write_csv(audit_path, audit)
    has_shortfall = bool(not audit.empty and audit["shortfall"].fillna(0).astype(int).gt(0).any())
    status = "complete" if not source_errors and not has_shortfall and not denominator.empty else "partial"
    manifest = {
        "command": "denominator",
        "status": status,
        "execute": True,
        "run_id": paths.run_id,
        "revision": paths.revision,
        "sources": source_specs,
        "source_errors": source_errors,
        "denominator_rows": int(len(denominator)),
        "denominator_csv_path": _portable_run_path(paths, denominator_path),
        "denominator_csv_sha256": _sha256_file(denominator_path),
        "audit_csv_path": _portable_run_path(paths, audit_path),
        "audit_csv_sha256": _sha256_file(audit_path),
    }
    _atomic_write_json(paths.report_dir / "denominator_manifest.json", manifest)
    _update_run_state(paths, input_sha256=input_sha256, cell="denominator", status=status, details=manifest)
    return manifest


def command_controls(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    _queue, _pilot, manifest, input_sha256 = _ensure_plan_artifacts(paths)
    positive_snapshot = _safe_run_artifact_path(paths, str(manifest["positive_snapshot_path"]))
    positives = pd.read_csv(positive_snapshot)
    denominator_path = paths.processed_dir / "deployment_denominator.csv"
    candidates_path = paths.processed_dir / "control_candidates.csv"
    audit_path = paths.report_dir / "control_candidate_audit.csv"
    manifest_path = paths.report_dir / "controls_manifest.json"
    if not denominator_path.exists():
        summary = {"command": "controls", "status": "waiting_external", "run_id": paths.run_id, "revision": paths.revision, "reason": "deployment_denominator_missing"}
        _atomic_write_json(manifest_path, summary)
        _write_csv(candidates_path, pd.DataFrame())
        _write_csv(audit_path, pd.DataFrame())
        _update_run_state(paths, input_sha256=input_sha256, cell="controls", status="waiting_external", details=summary)
        return summary

    try:
        denominator = pd.read_csv(denominator_path)
        preflight = preflight_control_inputs(positives, denominator)
        if preflight["decision"] != "READY_FOR_CANDIDATE_SELECTION":
            raise ValueError(json.dumps(preflight, sort_keys=True, separators=(",", ":")))
        candidates, audit = build_control_candidates(positives, denominator)
        revalidated = qualify_control_rows(candidates) if not candidates.empty else candidates
        _write_csv(candidates_path, revalidated if isinstance(revalidated, pd.DataFrame) else pd.DataFrame())
        _write_csv(audit_path, audit)
        summary = {
            "command": "controls",
            "status": "complete",
            "run_id": paths.run_id,
            "revision": paths.revision,
            "candidate_rows": int(len(revalidated)),
            "audit_rows": int(len(audit)),
        }
    except ValueError as exc:
        _write_csv(candidates_path, pd.DataFrame())
        _write_csv(audit_path, pd.DataFrame())
        summary = {
            "command": "controls",
            "status": "scientifically_incomplete",
            "run_id": paths.run_id,
            "revision": paths.revision,
            "reason": str(exc),
        }
    _atomic_write_json(manifest_path, summary)
    _update_run_state(paths, input_sha256=input_sha256, cell="controls", status=summary["status"], details=summary)
    return summary


def command_review_packets(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    _queue, _pilot, manifest, input_sha256 = _ensure_plan_artifacts(paths)
    positives = pd.read_csv(_safe_run_artifact_path(paths, str(manifest["positive_snapshot_path"])))
    controls_path = paths.processed_dir / "control_candidates.csv"
    control_rows = _safe_read_csv(controls_path)
    positive_packets = build_review_bundle(
        positives,
        packet_type="positive_case_review_packets",
        blinding_seed=args.blinding_seed or paths.run_id,
    )
    control_packets = (
        build_review_bundle(control_rows, packet_type="control_review_packets", blinding_seed=args.blinding_seed or paths.run_id)
        if not control_rows.empty and "case_name" in control_rows.columns
        else []
    )
    positive_path = paths.report_dir / "positive_case_review_packets.json"
    control_path = paths.report_dir / "control_review_packets.json"
    reviewer_a_template_path = paths.report_dir / "reviewer_a_response_template.json"
    reviewer_b_template_path = paths.report_dir / "reviewer_b_response_template.json"
    adjudication_protocol_path = paths.report_dir / "human_adjudication_protocol.json"
    handoff_manifest_path = paths.report_dir / "human_adjudication_handoff_manifest.json"
    reviewer_path = paths.report_dir / "reviewer_independence.json"
    finalized_path = paths.report_dir / "finalized_positive_adjudications.json"
    _atomic_write_json(positive_path, positive_packets)
    _atomic_write_json(control_path, control_packets)

    def reviewer_template(role: str) -> list[dict[str, Any]]:
        return [
            {
                "case_name": packet["visible_payload"]["case_name"],
                "packet_id": packet["packet_id"],
                "packet_sha256": packet["packet_sha256"],
                "reviewer_role": role,
                "reviewer_identity": "",
                "reviewer_accountable_owner": "",
                "conflict_statement": "",
                "conflict_clear": None,
                "review_started_at_utc": "",
                "review_completed_at_utc": "",
                "protocol_family": "",
                "primary_root_cause": "",
                "decision_rationale": "",
                "evidence_references": [],
                "confidence": "",
                "decision_sha256": "",
            }
            for packet in positive_packets
        ]

    _atomic_write_json(reviewer_a_template_path, reviewer_template("reviewer_a"))
    _atomic_write_json(reviewer_b_template_path, reviewer_template("reviewer_b"))
    _atomic_write_json(
        adjudication_protocol_path,
        {
            "artifact_schema_version": "2026-08-17.human-adjudication-handoff.v1",
            "case_count": len(positive_packets),
            "counter_rule": "A case counts only after two distinct conflict-cleared human reviewers under different accountable owners complete packet-bound decisions.",
            "reviewer_rules": [
                "Reviewers must be real accountable humans; AI, public labels, and generated packets are ineligible as reviewers.",
                "Reviewer A and reviewer B must have distinct identities and distinct accountable owners.",
                "Each reviewer must record UTC start and completion times, a conflict statement, decision, rationale, evidence references, confidence, and decision SHA-256.",
                "Both reviewer packet hashes must equal the deterministic packet hash for the same case.",
                "Reviewer decisions must be frozen before comparison.",
                "Agreement may finalize as REVIEWER_CONSENSUS only after both frozen decisions match.",
                "Every disagreement requires a third conflict-cleared human adjudicator under an owner distinct from both reviewers, with separate time, packet, decision, confidence, and hash evidence.",
                "The finalized row must bind all reviewer, packet, decision, timing, agreement, and third-adjudicator inputs.",
            ],
            "allowed_confidence": ["high", "very_high"],
            "final_output": "finalized_positive_adjudications.json",
            "final_status": "FINALIZED_INDEPENDENT_ADJUDICATION",
        },
    )
    _atomic_write_json(
        handoff_manifest_path,
        {
            "artifact_schema_version": "2026-08-17.human-adjudication-handoff-manifest.v1",
            "case_count": len(positive_packets),
            "status": "ready_for_external_human_assignment",
            "artifacts": {
                "positive_case_review_packets": {
                    "path": _portable_run_path(paths, positive_path),
                    "sha256": _sha256_file(positive_path),
                },
                "reviewer_a_response_template": {
                    "path": _portable_run_path(paths, reviewer_a_template_path),
                    "sha256": _sha256_file(reviewer_a_template_path),
                },
                "reviewer_b_response_template": {
                    "path": _portable_run_path(paths, reviewer_b_template_path),
                    "sha256": _sha256_file(reviewer_b_template_path),
                },
                "human_adjudication_protocol": {
                    "path": _portable_run_path(paths, adjudication_protocol_path),
                    "sha256": _sha256_file(adjudication_protocol_path),
                },
            },
            "external_dependency": "Assign two eligible human reviewers per case and a third human adjudicator for every disagreement.",
            "counter_effect": "none_until_valid_finalized_rows_are_imported",
        },
    )
    _atomic_write_json(
        reviewer_path,
        {
            "status": "waiting_external",
            "reason": "independent human review artifacts not yet bound",
            "required_artifacts": [
                "two distinct reviewer identities and accountable owners",
                "conflict checks",
                "review packet hashes",
                "UTC review start and completion timestamps",
                "confidence and decision hashes",
                "agreement status",
                "third-adjudicator evidence for disagreements",
                "finalized adjudications bound to the case and all review inputs",
                "handoff manifest artifact hashes",
            ],
        },
    )
    if not finalized_path.exists():
        _atomic_write_json(finalized_path, [])
    summary = {
        "command": "review-packets",
        "status": "complete",
        "run_id": paths.run_id,
        "revision": paths.revision,
        "positive_packets": len(positive_packets),
        "control_packets": len(control_packets),
        "human_adjudication_handoff_manifest_path": _portable_run_path(paths, handoff_manifest_path),
        "reviewer_independence_path": _portable_run_path(paths, reviewer_path),
    }
    _update_run_state(paths, input_sha256=input_sha256, cell="review-packets", status="complete", details=summary)
    return summary


def command_ai_adjudication_track(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    _queue, _pilot, plan_manifest, input_sha256 = _ensure_plan_artifacts(paths)
    positive_snapshot_path = _safe_run_artifact_path(paths, str(plan_manifest["positive_snapshot_path"]))
    if _sha256_file(positive_snapshot_path) != str(plan_manifest["positive_snapshot_sha256"]):
        raise ValueError("positive case snapshot hash mismatch")
    positive_rows = pd.read_csv(positive_snapshot_path, keep_default_na=False).to_dict("records")
    source_repository_root = (
        paths.raw_dir / "ai_evidence_source" / "DeFiHackLabs"
    )
    source_repository_commit = ""
    if source_repository_root.is_dir():
        source_repository_commit = subprocess.check_output(
            ["git", "-C", str(source_repository_root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    packets = build_ai_evidence_packets(
        positive_rows,
        source_snapshot_sha256=str(plan_manifest["positive_snapshot_sha256"]),
        source_repository_root=source_repository_root if source_repository_root.is_dir() else None,
        source_repository_commit=source_repository_commit,
    )
    amendment = yaml.safe_load(AI_ADJUDICATION_AMENDMENT_PATH.read_text(encoding="utf-8"))
    frozen_runs = dict(amendment.get("frozen_runs") or {})
    primary_specs = [dict(frozen_runs.get("primary_a") or {}), dict(frozen_runs.get("primary_b") or {})]
    adjudicator_spec = dict(frozen_runs.get("adjudicator") or {})
    sensitivity_spec = dict(frozen_runs.get("sensitivity") or {})
    visible_fields = set(packets[0].get("visible_fields", [])) if packets else set()
    evidence_fields = {"incident_reference_urls", "incident_tx_hashes", "incident_record_sha256"}
    direct_source_count = sum(
        packet["visible_payload"].get("incident_source_status") == "PINNED_SOURCE_PRESENT"
        for packet in packets
    )
    evidence_sufficiency = (
        f"PINNED_DIRECT_SOURCE_{direct_source_count}_OF_{len(packets)};"
        "REMAINDER_MUST_USE_UNKNOWN_IF_PACKET_EVIDENCE_IS_INADEQUATE"
        if evidence_fields.issubset(visible_fields)
        else "INSUFFICIENT_FOR_DEFENSIBLE_ROOT_CAUSE_RUNS"
    )
    output_dir = paths.report_dir / "ai_only_adjudication"
    result = build_ai_track_package(
        packets=packets,
        codebook_path=ROOT / "config" / "reviewer_codebook.yaml",
        output_dir=output_dir,
        primary_run_specs=primary_specs,
        adjudicator_run_spec=adjudicator_spec,
        sensitivity_run_spec=sensitivity_spec,
        evidence_sufficiency=evidence_sufficiency,
        protocol_amendment_path=AI_ADJUDICATION_AMENDMENT_PATH,
    )
    summary = {
        "command": "ai-adjudication-track",
        "status": result["status"],
        "run_id": paths.run_id,
        "revision": paths.revision,
        "case_count": result["case_count"],
        "track_name": result["track_name"],
        "claim_authority": result["claim_authority"],
        "evidence_sufficiency": evidence_sufficiency,
        "human_independent_adjudication_counter_effect": result[
            "human_independent_adjudication_counter_effect"
        ],
        "manifest_path": _portable_run_path(paths, output_dir / "ai_adjudication_manifest.json"),
    }
    _update_run_state(
        paths,
        input_sha256=input_sha256,
        cell="ai-adjudication-track",
        status="waiting_external" if "INSUFFICIENT" in evidence_sufficiency else "ready_not_executed",
        details=summary,
    )
    return summary


def _verified_historical_snapshot_overlay(
    paths: RunPaths,
    positive_cases: pd.DataFrame,
    run_root_value: str | Path,
) -> tuple[pd.DataFrame, dict[str, Any], dict[str, bytes]]:
    historical_root = Path(run_root_value).expanduser().resolve(strict=False)
    portable_root = _portable_output_path(paths, historical_root)
    paths.report_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="historical-verify-", dir=paths.report_dir.parent) as temp_dir:
        stage = Path(temp_dir)
        report = verify_historical_snapshot_run(historical_root, output_path=stage)
        if report.get("counter_authority") is not True or report.get("integrity_errors"):
            raise ValueError("historical_snapshot_verification_failed")
        report_path = stage / HISTORICAL_REPORT_FILENAME
        projection_path = stage / HISTORICAL_PROJECTION_FILENAME
        projection = pd.read_csv(projection_path, keep_default_na=False)
        if len(projection) != int(report.get("required") or 0) or len(projection) != 417:
            raise ValueError("historical_snapshot_projection_cardinality_mismatch")
        if list(projection.columns) != HISTORICAL_PROJECTION_FIELDS:
            raise ValueError("historical_snapshot_projection_schema_mismatch")
        overlay_columns = ["case_id", "case_name", *HISTORICAL_SNAPSHOT_OVERLAY_FIELDS]
        overlaid = overlay_historical_snapshot_projection(positive_cases, projection[overlay_columns])
        staged_bytes = {
            HISTORICAL_REPORT_FILENAME: report_path.read_bytes(),
            HISTORICAL_PROJECTION_FILENAME: projection_path.read_bytes(),
        }

    target_dir = paths.report_dir / "historical_snapshot_verification"
    report_target = target_dir / HISTORICAL_REPORT_FILENAME
    projection_target = target_dir / HISTORICAL_PROJECTION_FILENAME
    binding = {
        "run_root": portable_root,
        "report": {
            "path": _portable_run_path(paths, report_target),
            "sha256": hashlib.sha256(staged_bytes[HISTORICAL_REPORT_FILENAME]).hexdigest(),
            "format": "json",
        },
        "projection": {
            "path": _portable_run_path(paths, projection_target),
            "sha256": hashlib.sha256(staged_bytes[HISTORICAL_PROJECTION_FILENAME]).hexdigest(),
            "format": "csv",
        },
        "observed": int(report["observed"]),
        "required": int(report["required"]),
        "counter_authority": True,
    }
    return overlaid, binding, staged_bytes


def load_control_qualification_bundle_for_project(
    bundle_manifest_path: Path,
) -> dict[str, Any]:
    manifest_path = bundle_manifest_path.expanduser().resolve(strict=True)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("control_qualification_bundle_manifest_not_ordinary")
    try:
        result = verify_control_qualification_bundle(manifest_path=manifest_path)
    except ControlQualificationBundleError as exc:
        raise ValueError(f"control_qualification_bundle_verification_failed:{exc}") from exc
    manifest = _read_json(manifest_path)
    projection_relative = Path(manifest["files"]["qualified_controls"]["path"])
    projection_path = (manifest_path.parent / projection_relative).resolve(strict=True)
    return {
        **result,
        "bundle_manifest_path": manifest_path,
        "bundle_manifest_sha256": _sha256_file(manifest_path),
        "qualified_control_projection_path": projection_path,
    }


def command_project(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    _queue, _pilot, manifest, input_sha256 = _ensure_plan_artifacts(paths)
    positive_path = _safe_run_artifact_path(paths, str(manifest["positive_snapshot_path"]))
    denominator_path = paths.processed_dir / "deployment_denominator.csv"
    qualification_bundle_value = getattr(args, "control_qualification_bundle", None)
    qualification_bundle: dict[str, Any] | None = None
    if qualification_bundle_value:
        qualification_bundle = load_control_qualification_bundle_for_project(
            Path(qualification_bundle_value)
        )
        _portable_output_path(paths, qualification_bundle["bundle_manifest_path"])
        _portable_output_path(
            paths, qualification_bundle["qualified_control_projection_path"]
        )
        controls_path = qualification_bundle["qualified_control_projection_path"]
    else:
        controls_path = paths.processed_dir / "control_candidates.csv"
    positive_packets_path = paths.report_dir / "positive_case_review_packets.json"
    control_packets_path = paths.report_dir / "control_review_packets.json"
    finalized_path = paths.report_dir / "finalized_positive_adjudications.json"
    if not finalized_path.exists():
        _atomic_write_json(finalized_path, [])

    counter_targets = {
        "deployment_denominator_required": int(DEFAULT_COUNTER_TARGETS["deployment_denominator_required"]),
        "deployment_denominator_per_chain": {
            chain: int(DEFAULT_COUNTER_TARGETS["deployment_denominator_per_chain"][chain])
            for chain in sorted(DEFAULT_COUNTER_TARGETS["deployment_denominator_per_chain"])
        },
        "control_candidates_required": int(DEFAULT_COUNTER_TARGETS["control_candidates_required"]),
        "qualified_controls_required": int(DEFAULT_COUNTER_TARGETS["qualified_controls_required"]),
        "independent_r5_blocks_required": int(args.minimum_independent_r5_blocks),
    }
    positive_cases = _projectable_positive_cases(pd.read_csv(positive_path))
    historical_binding: dict[str, Any] | None = None
    historical_bytes: dict[str, bytes] = {}
    historical_run_root = getattr(args, "historical_snapshot_run_root", None)
    if historical_run_root:
        positive_cases, historical_binding, historical_bytes = _verified_historical_snapshot_overlay(
            paths,
            positive_cases,
            historical_run_root,
        )

    evidence = {
        "positive_cases": positive_cases,
        "deployment_denominator": _safe_read_csv(denominator_path),
        "control_rows": (
            qualification_bundle["qualified_control_projection"]
            if qualification_bundle is not None
            else _safe_read_csv(controls_path)
        ),
        "positive_case_review_packets": _read_json(positive_packets_path) if positive_packets_path.exists() else [],
        "control_review_packets": _read_json(control_packets_path) if control_packets_path.exists() else [],
        "finalized_positive_adjudications": _read_json(finalized_path) if finalized_path.exists() else [],
        "minimum_independent_r5_blocks": int(args.minimum_independent_r5_blocks),
        "counter_targets": counter_targets,
    }
    if qualification_bundle is not None:
        evidence["control_qualification_verification"] = qualification_bundle[
            "bundle_verification"
        ]

    manifest_inputs = {
        "positive_cases": {"path": _portable_run_path(paths, positive_path), "sha256": _sha256_file(positive_path), "format": "csv"},
        "deployment_denominator": {"path": _portable_run_path(paths, denominator_path), "sha256": _sha256_file(denominator_path) if denominator_path.exists() else "0" * 64, "format": "csv"},
        "control_rows": {"path": _portable_run_path(paths, controls_path), "sha256": _sha256_file(controls_path) if controls_path.exists() else "0" * 64, "format": "csv"},
        "positive_case_review_packets": {"path": _portable_run_path(paths, positive_packets_path), "sha256": _sha256_file(positive_packets_path) if positive_packets_path.exists() else "0" * 64, "format": "json"},
        "control_review_packets": {"path": _portable_run_path(paths, control_packets_path), "sha256": _sha256_file(control_packets_path) if control_packets_path.exists() else "0" * 64, "format": "json"},
        "finalized_positive_adjudications": {"path": _portable_run_path(paths, finalized_path), "sha256": _sha256_file(finalized_path), "format": "json"},
    }
    input_manifest = {
        "artifact_schema_version": COUNTER_SCHEMA_VERSION,
        "inputs": manifest_inputs,
        "minimum_independent_r5_blocks": int(args.minimum_independent_r5_blocks),
        "counter_targets": counter_targets,
    }
    if historical_binding is not None:
        input_manifest["historical_snapshot_verification"] = historical_binding
    if qualification_bundle is not None:
        input_manifest["control_qualification_bundle"] = {
            "manifest": {
                "path": _portable_output_path(
                    paths, qualification_bundle["bundle_manifest_path"]
                ),
                "sha256": qualification_bundle["bundle_manifest_sha256"],
                "format": "json",
            },
            "counter_authority": True,
        }
    input_manifest["input_manifest_sha256"] = canonical_manifest_sha256(input_manifest)
    input_manifest_path = paths.report_dir / "public_acquisition_counter_inputs.json"
    artifact = build_counter_artifact(evidence, input_manifest_sha256=input_manifest["input_manifest_sha256"])
    counter_path = paths.report_dir / "public_acquisition_counters.json"
    projected = project_counters(evidence)
    status = "complete" if int(artifact["counters"]["release_eligible_cases"]) > 0 and projected["production_qualification"]["qualified"] else "incomplete"
    summary = {
        "command": "project",
        "status": status,
        "run_id": paths.run_id,
        "revision": paths.revision,
        "counter_artifact_path": _portable_run_path(paths, counter_path),
        "counter_input_manifest_path": _portable_run_path(paths, input_manifest_path),
        "release_eligible_cases": int(artifact["counters"]["release_eligible_cases"]),
    }
    if historical_binding is not None:
        target_dir = paths.report_dir / "historical_snapshot_verification"
        _atomic_write_text(
            target_dir / HISTORICAL_REPORT_FILENAME,
            historical_bytes[HISTORICAL_REPORT_FILENAME].decode("utf-8"),
        )
        _atomic_write_text(
            target_dir / HISTORICAL_PROJECTION_FILENAME,
            historical_bytes[HISTORICAL_PROJECTION_FILENAME].decode("utf-8"),
        )
    _atomic_write_json(input_manifest_path, input_manifest)
    _atomic_write_json(counter_path, artifact)
    _atomic_write_json(paths.report_dir / "release_predicates.json", projected)
    _update_run_state(paths, input_sha256=input_sha256, cell="project", status=status, details=summary)
    return summary


def command_verify(args: argparse.Namespace) -> dict[str, Any]:
    from verify_public_evidence_acquisition import evaluate_public_acquisition  # noqa: WPS433

    return evaluate_public_acquisition(output_root=Path(args.output_root), revision=args.revision, run_id=args.run_id, latest=args.latest)


def _rebase_legacy_run_reference(paths: RunPaths, value: Any) -> tuple[Any, int, set[str]]:
    if isinstance(value, dict):
        replacements = 0
        roots: set[str] = set()
        normalized: dict[str, Any] = {}
        for key, nested in value.items():
            converted, nested_replacements, nested_roots = _rebase_legacy_run_reference(paths, nested)
            normalized[key] = converted
            replacements += nested_replacements
            roots.update(nested_roots)
        return normalized, replacements, roots
    if isinstance(value, list):
        replacements = 0
        roots: set[str] = set()
        normalized_list = []
        for nested in value:
            converted, nested_replacements, nested_roots = _rebase_legacy_run_reference(paths, nested)
            normalized_list.append(converted)
            replacements += nested_replacements
            roots.update(nested_roots)
        return normalized_list, replacements, roots
    if not isinstance(value, str) or not Path(value).is_absolute():
        return value, 0, set()

    candidate = Path(value)
    try:
        return _portable_run_path(paths, candidate), 1, {str(paths.output_root.resolve())}
    except ValueError:
        pass

    parts = candidate.parts
    for kind in ("raw", "processed", "reports"):
        marker = (kind, "public_acquisition", paths.revision, paths.run_id)
        for index in range(0, len(parts) - len(marker) + 1):
            if tuple(parts[index : index + len(marker)]) != marker:
                continue
            relative = Path(*parts[index:])
            mapped = (paths.output_root / relative).resolve(strict=False)
            if not mapped.exists():
                raise FileNotFoundError(f"legacy run reference target missing: {relative.as_posix()}")
            legacy_root = str(Path(*parts[:index]))
            return relative.as_posix(), 1, {legacy_root}
    return value, 0, set()


def command_migrate_paths(args: argparse.Namespace) -> dict[str, Any]:
    paths = _resolve_paths(args, require_explicit_identity=True)
    manifest_path = paths.report_dir / "case_queue_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"case queue manifest missing: {manifest_path}")

    target_names = (
        "case_queue_manifest.json",
        "inventory_manifest.json",
        "denominator_manifest.json",
        "rpc_case_results.json",
        "rpc_receipts.json",
        "run_state.json",
    )
    staged: dict[Path, Any] = {}
    changes: list[dict[str, Any]] = []
    legacy_roots: set[str] = set()
    replacement_count = 0
    for name in target_names:
        path = paths.report_dir / name
        if not path.exists():
            continue
        original = _read_json(path)
        normalized, replacements, roots = _rebase_legacy_run_reference(paths, original)
        if replacements:
            staged[path] = normalized
            replacement_count += replacements
            legacy_roots.update(roots)
            changes.append(
                {
                    "path": _portable_run_path(paths, path),
                    "before_sha256": _sha256_file(path),
                    "replacement_count": replacements,
                }
            )

    summary: dict[str, Any] = {
        "command": "migrate-paths",
        "status": "plan_only" if not args.execute else "complete",
        "execute": bool(args.execute),
        "run_id": paths.run_id,
        "revision": paths.revision,
        "replacement_count": replacement_count,
        "legacy_roots": sorted(legacy_roots),
        "files": changes,
        "semantics": "path-reference-only migration; referenced evidence bytes and scientific counters are not upgraded",
    }
    if not args.execute:
        return summary

    for path, payload in staged.items():
        _atomic_write_json(path, payload)

    rpc_results_path = paths.report_dir / "rpc_case_results.json"
    rpc_receipts_path = paths.report_dir / "rpc_receipts.json"
    recovery_audit_path = paths.report_dir / "rpc_receipt_recovery_audit.json"
    if recovery_audit_path.exists() and rpc_results_path.exists() and rpc_receipts_path.exists():
        recovery_audit = _read_json(recovery_audit_path)
        recovery_audit["post_recovery_rpc_case_results_sha256"] = _sha256_file(rpc_results_path)
        recovery_audit["post_recovery_rpc_receipts_sha256"] = _sha256_file(rpc_receipts_path)
        _atomic_write_json(recovery_audit_path, recovery_audit)

    project_args = argparse.Namespace(
        output_root=paths.output_root,
        revision=paths.revision,
        run_id=paths.run_id,
        latest=False,
        minimum_independent_r5_blocks=int(args.minimum_independent_r5_blocks),
    )
    project_summary = command_project(project_args)
    summary["project_regeneration"] = project_summary
    for change in changes:
        changed_path = paths.output_root / change["path"]
        change["after_sha256"] = _sha256_file(changed_path)

    audit_path = paths.report_dir / "path_reference_migration_audit.json"
    _atomic_write_json(audit_path, summary)
    summary["audit_path"] = _portable_run_path(paths, audit_path)
    return summary


def command_run_public(args: argparse.Namespace) -> dict[str, Any]:
    output_root = Path(args.output_root).resolve()
    revision = _validate_slug("revision", args.revision)
    explicit_run_id = getattr(args, "run_id", None)
    if explicit_run_id:
        initial_paths = _run_paths(output_root, revision, explicit_run_id)
        plan = (
            {
                "command": "plan",
                "status": "resume",
                "offline": True,
                "run_id": initial_paths.run_id,
                "revision": initial_paths.revision,
                "input_sha256": _read_json(initial_paths.report_dir / "case_queue_manifest.json")["input_sha256"],
            }
            if (initial_paths.report_dir / "case_queue_manifest.json").exists()
            else run_plan(output_root, revision=revision, run_id=explicit_run_id)
        )
    else:
        plan = run_plan(output_root, revision=revision, run_id=None)
    run_id = str(plan["run_id"])

    def _ns(**kwargs: Any) -> argparse.Namespace:
        return argparse.Namespace(output_root=output_root, revision=revision, run_id=run_id, latest=False, **kwargs)

    inventory = command_inventory(
        _ns(
            execute=args.execute,
            inventory_spec_file=args.inventory_spec_file,
            max_pages=args.max_pages,
            max_bytes=args.max_bytes,
            deadline_seconds=args.deadline_seconds,
        )
    )
    rpc = command_rpc(
        _ns(
            execute=args.execute,
            max_cases=args.max_cases,
            max_bytes=args.max_bytes,
            deadline_seconds=-1 if args.execute and args.deadline_seconds == 0 else args.deadline_seconds,
            rpc_fixture_file=args.rpc_fixture_file,
        )
    )
    denominator = command_denominator(
        _ns(
            execute=args.execute,
            source_file=args.source_file,
            max_bytes=args.max_bytes,
            deadline_seconds=args.deadline_seconds,
        )
    )
    controls = command_controls(_ns())
    packets = command_review_packets(_ns(blinding_seed=args.blinding_seed))
    ai_adjudication = command_ai_adjudication_track(_ns())
    project = command_project(
        _ns(
            minimum_independent_r5_blocks=args.minimum_independent_r5_blocks,
            historical_snapshot_run_root=args.historical_snapshot_run_root,
        )
    )
    verification = command_verify(_ns())

    stage_payloads = {
        "plan": plan,
        "inventory": inventory,
        "rpc": rpc,
        "denominator": denominator,
        "controls": controls,
        "review-packets": packets,
        "ai-adjudication-track": ai_adjudication,
        "project": project,
    }
    status = _derive_run_public_status(
        execute=bool(args.execute),
        stage_payloads=stage_payloads,
        verification=verification,
    )
    return {
        "command": "run-public",
        "status": status,
        "execute": bool(args.execute),
        "run_id": run_id,
        "revision": revision,
        "stages": stage_payloads,
        "verification": {
            "structure_valid": bool(verification["structure_valid"]),
            "scientifically_complete": bool(verification["scientifically_complete"]),
            "release_ready": bool(verification["release_ready"]),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resumable public-only Stage-2 acquisition workflow.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_flags(command: argparse.ArgumentParser, *, include_latest: bool = True) -> None:
        command.add_argument("--output-root", type=Path, default=ROOT)
        command.add_argument("--revision", default=DEFAULT_REVISION)
        command.add_argument("--run-id", default=None)
        if include_latest:
            command.add_argument("--latest", action="store_true")

    plan = subparsers.add_parser("plan", help="Build the canonical 417-case acquisition queue offline.")
    add_common_flags(plan, include_latest=False)
    plan.add_argument("--queue-source-path", type=Path, default=None)
    plan.add_argument("--positive-cases-path", type=Path, default=None)
    plan.set_defaults(func=command_plan)

    inventory = subparsers.add_parser("inventory", help="Capture public inventory manifests.")
    add_common_flags(inventory)
    inventory.add_argument("--execute", action="store_true")
    inventory.add_argument("--inventory-spec-file", default=None)
    inventory.add_argument("--max-pages", type=int, default=1)
    inventory.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024)
    inventory.add_argument("--deadline-seconds", type=int, default=0)
    inventory.set_defaults(func=command_inventory)

    rpc = subparsers.add_parser("rpc", help="Acquire public RPC evidence.")
    add_common_flags(rpc)
    rpc.add_argument("--execute", action="store_true")
    rpc.add_argument("--rpc-fixture-file", default=None)
    rpc.add_argument("--max-cases", type=int, default=0)
    rpc.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024)
    rpc.add_argument("--deadline-seconds", type=int, default=0)
    rpc.set_defaults(func=command_rpc)

    denominator = subparsers.add_parser("denominator", help="Materialize the public deployment denominator.")
    add_common_flags(denominator)
    denominator.add_argument("--execute", action="store_true")
    denominator.add_argument("--source-file", default=None)
    denominator.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024)
    denominator.add_argument("--deadline-seconds", type=int, default=0)
    denominator.set_defaults(func=command_denominator)

    controls = subparsers.add_parser("controls", help="Prepare control candidates from the denominator.")
    add_common_flags(controls)
    controls.set_defaults(func=command_controls)

    review_packets = subparsers.add_parser("review-packets", help="Build blinded reviewer packets.")
    add_common_flags(review_packets)
    review_packets.add_argument("--blinding-seed", default=None)
    review_packets.set_defaults(func=command_review_packets)

    ai_adjudication = subparsers.add_parser(
        "ai-adjudication-track",
        help="Generate the separate, non-human AI adjudication protocol and frozen run templates.",
    )
    add_common_flags(ai_adjudication)
    ai_adjudication.set_defaults(func=command_ai_adjudication_track)

    project = subparsers.add_parser("project", help="Project counters and release predicates.")
    add_common_flags(project)
    project.add_argument("--minimum-independent-r5-blocks", type=int, default=120)
    project.add_argument("--historical-snapshot-run-root", type=Path, default=None)
    project.add_argument("--control-qualification-bundle", type=Path, default=None)
    project.set_defaults(func=command_project)

    verify = subparsers.add_parser("verify", help="Run the independent public-acquisition verifier.")
    add_common_flags(verify)
    verify.set_defaults(func=command_verify)

    migrate_paths = subparsers.add_parser("migrate-paths", help="Rebase legacy run-owned absolute paths without changing evidence bytes.")
    add_common_flags(migrate_paths)
    migrate_paths.add_argument("--execute", action="store_true")
    migrate_paths.add_argument("--minimum-independent-r5-blocks", type=int, default=120)
    migrate_paths.set_defaults(func=command_migrate_paths)

    run_public = subparsers.add_parser("run-public", help="Execute the end-to-end public acquisition workflow.")
    add_common_flags(run_public, include_latest=False)
    run_public.add_argument("--execute", action="store_true")
    run_public.add_argument("--inventory-spec-file", default=None)
    run_public.add_argument("--rpc-fixture-file", default=None)
    run_public.add_argument("--max-cases", type=int, default=0)
    run_public.add_argument("--max-pages", type=int, default=1)
    run_public.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024)
    run_public.add_argument("--deadline-seconds", type=int, default=0)
    run_public.add_argument("--source-file", default=None)
    run_public.add_argument("--blinding-seed", default=None)
    run_public.add_argument("--minimum-independent-r5-blocks", type=int, default=120)
    run_public.add_argument("--historical-snapshot-run-root", type=Path, default=None)
    run_public.set_defaults(func=command_run_public)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
        print(_json_dumps(result))
        return 0 if result.get("structure_valid", True) else 1
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        payload = {"command": getattr(args, "command", "unknown"), "status": "error", "error": str(exc)}
        print(_json_dumps(payload))
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
