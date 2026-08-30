from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import hashlib
import json
import math
import os
import re
import threading
import tempfile
import time
from datetime import datetime, timezone
from numbers import Integral, Real
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import pandas as pd
import yaml

from chronosaudit_stage2.evidence_sources import parse_defihacklabs_snapshot_bytes
from chronosaudit_stage2.onchain import canonical_block_selector, normalize_block_header, normalize_hex
from chronosaudit_stage2.public_acquisition.managed_providers import ManagedProviderConfigurationError
from chronosaudit_stage2.public_acquisition.strict_snapshot import (
    InsufficientIncidentLeadTimeError,
    _load_schema,
    _cached_snapshot_valid,
    _provider_identity_material,
    _seal_strict_snapshot_artifact,
    acquire_strict_historical_snapshot,
    validate_strict_historical_snapshot,
)


FULL_CASE_TARGET = 417
_CHAIN_ALIASES = {
    "mainnet": "ethereum",
    "eth": "ethereum",
    "arb": "arbitrum",
    "arbi": "arbitrum",
}
_SUPPORTED_CHAINS = {"ethereum", "bsc", "base", "arbitrum"}
_ADDRESS_RE = re.compile(r"/address/(0x[a-fA-F0-9]{40})")
_SECRET_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "password",
}
_SECRET_SUBSTRINGS = ("auth", "token", "secret", "key", "cookie", "password")
_UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ROOT = Path(__file__).resolve().parents[3]
_HEADER_CONTAINER_KEYS = {"headers", "request_headers", "response_headers"}
_SHA256_HEX = set("0123456789abcdef")
_CASE_CLAIM_TIMEOUT_SECONDS = 5.0
_CASE_CLAIM_POLL_SECONDS = 0.05
_CASE_CLAIM_STALE_AFTER_SECONDS = 5.0
_CASE_CLAIM_HEARTBEAT_SECONDS = 1.0


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _normalize_chain(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    normalized = _CHAIN_ALIASES.get(normalized, normalized)
    if normalized not in _SUPPORTED_CHAINS:
        raise ValueError(f"unsupported chain: {value}")
    return normalized


def _normalize_address(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if not re.fullmatch(r"0x[a-f0-9]{40}", normalized):
        raise ValueError(f"invalid address: {value}")
    return normalized


def _normalize_case_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("case_name must be non-empty")
    return text


def _normalize_incident_block(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError(f"invalid incident block: {value}")
    if isinstance(value, Integral):
        number = int(value)
        if number < 0:
            raise ValueError(f"invalid incident block: {value}")
        return number
    if isinstance(value, Real):
        number = float(value)
        if not math.isfinite(number) or not number.is_integer() or number < 0:
            raise ValueError(f"invalid incident block: {value}")
        return int(number)

    text = str(value or "").strip()
    if not re.fullmatch(r"\d+", text):
        raise ValueError(f"invalid incident block: {value}")
    return int(text)


def _stable_scalar(value: Any) -> Any:
    if pd.isna(value):
        return None
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return value
    return str(value)


def _stable_record(row: pd.Series, *, columns: list[str]) -> dict[str, Any]:
    return {column: _stable_scalar(row[column]) for column in columns}


def _stable_case_mapping(case: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): _stable_scalar(value) for key, value in dict(case).items()}


def _portable_path(path: Path, *, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _now_utc_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_retrieval_utc(value: str | None) -> str:
    candidate = value or _now_utc_z()
    if not _UTC_Z_RE.fullmatch(candidate):
        raise ValueError("retrieval_utc must be strict UTC ISO-8601 in Z form")
    return candidate


def _case_id_material(case_name: str, chain: str, address: str, incident_block: int) -> str:
    material = f"{case_name}|{chain}|{address}|{incident_block}"
    return "ca2-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _canonical_case_id(row: pd.Series) -> str:
    return _case_id_material(
        _normalize_case_name(row["case_name"]),
        _normalize_chain(row["chain"]),
        _normalize_address(row["address"]),
        _normalize_incident_block(row["incident_block"]),
    )


def _validate_duplicate_case_ids(frame: pd.DataFrame, *, label: str) -> None:
    duplicates = frame.loc[frame["case_id"].duplicated(), "case_id"].astype(str).tolist()
    if duplicates:
        raise ValueError(f"duplicate case_id values are not allowed in {label}: {duplicates[:3]}")


def _prepare_queue_frame(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path).copy()
    if len(frame) != FULL_CASE_TARGET:
        raise ValueError(f"expected {FULL_CASE_TARGET} canonical cases, found {len(frame)} in queue")
    alias_pairs = (
        ("address", "target_contract_address"),
        ("incident_block", "fork_block_number"),
    )
    for canonical, alias in alias_pairs:
        if canonical in frame.columns and alias in frame.columns:
            normalizer = _normalize_address if canonical == "address" else _normalize_incident_block
            canonical_values = frame[canonical].map(normalizer)
            alias_values = frame[alias].map(normalizer)
            if not canonical_values.eq(alias_values).all():
                raise ValueError(f"conflicting queue alias columns: {canonical}!={alias}")
        if canonical not in frame.columns:
            if alias not in frame.columns:
                raise ValueError(f"queue is missing required column: {canonical}")
            frame[canonical] = frame[alias]
    frame["case_name"] = frame["case_name"].map(_normalize_case_name)
    frame["chain"] = frame["chain"].map(_normalize_chain)
    frame["address"] = frame["address"].map(_normalize_address)
    frame["incident_block"] = frame["incident_block"].map(_normalize_incident_block)
    expected_case_ids = frame.apply(_canonical_case_id, axis=1)
    if "case_id" in frame.columns:
        provided_case_ids = frame["case_id"].astype(str).str.strip()
        duplicate_case_ids = provided_case_ids.loc[provided_case_ids.duplicated()].tolist()
        if duplicate_case_ids:
            raise ValueError(f"duplicate case_id values are not allowed in queue: {duplicate_case_ids[:3]}")
        non_empty = provided_case_ids.ne("")
        if non_empty.any() and not provided_case_ids.loc[non_empty].eq(expected_case_ids.loc[non_empty]).all():
            raise ValueError("queue case_id does not match canonical case material")
    frame["case_id"] = expected_case_ids
    _validate_duplicate_case_ids(frame, label="queue")
    return frame


def _prepare_temporal_frame(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path).copy()
    if len(frame) != FULL_CASE_TARGET:
        raise ValueError(f"expected {FULL_CASE_TARGET} canonical cases, found {len(frame)} in temporal provenance")
    frame["case_name"] = frame["case_name"].map(_normalize_case_name)
    frame["chain"] = frame["chain"].map(_normalize_chain)
    frame["target_contract_address"] = frame["target_contract_address"].map(_normalize_address)
    frame["fork_block_number"] = frame["fork_block_number"].map(_normalize_incident_block)
    expected_case_ids = frame.apply(
        lambda row: _case_id_material(
            row["case_name"],
            row["chain"],
            row["target_contract_address"],
            row["fork_block_number"],
        ),
        axis=1,
    )
    provided_case_ids = frame["case_id"].astype(str).str.strip()
    if not provided_case_ids.eq(expected_case_ids).all():
        raise ValueError("queue/temporal mismatch: temporal provenance case_id does not match canonical case material")
    frame["case_id"] = expected_case_ids
    _validate_duplicate_case_ids(frame, label="temporal provenance")
    return frame


def load_canonical_snapshot_population(queue_path: str | Path, temporal_path: str | Path) -> pd.DataFrame:
    queue = _prepare_queue_frame(Path(queue_path))
    temporal = _prepare_temporal_frame(Path(temporal_path))
    merged = queue.merge(
        temporal,
        on="case_id",
        how="inner",
        suffixes=("", "_temporal"),
    )
    if len(merged) != FULL_CASE_TARGET:
        raise ValueError("queue/temporal mismatch: case_id membership differs")

    mismatch_columns = (
        ("case_name", "case_name_temporal"),
        ("chain", "chain_temporal"),
        ("address", "target_contract_address"),
        ("incident_block", "fork_block_number"),
    )
    mismatches: list[str] = []
    for left, right in mismatch_columns:
        unequal = merged.loc[merged[left].astype(str) != merged[right].astype(str), ["case_id", left, right]]
        if not unequal.empty:
            first = unequal.iloc[0]
            mismatches.append(f"{left}!={right} for {first['case_id']}")
    if mismatches:
        raise ValueError("queue/temporal mismatch: " + "; ".join(mismatches))

    merged = merged.drop(columns=["case_name_temporal", "chain_temporal", "target_contract_address", "fork_block_number"])
    merged = merged.sort_values(["case_name", "chain", "address", "incident_block"]).reset_index(drop=True)
    stable_columns = sorted(merged.columns.tolist())
    merged["input_row_sha256"] = merged.apply(
        lambda row: hashlib.sha256(
            _canonical_json(_stable_record(row, columns=stable_columns)).encode("utf-8")
        ).hexdigest(),
        axis=1,
    )
    return merged


def _default_policy_path() -> Path:
    return _ROOT / "config" / "public_acquisition_policy.yaml"


def _default_provider_template_path() -> Path:
    return _ROOT / "config" / "managed_archive_provider_templates.yaml"


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def build_snapshot_run_plan(
    queue_path: str | Path,
    temporal_path: str | Path,
    *,
    policy_path: str | Path | None = None,
    provider_template_path: str | Path | None = None,
    selected_cases: list[str] | None = None,
    max_cases: int | None = None,
) -> dict[str, Any]:
    if max_cases is not None and max_cases < 0:
        raise ValueError("max_cases must be >= 0")

    queue_file = Path(queue_path)
    temporal_file = Path(temporal_path)
    policy_file = Path(policy_path) if policy_path is not None else _default_policy_path()
    template_file = (
        Path(provider_template_path)
        if provider_template_path is not None
        else _default_provider_template_path()
    )

    population = load_canonical_snapshot_population(queue_file, temporal_file)
    chain_counts = {str(k): int(v) for k, v in population["chain"].value_counts().sort_index().items()}
    selected_frame = population
    requested_case_names: list[str] = []
    if selected_cases is not None:
        lookup = {str(name).strip().lower(): name for name in population["case_name"].tolist()}
        rows: list[pd.Series] = []
        seen: set[str] = set()
        for raw_name in selected_cases:
            requested_case_names.append(str(raw_name))
            key = str(raw_name).strip().lower()
            if key in seen:
                continue
            if key not in lookup:
                raise ValueError(f"unknown selected case: {raw_name}")
            rows.append(population.loc[population["case_name"].str.lower() == key].iloc[0])
            seen.add(key)
        selected_frame = pd.DataFrame(rows) if rows else population.iloc[0:0].copy()
    if max_cases is not None:
        selected_frame = selected_frame.head(max_cases).copy()

    runtime_paths = {
        "queue_path": str(queue_file),
        "temporal_path": str(temporal_file),
        "policy_path": str(policy_file),
        "provider_template_path": str(template_file),
    }
    plan = {
        "population": {
            "target_case_count": FULL_CASE_TARGET,
            "actual_case_count": int(len(population)),
            "chain_case_counts": chain_counts,
        },
        "selected": {
            "requested_case_names": requested_case_names,
            "selected_case_names": selected_frame["case_name"].tolist(),
            "selected_case_ids": selected_frame["case_id"].tolist(),
            "selected_case_count": int(len(selected_frame)),
            "selected_attempts": selected_frame[
                ["case_id", "case_name", "chain", "address", "incident_block", "input_row_sha256"]
            ].to_dict(orient="records"),
        },
        "hashes": {
            "queue_sha256": _sha256_file(queue_file),
            "temporal_sha256": _sha256_file(temporal_file),
            "policy_sha256": _sha256_file(policy_file),
            "provider_template_sha256": _sha256_file(template_file),
        },
        "inputs": {
            "logical_inputs": {
                "queue": "canonical_snapshot_queue",
                "temporal": "temporal_snapshot_population",
                "policy": "public_acquisition_policy",
                "provider_template": "managed_archive_provider_templates",
            },
            "runtime_paths": runtime_paths,
            "policy": _load_yaml(policy_file),
            "provider_templates": _load_yaml(template_file),
        },
    }
    hash_domain = {
        "logical_inputs": plan["inputs"]["logical_inputs"],
        "population": plan["population"],
        "selected": {
            "requested_case_names": plan["selected"]["requested_case_names"],
            "selected_case_names": plan["selected"]["selected_case_names"],
            "selected_case_ids": plan["selected"]["selected_case_ids"],
            "selected_case_count": plan["selected"]["selected_case_count"],
            "selected_attempts": plan["selected"]["selected_attempts"],
        },
        "hashes": plan["hashes"],
    }
    plan["plan_sha256"] = hashlib.sha256(_canonical_json(hash_domain).encode("utf-8")).hexdigest()
    return plan


def _default_historical_snapshot_revision() -> str:
    return "historical-snapshots-417"


def _default_historical_snapshot_run_id(plan_sha256: str) -> str:
    return f"historical-snapshots-{str(plan_sha256)[:12]}"


def _atomic_write_json(path: Path, payload: Any) -> None:
    _atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True))


def _freeze_input_bytes(
    frozen_root: Path,
    *,
    entry: Mapping[str, Any],
    source_path: str | Path,
) -> dict[str, Any]:
    path = Path(source_path)
    payload = path.read_bytes()
    destination = frozen_root / str(entry["frozen_path"]).replace("frozen_inputs/", "", 1)
    _atomic_write_bytes(destination, payload)
    return dict(entry)


def _freeze_unavailable_input(name: str, *, blocker: str) -> dict[str, Any]:
    return {
        "name": name,
        "available": False,
        "blocker": blocker,
    }


def _frozen_inputs_hash(entries: list[dict[str, Any]]) -> str:
    return _sha256_json(entries)


def _candidate_frozen_input_entry(name: str, *, source_path: str | Path) -> dict[str, Any]:
    path = Path(source_path)
    payload = path.read_bytes()
    sha256 = _sha256_bytes(payload)
    suffix = path.suffix or ".bin"
    relative_path = Path("frozen_inputs") / f"{name}{suffix}"
    return {
        "name": name,
        "available": True,
        "frozen_path": relative_path.as_posix(),
        "sha256": sha256,
        "bytes": len(payload),
    }


def _prepare_run_binding(
    *,
    revision: str,
    run_id: str,
    plan: Mapping[str, Any],
    frozen_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "revision": revision,
        "run_id": run_id,
        "plan_sha256": str(plan["plan_sha256"]),
        "population": {
            "target_case_count": int(plan["population"]["target_case_count"]),
            "actual_case_count": int(plan["population"]["actual_case_count"]),
            "chain_case_counts": dict(plan["population"]["chain_case_counts"]),
        },
        "selected": {
            "selected_case_ids": list(plan["selected"]["selected_case_ids"]),
            "selected_case_names": list(plan["selected"]["selected_case_names"]),
            "selected_case_count": int(plan["selected"]["selected_case_count"]),
        },
        "input_hashes": dict(plan["hashes"]),
        "frozen_inputs_sha256": _frozen_inputs_hash(frozen_entries),
    }


def _validate_frozen_input_entries(run_root: Path, entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        if not entry.get("available"):
            continue
        frozen_path = run_root / str(entry["frozen_path"])
        if not frozen_path.is_file():
            raise ValueError(f"frozen input is missing: {entry['name']}")
        frozen_bytes = frozen_path.read_bytes()
        if len(frozen_bytes) != int(entry.get("bytes") or -1):
            raise ValueError(f"frozen input hash mismatch: {entry['name']} (byte count)")
        if _sha256_bytes(frozen_bytes) != str(entry["sha256"]):
            raise ValueError(f"frozen input hash mismatch: {entry['name']}")


def _canonical_run_manifest(
    *,
    binding: Mapping[str, Any],
    frozen_entries: list[dict[str, Any]],
    aggregate_paths: Mapping[str, str] | None = None,
    summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "historical_snapshot_run.v1",
        "binding": dict(binding),
        "binding_sha256": _sha256_json(binding),
        "frozen_inputs": {
            "entries": list(frozen_entries),
            "manifest_path": "frozen_inputs/manifest.json",
        },
    }
    if aggregate_paths is not None:
        payload["aggregate_paths"] = dict(aggregate_paths)
    if summary is not None:
        payload["summary"] = dict(summary)
    return payload


def _load_existing_preparation_manifest(run_manifest_path: Path) -> dict[str, Any]:
    return json.loads(run_manifest_path.read_text(encoding="utf-8"))


def prepare_historical_snapshot_run(
    queue_path: str | Path,
    temporal_path: str | Path,
    *,
    policy_path: str | Path | None = None,
    provider_template_path: str | Path | None = None,
    incident_input_path: str | Path | None = None,
    output_root: str | Path,
    revision: str | None = None,
    run_id: str | None = None,
    selected_cases: list[str] | None = None,
    max_cases: int | None = None,
) -> dict[str, Any]:
    plan = build_snapshot_run_plan(
        queue_path,
        temporal_path,
        policy_path=policy_path,
        provider_template_path=provider_template_path,
        selected_cases=selected_cases,
        max_cases=max_cases,
    )
    resolved_revision = str(revision or _default_historical_snapshot_revision()).strip()
    if not resolved_revision:
        raise ValueError("revision must be non-empty")
    resolved_run_id = str(run_id or _default_historical_snapshot_run_id(plan["plan_sha256"])).strip()
    if not resolved_run_id:
        raise ValueError("run_id must be non-empty")

    run_root = Path(output_root).expanduser().resolve(strict=False) / resolved_revision / resolved_run_id
    frozen_root = run_root / "frozen_inputs"

    runtime_paths = dict(plan["inputs"]["runtime_paths"])
    frozen_entries = [
        _candidate_frozen_input_entry("queue", source_path=runtime_paths["queue_path"]),
        _candidate_frozen_input_entry("temporal", source_path=runtime_paths["temporal_path"]),
        _candidate_frozen_input_entry("policy", source_path=runtime_paths["policy_path"]),
        _candidate_frozen_input_entry(
            "provider_template",
            source_path=runtime_paths["provider_template_path"],
        ),
    ]
    if incident_input_path is None:
        frozen_entries.append(
            _freeze_unavailable_input("incident_input", blocker="incident_input_unavailable")
        )
    else:
        frozen_entries.append(
            _candidate_frozen_input_entry("incident_input", source_path=incident_input_path)
        )

    binding = _prepare_run_binding(
        revision=resolved_revision,
        run_id=resolved_run_id,
        plan=plan,
        frozen_entries=frozen_entries,
    )
    frozen_manifest_path = frozen_root / "manifest.json"
    run_manifest_path = run_root / "run_manifest.json"
    manifest = _canonical_run_manifest(binding=binding, frozen_entries=frozen_entries)

    if run_manifest_path.exists():
        existing = _load_existing_preparation_manifest(run_manifest_path)
        existing_entries = list(existing.get("frozen_inputs", {}).get("entries", []))
        _validate_frozen_input_entries(run_root, existing_entries)
        if dict(existing.get("binding", {})) != dict(binding):
            raise ValueError("resume input mismatch: run binding differs from existing manifest")
        if existing_entries != frozen_entries:
            raise ValueError("resume input mismatch: frozen inputs differ from existing manifest")
        return {
            "revision": resolved_revision,
            "run_id": resolved_run_id,
            "run_root": str(run_root),
            "run_manifest_path": str(run_manifest_path),
            "frozen_manifest_path": str(frozen_manifest_path),
            "binding": binding,
            "plan": plan,
            "frozen_inputs": {"entries": frozen_entries, "entries_sha256": _frozen_inputs_hash(frozen_entries)},
            "policy": plan["inputs"]["policy"],
            "provider_templates": plan["inputs"]["provider_templates"],
            "preparation_blockers": [
                str(entry["blocker"]) for entry in frozen_entries if not entry.get("available")
            ],
        }

    frozen_root.mkdir(parents=True, exist_ok=True)
    _freeze_input_bytes(frozen_root, entry=frozen_entries[0], source_path=runtime_paths["queue_path"])
    _freeze_input_bytes(frozen_root, entry=frozen_entries[1], source_path=runtime_paths["temporal_path"])
    _freeze_input_bytes(frozen_root, entry=frozen_entries[2], source_path=runtime_paths["policy_path"])
    _freeze_input_bytes(
        frozen_root,
        entry=frozen_entries[3],
        source_path=runtime_paths["provider_template_path"],
    )
    if incident_input_path is not None:
        _freeze_input_bytes(
            frozen_root,
            entry=frozen_entries[4],
            source_path=incident_input_path,
        )
    _atomic_write_json(
        frozen_manifest_path,
        {"entries": frozen_entries, "entries_sha256": _frozen_inputs_hash(frozen_entries)},
    )
    _atomic_write_json(run_manifest_path, manifest)
    return {
        "revision": resolved_revision,
        "run_id": resolved_run_id,
        "run_root": str(run_root),
        "run_manifest_path": str(run_manifest_path),
        "frozen_manifest_path": str(frozen_manifest_path),
        "binding": binding,
        "plan": plan,
        "frozen_inputs": {"entries": frozen_entries, "entries_sha256": _frozen_inputs_hash(frozen_entries)},
        "policy": plan["inputs"]["policy"],
        "provider_templates": plan["inputs"]["provider_templates"],
        "preparation_blockers": [
            str(entry["blocker"]) for entry in frozen_entries if not entry.get("available")
        ],
    }


def _is_secret_key(key: Any) -> bool:
    lowered = str(key).strip().lower()
    return lowered in _SECRET_KEYS or any(token in lowered for token in _SECRET_SUBSTRINGS)


def _sanitize_headers(headers: Mapping[str, Any] | None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in (headers or {}).items():
        if _is_secret_key(key):
            continue
        clean[str(key)] = _sanitize_metadata_value(value)
    return clean


def _sanitize_response_metadata(response_metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if response_metadata is None:
        return {}
    return _sanitize_metadata_mapping(response_metadata)


def _sanitize_metadata_mapping(metadata: Mapping[str, Any], *, parent_key: str | None = None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        lowered = str(key).strip().lower()
        if _is_secret_key(key):
            continue
        if lowered in _HEADER_CONTAINER_KEYS or lowered.endswith("_headers"):
            clean[str(key)] = _sanitize_headers(value if isinstance(value, Mapping) else {})
            continue
        clean[str(key)] = _sanitize_metadata_value(value, parent_key=lowered)
    return clean


def _sanitize_metadata_value(value: Any, *, parent_key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return _sanitize_metadata_mapping(value, parent_key=parent_key)
    if isinstance(value, list):
        return [_sanitize_metadata_value(item, parent_key=parent_key) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_metadata_value(item, parent_key=parent_key) for item in value]
    return value


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _atomic_write_text(path: Path, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))


def _atomic_write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    fieldnames: list[str] | tuple[str, ...] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    resolved_fieldnames = list(fieldnames or (rows[0].keys() if rows else []))
    if not resolved_fieldnames:
        _atomic_write_text(path, "")
        return
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=resolved_fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _extract_incident_address(references: tuple[str, ...]) -> str | None:
    for reference in references:
        match = _ADDRESS_RE.search(reference)
        if match:
            return match.group(1).lower()
    return None


def _incident_key(entry: Any) -> str:
    if getattr(entry, "basename_keys", ()):
        return str(entry.basename_keys[0])
    title = re.sub(r"[^a-z0-9]+", "", str(entry.title).lower())
    return title


def _normalized_row_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in row.items():
        if key == "normalized_row_sha256":
            continue
        if pd.isna(value):
            payload[str(key)] = None
            continue
        payload[str(key)] = value
    return payload


def _normalized_row_sha256(row: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(_normalized_row_payload(row)).encode("utf-8")).hexdigest()


def canonical_normalized_incident_row_sha256(row: Mapping[str, Any] | pd.Series) -> str:
    return _normalized_row_sha256(row)


def freeze_incident_metadata_bytes(
    raw_bytes: bytes,
    source_url: str,
    response_metadata: Mapping[str, Any] | None,
    output_root: str | Path,
    *,
    retrieval_utc: str | None = None,
) -> dict[str, Any]:
    root = Path(output_root)
    raw_sha256 = _sha256_bytes(raw_bytes)
    retrieval_utc_value = _normalize_retrieval_utc(retrieval_utc)
    raw_path = root / "raw" / raw_sha256[:2] / f"{raw_sha256}.bin"
    raw_metadata_path = root / "raw" / raw_sha256[:2] / f"{raw_sha256}.json"
    source_name = Path(urlsplit(source_url).path).name or "incident_metadata.md"
    entries = parse_defihacklabs_snapshot_bytes(
        raw_bytes,
        source_name=source_name,
        source_url=source_url,
    )
    normalized_rows = [
        {
            "incident_key": _incident_key(entry),
            "incident_name": entry.title,
            "incident_date": entry.incident_date,
            "incident_chain": entry.inferred_chain,
            "incident_type": entry.mechanism_raw,
            "incident_loss_text": entry.loss_text,
            "incident_contract_path": entry.contract_paths[0] if entry.contract_paths else "",
            "incident_address": _extract_incident_address(entry.references),
            "source_url": source_url,
            "source_status": "frozen_public_source_hashed",
            "source_role": "incident_metadata_only",
            "source_snapshot_sha256": raw_sha256,
            "raw_sha256": raw_sha256,
            "source_block_sha256": entry.block_sha256,
            "incident_reference_urls": json.dumps(list(entry.references), sort_keys=True),
            "incident_tx_hashes": json.dumps(list(entry.tx_hashes), sort_keys=True),
        }
        for entry in entries
    ]
    normalized_rows = [
        {**row, "normalized_row_sha256": _normalized_row_sha256(row)}
        for row in normalized_rows
    ]
    normalized_path = root / "normalized" / f"incident_metadata_{raw_sha256[:12]}.csv"
    manifest_path = root / "normalized" / f"incident_metadata_{raw_sha256[:12]}.manifest.json"
    _atomic_write_bytes(raw_path, raw_bytes)
    _atomic_write_text(
        raw_metadata_path,
        json.dumps(
            {
                "source_url": source_url,
                "sha256": raw_sha256,
                "bytes": len(raw_bytes),
                "retrieval_utc": retrieval_utc_value,
                "response_metadata": _sanitize_response_metadata(response_metadata),
            },
            indent=2,
            sort_keys=True,
        ),
    )
    _atomic_write_csv(normalized_path, normalized_rows)
    manifest = {
        "source_url": source_url,
        "source_name": source_name,
        "raw_sha256": raw_sha256,
        "raw_artifact_path": _portable_path(raw_path, root=root),
        "raw_metadata_path": _portable_path(raw_metadata_path, root=root),
        "normalized_csv_path": _portable_path(normalized_path, root=root),
        "retrieval_utc": retrieval_utc_value,
        "normalized_row_count": len(normalized_rows),
        "normalized_row_sha256": [row["normalized_row_sha256"] for row in normalized_rows],
        "source_role": "incident_metadata_only",
    }
    manifest["manifest_sha256"] = hashlib.sha256(_canonical_json(manifest).encode("utf-8")).hexdigest()
    _atomic_write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True))
    return {
        **manifest,
        "manifest_path": _portable_path(manifest_path, root=root),
    }


def _normalized_incident_key(row: pd.Series) -> str:
    candidate = row.get("incident_key", row.get("incident_name", ""))
    return re.sub(r"[^a-z0-9]+", "", str(candidate or "").lower())


def match_incident_metadata(canonical: pd.DataFrame, normalized: pd.DataFrame) -> pd.DataFrame:
    out = canonical.copy()
    normalized_copy = normalized.copy()
    normalized_copy["__incident_key__"] = normalized_copy.apply(_normalized_incident_key, axis=1)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in normalized_copy.to_dict(orient="records"):
        grouped.setdefault(str(record["__incident_key__"]), []).append(record)

    appended_rows: list[dict[str, Any]] = []
    for _, row in out.iterrows():
        key = re.sub(r"[^a-z0-9]+", "", str(row["case_name"]).lower())
        candidates = grouped.get(key, [])
        payload = row.to_dict()
        payload["incident_match_candidate_count"] = len(candidates)
        if not candidates:
            payload["incident_match_status"] = "missing"
            appended_rows.append(payload)
            continue
        if len(candidates) > 1:
            payload["incident_match_status"] = "multiple"
            appended_rows.append(payload)
            continue

        candidate = candidates[0]
        for field, value in candidate.items():
            if field == "__incident_key__":
                continue
            if field in {"chain", "address", "incident_block", "case_id", "case_name"}:
                continue
            payload[field] = value

        conflict_fields: list[str] = []
        incident_chain = candidate.get("incident_chain")
        if incident_chain and pd.notna(incident_chain):
            if _normalize_chain(incident_chain) != _normalize_chain(row["chain"]):
                conflict_fields.append("chain")
        incident_address = candidate.get("incident_address")
        if incident_address and pd.notna(incident_address):
            if _normalize_address(incident_address) != _normalize_address(row["address"]):
                conflict_fields.append("address")
        payload["incident_match_status"] = "conflict" if conflict_fields else "exact_unique"
        payload["incident_match_conflict_fields"] = json.dumps(conflict_fields)
        appended_rows.append(payload)

    return pd.DataFrame(appended_rows)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8")


def _is_sha256(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in _SHA256_HEX for ch in text)


def _verified_family_name(value: Any) -> str | None:
    lowered = str(value or "").strip().lower()
    if not lowered or lowered.startswith("unverified"):
        return None
    return lowered


def _safe_receipt_path(path_value: Any, *, allowed_root: Path) -> Path:
    try:
        path = Path(str(path_value or "")).resolve(strict=False)
    except Exception as exc:  # pragma: no cover - defensive normalization
        raise ValueError("receipt_hash_path_error") from exc
    root = allowed_root.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("receipt_hash_path_error") from exc
    if not path.is_file() or path.is_symlink():
        raise ValueError("receipt_hash_path_error")
    return path


def _expected_receipt_path(*, allowed_root: Path, response_sha256: str) -> Path:
    normalized = str(response_sha256 or "").strip().lower()
    if not _is_sha256(normalized):
        raise ValueError("receipt_hash_path_error")
    return allowed_root.resolve() / normalized[:2] / f"{normalized}.json"


def _normalize_transition_case(case: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(case.get("case_id") or "").strip()
    if not case_id:
        raise ValueError("case_id must be non-empty")
    address = _normalize_address(case.get("address") or case.get("target_contract_address"))
    chain = _normalize_chain(case.get("chain"))
    block_value = case.get("fork_block_number", case.get("incident_block"))
    incident_block = _normalize_incident_block(block_value)
    input_row_sha256 = str(case.get("input_row_sha256") or "").strip().lower()
    if not _is_sha256(input_row_sha256):
        raise ValueError("input_row_sha256 must be a sha256 digest")
    return {
        "case_id": case_id,
        "chain": chain,
        "address": address,
        "incident_block": incident_block,
        "input_row_sha256": input_row_sha256,
    }


def _provider_identity_summary(providers: list[Any]) -> dict[str, Any]:
    families: dict[str, dict[str, Any]] = {}
    providers_index: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    for provider in providers:
        provider_id = str(getattr(provider, "provider_id", "") or "").strip()
        family = _verified_family_name(getattr(provider, "provider_family", None))
        provider_identity = str(getattr(provider, "public_endpoint_id", "") or "").strip()
        evidence = dict(getattr(provider, "provider_identity_evidence", {}) or {})
        endpoint_template_sha256 = str(evidence.get("endpoint_template_sha256") or "").strip().lower()
        operator_evidence_url = str(evidence.get("operator_evidence_url") or "").strip()
        evidence_provider_id = str(evidence.get("provider_id") or provider_id).strip()
        provider_complete = bool(
            provider_id
            and family
            and provider_identity
            and evidence_provider_id == provider_id
            and _is_sha256(endpoint_template_sha256)
            and operator_evidence_url
        )
        if not provider_complete:
            errors.append("incomplete_identity")
        if not family:
            continue
        family_entry = families.setdefault(
            family,
            {
                "family_id": family,
                "operator_verified": True,
                "complete": True,
                "endpoint_template_sha256": endpoint_template_sha256 if _is_sha256(endpoint_template_sha256) else "",
                "evidence": [],
            },
        )
        family_entry["complete"] = bool(family_entry["complete"] and provider_complete)
        family_entry["evidence"].append(
            {
                "provider_id": provider_id,
                "provider_identity": provider_identity,
                "endpoint_template_sha256": endpoint_template_sha256 if _is_sha256(endpoint_template_sha256) else "",
                "operator_evidence_url": operator_evidence_url,
            }
        )
        if provider_complete:
            providers_index[provider_id] = {
                "family_id": family,
                "provider_identity": provider_identity,
            }
    distinct_families = sorted(families.keys())
    complete = bool(len(distinct_families) >= 2 and not errors and providers_index)
    return {
        "complete": complete,
        "families": [families[key] for key in distinct_families],
        "providers": providers_index,
        "errors": list(dict.fromkeys(errors)),
    }


def _sanitized_provider_record(provider: Any, *, chain: str) -> tuple[dict[str, Any], set[str], str | None]:
    provider_id = str(getattr(provider, "provider_id", "") or "").strip()
    family = _verified_family_name(getattr(provider, "provider_family", None))
    identity = str(getattr(provider, "public_endpoint_id", "") or "").strip()
    evidence = dict(getattr(provider, "provider_identity_evidence", {}) or {})
    endpoint_template_sha256 = str(evidence.get("endpoint_template_sha256") or "").strip().lower()

    errors: set[str] = set()
    if family is None:
        errors.add("unverified_family")
    if not provider_id or not identity or not _is_sha256(endpoint_template_sha256):
        errors.add("incomplete_identity")

    sanitized_evidence = {
        "chain": chain,
        "provider_id": provider_id,
        "provider_identity_id": identity,
        "endpoint_template_sha256": endpoint_template_sha256 if _is_sha256(endpoint_template_sha256) else "",
        "verified_operator_family": family or "",
    }
    return (
        {
            "chain": chain,
            "provider_id": provider_id,
            "verified_operator_family": family or "",
            "public_endpoint_identity_id": identity,
            "public_endpoint_identity_sha256": _sha256_json(identity) if identity else "",
            "endpoint_template_sha256": endpoint_template_sha256 if _is_sha256(endpoint_template_sha256) else "",
            "identity_evidence_sha256": _sha256_json(sanitized_evidence),
            "complete": not errors,
        },
        errors,
        family,
    )


def _provider_identity_verification_report(
    providers_by_chain: Mapping[str, list[Any]],
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    chains: list[dict[str, Any]] = []
    blockers_by_chain: dict[str, list[str]] = {}
    all_errors: set[str] = set()
    for chain in sorted(providers_by_chain):
        sanitized_records: list[dict[str, Any]] = []
        errors: set[str] = set()
        verified_families: set[str] = set()
        for provider in sorted(
            providers_by_chain[chain],
            key=lambda item: (
                str(getattr(item, "provider_id", "") or ""),
                str(getattr(item, "public_endpoint_id", "") or ""),
            ),
        ):
            sanitized, record_errors, family = _sanitized_provider_record(provider, chain=chain)
            sanitized_records.append(sanitized)
            errors.update(record_errors)
            if family:
                verified_families.add(family)
        if len(verified_families) < 2:
            errors.add("same_family")
        ordered_errors = sorted(errors)
        chain_complete = bool(sanitized_records) and not ordered_errors
        chains.append(
            {
                "chain": chain,
                "complete": chain_complete,
                "errors": ordered_errors,
                "provider_count": len(sanitized_records),
                "verified_operator_families": sorted(verified_families),
                "providers": sanitized_records,
            }
        )
        mapped_blockers: list[str] = []
        if "same_family" in errors:
            mapped_blockers.append("provider_identity_same_family")
        if "unverified_family" in errors:
            mapped_blockers.append("provider_identity_unverified")
        if "incomplete_identity" in errors:
            mapped_blockers.append("provider_identity_incomplete")
        if mapped_blockers:
            blockers_by_chain[chain] = sorted(set(mapped_blockers))
        all_errors.update(ordered_errors)
    report = {
        "schema_version": "historical_snapshot_provider_identity_verification.v1",
        "complete": bool(chains) and not blockers_by_chain,
        "chain_count": len(chains),
        "errors": sorted(all_errors),
        "chains": chains,
    }
    report["report_sha256"] = _sha256_json(
        {
            "schema_version": report["schema_version"],
            "complete": report["complete"],
            "chain_count": report["chain_count"],
            "errors": report["errors"],
            "chains": report["chains"],
        }
    )
    return report, blockers_by_chain


def _collect_receipt_references(value: Any) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    if isinstance(value, Mapping):
        raw_path = value.get("raw_response_path")
        response_sha256 = value.get("response_sha256")
        if raw_path is not None or response_sha256 is not None:
            references.append(
                {
                    "raw_response_path": str(raw_path or "").strip(),
                    "response_sha256": str(response_sha256 or "").strip().lower(),
                }
            )
        for nested in value.values():
            references.extend(_collect_receipt_references(nested))
    elif isinstance(value, list):
        for nested in value:
            references.extend(_collect_receipt_references(nested))
    return references


def _receipt_reference_relpath(raw_path: str, *, run_root: Path, receipt_root: Path) -> str:
    candidate = Path(raw_path)
    # Absolute paths are transport metadata, not receipt identity. Permit a
    # relocated sealed run only when the reference retains the canonical
    # content-addressed `rpc_receipts/<prefix>/<sha>.json` suffix.
    if candidate.is_absolute() and len(candidate.parts) >= 3:
        suffix = candidate.parts[-3:]
        if suffix[0] == receipt_root.name:
            candidate = Path(*suffix)
    if candidate.is_absolute():
        absolute = candidate
    else:
        candidate_parts = candidate.parts
        if candidate_parts and candidate_parts[0] == receipt_root.name:
            absolute = run_root / candidate
        else:
            absolute = receipt_root / candidate
    resolved = absolute.resolve(strict=False)
    receipt_resolved = receipt_root.resolve(strict=False)
    try:
        resolved.relative_to(receipt_resolved)
    except ValueError as exc:
        raise ValueError("receipt_reference_path_invalid") from exc
    try:
        return _portable_path(resolved, root=run_root)
    except ValueError as exc:
        raise ValueError("receipt_reference_path_invalid") from exc


def _receipt_reference_index(
    run_root: Path,
    *,
    receipt_root: Path,
    selected_cases: list[dict[str, Any]],
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    case_ids_by_digest: dict[str, set[str]] = {}
    case_ids_by_path: dict[str, set[str]] = {}
    case_blockers: dict[str, set[str]] = {}
    for case in selected_cases:
        case_id = str(case["case_id"])
        envelope_path = run_root / "cases" / f"{case_id}.json"
        try:
            persisted = json.loads(envelope_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for reference in _collect_receipt_references(persisted):
            response_sha256 = str(reference["response_sha256"]).strip().lower()
            raw_response_path = str(reference["raw_response_path"]).strip()
            if not _is_sha256(response_sha256):
                case_blockers.setdefault(case_id, set()).add("receipt_binding_invalid")
                continue
            expected_path = _portable_path(
                receipt_root / response_sha256[:2] / f"{response_sha256}.json",
                root=run_root,
            )
            try:
                actual_path = _receipt_reference_relpath(
                    raw_response_path,
                    run_root=run_root,
                    receipt_root=receipt_root,
                )
            except ValueError:
                case_blockers.setdefault(case_id, set()).add("receipt_binding_invalid")
                continue
            if actual_path != expected_path:
                case_blockers.setdefault(case_id, set()).add("receipt_binding_invalid")
            case_ids_by_digest.setdefault(response_sha256, set()).add(case_id)
            case_ids_by_path.setdefault(actual_path, set()).add(case_id)
    return case_ids_by_digest, case_ids_by_path, case_blockers


def _invalid_receipt_entry(
    *,
    path: str,
    receipt_sha256: str = "",
    content_sha256: str = "",
    code: str,
) -> dict[str, Any]:
    payload = {
        "path": path,
        "receipt_sha256": receipt_sha256,
        "content_sha256": content_sha256,
        "code": code,
    }
    payload["entry_sha256"] = _sha256_json(payload)
    return payload


def _scan_receipt_manifest(
    run_root: Path,
    *,
    receipt_root: Path,
    selected_cases: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    case_ids_by_digest, case_ids_by_path, case_blockers = _receipt_reference_index(
        run_root,
        receipt_root=receipt_root,
        selected_cases=selected_cases,
    )
    valid_entries: list[dict[str, Any]] = []
    invalid_entries: list[dict[str, Any]] = []
    valid_digests: set[str] = set()
    valid_paths: set[str] = set()
    invalid_digests: set[str] = set()
    invalid_paths: set[str] = set()

    receipt_resolved = receipt_root.resolve(strict=False)
    scanned_files: list[dict[str, Any]] = []
    if receipt_root.exists():
        for directory, dirnames, filenames in os.walk(receipt_root, topdown=True, followlinks=False):
            dirnames.sort()
            filenames.sort()
            directory_path = Path(directory)
            kept_dirnames: list[str] = []
            for dirname in dirnames:
                child = directory_path / dirname
                if child.is_symlink():
                    invalid_entries.append(
                        _invalid_receipt_entry(
                            path=_portable_path(child, root=run_root),
                            code="symlink",
                        )
                    )
                    continue
                kept_dirnames.append(dirname)
            dirnames[:] = kept_dirnames
            for filename in filenames:
                path = directory_path / filename
                relpath = _portable_path(path, root=run_root)
                if path.is_symlink():
                    invalid_entries.append(
                        _invalid_receipt_entry(path=relpath, code="symlink")
                    )
                    continue
                resolved = path.resolve(strict=False)
                try:
                    resolved.relative_to(receipt_resolved)
                except ValueError:
                    invalid_entries.append(
                        _invalid_receipt_entry(path=relpath, code="path_escape")
                    )
                    continue
                if not path.is_file():
                    invalid_entries.append(
                        _invalid_receipt_entry(path=relpath, code="nonregular")
                    )
                    continue
                receipt_sha256 = ""
                rel_to_receipt = path.relative_to(receipt_root)
                errors: set[str] = set()
                if len(rel_to_receipt.parts) != 2:
                    errors.add("malformed_name")
                else:
                    shard, name = rel_to_receipt.parts
                    if not re.fullmatch(r"[0-9a-f]{2}", shard):
                        errors.add("malformed_name")
                    if not name.endswith(".json"):
                        errors.add("malformed_name")
                    else:
                        receipt_sha256 = name[:-5].lower()
                        if not _is_sha256(receipt_sha256):
                            errors.add("malformed_name")
                        elif shard != receipt_sha256[:2]:
                            errors.add("wrong_shard")
                raw_bytes = path.read_bytes()
                content_sha256 = hashlib.sha256(raw_bytes).hexdigest()
                if receipt_sha256 and content_sha256 != receipt_sha256:
                    errors.add("content_mismatch")
                scanned_files.append(
                    {
                        "path": relpath,
                        "receipt_sha256": receipt_sha256,
                        "content_sha256": content_sha256,
                        "bytes": len(raw_bytes),
                        "errors": errors,
                    }
                )

    digest_counts: dict[str, int] = {}
    path_counts: dict[str, int] = {}
    for entry in scanned_files:
        if entry["receipt_sha256"]:
            digest_counts[entry["receipt_sha256"]] = digest_counts.get(entry["receipt_sha256"], 0) + 1
        path_counts[entry["path"]] = path_counts.get(entry["path"], 0) + 1

    for entry in scanned_files:
        errors = set(entry["errors"])
        if entry["receipt_sha256"] and digest_counts.get(entry["receipt_sha256"], 0) > 1:
            errors.add("duplicate_digest")
        if path_counts.get(entry["path"], 0) > 1:
            errors.add("duplicate_path")
        if errors:
            invalid_entries.append(
                _invalid_receipt_entry(
                    path=entry["path"],
                    receipt_sha256=entry["receipt_sha256"],
                    content_sha256=entry["content_sha256"],
                    code=sorted(errors)[0],
                )
            )
            if entry["receipt_sha256"]:
                invalid_digests.add(entry["receipt_sha256"])
            invalid_paths.add(entry["path"])
            continue
        valid_entries.append(
            {
                "path": entry["path"],
                "receipt_sha256": entry["receipt_sha256"],
                "bytes": entry["bytes"],
            }
        )
        valid_digests.add(entry["receipt_sha256"])
        valid_paths.add(entry["path"])

    for receipt_sha256, case_ids in case_ids_by_digest.items():
        expected_path = _portable_path(
            receipt_root / receipt_sha256[:2] / f"{receipt_sha256}.json",
            root=run_root,
        )
        if receipt_sha256 in valid_digests and expected_path in valid_paths:
            continue
        for case_id in case_ids:
            case_blockers.setdefault(case_id, set()).add("receipt_binding_invalid")
    for path, case_ids in case_ids_by_path.items():
        if path in valid_paths:
            continue
        for case_id in case_ids:
            case_blockers.setdefault(case_id, set()).add("receipt_binding_invalid")

    manifest = {
        "schema_version": "historical_snapshot_rpc_receipt_manifest.v1",
        "valid_receipt_count": len(valid_entries),
        "invalid_receipt_count": len(invalid_entries),
        "receipts": sorted(valid_entries, key=lambda item: (item["receipt_sha256"], item["path"])),
        "invalid_receipts": sorted(
            invalid_entries,
            key=lambda item: (item["code"], item["receipt_sha256"], item["path"]),
        ),
    }
    manifest["manifest_sha256"] = _sha256_json(
        {
            "schema_version": manifest["schema_version"],
            "valid_receipt_count": manifest["valid_receipt_count"],
            "invalid_receipt_count": manifest["invalid_receipt_count"],
            "receipts": manifest["receipts"],
            "invalid_receipts": manifest["invalid_receipts"],
        }
    )
    return manifest, {case_id: sorted(codes) for case_id, codes in sorted(case_blockers.items())}


def _with_aggregate_blockers(
    *,
    qualification_rows: list[dict[str, str]],
    blocker_rows: list[dict[str, str]],
    results_by_case_id: Mapping[str, dict[str, Any]],
    receipt_case_blockers: Mapping[str, list[str]],
    provider_chain_blockers: Mapping[str, list[str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, list[str]]]:
    combined_case_blockers: dict[str, list[str]] = {}
    updated_rows: list[dict[str, str]] = []
    for row in qualification_rows:
        case_id = row["case_id"]
        chain = row["chain"]
        aggregate_codes = sorted(
            set(receipt_case_blockers.get(case_id, [])) | set(provider_chain_blockers.get(chain, []))
        )
        result_codes = [
            str(code).strip()
            for code in (results_by_case_id[case_id].get("blockers") or [])
            if str(code).strip()
        ]
        combined_case_blockers[case_id] = sorted(set(result_codes) | set(aggregate_codes))
        updated = dict(row)
        if aggregate_codes:
            updated["candidate_closed"] = "false"
            updated["status"] = "PARTIAL"
        updated_rows.append(updated)

    merged_blockers = list(blocker_rows)
    for row in updated_rows:
        for code in combined_case_blockers[row["case_id"]]:
            merged_blockers.append(
                {
                    "chain": row["chain"],
                    "case_id": row["case_id"],
                    "code": code,
                }
            )
    unique_blockers = {
        (row["chain"], row["case_id"], row["code"]): row for row in merged_blockers if row["code"]
    }
    ordered_blockers = sorted(unique_blockers.values(), key=lambda row: (row["chain"], row["case_id"], row["code"]))
    return updated_rows, ordered_blockers, combined_case_blockers


def _candidate_closures_by_chain(qualification_rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in qualification_rows:
        counts.setdefault(row["chain"], 0)
        if row["candidate_closed"] == "true":
            counts[row["chain"]] += 1
    return {chain: counts[chain] for chain in sorted(counts)}


def _blockers_by_chain_code(blocker_rows: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    buckets: dict[str, dict[str, int]] = {}
    for row in blocker_rows:
        chain_bucket = buckets.setdefault(row["chain"], {})
        chain_bucket[row["code"]] = chain_bucket.get(row["code"], 0) + 1
    return {
        chain: {code: buckets[chain][code] for code in sorted(buckets[chain])}
        for chain in sorted(buckets)
    }


def _provider_families_by_chain(provider_report: Mapping[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for chain_entry in provider_report.get("chains", []):
        if not isinstance(chain_entry, Mapping):
            continue
        chain = str(chain_entry.get("chain") or "").strip()
        if not chain:
            continue
        result[chain] = list(chain_entry.get("verified_operator_families") or [])
    return {chain: result[chain] for chain in sorted(result)}


def _historical_snapshot_closure_report(
    *,
    binding: Mapping[str, Any],
    qualification_rows: list[dict[str, str]],
    blocker_rows: list[dict[str, str]],
    receipt_manifest: Mapping[str, Any],
    provider_report: Mapping[str, Any],
) -> dict[str, Any]:
    reused_case_count = sum(1 for row in qualification_rows if row["resumed"] == "true")
    quarantined_case_count = sum(1 for row in qualification_rows if row["quarantined"] == "true")
    retried_case_count = sum(1 for row in qualification_rows if row["retried"] == "true")
    report = {
        "schema_version": "historical_snapshot_closure_report.v1",
        "target_case_count": FULL_CASE_TARGET,
        "population_case_count": int(binding["population"]["actual_case_count"]),
        "selected_case_count": len(qualification_rows),
        "processed_case_count": len(qualification_rows),
        "candidate_closures_by_chain": _candidate_closures_by_chain(qualification_rows),
        "reused_case_count": reused_case_count,
        "quarantined_case_count": quarantined_case_count,
        "retried_case_count": retried_case_count,
        "blockers_by_chain": _blockers_by_chain_code(blocker_rows),
        "valid_receipt_count": int(receipt_manifest["valid_receipt_count"]),
        "invalid_receipt_count": int(receipt_manifest["invalid_receipt_count"]),
        "provider_families_by_chain": _provider_families_by_chain(provider_report),
        "counter_authority": False,
        "offline_verification_required": True,
        "historical_snapshots_observed": 0,
    }
    report["report_sha256"] = _sha256_json(
        {
            key: value
            for key, value in report.items()
            if key not in {"report_sha256"}
        }
    )
    return report


def _update_run_manifest_with_aggregates(
    run_root: Path,
    *,
    binding: Mapping[str, Any],
    frozen_entries: list[dict[str, Any]],
    aggregate_paths: Mapping[str, str],
    aggregate_hashes: Mapping[str, str],
    summary: Mapping[str, Any],
) -> None:
    manifest = _canonical_run_manifest(
        binding=binding,
        frozen_entries=frozen_entries,
        aggregate_paths=aggregate_paths,
        summary=summary,
    )
    manifest["aggregate_hashes"] = dict(aggregate_hashes)
    authoritative = {
        "binding_sha256": manifest["binding_sha256"],
        "frozen_inputs_sha256": _frozen_inputs_hash(frozen_entries),
        "aggregate_paths": dict(aggregate_paths),
        "aggregate_hashes": dict(aggregate_hashes),
        "summary": dict(summary),
    }
    manifest["authoritative_sha256"] = _sha256_json(authoritative)
    _atomic_write_text(
        run_root / "run_manifest.json",
        _canonical_json_bytes(manifest).decode("utf-8"),
    )


def _annotate_observation(provider: Any, observation: Any) -> dict[str, Any]:
    payload = dict(getattr(observation, "__dict__", {}) or {})
    payload["provider_id"] = str(getattr(provider, "provider_id", payload.get("provider_id", "")) or "")
    payload["provider_family"] = str(
        getattr(provider, "provider_family", payload.get("provider_family", "")) or ""
    ).strip().lower()
    payload["provider_identity"] = str(
        getattr(provider, "public_endpoint_id", payload.get("provider_identity", "")) or ""
    ).strip()
    params = list(payload.get("params", []) or [])
    method = str(payload.get("method", "") or "")
    payload["block_selector"] = params[0] if method == "eth_getBlockByNumber" and params else (params[-1] if params else None)
    return payload


def _validate_receipt_binding(observation: dict[str, Any], *, receipt_root: Path) -> list[str]:
    errors: list[str] = []
    if not str(observation.get("method", "")).strip():
        errors.append("receipt_hash_path_error")
    if not str(observation.get("observed_at_utc", "")).strip():
        errors.append("receipt_hash_path_error")
    if not _is_sha256(observation.get("request_sha256")):
        errors.append("receipt_hash_path_error")
    response_sha = str(observation.get("response_sha256") or "").strip().lower()
    if not _is_sha256(response_sha):
        errors.append("receipt_hash_path_error")
    if errors:
        return list(dict.fromkeys(errors))
    try:
        raw_path = _safe_receipt_path(observation.get("raw_response_path"), allowed_root=receipt_root)
        expected_path = _expected_receipt_path(allowed_root=receipt_root, response_sha256=response_sha)
    except ValueError:
        return ["receipt_hash_path_error"]
    if raw_path != expected_path:
        return ["receipt_hash_path_error"]
    if hashlib.sha256(raw_path.read_bytes()).hexdigest() != response_sha:
        return ["receipt_hash_path_error"]
    return []


def _normalize_code_result(value: Any) -> str:
    return normalize_hex(value)


def _normalize_header_result(value: Any) -> dict[str, Any]:
    header = normalize_block_header(value)
    if header is None:
        raise ValueError("missing header")
    raw = dict(value)
    return {
        "number": int(str(raw["number"]), 16),
        "hash": header["hash"],
        "timestamp": int(str(raw["timestamp"]), 16),
    }


def _consensus_observations(
    providers: list[Any],
    *,
    method: str,
    params_builder: Any,
    normalizer: Any,
    receipt_root: Path,
    provider_identity: dict[str, Any],
) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    blockers: list[str] = []
    normalized_values: dict[str, Any] = {}
    families: set[str] = set()
    for provider in providers:
        params = params_builder(provider)
        observation = _annotate_observation(provider, provider.call(method, params))
        observations.append(observation)
        blockers.extend(_validate_receipt_binding(observation, receipt_root=receipt_root))
        provider_id = str(observation.get("provider_id", "")).strip()
        binding = (provider_identity.get("providers") or {}).get(provider_id)
        if binding is None or binding.get("family_id") != _verified_family_name(observation.get("provider_family")):
            blockers.append("incomplete_identity")
        if (
            binding is None
            or binding.get("provider_identity") != str(observation.get("provider_identity", "")).strip()
        ):
            blockers.append("incomplete_identity")
        if observation.get("error") not in (None, ""):
            blockers.append("missing_historical_header" if method == "eth_getBlockByNumber" else "missing_historical_code")
            continue
        try:
            normalized = normalizer(observation.get("result"))
        except Exception:
            blockers.append("missing_historical_header" if method == "eth_getBlockByNumber" else "missing_historical_code")
            continue
        key = _canonical_json(normalized)
        normalized_values.setdefault(key, normalized)
        family = _verified_family_name(observation.get("provider_family"))
        if family:
            families.add(family)
    if len(families) < 2:
        blockers.append("same_family")
    if len(normalized_values) > 1:
        blockers.append("provider_disagreement")
    status = "consensus" if not blockers and len(normalized_values) == 1 else "partial"
    value = next(iter(normalized_values.values())) if len(normalized_values) == 1 else None
    return {
        "status": status,
        "value": value,
        "observations": observations,
        "agreement_provider_families": sorted(families),
        "blockers": list(dict.fromkeys(blockers)),
    }


def discover_deployment_transition(
    case: Mapping[str, Any],
    providers: list[Any],
    receipt_root: str | Path,
    *,
    max_search_calls: int = 64,
    discovery_provider_index: int = 0,
) -> dict[str, Any]:
    normalized_case = _normalize_transition_case(case)
    if max_search_calls <= 0:
        raise ValueError("max_search_calls must be > 0")
    if not providers:
        raise ValueError("providers must be non-empty")
    if discovery_provider_index < 0 or discovery_provider_index >= len(providers):
        raise ValueError("discovery_provider_index out of range")

    root = Path(receipt_root)
    identity = _provider_identity_summary(providers)
    blockers = list(identity["errors"])
    discovery_provider = providers[discovery_provider_index]
    search_calls = 0
    search_observations: list[dict[str, Any]] = []
    optional_unbound_probe_failures: list[dict[str, Any]] = []
    observed_code_values: dict[tuple[str, int], set[str]] = {}
    candidate_block: int | None = None

    def record_observation(block_number: int, normalized_code: str | None, observation: dict[str, Any]) -> None:
        if normalized_code is None:
            return
        key = (str(observation.get("provider_id", "")).strip(), block_number)
        observed_code_values.setdefault(key, set()).add(normalized_code)

    def search_code(block_number: int, *, required: bool = True) -> str | None:
        nonlocal search_calls
        if search_calls >= max_search_calls:
            blockers.append("search_budget_exceeded")
            return None
        search_calls += 1
        observation = _annotate_observation(
            discovery_provider,
            discovery_provider.call("eth_getCode", [normalized_case["address"], hex(block_number)]),
        )
        observation["search_block_number"] = block_number
        observation["search_stage"] = "discovery"
        receipt_errors = _validate_receipt_binding(observation, receipt_root=root)
        optional_unbound_failure = (
            not required
            and observation.get("error") not in (None, "")
            and bool(receipt_errors)
        )
        if optional_unbound_failure:
            optional_unbound_probe_failures.append(
                {
                    "method": "eth_getCode",
                    "provider_id": str(observation.get("provider_id", "")).strip(),
                    "search_block_number": block_number,
                    "status": "receipt_unavailable",
                }
            )
        else:
            search_observations.append(observation)
        if required or observation.get("error") in (None, ""):
            blockers.extend(receipt_errors)
        provider_id = str(observation.get("provider_id", "")).strip()
        binding = (identity.get("providers") or {}).get(provider_id)
        if binding is None or binding.get("provider_identity") != str(observation.get("provider_identity", "")).strip():
            blockers.append("incomplete_identity")
        if observation.get("error") not in (None, ""):
            if required:
                blockers.append("missing_historical_code")
            return None
        try:
            normalized = _normalize_code_result(observation.get("result"))
        except Exception:
            if required:
                blockers.append("missing_historical_code")
            return None
        record_observation(block_number, normalized, observation)
        return normalized

    incident_block = int(normalized_case["incident_block"])
    fork_code = search_code(incident_block)
    if fork_code == "0x":
        blockers.append("fork_code_empty")
    if fork_code not in (None, "0x"):
        zero_code = search_code(0, required=False)
        if zero_code not in (None, "0x"):
            blockers.append("candidate0")
            candidate_block = 0
        else:
            upper = incident_block
            lower: int | None = 0 if zero_code == "0x" else None
            if lower is None:
                stride = 1
                while not blockers and search_calls < max_search_calls:
                    probe = max(1, incident_block - stride)
                    if probe >= upper:
                        stride *= 2
                        continue
                    probe_code = search_code(probe, required=False)
                    if probe_code == "0x":
                        lower = probe
                        break
                    if probe_code not in (None, "0x"):
                        upper = probe
                    if probe == 1:
                        break
                    stride *= 2
                if lower is None:
                    blockers.append("missing_historical_code")
            if lower is not None:
                while not blockers and lower + 1 < upper:
                    midpoint = (lower + upper) // 2
                    midpoint_code = search_code(midpoint)
                    if midpoint_code is None:
                        break
                    if midpoint_code == "0x":
                        lower = midpoint
                    else:
                        upper = midpoint
                if not blockers:
                    candidate_block = upper

    if candidate_block is not None:
        sorted_search = sorted(
            (int(observation["search_block_number"]), _normalize_code_result(observation["result"]))
            for observation in search_observations
            if observation.get("error") in (None, "")
        )
        for block_number, code in sorted_search:
            if (block_number < candidate_block and code != "0x") or (block_number >= candidate_block and code == "0x"):
                blockers.append("nonmonotonic_or_ambiguous_observations")
                break
    if any(len(values) > 1 for values in observed_code_values.values()):
        blockers.append("nonmonotonic_or_ambiguous_observations")

    proof = {
        "headers": {"previous": {"status": "missing", "value": None, "observations": []}, "candidate": {"status": "missing", "value": None, "observations": []}},
        "code": {"previous": {"status": "missing", "value": None, "observations": []}, "candidate": {"status": "missing", "value": None, "observations": []}},
    }
    candidate_timestamp: int | None = None
    hard_stop = {"fork_code_empty", "candidate0", "search_budget_exceeded", "missing_historical_code", "receipt_hash_path_error"}
    if candidate_block is not None and candidate_block > 0 and not hard_stop.intersection(blockers):
        previous_block = candidate_block - 1
        header_previous = _consensus_observations(
            providers,
            method="eth_getBlockByNumber",
            params_builder=lambda _provider: [hex(previous_block), False],
            normalizer=_normalize_header_result,
            receipt_root=root,
            provider_identity=identity,
        )
        header_candidate = _consensus_observations(
            providers,
            method="eth_getBlockByNumber",
            params_builder=lambda _provider: [hex(candidate_block), False],
            normalizer=_normalize_header_result,
            receipt_root=root,
            provider_identity=identity,
        )
        proof["headers"]["previous"] = header_previous
        proof["headers"]["candidate"] = header_candidate
        blockers.extend(header_previous["blockers"])
        blockers.extend(header_candidate["blockers"])
        if header_previous["status"] == "consensus" and header_candidate["status"] == "consensus":
            code_previous = _consensus_observations(
                providers,
                method="eth_getCode",
                params_builder=lambda _provider: [
                    normalized_case["address"],
                    canonical_block_selector(header_previous["value"]["hash"]),
                ],
                normalizer=_normalize_code_result,
                receipt_root=root,
                provider_identity=identity,
            )
            code_candidate = _consensus_observations(
                providers,
                method="eth_getCode",
                params_builder=lambda _provider: [
                    normalized_case["address"],
                    canonical_block_selector(header_candidate["value"]["hash"]),
                ],
                normalizer=_normalize_code_result,
                receipt_root=root,
                provider_identity=identity,
            )
            proof["code"]["previous"] = code_previous
            proof["code"]["candidate"] = code_candidate
            blockers.extend(code_previous["blockers"])
            blockers.extend(code_candidate["blockers"])
            for label, block_number, section in (
                ("previous", previous_block, code_previous),
                ("candidate", candidate_block, code_candidate),
            ):
                for observation in section["observations"]:
                    if observation.get("error") in (None, ""):
                        try:
                            normalized = _normalize_code_result(observation.get("result"))
                        except Exception:
                            continue
                        record_observation(block_number, normalized, observation)
            if any(len(values) > 1 for values in observed_code_values.values()):
                blockers.append("nonmonotonic_or_ambiguous_observations")
            if code_previous.get("value") != "0x" or code_candidate.get("value") in (None, "0x"):
                blockers.append("nonmonotonic_or_ambiguous_observations")
            candidate_timestamp = int(header_candidate["value"]["timestamp"])

    result = {
        "case_id": normalized_case["case_id"],
        "chain": normalized_case["chain"],
        "address": normalized_case["address"],
        "incident_block": incident_block,
        "input_row_sha256": normalized_case["input_row_sha256"],
        "candidate_block": candidate_block,
        "candidate_timestamp": candidate_timestamp,
        "provider_identity": {
            "complete": bool(identity["complete"]),
            "families": identity["families"],
        },
        "search": {
            "status": "PROPOSED" if candidate_block is not None and "search_budget_exceeded" not in blockers else "PARTIAL",
            "algorithm": "bounded_binary_search_empty_to_nonempty",
            "discovery_provider_id": str(getattr(discovery_provider, "provider_id", "")),
            "discovery_provider_index": discovery_provider_index,
            "max_search_calls": max_search_calls,
            "calls_used": search_calls,
            "candidate_block": candidate_block,
            "assumptions": [
                "search provider observations only propose the transition",
                "verification requires independent canonical header and EIP-1898 code agreement",
            ],
            "observations": search_observations,
            "optional_unbound_probe_failures": optional_unbound_probe_failures,
        },
        "proof": proof,
    }
    result["blockers"] = list(dict.fromkeys(blockers))
    result["status"] = "VERIFIED" if not result["blockers"] and candidate_block is not None else "PARTIAL"
    result["proof_sha256_without_self_hash"] = _sha256_json(result)
    sealed = dict(result)
    sealed["proof_sha256_without_self_hash"] = result["proof_sha256_without_self_hash"]
    result["proof_sha256"] = _sha256_json(sealed)
    return result


def _snapshot_case_hash_payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(envelope)
    payload.pop("envelope_sha256_without_self_hash", None)
    payload.pop("envelope_sha256", None)
    payload.pop("resumed", None)
    payload.pop("quarantined", None)
    payload.pop("quarantine_reason", None)
    return payload


def _seal_snapshot_case_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    payload = _snapshot_case_hash_payload(envelope)
    sealed = dict(payload)
    sealed["envelope_sha256_without_self_hash"] = _sha256_json(payload)
    sealed["envelope_sha256"] = _sha256_json(sealed)
    return sealed


def _typed_blocker_code(prefix: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(prefix or "").strip().lower()).strip("_")
    if not normalized:
        return "provider_resolution_failed"
    if normalized in {"transition_exception", "snapshot_acquisition_exception"}:
        return normalized

    tokens = [token for token in normalized.split("_") if token]
    unsafe_tokens = {token for token in tokens if token in {"api", "auth", "token", "secret", "key", "cookie", "password"}}
    if unsafe_tokens:
        if "missing" in tokens:
            return "provider_credentials_missing"
        return "provider_resolution_failed"
    return normalized


def _with_snapshot_case_runtime_flags(
    envelope: Mapping[str, Any],
    *,
    resumed: bool,
    quarantined: bool,
    quarantine_reason: str | None,
) -> dict[str, Any]:
    enriched = dict(envelope)
    enriched["resumed"] = resumed
    enriched["quarantined"] = quarantined
    enriched["quarantine_reason"] = quarantine_reason
    return enriched


def _validate_snapshot_case_envelope_hashes(envelope: Mapping[str, Any]) -> bool:
    inner = _snapshot_case_hash_payload(envelope)
    if envelope.get("envelope_sha256_without_self_hash") != _sha256_json(inner):
        return False
    outer = dict(inner)
    outer["envelope_sha256_without_self_hash"] = envelope.get("envelope_sha256_without_self_hash")
    return envelope.get("envelope_sha256") == _sha256_json(outer)


def _validate_transition_proof_hashes(transition: Mapping[str, Any]) -> bool:
    if not isinstance(transition, Mapping):
        return False
    inner = dict(transition)
    inner.pop("proof_sha256_without_self_hash", None)
    inner.pop("proof_sha256", None)
    if transition.get("proof_sha256_without_self_hash") != _sha256_json(inner):
        return False
    outer = dict(inner)
    outer["proof_sha256_without_self_hash"] = transition.get("proof_sha256_without_self_hash")
    return transition.get("proof_sha256") == _sha256_json(outer)


def _iter_transition_receipt_observations(transition: Mapping[str, Any]) -> list[dict[str, Any]]:
    proof = dict(transition.get("proof") or {})
    observations: list[dict[str, Any]] = []
    for category in ("headers", "code"):
        category_payload = dict(proof.get(category) or {})
        for label in category_payload.values():
            if not isinstance(label, Mapping):
                continue
            for observation in label.get("observations", []) or []:
                if isinstance(observation, Mapping):
                    observations.append(dict(observation))
    search = dict(transition.get("search") or {})
    for observation in search.get("observations", []) or []:
        if isinstance(observation, Mapping):
            observations.append(dict(observation))
    return observations


def _validate_receipt_observation_paths(
    observations: list[dict[str, Any]],
    *,
    receipt_root: Path,
) -> bool:
    for observation in observations:
        try:
            expected = _expected_receipt_path(
                allowed_root=receipt_root,
                response_sha256=str(observation.get("response_sha256", "")),
            )
            actual = _safe_receipt_path(observation.get("raw_response_path"), allowed_root=receipt_root)
        except ValueError:
            return False
        if actual != expected or _sha256_file(actual) != str(observation.get("response_sha256", "")).strip().lower():
            return False
    return True


def _load_existing_snapshot_case_envelope(
    case_path: Path,
    *,
    case: Mapping[str, Any],
    policy: Mapping[str, Any],
    providers: list[Any],
    receipt_root: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    if not case_path.is_file():
        return None, None
    try:
        envelope = json.loads(case_path.read_text(encoding="utf-8"))
    except Exception:
        return None, "corrupt_json"
    if not isinstance(envelope, dict):
        return None, "corrupt_json"
    if not _validate_snapshot_case_envelope_hashes(envelope):
        return None, "self_hash_mismatch"
    if envelope.get("case_path") != case_path.name:
        return None, "case_path_mismatch"
    if envelope.get("case_input") != dict(case) or envelope.get("case_input_sha256") != _sha256_json(case):
        return None, "case_mismatch"
    if envelope.get("policy_input") != dict(policy) or envelope.get("policy_sha256") != _sha256_json(policy):
        return None, "policy_mismatch"
    transition = dict(envelope.get("transition_proof") or {})
    if not _validate_transition_proof_hashes(transition):
        return None, "transition_proof_hash_mismatch"
    if not _validate_receipt_observation_paths(
        _iter_transition_receipt_observations(transition),
        receipt_root=receipt_root,
    ):
        return None, "receipt_binding_invalid"
    strict_snapshot_closed = envelope.get("strict_snapshot_closed") is True
    strict_snapshot = dict(envelope.get("strict_snapshot") or {})
    if strict_snapshot_closed:
        provider_identity = _provider_identity_material(providers, dict(policy))
        strict_case = dict(case)
        candidate_block = transition.get("candidate_block")
        if not isinstance(candidate_block, Integral) or isinstance(candidate_block, bool) or int(candidate_block) < 0:
            return None, "strict_artifact_invalid"
        strict_case["deployment_block"] = int(candidate_block)
        if not _cached_snapshot_valid(
            strict_snapshot,
            case=strict_case,
            policy=dict(policy),
            receipt_root=receipt_root,
            provider_identity=provider_identity,
        ):
            validation = validate_strict_historical_snapshot(
                strict_snapshot,
                schema=_load_schema("strict_historical_snapshot.schema.json"),
                receipt_root=receipt_root,
                provider_identity=provider_identity,
            )
            if "receipt_hash_path_error" in validation.errors or "response_hash_mismatch" in validation.errors:
                return None, "receipt_binding_invalid"
            if "artifact_sha256_mismatch" in validation.errors or "artifact_sha256_without_self_hash_mismatch" in validation.errors:
                return None, "strict_artifact_hash_mismatch"
            return None, "strict_artifact_invalid"
    else:
        partial_reason = _validate_partial_strict_snapshot_artifact(
            strict_snapshot,
            case=dict(case),
            policy=dict(policy),
            providers=providers,
            receipt_root=receipt_root,
        )
        if partial_reason is not None:
            return None, partial_reason
        if envelope.get("status") != "PARTIAL":
            return None, "fail_closed_status_mismatch"
    return envelope, None


def _map_strict_validation_reason(errors: tuple[str, ...], *, fallback: str) -> str:
    if "receipt_hash_path_error" in errors or "response_hash_mismatch" in errors:
        return "receipt_binding_invalid"
    if "artifact_sha256_mismatch" in errors or "artifact_sha256_without_self_hash_mismatch" in errors:
        return "strict_artifact_hash_mismatch"
    return fallback


def _validate_partial_strict_snapshot_artifact(
    strict_snapshot: Mapping[str, Any],
    *,
    case: Mapping[str, Any],
    policy: Mapping[str, Any],
    providers: list[Any],
    receipt_root: Path,
) -> str | None:
    if not isinstance(strict_snapshot, Mapping):
        return "partial_strict_artifact_invalid"
    if strict_snapshot.get("strict_snapshot_closed") is not False:
        return "partial_strict_artifact_invalid"
    blockers = [str(item).strip() for item in (strict_snapshot.get("blockers") or []) if str(item).strip()]
    if not blockers:
        return "partial_strict_artifact_invalid"
    if strict_snapshot.get("status") not in (None, "PARTIAL"):
        return "partial_strict_artifact_invalid"
    if strict_snapshot.get("blocked_reason") not in (None, blockers[0]):
        return "partial_strict_artifact_invalid"

    looks_like_strict_artifact = any(
        key in strict_snapshot
        for key in (
            "schema_version",
            "case_input",
            "policy_input",
            "provider_identity",
            "receipt_bindings",
            "state_cells",
            "artifact_sha256_without_self_hash",
            "artifact_sha256",
        )
    )
    if not looks_like_strict_artifact:
        return None

    provider_identity = _provider_identity_material(providers, dict(policy))
    validation = validate_strict_historical_snapshot(
        dict(strict_snapshot),
        schema=_load_schema("strict_historical_snapshot.schema.json"),
        receipt_root=receipt_root,
        provider_identity=provider_identity,
    )
    if validation.ok:
        return None
    return _map_strict_validation_reason(validation.errors, fallback="partial_strict_artifact_invalid")


def _quarantine_case_file(case_path: Path, *, case_id: str, reason: str) -> Path:
    suffix = _sha256_bytes(case_path.read_bytes())[:16]
    quarantine_path = case_path.parent / "quarantine" / case_id / f"{reason}-{suffix}.json"
    quarantine_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(case_path, quarantine_path)
    return quarantine_path


def _case_claim_path(case_root: Path, *, case_id: str) -> Path:
    return case_root / ".claims" / f"{case_id}.lock"


def _claim_is_stale(claim_path: Path, *, stale_after_seconds: float) -> bool:
    try:
        age_seconds = max(0.0, time.time() - claim_path.stat().st_mtime)
    except FileNotFoundError:
        return False
    return age_seconds >= stale_after_seconds


def _claim_token_matches(claim_path: Path, *, token: str) -> bool:
    try:
        payload = json.loads(claim_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    return payload.get("token") == token


def _claim_heartbeat_loop(claim_path: Path, *, token: str, stop_event: threading.Event, interval_seconds: float) -> None:
    while not stop_event.wait(interval_seconds):
        if not _claim_token_matches(claim_path, token=token):
            return
        try:
            os.utime(claim_path, None)
        except FileNotFoundError:
            return


def _acquire_case_claim(
    case_root: Path,
    *,
    case_id: str,
    timeout_seconds: float = _CASE_CLAIM_TIMEOUT_SECONDS,
    poll_seconds: float = _CASE_CLAIM_POLL_SECONDS,
    stale_after_seconds: float = _CASE_CLAIM_STALE_AFTER_SECONDS,
    heartbeat_seconds: float = _CASE_CLAIM_HEARTBEAT_SECONDS,
) -> tuple[Path, str, threading.Event, threading.Thread]:
    claim_path = _case_claim_path(case_root, case_id=case_id)
    claim_path.parent.mkdir(parents=True, exist_ok=True)
    token = f"{os.getpid()}-{time.time_ns()}"
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fd = os.open(claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if _claim_is_stale(claim_path, stale_after_seconds=stale_after_seconds):
                try:
                    claim_path.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("case_claim_timeout")
            time.sleep(poll_seconds)
            continue
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"token": token, "created_at_utc": _now_utc_z()}, handle, sort_keys=True)
        except Exception:
            try:
                claim_path.unlink()
            except FileNotFoundError:
                pass
            raise
        stop_event = threading.Event()
        heartbeat = threading.Thread(
            target=_claim_heartbeat_loop,
            kwargs={
                "claim_path": claim_path,
                "token": token,
                "stop_event": stop_event,
                "interval_seconds": heartbeat_seconds,
            },
            daemon=True,
        )
        heartbeat.start()
        return claim_path, token, stop_event, heartbeat


def _release_case_claim(
    claim_path: Path,
    *,
    token: str,
    stop_event: threading.Event,
    heartbeat: threading.Thread,
) -> None:
    stop_event.set()
    heartbeat.join(timeout=0.2)
    try:
        payload = json.loads(claim_path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    if payload.get("token") == token:
        try:
            claim_path.unlink()
        except FileNotFoundError:
            pass


def execute_snapshot_case(
    case,
    *,
    providers,
    policy,
    receipt_root,
    case_root,
    transition_discoverer=discover_deployment_transition,
    snapshot_acquirer=acquire_strict_historical_snapshot,
    resume=True,
    retry_partial=False,
) -> dict:
    normalized_case = _stable_case_mapping(case)
    transition_case = _normalize_transition_case(normalized_case)
    case_id = transition_case["case_id"]
    case_root_path = Path(case_root)
    case_path = case_root_path / f"{case_id}.json"
    receipt_root_path = Path(receipt_root)
    policy_input = dict(policy)

    if resume:
        cached_envelope, invalid_reason = _load_existing_snapshot_case_envelope(
            case_path,
            case=normalized_case,
            policy=policy_input,
            providers=providers,
            receipt_root=receipt_root_path,
        )
        if cached_envelope is not None and not (
            retry_partial and cached_envelope.get("strict_snapshot_closed") is not True
        ):
            return _with_snapshot_case_runtime_flags(
                cached_envelope,
                resumed=True,
                quarantined=False,
                quarantine_reason=None,
            )

    claim_path, claim_token, claim_stop_event, claim_heartbeat = _acquire_case_claim(case_root_path, case_id=case_id)
    try:
        quarantined = False
        quarantine_reason = None
        if resume:
            cached_envelope, invalid_reason = _load_existing_snapshot_case_envelope(
                case_path,
                case=normalized_case,
                policy=policy_input,
                providers=providers,
                receipt_root=receipt_root_path,
            )
            if cached_envelope is not None:
                if retry_partial and cached_envelope.get("strict_snapshot_closed") is not True:
                    _quarantine_case_file(case_path, case_id=case_id, reason="retry_partial")
                    quarantined = True
                    quarantine_reason = "retry_partial"
                else:
                    return _with_snapshot_case_runtime_flags(
                        cached_envelope,
                        resumed=True,
                        quarantined=False,
                        quarantine_reason=None,
                    )
            elif invalid_reason is not None:
                _quarantine_case_file(case_path, case_id=case_id, reason=invalid_reason)
                quarantined = True
                quarantine_reason = invalid_reason

        try:
            transition = dict(transition_discoverer(normalized_case, providers, receipt_root_path))
        except Exception:
            transition = {
                "status": "PARTIAL",
                "blockers": [_typed_blocker_code("transition_exception")],
            }
        if "proof_sha256_without_self_hash" not in transition or "proof_sha256" not in transition:
            transition = dict(transition)
            transition["proof_sha256_without_self_hash"] = _sha256_json(transition)
            transition_with_inner = dict(transition)
            transition_with_inner["proof_sha256_without_self_hash"] = transition["proof_sha256_without_self_hash"]
            transition["proof_sha256"] = _sha256_json(transition_with_inner)

        blockers = list(dict.fromkeys(str(item) for item in (transition.get("blockers") or []) if str(item).strip()))
        candidate_block = transition.get("candidate_block")
        verified_transition = (
            transition.get("status") == "VERIFIED"
            and not blockers
            and isinstance(candidate_block, Integral)
            and not isinstance(candidate_block, bool)
            and int(candidate_block) >= 0
        )

        strict_snapshot: dict[str, Any]
        strict_snapshot_closed = False
        if verified_transition:
            strict_case = dict(normalized_case)
            strict_case["deployment_block"] = int(candidate_block)
            provider_identity = _provider_identity_material(providers, policy_input)
            try:
                strict_snapshot_candidate = dict(
                    snapshot_acquirer(
                        strict_case,
                        providers=providers,
                        policy=policy_input,
                        receipt_root=receipt_root_path,
                        cached_artifact=None,
                    )
                )
                strict_snapshot = _seal_strict_snapshot_artifact(
                    strict_snapshot_candidate,
                    schema=_load_schema("strict_historical_snapshot.schema.json"),
                    receipt_root=receipt_root_path,
                    provider_identity=provider_identity,
                    include_runtime_status=True,
                )
                strict_snapshot_closed = strict_snapshot.get("strict_snapshot_closed") is True
                blockers.extend(
                    str(item)
                    for item in (strict_snapshot.get("blockers") or [])
                    if str(item).strip()
                )
            except InsufficientIncidentLeadTimeError:
                strict_snapshot = {
                    "strict_snapshot_closed": False,
                    "blockers": ["insufficient_incident_lead_time"],
                    "status": "PARTIAL",
                    "blocked_reason": "insufficient_incident_lead_time",
                }
                blockers.extend(strict_snapshot["blockers"])
            except Exception:
                strict_snapshot = {
                    "strict_snapshot_closed": False,
                    "blockers": [_typed_blocker_code("snapshot_acquisition_exception")],
                    "status": "PARTIAL",
                    "blocked_reason": "snapshot_acquisition_exception",
                }
                blockers.extend(strict_snapshot["blockers"])
        else:
            strict_snapshot = {
                "strict_snapshot_closed": False,
                "blockers": blockers or ["transition_not_verified"],
                "status": "PARTIAL",
                "blocked_reason": (blockers or ["transition_not_verified"])[0],
            }

        envelope = {
            "case_id": case_id,
            "case_input": normalized_case,
            "case_input_sha256": _sha256_json(normalized_case),
            "policy_input": policy_input,
            "policy_sha256": _sha256_json(policy_input),
            "transition_proof": transition,
            "transition_proof_sha256": str(transition.get("proof_sha256") or _sha256_json(transition)),
            "strict_snapshot": strict_snapshot,
            "strict_snapshot_sha256": str(strict_snapshot.get("artifact_sha256") or _sha256_json(strict_snapshot)),
            "strict_snapshot_closed": strict_snapshot_closed,
            "status": "VERIFIED" if strict_snapshot_closed and not blockers else "PARTIAL",
            "blockers": list(dict.fromkeys(blockers)),
            "case_path": case_path.name,
            "receipt_root": _portable_path(receipt_root_path, root=case_root.parent),
        }
        sealed = _seal_snapshot_case_envelope(envelope)
        _atomic_write_text(case_path, json.dumps(sealed, indent=2, sort_keys=True))
        return _with_snapshot_case_runtime_flags(
            sealed,
            resumed=False,
            quarantined=quarantined,
            quarantine_reason=quarantine_reason,
        )
    finally:
        _release_case_claim(
            claim_path,
            token=claim_token,
            stop_event=claim_stop_event,
            heartbeat=claim_heartbeat,
        )


def _load_validated_prepared_run(prepared_run: Mapping[str, Any]) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
    run_root = Path(str(prepared_run.get("run_root") or "")).expanduser()
    if not str(run_root):
        raise ValueError("prepared run is missing run_root")
    run_manifest_path = run_root / "run_manifest.json"
    if not run_manifest_path.is_file():
        raise ValueError("prepared run manifest is missing")

    manifest = _load_existing_preparation_manifest(run_manifest_path)
    binding = dict(manifest.get("binding") or {})
    if manifest.get("binding_sha256") != _sha256_json(binding):
        raise ValueError("prepared run binding hash mismatch")

    manifest_frozen = dict(manifest.get("frozen_inputs") or {})
    frozen_entries = list(manifest_frozen.get("entries") or [])
    frozen_manifest_relpath = str(manifest_frozen.get("manifest_path") or "").strip()
    if not frozen_manifest_relpath:
        raise ValueError("prepared run frozen manifest path is missing")
    frozen_manifest_path = run_root / frozen_manifest_relpath
    if not frozen_manifest_path.is_file():
        raise ValueError("prepared run frozen manifest is missing")
    frozen_manifest = json.loads(frozen_manifest_path.read_text(encoding="utf-8"))
    if list(frozen_manifest.get("entries") or []) != frozen_entries:
        raise ValueError("prepared run frozen manifest entries mismatch")
    if frozen_manifest.get("entries_sha256") != _frozen_inputs_hash(frozen_entries):
        raise ValueError("prepared run frozen manifest hash mismatch")
    _validate_frozen_input_entries(run_root, frozen_entries)

    if prepared_run.get("binding") is not None and dict(prepared_run.get("binding") or {}) != binding:
        raise ValueError("resume input mismatch: prepared run binding differs from existing manifest")
    prepared_frozen = dict(prepared_run.get("frozen_inputs") or {})
    if prepared_frozen:
        if list(prepared_frozen.get("entries") or []) != frozen_entries:
            raise ValueError("resume input mismatch: prepared run frozen inputs differ from existing manifest")
        if prepared_frozen.get("entries_sha256") != _frozen_inputs_hash(frozen_entries):
            raise ValueError("resume input mismatch: prepared run frozen input hash differs from existing manifest")
    return run_root, binding, frozen_entries


def _require_available_frozen_input(
    frozen_entries: list[dict[str, Any]],
    *,
    name: str,
) -> dict[str, Any]:
    for entry in frozen_entries:
        if str(entry.get("name") or "") == name:
            if not entry.get("available"):
                raise ValueError(f"prepared run frozen input unavailable: {name}")
            return dict(entry)
    raise ValueError(f"prepared run frozen input missing: {name}")


def _frozen_input_path(run_root: Path, entry: Mapping[str, Any]) -> Path:
    return run_root / str(entry["frozen_path"])


def _selected_cases_from_binding(
    population: pd.DataFrame,
    *,
    binding: Mapping[str, Any],
) -> list[dict[str, Any]]:
    population_section = dict(binding.get("population") or {})
    if int(population_section.get("target_case_count") or 0) != FULL_CASE_TARGET:
        raise ValueError("prepared run target population mismatch")
    if int(population_section.get("actual_case_count") or 0) != FULL_CASE_TARGET or len(population) != FULL_CASE_TARGET:
        raise ValueError("prepared run actual population mismatch")

    selected_section = dict(binding.get("selected") or {})
    selected_case_ids = [str(item) for item in (selected_section.get("selected_case_ids") or [])]
    selected_case_names = [str(item) for item in (selected_section.get("selected_case_names") or [])]
    selected_case_count = int(selected_section.get("selected_case_count") or 0)
    if len(selected_case_ids) != selected_case_count or len(selected_case_names) != selected_case_count:
        raise ValueError("prepared run selected case binding mismatch")
    if len(selected_case_ids) != len(set(selected_case_ids)):
        raise ValueError("prepared run duplicate selected case IDs are not allowed")

    by_case_id = {
        str(record["case_id"]): dict(record)
        for record in population.to_dict(orient="records")
    }
    selected_cases: list[dict[str, Any]] = []
    for expected_case_id, expected_name in zip(selected_case_ids, selected_case_names, strict=True):
        case = by_case_id.get(expected_case_id)
        if case is None:
            raise ValueError(f"prepared run selected case is missing from frozen inputs: {expected_case_id}")
        if str(case["case_name"]) != expected_name:
            raise ValueError(f"prepared run selected case name mismatch: {expected_case_id}")
        selected_cases.append(case)
    return selected_cases


def _partial_transition_for_blocker(code: str) -> dict[str, Any]:
    transition = {
        "status": "PARTIAL",
        "blockers": [code],
        "candidate_block": None,
        "proof": {
            "headers": {"previous": {"observations": []}, "candidate": {"observations": []}},
            "code": {"previous": {"observations": []}, "candidate": {"observations": []}},
        },
        "search": {"observations": []},
    }
    transition["proof_sha256_without_self_hash"] = _sha256_json(transition)
    outer = dict(transition)
    outer["proof_sha256_without_self_hash"] = transition["proof_sha256_without_self_hash"]
    transition["proof_sha256"] = _sha256_json(outer)
    return transition


def _provider_failure_case_result(
    case: Mapping[str, Any],
    *,
    run_root: Path,
    policy: Mapping[str, Any],
    blocker_code: str,
) -> dict[str, Any]:
    stable_case = _stable_case_mapping(case)
    receipt_root = run_root / "rpc_receipts"
    case_root = run_root / "cases"
    case_path = case_root / f"{stable_case['case_id']}.json"
    transition = _partial_transition_for_blocker(blocker_code)
    strict_snapshot = {
        "strict_snapshot_closed": False,
        "status": "PARTIAL",
        "blockers": [blocker_code],
        "blocked_reason": blocker_code,
    }
    envelope = {
        "case_id": str(stable_case["case_id"]),
        "case_input": stable_case,
        "case_input_sha256": _sha256_json(stable_case),
        "policy_input": dict(policy),
        "policy_sha256": _sha256_json(policy),
        "transition_proof": transition,
        "transition_proof_sha256": str(transition["proof_sha256"]),
        "strict_snapshot": strict_snapshot,
        "strict_snapshot_sha256": _sha256_json(strict_snapshot),
        "strict_snapshot_closed": False,
        "status": "PARTIAL",
        "blockers": [blocker_code],
        "case_path": case_path.name,
        "receipt_root": _portable_path(receipt_root, root=case_root.parent),
    }
    sealed = _seal_snapshot_case_envelope(envelope)
    _atomic_write_text(case_path, json.dumps(sealed, indent=2, sort_keys=True))
    return _with_snapshot_case_runtime_flags(
        sealed,
        resumed=False,
        quarantined=False,
        quarantine_reason=None,
    )


def _canonical_result_row_path(*, case_id: str) -> str:
    return (Path("cases") / f"{case_id}.json").as_posix()


def _result_row_path(run_root: Path, result: Mapping[str, Any], *, case_id: str) -> str:
    del run_root, result
    return _canonical_result_row_path(case_id=case_id)


def _csv_bool(value: Any) -> str:
    return "true" if value else "false"


def _resolve_persisted_case_envelope_path(
    run_root: Path,
    result: Mapping[str, Any],
    *,
    case_id: str,
) -> Path | None:
    expected_relpath = _canonical_result_row_path(case_id=case_id)
    declared_path = str(result.get("case_path") or "").strip()
    if declared_path not in {f"{case_id}.json", expected_relpath}:
        return None
    cases_root = (run_root / "cases").resolve()
    path = (run_root / expected_relpath).resolve(strict=False)
    try:
        path.relative_to(cases_root)
    except ValueError:
        return None
    if path.name != f"{case_id}.json" or not path.is_file() or path.is_symlink():
        return None
    return path


def _candidate_closed(
    run_root: Path,
    case: Mapping[str, Any],
    result: Mapping[str, Any],
) -> bool:
    case_id = str(case["case_id"])
    envelope_path = _resolve_persisted_case_envelope_path(run_root, result, case_id=case_id)
    if envelope_path is None:
        return False
    try:
        persisted = json.loads(envelope_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(persisted, dict):
        return False
    if persisted.get("envelope_sha256") != result.get("envelope_sha256"):
        return False
    if not _validate_snapshot_case_envelope_hashes(persisted):
        return False
    if persisted.get("case_id") != case_id:
        return False
    if persisted.get("case_path") != f"{case_id}.json":
        return False
    if persisted.get("case_input_sha256") != _sha256_json(_stable_case_mapping(case)):
        return False
    if persisted.get("strict_snapshot_closed") is not True:
        return False
    if persisted.get("status") != "VERIFIED":
        return False
    blockers = [str(item).strip() for item in (persisted.get("blockers") or []) if str(item).strip()]
    return not blockers


def _result_to_qualification_row(
    case: Mapping[str, Any],
    *,
    result: Mapping[str, Any],
    run_root: Path,
) -> dict[str, str]:
    quarantined = bool(result.get("quarantined"))
    resumed = bool(result.get("resumed"))
    retried = bool(result.get("retried", quarantined))
    return {
        "case_id": str(case["case_id"]),
        "case_name": str(case["case_name"]),
        "chain": str(case["chain"]),
        "input_row_sha256": str(case["input_row_sha256"]),
        "envelope_path": _result_row_path(run_root, result, case_id=str(case["case_id"])),
        "envelope_sha256": str(result.get("envelope_sha256") or ""),
        "status": str(result.get("status") or "PARTIAL"),
        "candidate_closed": _csv_bool(_candidate_closed(run_root, case, result)),
        "resumed": _csv_bool(resumed),
        "quarantined": _csv_bool(quarantined),
        "retried": _csv_bool(retried),
        "counter_authority": "false",
    }


def _result_to_blocker_rows(case: Mapping[str, Any], *, result: Mapping[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for code in (result.get("blockers") or []):
        normalized = str(code or "").strip()
        if not normalized:
            continue
        rows.append(
            {
                "chain": str(case["chain"]),
                "case_id": str(case["case_id"]),
                "code": normalized,
            }
        )
    return rows


def execute_historical_snapshot_cases(
    prepared_run,
    *,
    provider_resolver,
    case_executor=execute_snapshot_case,
    max_workers=1,
    resume=True,
    retry_partial=False,
) -> dict:
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")

    run_root, binding, frozen_entries = _load_validated_prepared_run(prepared_run)
    queue_entry = _require_available_frozen_input(frozen_entries, name="queue")
    temporal_entry = _require_available_frozen_input(frozen_entries, name="temporal")
    policy_entry = _require_available_frozen_input(frozen_entries, name="policy")
    _require_available_frozen_input(frozen_entries, name="provider_template")

    population = load_canonical_snapshot_population(
        _frozen_input_path(run_root, queue_entry),
        _frozen_input_path(run_root, temporal_entry),
    )
    selected_cases = [
        _stable_case_mapping(case)
        for case in _selected_cases_from_binding(population, binding=binding)
    ]
    policy = _load_yaml(_frozen_input_path(run_root, policy_entry))
    receipt_root = run_root / "rpc_receipts"
    case_root = run_root / "cases"

    results_by_case_id: dict[str, dict[str, Any]] = {}
    providers_by_chain: dict[str, list[Any]] = {}
    ordered_case_ids = [str(case["case_id"]) for case in selected_cases]

    cases_by_chain: dict[str, list[dict[str, Any]]] = {}
    for case in selected_cases:
        cases_by_chain.setdefault(str(case["chain"]), []).append(case)

    for chain in sorted(cases_by_chain):
        chain_cases = cases_by_chain[chain]
        try:
            providers = list(provider_resolver(chain, receipt_root))
        except ManagedProviderConfigurationError as exc:
            blocker_code = _typed_blocker_code(str(exc.code or "provider_resolution_failed"))
            for case in chain_cases:
                results_by_case_id[str(case["case_id"])] = _provider_failure_case_result(
                    case,
                    run_root=run_root,
                    policy=policy,
                    blocker_code=blocker_code,
                )
            continue
        providers_by_chain[chain] = list(providers)

        if max_workers == 1 or len(chain_cases) <= 1:
            for case in chain_cases:
                executor_kwargs = {
                    "providers": providers,
                    "policy": policy,
                    "receipt_root": receipt_root,
                    "case_root": case_root,
                    "resume": resume,
                }
                if retry_partial:
                    executor_kwargs["retry_partial"] = True
                results_by_case_id[str(case["case_id"])] = dict(
                    case_executor(dict(case), **executor_kwargs)
                )
            continue

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor_kwargs = {
                "providers": providers,
                "policy": policy,
                "receipt_root": receipt_root,
                "case_root": case_root,
                "resume": resume,
            }
            if retry_partial:
                executor_kwargs["retry_partial"] = True
            futures = {
                executor.submit(
                    case_executor,
                    dict(case),
                    **executor_kwargs,
                ): str(case["case_id"])
                for case in chain_cases
            }
            for future in as_completed(futures):
                case_id = futures[future]
                results_by_case_id[case_id] = dict(future.result())

    if set(results_by_case_id) != set(ordered_case_ids):
        raise ValueError("scheduler results do not cover selected cases exactly once")

    qualification_rows = [
        _result_to_qualification_row(
            next(case for case in selected_cases if str(case["case_id"]) == case_id),
            result=results_by_case_id[case_id],
            run_root=run_root,
        )
        for case_id in sorted(ordered_case_ids)
    ]
    blocker_rows: list[dict[str, str]] = []
    for case in selected_cases:
        blocker_rows.extend(
            _result_to_blocker_rows(case, result=results_by_case_id[str(case["case_id"])])
        )
    blocker_rows.sort(key=lambda row: (row["chain"], row["case_id"], row["code"]))

    _atomic_write_csv(
        run_root / "case_qualification.csv",
        qualification_rows,
        fieldnames=[
            "case_id",
            "case_name",
            "chain",
            "input_row_sha256",
            "envelope_path",
            "envelope_sha256",
            "status",
            "candidate_closed",
            "resumed",
            "quarantined",
            "retried",
            "counter_authority",
        ],
    )
    _atomic_write_csv(
        run_root / "blocker_ledger.csv",
        blocker_rows,
        fieldnames=["chain", "case_id", "code"],
    )

    receipt_manifest, receipt_case_blockers = _scan_receipt_manifest(
        run_root,
        receipt_root=receipt_root,
        selected_cases=selected_cases,
    )
    provider_report, provider_chain_blockers = _provider_identity_verification_report(providers_by_chain)
    qualification_rows, blocker_rows, combined_case_blockers = _with_aggregate_blockers(
        qualification_rows=qualification_rows,
        blocker_rows=blocker_rows,
        results_by_case_id=results_by_case_id,
        receipt_case_blockers=receipt_case_blockers,
        provider_chain_blockers=provider_chain_blockers,
    )
    _atomic_write_csv(
        run_root / "case_qualification.csv",
        qualification_rows,
        fieldnames=[
            "case_id",
            "case_name",
            "chain",
            "input_row_sha256",
            "envelope_path",
            "envelope_sha256",
            "status",
            "candidate_closed",
            "resumed",
            "quarantined",
            "retried",
            "counter_authority",
        ],
    )
    _atomic_write_csv(
        run_root / "blocker_ledger.csv",
        blocker_rows,
        fieldnames=["chain", "case_id", "code"],
    )

    sanitized_case_results = []
    for row in qualification_rows:
        case_id = row["case_id"]
        sanitized_case_results.append(
            {
                "case_id": case_id,
                "status": row["status"],
                "candidate_closed": row["candidate_closed"] == "true",
                "resumed": row["resumed"] == "true",
                "quarantined": row["quarantined"] == "true",
                "retried": row["retried"] == "true",
                "envelope_path": row["envelope_path"],
                "envelope_sha256": row["envelope_sha256"],
                "blockers": list(combined_case_blockers.get(case_id, [])),
            }
        )

    summary = {
        "selected_case_count": len(selected_cases),
        "processed_case_count": len(sanitized_case_results),
        "candidate_closed_count": sum(1 for row in qualification_rows if row["candidate_closed"] == "true"),
        "reused_case_count": sum(1 for row in qualification_rows if row["resumed"] == "true"),
        "quarantined_case_count": sum(1 for row in qualification_rows if row["quarantined"] == "true"),
        "retried_case_count": sum(1 for row in qualification_rows if row["retried"] == "true"),
    }
    closure_report = _historical_snapshot_closure_report(
        binding=binding,
        qualification_rows=qualification_rows,
        blocker_rows=blocker_rows,
        receipt_manifest=receipt_manifest,
        provider_report=provider_report,
    )
    aggregate_paths = {
        "rpc_receipt_manifest": "rpc_receipt_manifest.json",
        "provider_identity_verification": "provider_identity_verification.json",
        "historical_snapshot_closure_report": "historical_snapshot_closure_report.json",
        "case_qualification": "case_qualification.csv",
        "blocker_ledger": "blocker_ledger.csv",
    }
    _atomic_write_text(
        run_root / aggregate_paths["rpc_receipt_manifest"],
        _canonical_json_bytes(receipt_manifest).decode("utf-8"),
    )
    _atomic_write_text(
        run_root / aggregate_paths["provider_identity_verification"],
        _canonical_json_bytes(provider_report).decode("utf-8"),
    )
    _atomic_write_text(
        run_root / aggregate_paths["historical_snapshot_closure_report"],
        _canonical_json_bytes(closure_report).decode("utf-8"),
    )
    aggregate_hashes = {
        name: _sha256_file(run_root / relpath) for name, relpath in sorted(aggregate_paths.items())
    }
    _update_run_manifest_with_aggregates(
        run_root,
        binding=binding,
        frozen_entries=frozen_entries,
        aggregate_paths=aggregate_paths,
        aggregate_hashes=aggregate_hashes,
        summary=summary,
    )
    return {
        "summary": summary,
        "qualification_rows": qualification_rows,
        "blocker_rows": blocker_rows,
        "case_results": sanitized_case_results,
        "aggregate_artifacts": {
            "paths": dict(aggregate_paths),
            "hashes": dict(aggregate_hashes),
        },
    }
