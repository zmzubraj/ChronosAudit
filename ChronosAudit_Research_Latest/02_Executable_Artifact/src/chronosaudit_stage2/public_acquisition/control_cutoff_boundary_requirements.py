from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

import pandas as pd


REQUIREMENTS_SCHEMA = "stage2_control_cutoff_boundary_requirements.v1"
TARGET_SCHEMA = "stage2_control_cutoff_boundary_requirement.v1"
# Frozen block timestamps have one-second resolution on some supported chains,
# so several adjacent blocks can legitimately share the cutoff timestamp.  A
# fixed successor envelope keeps the search deterministic and range-bound while
# allowing the resolver to prove the first strictly-later adjacent block.
UPPER_BOUND_SUCCESSOR_ENVELOPE_BLOCKS = 64


class ControlCutoffBoundaryRequirementsError(ValueError):
    """Raised when cutoff-boundary requirements cannot be frozen safely."""


_WINDOW_COLUMNS = {
    "case_name",
    "chain",
    "chain_id",
    "admissible_deployment_start",
    "admissible_deployment_end",
    "start_block",
    "end_block",
    "start_boundary_sha256",
    "end_boundary_sha256",
    "expansion_requirement_sha256",
    "boundary_status",
    "block_window_sha256",
}
_FALSE_AUTHORITY = (
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCutoffBoundaryRequirementsError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCutoffBoundaryRequirementsError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCutoffBoundaryRequirementsError(f"{label}_not_ordinary")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCutoffBoundaryRequirementsError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCutoffBoundaryRequirementsError(f"{label}_root_invalid")
    return payload


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ControlCutoffBoundaryRequirementsError(f"{label}_invalid")
    return text


def _canonical_time(value: object, label: str) -> str:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlCutoffBoundaryRequirementsError(f"{label}_invalid")
    return parsed.isoformat().replace("+00:00", "Z")


def _require_false_authority(payload: Mapping[str, object], label: str) -> None:
    for field in _FALSE_AUTHORITY:
        if payload.get(field) is not False:
            raise ControlCutoffBoundaryRequirementsError(
                f"{label}_{field}_invalid"
            )


def _require_self_hash(
    payload: Mapping[str, object], field: str, label: str
) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlCutoffBoundaryRequirementsError(f"{label}_self_hash_invalid")


def _normalized_window(row: Mapping[str, object]) -> dict[str, object]:
    try:
        chain_id = int(str(row["chain_id"]))
        start_block = int(str(row["start_block"]))
        end_block = int(str(row["end_block"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlCutoffBoundaryRequirementsError("block_window_number_invalid") from exc
    if chain_id <= 0 or start_block < 0 or end_block <= start_block:
        raise ControlCutoffBoundaryRequirementsError("block_window_range_invalid")
    normalized: dict[str, object] = {
        "case_name": str(row["case_name"]).strip(),
        "chain": str(row["chain"]).strip().lower(),
        "chain_id": chain_id,
        "admissible_deployment_start": _canonical_time(
            row["admissible_deployment_start"], "admissible_deployment_start"
        ),
        "admissible_deployment_end": _canonical_time(
            row["admissible_deployment_end"], "admissible_deployment_end"
        ),
        "start_block": start_block,
        "end_block": end_block,
        "start_boundary_sha256": _sha(
            row["start_boundary_sha256"], "start_boundary_sha256"
        ),
        "end_boundary_sha256": _sha(
            row["end_boundary_sha256"], "end_boundary_sha256"
        ),
        "expansion_requirement_sha256": _sha(
            row["expansion_requirement_sha256"],
            "expansion_requirement_sha256",
        ),
        "boundary_status": str(row["boundary_status"]).strip(),
    }
    if not normalized["case_name"] or not normalized["chain"]:
        raise ControlCutoffBoundaryRequirementsError("block_window_identity_invalid")
    if (
        normalized["boundary_status"]
        != "LOCAL_TEST_SINGLE_PROVIDER_EXACT_BLOCK_BRACKET"
    ):
        raise ControlCutoffBoundaryRequirementsError("block_window_status_invalid")
    expected = _canonical_sha(normalized)
    if _sha(row["block_window_sha256"], "block_window_sha256") != expected:
        raise ControlCutoffBoundaryRequirementsError("block_window_self_hash_invalid")
    normalized["block_window_sha256"] = expected
    return normalized


def build_cutoff_boundary_requirements(
    *,
    reserve_pair_scope_path: Path,
    block_windows_path: Path,
    block_windows_manifest_path: Path,
) -> dict[str, object]:
    """Freeze bounded cutoff-block search requirements without granting RPC.

    The input block windows are single-provider local-test evidence. They bound a
    future deterministic search only; they are not accepted as the final
    canonical cutoff block or adjacent next-block bracket.
    """
    pair_file = _ordinary(reserve_pair_scope_path, "reserve_pair_scope")
    windows_file = _ordinary(block_windows_path, "block_windows")
    manifest_file = _ordinary(
        block_windows_manifest_path, "block_windows_manifest"
    )

    pair_scope = _load_json(pair_file, "reserve_pair_scope")
    if pair_scope.get("schema_version") != "stage2_control_reserve_pair_scope.v1":
        raise ControlCutoffBoundaryRequirementsError("pair_scope_schema_invalid")
    _require_self_hash(pair_scope, "projection_sha256", "pair_scope")
    _require_false_authority(pair_scope, "pair_scope")
    if pair_scope.get("counter_authority") is not False:
        raise ControlCutoffBoundaryRequirementsError(
            "pair_scope_counter_authority_invalid"
        )
    records = pair_scope.get("records")
    if (
        not isinstance(records, list)
        or not records
        or len(records) != pair_scope.get("record_count")
        or not all(isinstance(row, Mapping) for row in records)
    ):
        raise ControlCutoffBoundaryRequirementsError("pair_scope_records_invalid")

    manifest = _load_json(manifest_file, "block_windows_manifest")
    if manifest.get("schema_version") != (
        "chronosaudit.control_block_window_resolution.local_test.v1"
    ):
        raise ControlCutoffBoundaryRequirementsError(
            "block_windows_manifest_schema_invalid"
        )
    _require_false_authority(manifest, "block_windows_manifest")
    if (
        manifest.get("decision")
        != "LOCAL_TEST_BLOCK_WINDOWS_RESOLVED_NON_AUTHORIZING"
        or manifest.get("local_test_only") is not True
        or manifest.get("single_provider_non_independent") is not True
    ):
        raise ControlCutoffBoundaryRequirementsError(
            "block_windows_manifest_status_invalid"
        )
    if manifest.get("output_csv_sha256") != _file_sha(windows_file):
        raise ControlCutoffBoundaryRequirementsError("block_windows_hash_mismatch")

    windows = pd.read_csv(
        windows_file, dtype=str, keep_default_na=False, low_memory=False
    )
    missing = sorted(_WINDOW_COLUMNS - set(windows.columns))
    if missing:
        raise ControlCutoffBoundaryRequirementsError(
            "block_windows_missing_columns:" + ",".join(missing)
        )
    # The historical manifest's boundary_target_count counts the lower/upper
    # timestamp-resolution targets, while the CSV contains one joined window
    # per case. case_count is therefore the correct CSV cardinality binding.
    if len(windows) != int(manifest.get("case_count", -1)):
        raise ControlCutoffBoundaryRequirementsError("block_windows_count_mismatch")
    if windows.duplicated(["case_name", "chain"]).any():
        raise ControlCutoffBoundaryRequirementsError("block_window_duplicate")
    normalized_windows = [_normalized_window(row) for row in windows.to_dict("records")]
    if len({row["case_name"] for row in normalized_windows}) != int(
        manifest.get("case_count", -1)
    ):
        raise ControlCutoffBoundaryRequirementsError(
            "block_windows_case_count_mismatch"
        )
    windows_by_identity = {
        (str(row["case_name"]), str(row["chain"])): row
        for row in normalized_windows
    }

    grouped: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    seen_pair_hashes: set[str] = set()
    for record in records:
        _require_self_hash(record, "pair_scope_record_sha256", "pair_record")
        _require_false_authority(record, "pair_record")
        if (
            record.get("counter_authority") is not False
            or record.get("reserve_evidence_verified") is not True
            or record.get("scope_status")
            != "RESERVE_PAIR_CUTOFF_STATE_EVIDENCE_REQUIRED"
        ):
            raise ControlCutoffBoundaryRequirementsError("pair_record_status_invalid")
        case_id = str(record.get("case_name", "")).strip()
        chain = str(record.get("chain", "")).strip().lower()
        cutoff = _canonical_time(
            record.get("required_covariate_cutoff_time"),
            "required_covariate_cutoff_time",
        )
        if cutoff != _canonical_time(
            record.get("positive_prediction_cutoff_time"),
            "positive_prediction_cutoff_time",
        ):
            raise ControlCutoffBoundaryRequirementsError("pair_cutoff_mismatch")
        pair_hash = _sha(
            record.get("pair_scope_record_sha256"),
            "pair_scope_record_sha256",
        )
        if pair_hash in seen_pair_hashes:
            raise ControlCutoffBoundaryRequirementsError("pair_record_duplicate")
        seen_pair_hashes.add(pair_hash)
        if not case_id or not chain:
            raise ControlCutoffBoundaryRequirementsError("pair_identity_invalid")
        grouped[(case_id, chain, cutoff)].append(pair_hash)

    targets: list[dict[str, object]] = []
    for (case_id, chain, cutoff), pair_hashes in sorted(grouped.items()):
        window = windows_by_identity.get((case_id, chain))
        if window is None:
            raise ControlCutoffBoundaryRequirementsError("block_window_missing")
        if cutoff != window["admissible_deployment_end"]:
            raise ControlCutoffBoundaryRequirementsError("cutoff_window_mismatch")
        source_upper_bound = int(window["end_block"])
        # The source window's end block may itself be at the cutoff timestamp,
        # and multiple adjacent blocks can share that same whole-second value.
        # Freeze a bounded multi-block successor envelope rather than assuming
        # that one successor must already be strictly after the cutoff.
        upper_bound_expansion_blocks = UPPER_BOUND_SUCCESSOR_ENVELOPE_BLOCKS
        upper_bound = source_upper_bound + upper_bound_expansion_blocks
        interval_size = upper_bound - int(window["start_block"]) + 1
        identity = {
            "case_id": case_id,
            "chain": chain,
            "cutoff_timestamp": cutoff,
            "block_window_sha256": window["block_window_sha256"],
        }
        target: dict[str, object] = {
            "schema_version": TARGET_SCHEMA,
            "target_id": "cutoff-boundary:" + _canonical_sha(identity),
            **identity,
            "chain_id": window["chain_id"],
            "lower_bound_block": window["start_block"],
            "source_upper_bound_block": source_upper_bound,
            "upper_bound_expansion_blocks": upper_bound_expansion_blocks,
            "upper_bound_block": upper_bound,
            "lower_boundary_evidence_sha256": window["start_boundary_sha256"],
            "upper_boundary_evidence_sha256": window["end_boundary_sha256"],
            "expansion_requirement_sha256": window[
                "expansion_requirement_sha256"
            ],
            "pair_scope_record_count": len(pair_hashes),
            "pair_scope_record_sha256s": sorted(pair_hashes),
            "search_algorithm": "DETERMINISTIC_INTEGER_BINARY_SEARCH_V1",
            "maximum_block_header_queries_per_provider": math.ceil(
                math.log2(interval_size)
            )
            + 2,
            "required_result": (
                "LAST_CANONICAL_BLOCK_NOT_AFTER_CUTOFF_AND_ADJACENT_NEXT_BLOCK_AFTER_CUTOFF"
            ),
            "source_window_evidence_status": (
                "LOCAL_TEST_SINGLE_PROVIDER_NON_INDEPENDENT_RANGE_BOUND_ONLY"
            ),
            "provider_registry_verified": False,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        target["target_sha256"] = _canonical_sha(target)
        targets.append(target)

    output: dict[str, object] = {
        "schema_version": REQUIREMENTS_SCHEMA,
        "decision": "CUTOFF_BOUNDARY_REQUIREMENTS_FROZEN_AWAITING_DUAL_PROVIDER_ACTIVATION",
        "reserve_pair_scope_file_sha256": _file_sha(pair_file),
        "reserve_pair_scope_projection_sha256": pair_scope["projection_sha256"],
        "block_windows_file_sha256": _file_sha(windows_file),
        "block_windows_manifest_file_sha256": _file_sha(manifest_file),
        "pair_scope_record_count": len(records),
        "boundary_target_count": len(targets),
        "case_count": len({str(target["case_id"]) for target in targets}),
        "complete": len(targets) == len(grouped) and sum(
            int(target["pair_scope_record_count"]) for target in targets
        )
        == len(records),
        "targets": targets,
        "final_cutoff_brackets_resolved": False,
        "provider_registry_verified": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["requirements_sha256"] = _canonical_sha(output)
    return output
