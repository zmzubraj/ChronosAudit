from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import pandas as pd

from chronosaudit_stage2.public_acquisition.control_dynamic_horizon import (
    make_feature_vector_sha256,
    validate_cutoff_safe_pair_features,
)


PAIR_FEATURE_SCHEMA = "stage2_control_pair_feature.v1"
PAIR_FEATURE_MANIFEST_SCHEMA = "stage2_control_pair_feature_manifest.v1"
UNKNOWN = "unknown"


class ControlPairFeatureProjectionError(ValueError):
    """A pair feature is not cutoff-safe or does not bind its upstream evidence."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _is_sha(text):
        raise ControlPairFeatureProjectionError(f"{label}_invalid")
    return text


def _time(value: object, label: str) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        raise ControlPairFeatureProjectionError(f"{label}_invalid")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlPairFeatureProjectionError(f"{label}_invalid") from exc
    if parsed.tzinfo is None:
        raise ControlPairFeatureProjectionError(f"{label}_timezone_missing")
    return parsed.astimezone(timezone.utc)


def _canonical_time(value: object, label: str) -> str:
    parsed = _time(value, label)
    if parsed.microsecond:
        raise ControlPairFeatureProjectionError(f"{label}_not_second_precision")
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _lower(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        raise ControlPairFeatureProjectionError(f"{label}_empty")
    return text


def normalize_cutoff_category(value: object, *, status: str) -> str:
    normalized_status = str(status or "").strip().lower()
    if normalized_status == "unavailable":
        return UNKNOWN
    if normalized_status not in {"observed", "observable"}:
        raise ControlPairFeatureProjectionError("acquisition_error_not_category")
    normalized = str(value or "").strip().lower()
    return normalized or UNKNOWN


def _source_projection(
    source: Mapping[str, object] | None, cutoff: datetime
) -> tuple[bool, str, str]:
    if source is None:
        return False, "NOT_ESTABLISHED_AT_CUTOFF", "0" * 64
    status = str(source.get("status", "")).strip().lower()
    if status == "unavailable":
        return False, "NOT_ESTABLISHED_AT_CUTOFF", _sha(
            source.get("evidence_sha256"), "source_evidence_sha256"
        )
    if status != "observed":
        raise ControlPairFeatureProjectionError("acquisition_error_not_category")
    observed_at = _time(source.get("verified_at_utc"), "source_verified_at_utc")
    if observed_at > cutoff:
        raise ControlPairFeatureProjectionError("source_after_cutoff")
    if source.get("historical_cutoff_proven") is not True:
        raise ControlPairFeatureProjectionError("source_cutoff_not_proven")
    verified = source.get("verified") is True
    return (
        verified,
        "PUBLISHED_BY_CUTOFF" if verified else "NOT_PUBLISHED_BY_CUTOFF",
        _sha(source.get("evidence_sha256"), "source_evidence_sha256"),
    )


def _protocol_projection(
    protocol: Mapping[str, object] | None, cutoff: datetime
) -> tuple[str, str, str]:
    if protocol is None:
        return UNKNOWN, UNKNOWN, "0" * 64
    status = str(protocol.get("status", "")).strip().lower()
    if status == "unavailable":
        return UNKNOWN, UNKNOWN, _sha(
            protocol.get("evidence_sha256"), "protocol_evidence_sha256"
        )
    if status != "observed":
        raise ControlPairFeatureProjectionError("acquisition_error_not_category")
    observed_at = _time(protocol.get("observed_at_utc"), "protocol_observed_at_utc")
    if observed_at > cutoff:
        raise ControlPairFeatureProjectionError("protocol_after_cutoff")
    if protocol.get("valid_at_cutoff") is not True:
        raise ControlPairFeatureProjectionError("protocol_cutoff_not_proven")
    return (
        normalize_cutoff_category(protocol.get("protocol_family"), status="observed"),
        normalize_cutoff_category(protocol.get("mechanism_family"), status="observed"),
        _sha(protocol.get("evidence_sha256"), "protocol_evidence_sha256"),
    )


def build_pair_feature(
    *,
    pair_scope: Mapping[str, object],
    denominator: Mapping[str, object],
    trace: Mapping[str, object],
    state: Mapping[str, object],
    source: Mapping[str, object] | None,
    protocol: Mapping[str, object] | None,
    dynamic_horizon_spec_sha256: str,
) -> dict[str, object]:
    """Build one self-hashed cutoff-safe feature with full upstream bindings."""
    if trace.get("disposition") != "complete":
        raise ControlPairFeatureProjectionError("trace_not_complete")
    if state.get("status") != "complete":
        raise ControlPairFeatureProjectionError("acquisition_error_not_category")
    chain = _lower(pair_scope.get("chain"), "pair_chain")
    address = _lower(pair_scope.get("control_address"), "control_address")
    chain_address = f"{chain}:{address}"
    if (
        _lower(denominator.get("chain"), "denominator_chain") != chain
        or _lower(denominator.get("contract_address"), "denominator_address") != address
        or _lower(trace.get("chain_address"), "trace_chain_address") != chain_address
        or _lower(state.get("chain_address"), "state_chain_address") != chain_address
    ):
        raise ControlPairFeatureProjectionError("pair_identity_mismatch")
    denominator_hash = _sha(
        pair_scope.get("denominator_record_sha256"), "denominator_record_sha256"
    )
    if _sha(denominator.get("denominator_record_sha256"), "denominator_record_sha256") != denominator_hash:
        raise ControlPairFeatureProjectionError("denominator_mismatch")
    if denominator.get("counter_authority") is not True:
        raise ControlPairFeatureProjectionError("denominator_not_authorized")
    cutoff_text = _canonical_time(
        pair_scope.get("required_covariate_cutoff_time"), "prediction_cutoff_time_utc"
    )
    cutoff = _time(cutoff_text, "prediction_cutoff_time_utc")
    if int(state.get("cutoff_timestamp", -1)) != int(cutoff.timestamp()):
        raise ControlPairFeatureProjectionError("state_cutoff_mismatch")
    deployment = _time(pair_scope.get("control_deployment_time"), "control_deployment_time")
    if deployment > cutoff:
        raise ControlPairFeatureProjectionError("control_deployment_after_cutoff")
    age_days = int((cutoff - deployment).total_seconds() // 86400)
    source_verified, source_basis, source_sha = _source_projection(source, cutoff)
    protocol_family, mechanism_family, protocol_sha = _protocol_projection(protocol, cutoff)
    field_statuses = state.get("field_statuses")
    if not isinstance(field_statuses, Mapping):
        raise ControlPairFeatureProjectionError("state_field_statuses_invalid")
    proxy_status = normalize_cutoff_category(
        state.get("proxy_status"),
        status=str(field_statuses.get("proxy_classification", "error")),
    )
    proxy_family = normalize_cutoff_category(
        state.get("proxy_family"),
        status=str(field_statuses.get("proxy_classification", "error")),
    )
    clone_family = normalize_cutoff_category(
        state.get("clone_family"), status="observed"
    )
    raw_hashes = state.get("raw_evidence_hashes")
    if not isinstance(raw_hashes, list) or not raw_hashes or not all(_is_sha(value) for value in raw_hashes):
        raise ControlPairFeatureProjectionError("state_raw_evidence_hashes_invalid")
    feature: dict[str, object] = {
        "positive_case_id": str(pair_scope.get("case_name", "")).strip(),
        "positive_record_sha256": _sha(
            pair_scope.get("positive_record_sha256"), "positive_record_sha256"
        ),
        "chain": chain,
        "control_address": address,
        "candidate_control_row_sha256": denominator_hash,
        "prediction_cutoff_time_utc": cutoff_text,
        "mechanism_family": mechanism_family,
        "protocol_family": protocol_family,
        "architecture_proxy_pattern": proxy_family,
        "code_pattern_family": clone_family,
        "code_size_bytes": int(state.get("runtime_code_size", -1)),
        # No approved size-to-complexity mapping exists in DYNAMIC_HORIZON_V1;
        # the frozen missingness rule therefore yields the explicit category.
        "complexity_class": UNKNOWN,
        "contract_age_days_at_cutoff": age_days,
        "source_verified_at_cutoff": source_verified,
    }
    if not feature["positive_case_id"] or int(feature["code_size_bytes"]) < 0:
        raise ControlPairFeatureProjectionError("feature_value_invalid")
    feature["feature_vector_sha256"] = make_feature_vector_sha256(feature)
    separation_values = (mechanism_family, protocol_family, proxy_family, clone_family)
    row: dict[str, object] = {
        "schema_version": PAIR_FEATURE_SCHEMA,
        **feature,
        "pair_scope_record_sha256": _sha(
            pair_scope.get("pair_scope_record_sha256"), "pair_scope_record_sha256"
        ),
        "denominator_record_sha256": denominator_hash,
        "trace_result_sha256": _sha(trace.get("record_sha256"), "trace_result_sha256"),
        "trace_creation_set_sha256": _sha(
            trace.get("creation_set_sha256"), "trace_creation_set_sha256"
        ),
        "state_result_sha256": _sha(state.get("result_sha256"), "state_result_sha256"),
        "state_raw_evidence_hashes": sorted(str(value).lower() for value in raw_hashes),
        "source_verification_basis": source_basis,
        "source_evidence_sha256": source_sha,
        "protocol_evidence_sha256": protocol_sha,
        "proxy_status": proxy_status,
        "dynamic_horizon_spec_sha256": _sha(
            dynamic_horizon_spec_sha256, "dynamic_horizon_spec_sha256"
        ),
        "complexity_mapping_status": "unavailable",
        "separation_eligible": all(value != UNKNOWN for value in separation_values),
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }
    row["pair_feature_record_sha256"] = _canonical_sha(row)
    return row


_DYNAMIC_COLUMNS = (
    "positive_case_id", "positive_record_sha256", "chain", "control_address",
    "candidate_control_row_sha256", "prediction_cutoff_time_utc",
    "mechanism_family", "protocol_family", "architecture_proxy_pattern",
    "code_pattern_family", "code_size_bytes", "complexity_class",
    "contract_age_days_at_cutoff", "source_verified_at_cutoff",
    "feature_vector_sha256",
)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlPairFeatureProjectionError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def project_pair_features(
    *,
    rows: list[Mapping[str, object]],
    output_root: Path,
    upstream_artifacts: Mapping[str, Path] | None = None,
) -> dict[str, object]:
    if not rows:
        raise ControlPairFeatureProjectionError("rows_empty")
    ordered = sorted(
        (dict(row) for row in rows),
        key=lambda row: (
            str(row.get("positive_case_id", "")),
            str(row.get("chain", "")),
            str(row.get("control_address", "")),
        ),
    )
    pair_ids = [
        (row.get("positive_case_id"), row.get("chain"), row.get("control_address"))
        for row in ordered
    ]
    if len(pair_ids) != len(set(pair_ids)):
        raise ControlPairFeatureProjectionError("duplicate_pair")
    for row in ordered:
        supplied = str(row.get("pair_feature_record_sha256", ""))
        material = {
            key: value for key, value in row.items() if key != "pair_feature_record_sha256"
        }
        if supplied != _canonical_sha(material):
            raise ControlPairFeatureProjectionError("pair_feature_record_hash_mismatch")
    frame = pd.DataFrame(
        [{column: row[column] for column in _DYNAMIC_COLUMNS} for row in ordered],
        columns=list(_DYNAMIC_COLUMNS),
    )
    normalized, report = validate_cutoff_safe_pair_features(frame)
    output = output_root.expanduser()
    if output.is_symlink():
        raise ControlPairFeatureProjectionError("output_root_symlink")
    output.mkdir(parents=True, exist_ok=True)
    copied_upstream: list[dict[str, str]] = []
    copied_names: set[str] = set()
    for label, source_value in sorted((upstream_artifacts or {}).items()):
        source = source_value.expanduser()
        if source.is_symlink():
            raise ControlPairFeatureProjectionError("upstream_not_ordinary_file")
        source = source.resolve(strict=True)
        if not source.is_file() or not str(label).strip():
            raise ControlPairFeatureProjectionError("upstream_not_ordinary_file")
        if source.name in copied_names:
            raise ControlPairFeatureProjectionError("upstream_filename_duplicate")
        copied_names.add(source.name)
        destination = output / "input-evidence" / source.name
        _atomic_write(destination, source.read_bytes())
        copied_upstream.append({
            "label": str(label),
            "path": destination.relative_to(output).as_posix(),
            "sha256": _file_sha(destination),
        })
    csv_path = output / "cutoff-safe-pair-features.csv"
    csv_bytes = normalized.to_csv(index=False, lineterminator="\n").encode("utf-8")
    _atomic_write(csv_path, csv_bytes)
    records_path = output / "cutoff-safe-pair-feature-records.json"
    _atomic_write(
        records_path,
        (json.dumps({"schema_version": PAIR_FEATURE_SCHEMA, "records": ordered}, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    manifest: dict[str, object] = {
        "schema_version": PAIR_FEATURE_MANIFEST_SCHEMA,
        "decision": "CUTOFF_SAFE_PAIR_FEATURES_PROJECTED_NON_AUTHORIZING",
        "record_count": len(ordered),
        "case_count": len({str(row["positive_case_id"]) for row in ordered}),
        "csv_path": csv_path.name,
        "csv_sha256": _file_sha(csv_path),
        "records_path": records_path.name,
        "records_sha256": _file_sha(records_path),
        "pair_feature_record_sha256s": [
            row["pair_feature_record_sha256"] for row in ordered
        ],
        "upstream_binding_sha256": _canonical_sha([
            {
                "pair_scope_record_sha256": row["pair_scope_record_sha256"],
                "denominator_record_sha256": row["denominator_record_sha256"],
                "trace_result_sha256": row["trace_result_sha256"],
                "state_result_sha256": row["state_result_sha256"],
                "source_evidence_sha256": row["source_evidence_sha256"],
                "protocol_evidence_sha256": row["protocol_evidence_sha256"],
            }
            for row in ordered
        ]),
        "upstream_artifacts": copied_upstream,
        "explicit_unknown_protocol_count": sum(
            row["protocol_family"] == UNKNOWN for row in ordered
        ),
        "explicit_unknown_proxy_count": sum(
            row["proxy_status"] == UNKNOWN for row in ordered
        ),
        "explicit_unknown_complexity_count": sum(
            row["complexity_class"] == UNKNOWN for row in ordered
        ),
        "source_verified_at_cutoff_true_count": sum(
            row["source_verified_at_cutoff"] is True for row in ordered
        ),
        "dynamic_validation": report,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "errors": [],
    }
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    manifest_path = output / "cutoff-safe-pair-feature-manifest.json"
    _atomic_write(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return {
        "status": "COMPLETE_NON_AUTHORIZING",
        "csv_path": str(csv_path),
        "csv_sha256": manifest["csv_sha256"],
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest["manifest_sha256"],
        "records_path": str(records_path),
        "records_sha256": manifest["records_sha256"],
        "record_count": len(ordered),
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlPairFeatureProjectionError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlPairFeatureProjectionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlPairFeatureProjectionError(f"{label}_not_ordinary_file")
    return resolved


def _child(root: Path, value: object, label: str) -> Path:
    relative = Path(str(value or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ControlPairFeatureProjectionError("artifact_path_escape")
    child = _ordinary(root / relative, label)
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise ControlPairFeatureProjectionError("artifact_path_escape") from exc
    return child


def verify_pair_feature_projection(manifest_path: Path) -> dict[str, object]:
    manifest_file = _ordinary(manifest_path, "manifest")
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlPairFeatureProjectionError("manifest_json_invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != PAIR_FEATURE_MANIFEST_SCHEMA:
        raise ControlPairFeatureProjectionError("manifest_schema_invalid")
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if manifest.get("manifest_sha256") != _canonical_sha(material):
        raise ControlPairFeatureProjectionError("manifest_self_hash_invalid")
    for flag in ("selection_authorized", "qualification_authorized", "counter_authority"):
        if manifest.get(flag) is not False:
            raise ControlPairFeatureProjectionError(f"manifest_{flag}_invalid")
    root = manifest_file.parent.resolve(strict=True)
    csv_path = _child(root, manifest.get("csv_path"), "csv")
    records_path = _child(root, manifest.get("records_path"), "records")
    if _file_sha(csv_path) != manifest.get("csv_sha256"):
        raise ControlPairFeatureProjectionError("csv_hash_mismatch")
    if _file_sha(records_path) != manifest.get("records_sha256"):
        raise ControlPairFeatureProjectionError("records_hash_mismatch")
    upstream = manifest.get("upstream_artifacts")
    if not isinstance(upstream, list):
        raise ControlPairFeatureProjectionError("upstream_artifacts_invalid")
    seen_labels: set[str] = set()
    for artifact in upstream:
        if not isinstance(artifact, Mapping):
            raise ControlPairFeatureProjectionError("upstream_artifact_invalid")
        label = str(artifact.get("label", ""))
        if not label or label in seen_labels:
            raise ControlPairFeatureProjectionError("upstream_artifact_invalid")
        seen_labels.add(label)
        path = _child(root, artifact.get("path"), "upstream")
        if _file_sha(path) != artifact.get("sha256"):
            raise ControlPairFeatureProjectionError("upstream_hash_mismatch")
    payload = json.loads(records_path.read_text(encoding="utf-8"))
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list) or len(records) != int(manifest.get("record_count", -1)):
        raise ControlPairFeatureProjectionError("records_count_mismatch")
    supplied_hashes = []
    feature_rows = []
    for record in records:
        if not isinstance(record, dict):
            raise ControlPairFeatureProjectionError("record_invalid")
        supplied = str(record.get("pair_feature_record_sha256", ""))
        record_material = {
            key: value for key, value in record.items() if key != "pair_feature_record_sha256"
        }
        if supplied != _canonical_sha(record_material):
            raise ControlPairFeatureProjectionError("pair_feature_record_hash_mismatch")
        supplied_hashes.append(supplied)
        feature_rows.append({column: record[column] for column in _DYNAMIC_COLUMNS})
    if supplied_hashes != manifest.get("pair_feature_record_sha256s"):
        raise ControlPairFeatureProjectionError("record_inventory_mismatch")
    normalized, dynamic_report = validate_cutoff_safe_pair_features(pd.DataFrame(feature_rows))
    observed_csv = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    observed_normalized, _ = validate_cutoff_safe_pair_features(observed_csv)
    pd.testing.assert_frame_equal(
        normalized.reset_index(drop=True),
        observed_normalized.reset_index(drop=True),
    )
    report: dict[str, object] = {
        "schema_version": "stage2_control_pair_feature_verification.v1",
        "complete": True,
        "decision": "CUTOFF_SAFE_PAIR_FEATURES_VERIFIED_NON_AUTHORIZING",
        "manifest_sha256": manifest["manifest_sha256"],
        "manifest_file_sha256": _file_sha(manifest_file),
        "csv_sha256": manifest["csv_sha256"],
        "records_sha256": manifest["records_sha256"],
        "record_count": manifest["record_count"],
        "upstream_artifact_count": len(upstream),
        "dynamic_validation": dynamic_report,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "errors": [],
    }
    report["verification_sha256"] = _canonical_sha(report)
    return report
