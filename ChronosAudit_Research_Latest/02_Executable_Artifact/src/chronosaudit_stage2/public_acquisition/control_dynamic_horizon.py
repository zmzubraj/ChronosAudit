from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
from typing import Mapping

import numpy as np
import pandas as pd


class ControlDynamicHorizonError(ValueError):
    """Raised when dynamic-horizon evidence violates the frozen contract."""


REFERENCE_SCHEMA_VERSION = "chronosaudit.control_reference_latency_cohort.v1"
PAIR_FEATURE_SCHEMA_VERSION = "chronosaudit.control_cutoff_safe_pair_features.v1"
SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-dynamic-horizon-v1"
REFERENCE_IDENTITY_DEDUP_POLICY = "REFERENCE_IDENTITY_DEDUP_V1"
UNKNOWN_CATEGORY = "unknown"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_REFERENCE_HASH_FIELDS = (
    "reference_id",
    "chain",
    "contract_address",
    "mechanism_family",
    "protocol_family",
    "architecture_proxy_pattern",
    "code_pattern_family",
    "code_size_bytes",
    "complexity_class",
    "contract_age_days_at_risk_entry",
    "source_verified_at_cutoff",
    "risk_entry_time_utc",
    "event_or_censoring_time_utc",
    "event_observed",
    "latency_seconds",
    "timing_precision",
    "risk_entry_source_sha256",
    "event_time_source_sha256",
    "provenance_record_sha256",
)
_REFERENCE_COLUMNS = set(_REFERENCE_HASH_FIELDS) | {"reference_record_sha256"}

_PAIR_HASH_FIELDS = (
    "positive_case_id",
    "positive_record_sha256",
    "chain",
    "control_address",
    "candidate_control_row_sha256",
    "prediction_cutoff_time_utc",
    "mechanism_family",
    "protocol_family",
    "architecture_proxy_pattern",
    "code_pattern_family",
    "code_size_bytes",
    "complexity_class",
    "contract_age_days_at_cutoff",
    "source_verified_at_cutoff",
)
_PAIR_COLUMNS = set(_PAIR_HASH_FIELDS) | {"feature_vector_sha256"}

_PROHIBITED_FIELD_FRAGMENTS = (
    "control_outcome",
    "future_exploit",
    "post_cutoff",
    "last_observed",
    "maturity_status",
    "qualification_status",
    "qualified_control",
    "allocation_success",
    "target_pressure",
    "replacement_status",
    "incident_status",
    "incident_time",
    "event_observed",
    "event_or_censoring",
    "latency_seconds",
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _text(value: object, label: str) -> str:
    result = str(value).strip()
    if not result:
        raise ControlDynamicHorizonError(f"{label}_invalid")
    return result


def _lower_text(value: object, label: str) -> str:
    return _text(value, label).lower()


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ControlDynamicHorizonError(f"{label}_invalid") from exc
    if isinstance(value, float) and not value.is_integer():
        raise ControlDynamicHorizonError(f"{label}_invalid")
    if number < minimum:
        raise ControlDynamicHorizonError(f"{label}_invalid")
    return number


def _boolean(value: object, label: str) -> bool:
    if value is True or str(value).strip().lower() == "true":
        return True
    if value is False or str(value).strip().lower() == "false":
        return False
    raise ControlDynamicHorizonError(f"{label}_invalid")


def _sha(value: object, label: str) -> str:
    result = str(value).strip().lower()
    if not _SHA256.fullmatch(result):
        raise ControlDynamicHorizonError(f"{label}_invalid")
    return result


def _address(value: object, label: str) -> str:
    result = str(value).strip().lower()
    if not _ADDRESS.fullmatch(result):
        raise ControlDynamicHorizonError(f"{label}_invalid")
    return result


def _time(value: object, label: str) -> pd.Timestamp:
    raw = str(value)
    if not _CANONICAL_UTC.fullmatch(raw):
        raise ControlDynamicHorizonError(f"{label}_not_canonical")
    parsed = pd.to_datetime(raw, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlDynamicHorizonError(f"{label}_invalid")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != raw:
        raise ControlDynamicHorizonError(f"{label}_not_canonical")
    return parsed


def _normalize_reference(row: Mapping[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {
        "reference_id": _text(row.get("reference_id"), "reference_id"),
        "chain": _lower_text(row.get("chain"), "chain"),
        "contract_address": _address(row.get("contract_address"), "contract_address"),
        "mechanism_family": _lower_text(row.get("mechanism_family"), "mechanism_family"),
        "protocol_family": _lower_text(row.get("protocol_family"), "protocol_family"),
        "architecture_proxy_pattern": _lower_text(
            row.get("architecture_proxy_pattern"), "architecture_proxy_pattern"
        ),
        "code_pattern_family": _lower_text(row.get("code_pattern_family"), "code_pattern_family"),
        "code_size_bytes": _integer(row.get("code_size_bytes"), "code_size_bytes"),
        "complexity_class": _lower_text(row.get("complexity_class"), "complexity_class"),
        "contract_age_days_at_risk_entry": _integer(
            row.get("contract_age_days_at_risk_entry"),
            "contract_age_days_at_risk_entry",
        ),
        "source_verified_at_cutoff": _boolean(
            row.get("source_verified_at_cutoff"), "source_verified_at_cutoff"
        ),
        "risk_entry_time_utc": _text(row.get("risk_entry_time_utc"), "risk_entry_time_utc"),
        "event_or_censoring_time_utc": _text(
            row.get("event_or_censoring_time_utc"),
            "event_or_censoring_time_utc",
        ),
        "event_observed": _boolean(row.get("event_observed"), "event_observed"),
        "latency_seconds": _integer(row.get("latency_seconds"), "latency_seconds", minimum=1),
        "timing_precision": _text(row.get("timing_precision"), "timing_precision").upper(),
        "risk_entry_source_sha256": _sha(
            row.get("risk_entry_source_sha256"), "risk_entry_source_sha256"
        ),
        "event_time_source_sha256": _sha(
            row.get("event_time_source_sha256"), "event_time_source_sha256"
        ),
        "provenance_record_sha256": _sha(
            row.get("provenance_record_sha256"), "provenance_record_sha256"
        ),
    }
    return normalized


def _normalize_pair(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "positive_case_id": _text(row.get("positive_case_id"), "positive_case_id"),
        "positive_record_sha256": _sha(
            row.get("positive_record_sha256"), "positive_record_sha256"
        ),
        "chain": _lower_text(row.get("chain"), "chain"),
        "control_address": _address(row.get("control_address"), "control_address"),
        "candidate_control_row_sha256": _sha(
            row.get("candidate_control_row_sha256"), "candidate_control_row_sha256"
        ),
        "prediction_cutoff_time_utc": _text(
            row.get("prediction_cutoff_time_utc"), "prediction_cutoff_time_utc"
        ),
        "mechanism_family": _lower_text(row.get("mechanism_family"), "mechanism_family"),
        "protocol_family": _lower_text(row.get("protocol_family"), "protocol_family"),
        "architecture_proxy_pattern": _lower_text(
            row.get("architecture_proxy_pattern"), "architecture_proxy_pattern"
        ),
        "code_pattern_family": _lower_text(row.get("code_pattern_family"), "code_pattern_family"),
        "code_size_bytes": _integer(row.get("code_size_bytes"), "code_size_bytes"),
        "complexity_class": _lower_text(row.get("complexity_class"), "complexity_class"),
        "contract_age_days_at_cutoff": _integer(
            row.get("contract_age_days_at_cutoff"), "contract_age_days_at_cutoff"
        ),
        "source_verified_at_cutoff": _boolean(
            row.get("source_verified_at_cutoff"), "source_verified_at_cutoff"
        ),
    }


def make_reference_record_sha256(row: Mapping[str, object]) -> str:
    normalized = _normalize_reference(row)
    return _canonical_sha256({field: normalized[field] for field in _REFERENCE_HASH_FIELDS})


def make_feature_vector_sha256(row: Mapping[str, object]) -> str:
    normalized = _normalize_pair(row)
    return _canonical_sha256({field: normalized[field] for field in _PAIR_HASH_FIELDS})


def _report(*, schema_version: str, decision: str, rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "decision": decision,
        "row_count": len(rows),
        "records_sha256": _canonical_sha256(rows),
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }


def validate_reference_latency_cohort(
    frame: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, object]]:
    missing = sorted(_REFERENCE_COLUMNS - set(frame.columns))
    unknown = sorted(set(frame.columns) - _REFERENCE_COLUMNS)
    if missing:
        raise ControlDynamicHorizonError(f"reference_missing_columns:{','.join(missing)}")
    if unknown:
        raise ControlDynamicHorizonError(f"reference_unknown_columns:{','.join(unknown)}")
    if frame.empty:
        raise ControlDynamicHorizonError("reference_cohort_empty")

    rows: list[dict[str, object]] = []
    identities: set[tuple[str, str]] = set()
    reference_ids: set[str] = set()
    for source in frame.to_dict(orient="records"):
        normalized = _normalize_reference(source)
        start = _time(normalized["risk_entry_time_utc"], "risk_entry_time_utc")
        end = _time(
            normalized["event_or_censoring_time_utc"],
            "event_or_censoring_time_utc",
        )
        if end <= start:
            raise ControlDynamicHorizonError("reference_time_order_invalid")
        observed = int((end - start).total_seconds())
        if observed != normalized["latency_seconds"]:
            raise ControlDynamicHorizonError("reference_latency_mismatch")
        if normalized["timing_precision"] != "SECONDS":
            raise ControlDynamicHorizonError("reference_timing_precision_invalid")
        expected = _canonical_sha256(
            {field: normalized[field] for field in _REFERENCE_HASH_FIELDS}
        )
        supplied = _sha(source.get("reference_record_sha256"), "reference_record_sha256")
        if supplied != expected:
            raise ControlDynamicHorizonError("reference_record_hash_mismatch")
        identity = (str(normalized["chain"]), str(normalized["contract_address"]))
        if identity in identities:
            raise ControlDynamicHorizonError("reference_identity_duplicate")
        identities.add(identity)
        reference_id = str(normalized["reference_id"])
        if reference_id in reference_ids:
            raise ControlDynamicHorizonError("reference_id_duplicate")
        reference_ids.add(reference_id)
        normalized["reference_record_sha256"] = supplied
        rows.append(normalized)
    rows.sort(key=lambda row: str(row["reference_id"]))
    report = _report(
        schema_version=REFERENCE_SCHEMA_VERSION,
        decision="REFERENCE_LATENCY_COHORT_VERIFIED",
        rows=rows,
    )
    report["reference_identity_count"] = len(identities)
    return pd.DataFrame(rows, columns=sorted(_REFERENCE_COLUMNS)), report


def validate_cutoff_safe_pair_features(
    frame: pd.DataFrame,
    *,
    reference_identities: set[tuple[str, str]] | None = None,
) -> tuple[pd.DataFrame, dict[str, object]]:
    prohibited = sorted(
        column
        for column in frame.columns
        if any(fragment in column.strip().lower() for fragment in _PROHIBITED_FIELD_FRAGMENTS)
    )
    if prohibited:
        raise ControlDynamicHorizonError(f"pair_prohibited_fields:{','.join(prohibited)}")
    missing = sorted(_PAIR_COLUMNS - set(frame.columns))
    unknown = sorted(set(frame.columns) - _PAIR_COLUMNS)
    if missing:
        raise ControlDynamicHorizonError(f"pair_missing_columns:{','.join(missing)}")
    if unknown:
        raise ControlDynamicHorizonError(f"pair_unknown_columns:{','.join(unknown)}")
    if frame.empty:
        raise ControlDynamicHorizonError("pair_features_empty")

    references = {(chain.lower(), address.lower()) for chain, address in (reference_identities or set())}
    rows: list[dict[str, object]] = []
    pair_ids: set[tuple[str, str, str]] = set()
    for source in frame.to_dict(orient="records"):
        normalized = _normalize_pair(source)
        _time(normalized["prediction_cutoff_time_utc"], "prediction_cutoff_time_utc")
        identity = (str(normalized["chain"]), str(normalized["control_address"]))
        if identity in references:
            raise ControlDynamicHorizonError("pair_reference_overlap")
        pair_id = (
            str(normalized["positive_case_id"]),
            str(normalized["chain"]),
            str(normalized["control_address"]),
        )
        if pair_id in pair_ids:
            raise ControlDynamicHorizonError("pair_identity_duplicate")
        pair_ids.add(pair_id)
        expected = _canonical_sha256(
            {field: normalized[field] for field in _PAIR_HASH_FIELDS}
        )
        supplied = _sha(source.get("feature_vector_sha256"), "feature_vector_sha256")
        if supplied != expected:
            raise ControlDynamicHorizonError("pair_feature_hash_mismatch")
        normalized["feature_vector_sha256"] = supplied
        rows.append(normalized)
    rows.sort(
        key=lambda row: (
            str(row["positive_case_id"]),
            str(row["chain"]),
            str(row["control_address"]),
        )
    )
    report = _report(
        schema_version=PAIR_FEATURE_SCHEMA_VERSION,
        decision="CUTOFF_SAFE_PAIR_FEATURES_VERIFIED",
        rows=rows,
    )
    report["prohibited_field_count"] = 0
    return pd.DataFrame(rows, columns=sorted(_PAIR_COLUMNS)), report


def verify_final_pair_feature_binding(
    *, pair_features_path: Path, pair_feature_manifest_path: Path
) -> dict[str, object]:
    """Require the additive cutoff-safe import gate before horizon fitting."""
    from chronosaudit_stage2.public_acquisition.control_pair_covariate_import import (
        PairCovariateImportError,
        verify_cutoff_safe_pair_feature_manifest,
    )

    pair_file = _ordinary_file(pair_features_path, "pair_features")
    manifest_file = _ordinary_file(pair_feature_manifest_path, "pair_feature_manifest")
    try:
        report = verify_cutoff_safe_pair_feature_manifest(manifest_file)
    except PairCovariateImportError as exc:
        raise ControlDynamicHorizonError(str(exc)) from exc
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    relative = Path(str(manifest.get("csv_path", "")))
    if relative.is_absolute() or ".." in relative.parts:
        raise ControlDynamicHorizonError("pair_feature_manifest_path_escape")
    bound_csv = (manifest_file.parent / relative).resolve(strict=True)
    if bound_csv != pair_file or _sha256_file_bytes(pair_file) != manifest.get("csv_sha256"):
        raise ControlDynamicHorizonError("pair_feature_manifest_csv_mismatch")
    return {
        "complete": True,
        "decision": "FINAL_PAIR_FEATURE_BINDING_VERIFIED_NON_AUTHORIZING",
        "pair_features_sha256": _sha256_file_bytes(pair_file),
        "pair_feature_manifest_sha256": _sha256_file_bytes(manifest_file),
        "pair_feature_manifest_internal_sha256": manifest["manifest_sha256"],
        "upstream_artifact_count": report["upstream_artifact_count"],
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }


def _sha256_file_bytes(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_reference_latency_cohort_from_verified_snapshots(
    *,
    positive_projection_path: Path,
    verified_projection_path: Path,
    snapshot_root: Path,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Assemble event latencies only from the counter-authorized v4 snapshots."""
    positives_path = positive_projection_path.expanduser().resolve(strict=True)
    verification_path = verified_projection_path.expanduser().resolve(strict=True)
    snapshots = snapshot_root.expanduser().resolve(strict=True)
    if not snapshots.is_dir():
        raise ControlDynamicHorizonError("snapshot_root_not_directory")
    positives = pd.read_csv(positives_path, keep_default_na=False, low_memory=False)
    verified = pd.read_csv(verification_path, keep_default_na=False, low_memory=False)
    positive_required = {
        "case_id", "case_name", "chain", "target_contract_address", "mechanism_raw",
        "code_size", "proxy_family", "clone_family", "protocol_family",
        "source_verified_at_cutoff",
    }
    verified_required = {
        "case_id", "case_name", "chain", "envelope_path", "envelope_sha256",
        "counter_authority", "historical_snapshot_status", "historical_snapshot_hash_bound",
    }
    if positive_required - set(positives.columns):
        raise ControlDynamicHorizonError("reference_positive_projection_schema_invalid")
    if verified_required - set(verified.columns):
        raise ControlDynamicHorizonError("reference_verified_projection_schema_invalid")
    if positives["case_id"].duplicated().any() or verified["case_id"].duplicated().any():
        raise ControlDynamicHorizonError("reference_source_case_duplicate")
    positive_by_id = positives.set_index("case_id", drop=False)
    if set(positive_by_id.index) != set(verified["case_id"]):
        raise ControlDynamicHorizonError("reference_source_case_membership_mismatch")

    candidates: list[dict[str, object]] = []
    for verification in verified.sort_values("case_id").to_dict(orient="records"):
        case_id = str(verification["case_id"])
        if _boolean(verification["counter_authority"], "snapshot_counter_authority") is not True:
            raise ControlDynamicHorizonError("reference_snapshot_not_counter_authorized")
        if verification["historical_snapshot_status"] != "HISTORICAL_SNAPSHOT_VERIFIED":
            raise ControlDynamicHorizonError("reference_snapshot_status_invalid")
        if _boolean(verification["historical_snapshot_hash_bound"], "snapshot_hash_bound") is not True:
            raise ControlDynamicHorizonError("reference_snapshot_not_hash_bound")
        envelope_path = (snapshots / str(verification["envelope_path"])).resolve(strict=True)
        try:
            envelope_path.relative_to(snapshots)
        except ValueError as exc:
            raise ControlDynamicHorizonError("reference_snapshot_path_escape") from exc
        if envelope_path.is_symlink() or not envelope_path.is_file():
            raise ControlDynamicHorizonError("reference_snapshot_not_ordinary_file")
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict) or envelope.get("envelope_sha256") != verification["envelope_sha256"]:
            raise ControlDynamicHorizonError("reference_snapshot_envelope_hash_mismatch")
        strict = envelope.get("strict_snapshot")
        if not isinstance(strict, Mapping):
            raise ControlDynamicHorizonError("reference_strict_snapshot_missing")
        if strict.get("strict_snapshot_closed") is not True or strict.get("blockers") != []:
            raise ControlDynamicHorizonError("reference_strict_snapshot_not_closed")
        positive = positive_by_id.loc[case_id].to_dict()
        for left, right, label in (
            (strict.get("case_name"), positive["case_name"], "case_name"),
            (strict.get("chain"), positive["chain"], "chain"),
            (str(strict.get("address") or "").lower(), str(positive["target_contract_address"]).lower(), "address"),
        ):
            if left != right:
                raise ControlDynamicHorizonError(f"reference_snapshot_{label}_mismatch")
        def source_timestamp(value: object, label: str) -> pd.Timestamp:
            if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
                try:
                    return pd.Timestamp(int(value), unit="s", tz="UTC")
                except (ValueError, OverflowError) as exc:
                    raise ControlDynamicHorizonError(f"{label}_invalid") from exc
            return _time(value, label)

        start = source_timestamp(
            strict.get("prediction_cutoff_timestamp"), "reference_risk_entry_time_utc"
        )
        event = source_timestamp(strict.get("incident_timestamp"), "reference_event_time_utc")
        deployment = source_timestamp(
            strict.get("deployment_timestamp"), "reference_deployment_time_utc"
        )
        latency_seconds = int((event - start).total_seconds())
        if latency_seconds <= 0 or start < deployment:
            raise ControlDynamicHorizonError("reference_snapshot_time_order_invalid")
        artifact_sha = _sha(strict.get("artifact_sha256"), "reference_strict_snapshot_sha256")
        protocol = str(positive["protocol_family"]).strip() or UNKNOWN_CATEGORY
        architecture = str(positive["proxy_family"]).strip() or UNKNOWN_CATEGORY
        code_pattern = str(positive["clone_family"]).strip() or UNKNOWN_CATEGORY
        source_state = str(positive["source_verified_at_cutoff"]).strip().lower() == "true"
        candidates.append({
            "case_id": case_id,
            "chain": positive["chain"],
            "contract_address": positive["target_contract_address"],
            "mechanism_family": positive["mechanism_raw"],
            "protocol_family": protocol,
            "architecture_proxy_pattern": architecture,
            "code_pattern_family": code_pattern,
            "code_size_bytes": int(positive["code_size"]),
            "complexity_class": UNKNOWN_CATEGORY,
            "contract_age_days_at_risk_entry": int((start - deployment).total_seconds() // 86_400),
            "source_verified_at_cutoff": source_state,
            "risk_entry_time": start,
            "event_time": event,
            "artifact_sha256": artifact_sha,
            "envelope_sha256": _sha(
                verification["envelope_sha256"], "reference_envelope_sha256"
            ),
        })

    grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
    for candidate in candidates:
        identity = (
            str(candidate["chain"]).strip().lower(),
            str(candidate["contract_address"]).strip().lower(),
        )
        grouped.setdefault(identity, []).append(candidate)

    rows: list[dict[str, object]] = []
    lineage: list[dict[str, object]] = []
    duplicate_groups = 0
    for identity in sorted(grouped):
        group = grouped[identity]
        if len(group) > 1:
            duplicate_groups += 1
        risk_owner = min(
            group,
            key=lambda item: (item["risk_entry_time"], str(item["case_id"])),
        )
        risk_entry = risk_owner["risk_entry_time"]
        qualifying_events = [item for item in group if item["event_time"] > risk_entry]
        if not qualifying_events:
            raise ControlDynamicHorizonError("reference_identity_no_post_risk_event")
        event_owner = min(
            qualifying_events,
            key=lambda item: (item["event_time"], str(item["case_id"])),
        )
        event_time = event_owner["event_time"]
        latency_seconds = int((event_time - risk_entry).total_seconds())
        provenance_binding = {
            "deduplication_policy": REFERENCE_IDENTITY_DEDUP_POLICY,
            "chain": identity[0],
            "contract_address": identity[1],
            "risk_entry_case_id": risk_owner["case_id"],
            "risk_entry_envelope_sha256": risk_owner["envelope_sha256"],
            "event_case_id": event_owner["case_id"],
            "event_envelope_sha256": event_owner["envelope_sha256"],
        }
        row: dict[str, object] = {
            "reference_id": risk_owner["case_id"],
            "chain": risk_owner["chain"],
            "contract_address": risk_owner["contract_address"],
            "mechanism_family": risk_owner["mechanism_family"],
            "protocol_family": risk_owner["protocol_family"],
            "architecture_proxy_pattern": risk_owner["architecture_proxy_pattern"],
            "code_pattern_family": risk_owner["code_pattern_family"],
            "code_size_bytes": risk_owner["code_size_bytes"],
            "complexity_class": risk_owner["complexity_class"],
            "contract_age_days_at_risk_entry": risk_owner["contract_age_days_at_risk_entry"],
            "source_verified_at_cutoff": risk_owner["source_verified_at_cutoff"],
            "risk_entry_time_utc": risk_entry.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_or_censoring_time_utc": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_observed": True,
            "latency_seconds": latency_seconds,
            "timing_precision": "SECONDS",
            "risk_entry_source_sha256": risk_owner["artifact_sha256"],
            "event_time_source_sha256": event_owner["artifact_sha256"],
            "provenance_record_sha256": _canonical_sha256(provenance_binding),
        }
        row["reference_record_sha256"] = make_reference_record_sha256(row)
        rows.append(row)
        lineage.append({
            **provenance_binding,
            "source_case_ids": sorted(str(item["case_id"]) for item in group),
            "source_row_count": len(group),
            "risk_entry_time_utc": row["risk_entry_time_utc"],
            "event_time_utc": row["event_or_censoring_time_utc"],
            "provenance_record_sha256": row["provenance_record_sha256"],
            "reference_record_sha256": row["reference_record_sha256"],
        })
    cohort, validation = validate_reference_latency_cohort(pd.DataFrame(rows))
    report = {
        "schema_version": "chronosaudit.control_reference_latency_assembly.v1",
        "decision": "REFERENCE_LATENCY_COHORT_ASSEMBLED_FROM_VERIFIED_SNAPSHOTS",
        "positive_projection_sha256": _sha256_file_bytes(positives_path),
        "verified_projection_sha256": _sha256_file_bytes(verification_path),
        "verified_snapshot_count": len(verified),
        "source_row_count": len(candidates),
        "reference_row_count": len(cohort),
        "deduplication_policy": REFERENCE_IDENTITY_DEDUP_POLICY,
        "deduplication_identity_unit": "chain_address",
        "risk_entry_rule": "earliest_frozen_risk_entry_then_ascending_case_id",
        "event_rule": "first_qualifying_incident_strictly_after_risk_entry_then_ascending_case_id",
        "duplicate_identity_group_count": duplicate_groups,
        "deduplicated_source_row_count": len(candidates) - len(cohort),
        "unknown_category": UNKNOWN_CATEGORY,
        "reference_records_sha256": validation["records_sha256"],
        "event_observed_count": int(cohort["event_observed"].sum()),
        "explicit_unknown_protocol_count": int(cohort["protocol_family"].eq(UNKNOWN_CATEGORY).sum()),
        "explicit_unknown_architecture_count": int(cohort["architecture_proxy_pattern"].eq(UNKNOWN_CATEGORY).sum()),
        "explicit_unknown_complexity_count": int(cohort["complexity_class"].eq(UNKNOWN_CATEGORY).sum()),
        "source_verified_at_cutoff_true_count": int(cohort["source_verified_at_cutoff"].sum()),
        "assembly_lineage": lineage,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }
    return cohort, report


def kaplan_meier_quantile_seconds(
    durations: list[int] | pd.Series,
    events: list[bool] | pd.Series,
    probability: float,
) -> int | None:
    """Return the first event time whose KM cumulative incidence reaches p."""
    if not 0 < probability < 1:
        raise ControlDynamicHorizonError("km_probability_invalid")
    if len(durations) != len(events) or not len(durations):
        raise ControlDynamicHorizonError("km_inputs_invalid")
    observations = sorted(
        [(_integer(duration, "km_duration", minimum=1), _boolean(event, "km_event"))
         for duration, event in zip(durations, events, strict=True)],
        key=lambda item: item[0],
    )
    survival = 1.0
    for event_time in sorted({duration for duration, _ in observations}):
        at_risk = sum(duration >= event_time for duration, _ in observations)
        event_count = sum(
            duration == event_time and event for duration, event in observations
        )
        if event_count:
            survival *= 1.0 - (event_count / at_risk)
            if 1.0 - survival >= probability - 1e-12:
                return event_time
    return None


def _bootstrap_quantiles(
    frame: pd.DataFrame,
    *,
    probability: float,
    replicates: int,
    seed_material: object,
) -> list[int]:
    seed = int(_canonical_sha256(seed_material)[:16], 16)
    rng = np.random.Generator(np.random.PCG64(seed))
    durations = frame["latency_seconds"].astype(int).to_numpy()
    events = frame["event_observed"].astype(bool).to_numpy()
    results: list[int] = []
    for _ in range(replicates):
        indexes = rng.integers(0, len(frame), size=len(frame))
        estimate = kaplan_meier_quantile_seconds(
            durations[indexes].tolist(), events[indexes].tolist(), probability
        )
        if estimate is not None:
            results.append(estimate)
    return results


def _percentile_higher(values: list[int], probability: float) -> int:
    if not values:
        raise ControlDynamicHorizonError("bootstrap_quantiles_empty")
    return int(np.quantile(np.asarray(values, dtype=np.int64), probability, method="higher"))


def _fit_stratum(
    frame: pd.DataFrame,
    *,
    level: str,
    key: dict[str, str],
    probability: float,
    bootstrap_replicates: int,
    minimum_rows: int,
    minimum_events: int,
) -> dict[str, object]:
    row_count = len(frame)
    event_count = int(frame["event_observed"].astype(bool).sum())
    base: dict[str, object] = {
        "level": level,
        "key": key,
        "row_count": row_count,
        "event_count": event_count,
        "status": "INSUFFICIENT_REFERENCE_EVIDENCE",
        "quantile_seconds": None,
        "bootstrap_usable_replicates": 0,
        "uncertainty_allowance_seconds": None,
    }
    if row_count < minimum_rows or event_count < minimum_events:
        return base
    quantile = kaplan_meier_quantile_seconds(
        frame["latency_seconds"].astype(int).tolist(),
        frame["event_observed"].astype(bool).tolist(),
        probability,
    )
    if quantile is None:
        return base
    bootstrap = _bootstrap_quantiles(
        frame,
        probability=probability,
        replicates=bootstrap_replicates,
        seed_material={
            "schema_version": "chronosaudit.control_dynamic_horizon_bootstrap.v1",
            "level": level,
            "key": key,
            "probability": probability,
            "bootstrap_replicates": bootstrap_replicates,
        },
    )
    if len(bootstrap) < math.ceil(bootstrap_replicates * 0.9):
        return base
    upper = _percentile_higher(bootstrap, 0.95)
    base.update(
        {
            "status": "ESTIMABLE",
            "quantile_seconds": quantile,
            "bootstrap_usable_replicates": len(bootstrap),
            "uncertainty_allowance_seconds": max(0, upper - quantile),
        }
    )
    return base


def fit_dynamic_horizon_model(
    reference_frame: pd.DataFrame,
    *,
    bootstrap_replicates: int = 1000,
    minimum_rows: int = 30,
    minimum_events: int = 20,
) -> dict[str, object]:
    """Fit the frozen outcome-blind hierarchy from validated reference rows."""
    if bootstrap_replicates != 1000:
        raise ControlDynamicHorizonError("bootstrap_replicates_not_frozen")
    if minimum_rows != 30 or minimum_events != 20:
        raise ControlDynamicHorizonError("stratum_thresholds_not_frozen")
    required = _REFERENCE_COLUMNS
    if required - set(reference_frame.columns):
        raise ControlDynamicHorizonError("model_reference_schema_invalid")

    hierarchy: list[tuple[str, tuple[str, ...]]] = [
        (
            "EXACT",
            ("mechanism_family", "protocol_family", "architecture_proxy_pattern"),
        ),
        ("ARCHITECTURE_PROTOCOL", ("architecture_proxy_pattern", "protocol_family")),
        ("CHAIN", ("chain",)),
        ("GLOBAL", ()),
    ]
    strata: list[dict[str, object]] = []
    for level, fields in hierarchy:
        if fields:
            grouper: str | list[str] = fields[0] if len(fields) == 1 else list(fields)
            groups = reference_frame.groupby(grouper, sort=True, dropna=False)
            for raw_key, group in groups:
                values = raw_key if isinstance(raw_key, tuple) else (raw_key,)
                key = {field: str(value) for field, value in zip(fields, values, strict=True)}
                strata.append(
                    _fit_stratum(
                        group,
                        level=level,
                        key=key,
                        probability=0.95,
                        bootstrap_replicates=bootstrap_replicates,
                        minimum_rows=minimum_rows,
                        minimum_events=minimum_events,
                    )
                )
        else:
            strata.append(
                _fit_stratum(
                    reference_frame,
                    level=level,
                    key={},
                    probability=0.95,
                    bootstrap_replicates=bootstrap_replicates,
                    minimum_rows=minimum_rows,
                    minimum_events=minimum_events,
                )
            )

    lower = kaplan_meier_quantile_seconds(
        reference_frame["latency_seconds"].astype(int).tolist(),
        reference_frame["event_observed"].astype(bool).tolist(),
        0.80,
    )
    global_q99 = kaplan_meier_quantile_seconds(
        reference_frame["latency_seconds"].astype(int).tolist(),
        reference_frame["event_observed"].astype(bool).tolist(),
        0.99,
    )
    upper: int | None = None
    global_bound_usable = 0
    if len(reference_frame) >= minimum_rows and int(reference_frame["event_observed"].astype(bool).sum()) >= minimum_events and global_q99 is not None:
        bootstrap_q99 = _bootstrap_quantiles(
            reference_frame,
            probability=0.99,
            replicates=bootstrap_replicates,
            seed_material={
                "schema_version": "chronosaudit.control_dynamic_horizon_global_bound.v1",
                "probability": 0.99,
                "bootstrap_replicates": bootstrap_replicates,
            },
        )
        global_bound_usable = len(bootstrap_q99)
        if global_bound_usable >= math.ceil(bootstrap_replicates * 0.9):
            upper = global_q99 + max(
                0, _percentile_higher(bootstrap_q99, 0.95) - global_q99
            )
    if len(reference_frame) < minimum_rows or lower is None or upper is None or upper < lower:
        lower = None
        upper = None

    model: dict[str, object] = {
        "schema_version": "chronosaudit.control_dynamic_horizon_model.v1",
        "decision": "DYNAMIC_HORIZON_MODEL_FITTED",
        "method": "KAPLAN_MEIER_HIERARCHICAL_QUANTILE",
        "quantile_probability": 0.95,
        "uncertainty_method": "NONPARAMETRIC_ROW_BOOTSTRAP_PCG64",
        "uncertainty_upper_probability": 0.95,
        "bootstrap_replicates": bootstrap_replicates,
        "bootstrap_minimum_usable_replicates": 900,
        "minimum_stratum_rows": minimum_rows,
        "minimum_stratum_events": minimum_events,
        "hierarchy": [level for level, _ in hierarchy],
        "global_lower_bound_method": "POOLED_KM_Q80",
        "global_upper_bound_method": "POOLED_KM_Q99_PLUS_ONE_SIDED_95_BOOTSTRAP_ALLOWANCE",
        "global_lower_bound_seconds": lower,
        "global_upper_bound_seconds": upper,
        "global_bound_bootstrap_usable_replicates": global_bound_usable,
        "reference_records_sha256": _canonical_sha256(
            reference_frame.sort_values("reference_id").to_dict(orient="records")
        ),
        "strata": strata,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }
    model["model_sha256"] = _canonical_sha256(model)
    return model


def _stratum_matches(row: Mapping[str, object], stratum: Mapping[str, object]) -> bool:
    key = stratum.get("key")
    return isinstance(key, Mapping) and all(str(row.get(field)) == str(value) for field, value in key.items())


def assign_dynamic_horizons(
    pair_frame: pd.DataFrame,
    model: Mapping[str, object],
) -> tuple[pd.DataFrame, dict[str, object]]:
    if model.get("schema_version") != "chronosaudit.control_dynamic_horizon_model.v1":
        raise ControlDynamicHorizonError("assignment_model_schema_invalid")
    supplied_hash = str(model.get("model_sha256") or "")
    expected_hash = _canonical_sha256({key: value for key, value in model.items() if key != "model_sha256"})
    if supplied_hash != expected_hash:
        raise ControlDynamicHorizonError("assignment_model_hash_mismatch")
    if any(model.get(field) is not False for field in ("selection_authorized", "qualification_authorized", "counter_authority")):
        raise ControlDynamicHorizonError("assignment_model_authority_invalid")
    lower = model.get("global_lower_bound_seconds")
    upper = model.get("global_upper_bound_seconds")
    strata = model.get("strata")
    hierarchy = model.get("hierarchy")
    if not isinstance(strata, list) or not isinstance(hierarchy, list):
        raise ControlDynamicHorizonError("assignment_model_structure_invalid")

    output: list[dict[str, object]] = []
    assigned_count = 0
    for row in pair_frame.to_dict(orient="records"):
        result = dict(row)
        result.update(
            {
                "dynamic_horizon_status": "INSUFFICIENT_REFERENCE_EVIDENCE",
                "selected_stratum_level": "",
                "selected_stratum_key_json": "",
                "selected_stratum_row_count": "",
                "selected_stratum_event_count": "",
                "point_quantile_seconds": "",
                "uncertainty_allowance_seconds": "",
                "global_lower_bound_seconds": lower if isinstance(lower, int) else "",
                "global_upper_bound_seconds": upper if isinstance(upper, int) else "",
                "dynamic_horizon_days": "",
                "maturity_time_utc": "",
                "dynamic_horizon_model_sha256": supplied_hash,
                "reference_records_sha256": model.get("reference_records_sha256", ""),
            }
        )
        if isinstance(lower, int) and isinstance(upper, int):
            selected: Mapping[str, object] | None = None
            for level in hierarchy:
                candidates = [
                    stratum
                    for stratum in strata
                    if isinstance(stratum, Mapping)
                    and stratum.get("level") == level
                    and stratum.get("status") == "ESTIMABLE"
                    and _stratum_matches(row, stratum)
                ]
                if candidates:
                    selected = candidates[0]
                    break
            if selected is not None:
                point = int(selected["quantile_seconds"])
                allowance = int(selected["uncertainty_allowance_seconds"])
                bounded_seconds = min(max(point + allowance, lower), upper)
                horizon_days = math.ceil(bounded_seconds / 86_400)
                cutoff = _time(row["prediction_cutoff_time_utc"], "prediction_cutoff_time_utc")
                maturity = cutoff + pd.Timedelta(days=horizon_days)
                result.update(
                    {
                        "dynamic_horizon_status": "ASSIGNED",
                        "selected_stratum_level": selected["level"],
                        "selected_stratum_key_json": _canonical_json(selected["key"]),
                        "selected_stratum_row_count": int(selected["row_count"]),
                        "selected_stratum_event_count": int(selected["event_count"]),
                        "point_quantile_seconds": point,
                        "uncertainty_allowance_seconds": allowance,
                        "dynamic_horizon_days": horizon_days,
                        "maturity_time_utc": maturity.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                )
                assigned_count += 1
        result["assignment_record_sha256"] = _canonical_sha256(result)
        output.append(result)
    report = {
        "schema_version": "chronosaudit.control_dynamic_horizon_assignments.v1",
        "decision": "DYNAMIC_HORIZON_ASSIGNMENTS_COMPUTED",
        "pair_count": len(output),
        "assigned_count": assigned_count,
        "insufficient_reference_evidence_count": len(output) - assigned_count,
        "model_sha256": supplied_hash,
        "assignments_sha256": _canonical_sha256(output),
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }
    return pd.DataFrame(output), report


def verify_dynamic_horizon_artifacts(
    *,
    reference_frame: pd.DataFrame,
    pair_frame: pd.DataFrame,
    model: Mapping[str, object],
    assignments: pd.DataFrame,
    assignment_report: Mapping[str, object],
) -> dict[str, object]:
    """Independently reconstruct the model and assignments; grant no authority."""
    reconstructed_model = fit_dynamic_horizon_model(reference_frame)
    if dict(model) != reconstructed_model:
        raise ControlDynamicHorizonError("verification_model_mismatch")
    reconstructed_assignments, reconstructed_report = assign_dynamic_horizons(
        pair_frame, reconstructed_model
    )
    supplied_rows = assignments.to_dict(orient="records")
    expected_rows = reconstructed_assignments.to_dict(orient="records")

    def comparable(value: object) -> str:
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return ""
        if isinstance(value, (bool, np.bool_)):
            return "true" if bool(value) else "false"
        if isinstance(value, (int, np.integer)):
            return str(int(value))
        if isinstance(value, (float, np.floating)) and float(value).is_integer():
            return str(int(value))
        return str(value)

    if set(assignments.columns) != set(reconstructed_assignments.columns) or [
        {key: comparable(value) for key, value in sorted(row.items())}
        for row in supplied_rows
    ] != [
        {key: comparable(value) for key, value in sorted(row.items())}
        for row in expected_rows
    ]:
        raise ControlDynamicHorizonError("verification_assignments_mismatch")
    if dict(assignment_report) != reconstructed_report:
        raise ControlDynamicHorizonError("verification_assignment_report_mismatch")
    return {
        "schema_version": "chronosaudit.control_dynamic_horizon_verification.v1",
        "decision": "DYNAMIC_HORIZON_ARTIFACTS_VERIFIED",
        "model_sha256": model["model_sha256"],
        "reference_records_sha256": model["reference_records_sha256"],
        "assignments_sha256": assignment_report["assignments_sha256"],
        "pair_count": len(expected_rows),
        "assigned_count": reconstructed_report["assigned_count"],
        "insufficient_reference_evidence_count": reconstructed_report[
            "insufficient_reference_evidence_count"
        ],
        "deterministic_reconstruction_verified": True,
        "hierarchy_verified": True,
        "assignment_math_verified": True,
        "maturity_calculation_verified": True,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }


def build_dynamic_horizon_approval_record(
    *,
    principal: str,
    approved_at_utc: str,
    design_spec_sha256: str,
    dynamic_horizon_spec_sha256: str,
    reference_cohort_sha256: str,
    model_sha256: str,
    pair_feature_manifest_sha256: str | None = None,
) -> dict[str, object]:
    _time(approved_at_utc, "approval_approved_at_utc")
    record: dict[str, object] = {
        "schema_version": "chronosaudit.control_dynamic_horizon_user_approval.v1",
        "decision": "APPROVE_DYNAMIC_HORIZON_V1",
        "principal": _text(principal, "approval_principal"),
        "principal_role": "AUTHOR_AND_METHODS_OWNER",
        "approved_at_utc": approved_at_utc,
        "governance_label": "AI_DESIGNED_USER_APPROVED",
        "approval_statement": "DYNAMIC_HORIZON_V1 approved",
        "outcome_inspection_attestation": (
            "NO_CONTROL_OUTCOMES_INSPECTED_BEFORE_HORIZON_FREEZE"
        ),
        "design_spec_sha256": _sha(design_spec_sha256, "design_spec_sha256"),
        "dynamic_horizon_spec_sha256": _sha(
            dynamic_horizon_spec_sha256, "dynamic_horizon_spec_sha256"
        ),
        "reference_cohort_sha256": _sha(
            reference_cohort_sha256, "reference_cohort_sha256"
        ),
        "model_sha256": _sha(model_sha256, "model_sha256"),
        "signature_namespace": SIGNATURE_NAMESPACE,
        "key_possession_proves_real_world_identity": False,
        "independent_human_review": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "rpc_authorized": False,
        "source_acquisition_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    if pair_feature_manifest_sha256 is not None:
        record["pair_feature_manifest_sha256"] = _sha(
            pair_feature_manifest_sha256, "pair_feature_manifest_sha256"
        )
    record["approval_record_sha256"] = _canonical_sha256(record)
    return record


def canonical_dynamic_horizon_signed_payload(record: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(record)) + "\n").encode("utf-8")


def _ordinary_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlDynamicHorizonError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlDynamicHorizonError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlDynamicHorizonError(f"{label}_not_ordinary_file")
    return resolved


def verify_signed_dynamic_horizon_approval(
    *,
    approval_record_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    expected_design_spec_sha256: str,
    expected_dynamic_horizon_spec_sha256: str,
    expected_reference_cohort_sha256: str,
    expected_model_sha256: str,
    expected_pair_feature_manifest_sha256: str | None = None,
) -> dict[str, object]:
    record_path = _ordinary_file(approval_record_path, "approval_record")
    signature = _ordinary_file(signature_path, "approval_signature")
    allowed = _ordinary_file(allowed_signers_path, "allowed_signers")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlDynamicHorizonError("approval_record_json_invalid") from exc
    if not isinstance(record, dict):
        raise ControlDynamicHorizonError("approval_record_root_invalid")
    if record.get("schema_version") != "chronosaudit.control_dynamic_horizon_user_approval.v1":
        raise ControlDynamicHorizonError("approval_record_schema_invalid")
    if record.get("principal") != expected_principal:
        raise ControlDynamicHorizonError("approval_principal_mismatch")
    expected_bindings = {
        "design_spec_sha256": expected_design_spec_sha256,
        "dynamic_horizon_spec_sha256": expected_dynamic_horizon_spec_sha256,
        "reference_cohort_sha256": expected_reference_cohort_sha256,
        "model_sha256": expected_model_sha256,
    }
    if expected_pair_feature_manifest_sha256 is not None:
        expected_bindings["pair_feature_manifest_sha256"] = (
            expected_pair_feature_manifest_sha256
        )
    for field, expected in expected_bindings.items():
        if record.get(field) != _sha(expected, field):
            raise ControlDynamicHorizonError(f"approval_{field.removesuffix('_sha256')}_hash_mismatch")
    expected_record_hash = _canonical_sha256(
        {key: value for key, value in record.items() if key != "approval_record_sha256"}
    )
    if record.get("approval_record_sha256") != expected_record_hash:
        raise ControlDynamicHorizonError("approval_record_hash_mismatch")
    if record.get("signature_namespace") != SIGNATURE_NAMESPACE:
        raise ControlDynamicHorizonError("approval_signature_namespace_mismatch")
    required_false = (
        "key_possession_proves_real_world_identity",
        "independent_human_review",
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "rpc_authorized",
        "source_acquisition_authorized",
        "recovery3_mutation_authorized",
    )
    if any(record.get(field) is not False for field in required_false):
        raise ControlDynamicHorizonError("approval_authority_flags_invalid")
    completed = subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed),
            "-I",
            expected_principal,
            "-n",
            SIGNATURE_NAMESPACE,
            "-s",
            str(signature),
        ],
        input=canonical_dynamic_horizon_signed_payload(record),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ControlDynamicHorizonError("approval_signature_invalid")
    return {
        "schema_version": "chronosaudit.control_dynamic_horizon_approval_verification.v1",
        "decision": "DYNAMIC_HORIZON_USER_APPROVAL_VERIFIED",
        "principal": expected_principal,
        "approval_record_sha256": expected_record_hash,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "signature_verified": True,
        "key_possession_proves_real_world_identity": False,
        "independent_human_review": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
    }
