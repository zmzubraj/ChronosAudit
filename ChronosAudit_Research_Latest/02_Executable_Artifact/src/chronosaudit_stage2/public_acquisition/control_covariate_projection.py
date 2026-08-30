from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd


class CovariateProjectionError(ValueError):
    """Raised when an offline covariate cannot be projected with frozen evidence."""


_CHAIN_IDS = {
    "ethereum": "1",
    "bsc": "56",
    "base": "8453",
    "arbitrum": "42161",
}

_POSITIVE_COVARIATES = (
    "deployment_time",
    "prediction_cutoff_time",
    "code_size",
    "proxy_status",
    "source_verified_at_cutoff",
    "identity_group",
    "clone_family",
    "proxy_family",
    "protocol_family",
    "mechanism_family",
    "follow_up_horizon",
    "positive_record_sha256",
)

_DENOMINATOR_COVARIATES = (
    "code_size",
    "proxy_status",
    "source_verified_at_cutoff",
    "identity_group",
    "clone_family",
    "proxy_family",
    "protocol_family",
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _normalize_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _utc_iso(timestamp: object) -> str:
    try:
        value = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise CovariateProjectionError("historical_timestamp_invalid") from exc
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_case_artifact(snapshot_root: Path, relative_path: object) -> Path:
    root = snapshot_root.expanduser().resolve(strict=True)
    relative = Path(str(relative_path or ""))
    if relative.is_absolute():
        raise CovariateProjectionError("case_artifact_path_absolute")
    resolved = (root / relative).resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise CovariateProjectionError("case_artifact_path_escape") from exc
    if resolved.is_symlink() or not resolved.is_file():
        raise CovariateProjectionError("case_artifact_not_ordinary_file")
    return resolved


def _consensus_value(snapshot: dict[str, Any], field: str) -> object:
    cell = snapshot.get(field)
    if not isinstance(cell, dict) or cell.get("status") not in {"consensus", "not_applicable"}:
        raise CovariateProjectionError(f"snapshot_{field}_not_consensus")
    return cell.get("value")


def _proxy_classification(snapshot: dict[str, Any]) -> tuple[str, str, str]:
    signals: list[tuple[str, str]] = []
    eip1167 = str(snapshot.get("eip1167_target") or "").strip().lower()
    implementation = str(_consensus_value(snapshot, "implementation") or "").strip().lower()
    beacon = str(_consensus_value(snapshot, "beacon") or "").strip().lower()
    beacon_implementation = str(
        _consensus_value(snapshot, "beacon_implementation") or ""
    ).strip().lower()
    if eip1167:
        signals.append(("EIP1167_PROXY", eip1167))
    if beacon:
        signals.append(("BEACON_PROXY", beacon_implementation or beacon))
    if implementation:
        signals.append(("EIP1967_PROXY", implementation))
    unique = sorted(set(signals))
    if len(unique) == 1:
        status, target = unique[0]
        return status, f"{status.removesuffix('_PROXY').lower()}:{target}", "VERIFIED_STANDARD_PROXY"
    if len(unique) > 1:
        family = _canonical_sha256([{"status": status, "target": target} for status, target in unique])
        return "MULTIPLE_STANDARD_PROXY_SIGNALS", f"multi:{family}", "VERIFIED_MULTIPLE_STANDARD_SIGNALS"
    diamond_status = str(snapshot.get("diamond_resolution_status") or "").strip()
    if diamond_status == "not_diamond":
        return "DIRECT", "direct", "VERIFIED_NO_SUPPORTED_PROXY_SIGNAL"
    return "", "", f"UNRESOLVED:{diamond_status or 'nonstandard_proxy_not_checked'}"


def _coverage(frame: pd.DataFrame, columns: tuple[str, ...]) -> dict[str, int]:
    return {
        column: int(frame[column].astype(str).str.strip().ne("").sum())
        for column in columns
    }


def build_positive_covariate_projection(
    *,
    positives_path: Path,
    verified_projection_path: Path,
    snapshot_root: Path,
) -> tuple[pd.DataFrame, dict[str, object]]:
    positives_path = positives_path.expanduser().resolve(strict=True)
    verified_projection_path = verified_projection_path.expanduser().resolve(strict=True)
    positives = pd.read_csv(positives_path, dtype=str, keep_default_na=False, low_memory=False)
    verified = pd.read_csv(
        verified_projection_path, dtype=str, keep_default_na=False, low_memory=False
    )
    for frame, label, required in (
        (positives, "positive", {"case_name", "chain", "target_contract_address"}),
        (
            verified,
            "verified_projection",
            {"case_name", "case_artifact_path", "case_artifact_sha256", "counter_authority"},
        ),
    ):
        missing = sorted(required - set(frame.columns))
        if missing:
            raise CovariateProjectionError(f"{label}_missing_columns:{','.join(missing)}")
        if frame["case_name"].duplicated().any():
            raise CovariateProjectionError(f"{label}_duplicate_case_name")
    if set(positives["case_name"]) != set(verified["case_name"]):
        raise CovariateProjectionError("positive_verified_case_set_mismatch")
    if not verified["counter_authority"].map(_normalize_bool).all():
        raise CovariateProjectionError("verified_projection_unauthorized_case")

    verified_by_case = verified.set_index("case_name")
    records: list[dict[str, object]] = []
    for source_row in positives.to_dict("records"):
        case_name = str(source_row["case_name"])
        authority = verified_by_case.loc[case_name]
        artifact_path = _safe_case_artifact(snapshot_root, authority["case_artifact_path"])
        artifact_sha256 = _sha256_file(artifact_path)
        if artifact_sha256 != str(authority["case_artifact_sha256"]):
            raise CovariateProjectionError(f"case_artifact_sha256_mismatch:{case_name}")
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        strict = artifact.get("strict_snapshot")
        if not isinstance(strict, dict) or strict.get("strict_snapshot_closed") is not True:
            raise CovariateProjectionError(f"strict_snapshot_not_closed:{case_name}")
        if strict.get("strict_snapshot_validation", {}).get("ok") is False:
            raise CovariateProjectionError(f"strict_snapshot_validation_failed:{case_name}")
        snapshot = strict.get("snapshot")
        if not isinstance(snapshot, dict) or snapshot.get("status") != "complete":
            raise CovariateProjectionError(f"snapshot_not_complete:{case_name}")
        code = _consensus_value(snapshot, "code")
        if not isinstance(code, str) or not code.startswith("0x") or (len(code) - 2) % 2:
            raise CovariateProjectionError(f"snapshot_code_invalid:{case_name}")
        clone_family = str(snapshot.get("metadata_stripped_bytecode_sha256") or "")
        if not _is_sha256(clone_family):
            raise CovariateProjectionError(f"clone_family_hash_invalid:{case_name}")
        chain = str(source_row["chain"]).strip().lower()
        chain_id = _CHAIN_IDS.get(chain)
        if not chain_id:
            raise CovariateProjectionError(f"positive_chain_unsupported:{case_name}")
        address = str(source_row["target_contract_address"]).strip().lower()
        proxy_status, proxy_family, proxy_resolution = _proxy_classification(snapshot)
        strict_sha256 = str(artifact.get("strict_snapshot_sha256") or "")
        if not _is_sha256(strict_sha256):
            raise CovariateProjectionError(f"strict_snapshot_sha256_invalid:{case_name}")

        derived: dict[str, object] = dict(source_row)
        derived.update(
            {
                "deployment_time": _utc_iso(strict.get("deployment_timestamp")),
                "prediction_cutoff_time": _utc_iso(
                    strict.get("prediction_cutoff_timestamp")
                ),
                "code_size": (len(code) - 2) // 2,
                "proxy_status": proxy_status,
                "source_verified_at_cutoff": "",
                "identity_group": f"{chain_id}:{address}",
                "clone_family": clone_family.lower(),
                "proxy_family": proxy_family,
                "protocol_family": "",
                "mechanism_family": "",
                "follow_up_horizon": "",
                "positive_record_sha256": "",
                "case_artifact_sha256": artifact_sha256,
                "strict_snapshot_sha256": strict_sha256.lower(),
                "deployment_time_resolution": "DERIVED_STRICT_SNAPSHOT",
                "prediction_cutoff_time_resolution": "DERIVED_STRICT_SNAPSHOT",
                "code_size_resolution": "DERIVED_CONSENSUS_RUNTIME_CODE",
                "proxy_resolution": proxy_resolution,
                "source_verified_at_cutoff_resolution": (
                    "UNRESOLVED_NO_CUTOFF_SOURCE_VERIFICATION_EVIDENCE"
                ),
                "identity_group_resolution": "DERIVED_EXACT_CHAIN_ADDRESS",
                "clone_family_resolution": "DERIVED_METADATA_STRIPPED_BYTECODE_SHA256",
                "protocol_family_resolution": "UNRESOLVED_INDEPENDENT_ADJUDICATION_REQUIRED",
                "mechanism_family_resolution": "UNRESOLVED_INDEPENDENT_ADJUDICATION_REQUIRED",
                "follow_up_horizon_resolution": "UNRESOLVED_METHODS_OWNER_FREEZE_REQUIRED",
            }
        )
        derived["positive_record_sha256"] = _canonical_sha256(
            {key: derived[key] for key in sorted(derived) if key != "positive_record_sha256"}
        )
        records.append(derived)

    output = pd.DataFrame(records)
    coverage = _coverage(output, _POSITIVE_COVARIATES)
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.positive_control_covariate_projection.v1",
        "decision": "PARTIAL_COVARIATE_PROJECTION",
        "selection_authorized": False,
        "row_count": int(len(output)),
        "coverage": coverage,
        "complete_fields": sorted(field for field, count in coverage.items() if count == len(output)),
        "incomplete_fields": sorted(field for field, count in coverage.items() if count != len(output)),
        "inputs": {
            "positives": {"path": str(positives_path), "sha256": _sha256_file(positives_path)},
            "verified_projection": {
                "path": str(verified_projection_path),
                "sha256": _sha256_file(verified_projection_path),
            },
            "snapshot_root": str(snapshot_root.expanduser().resolve(strict=True)),
        },
        "records_sha256": _canonical_sha256(output.to_dict("records")),
    }
    return output, manifest


def build_denominator_covariate_projection(
    *, authority_projection_path: Path
) -> tuple[pd.DataFrame, dict[str, object]]:
    authority_projection_path = authority_projection_path.expanduser().resolve(strict=True)
    output = pd.read_csv(
        authority_projection_path, dtype=str, keep_default_na=False, low_memory=False
    )
    required = {
        "chain",
        "chain_id",
        "contract_address",
        "deployment_time",
        "source_record_sha256",
        "source_manifest_sha256",
        "row_evidence_sha256",
        "counter_authority",
    }
    missing = sorted(required - set(output.columns))
    if missing:
        raise CovariateProjectionError(
            f"authority_projection_missing_columns:{','.join(missing)}"
        )
    if not output["counter_authority"].map(_normalize_bool).all():
        raise CovariateProjectionError("authority_projection_unauthorized_row")
    if output.duplicated(["chain", "contract_address"]).any():
        raise CovariateProjectionError("authority_projection_duplicate_chain_address")

    output["identity_group"] = (
        output["chain_id"].astype(str).str.strip()
        + ":"
        + output["contract_address"].astype(str).str.strip().str.lower()
    )
    output["identity_group_resolution"] = "DERIVED_EXACT_CHAIN_ADDRESS"
    unresolved = {
        "code_size": "UNRESOLVED_NO_FROZEN_RUNTIME_CODE",
        "proxy_status": "UNRESOLVED_NO_CUTOFF_PROXY_EVIDENCE",
        "source_verified_at_cutoff": "UNRESOLVED_NO_CUTOFF_SOURCE_VERIFICATION_EVIDENCE",
        "clone_family": "UNRESOLVED_NO_FROZEN_RUNTIME_CODE",
        "proxy_family": "UNRESOLVED_NO_CUTOFF_PROXY_EVIDENCE",
        "protocol_family": "UNRESOLVED_NO_PROTOCOL_CLASSIFICATION_EVIDENCE",
    }
    for field, resolution in unresolved.items():
        output[field] = ""
        output[f"{field}_resolution"] = resolution

    coverage = _coverage(output, _DENOMINATOR_COVARIATES)
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.denominator_control_covariate_projection.v1",
        "decision": "PARTIAL_COVARIATE_PROJECTION",
        "selection_authorized": False,
        "row_count": int(len(output)),
        "coverage": coverage,
        "complete_fields": sorted(field for field, count in coverage.items() if count == len(output)),
        "incomplete_fields": sorted(field for field, count in coverage.items() if count != len(output)),
        "input": {
            "path": str(authority_projection_path),
            "sha256": _sha256_file(authority_projection_path),
        },
        "records_sha256": _canonical_sha256(output.to_dict("records")),
    }
    return output, manifest
