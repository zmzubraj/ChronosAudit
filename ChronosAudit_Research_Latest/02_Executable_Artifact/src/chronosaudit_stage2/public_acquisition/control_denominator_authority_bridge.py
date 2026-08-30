from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pandas as pd


class AuthorityBridgeError(ValueError):
    """Raised when denominator authority cannot be inherited without ambiguity."""


_REQUIRED_PROJECTION_COLUMNS = {
    "deployment_id",
    "chain",
    "chain_id",
    "contract_address",
    "deployment_time",
    "selection_rank_sha256",
    "source_record_sha256",
    "row_evidence_sha256",
    "qualification_status",
    "counter_authority",
}

_SEALED_ROW_BINDINGS = (
    "deployment_id",
    "chain",
    "chain_id",
    "contract_address",
    "deployment_time",
    "selection_rank_sha256",
    "source_record_sha256",
    "row_evidence_sha256",
    "qualification_status",
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


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AuthorityBridgeError(f"{path.name}_root_not_object")
    return payload


def _normalize_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _normalized(value: object, *, lower: bool = False) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    text = str(value).strip()
    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]
    return text.lower() if lower else text


def _sorted_seal_rows(rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(row) for row in rows]
    normalized.sort(
        key=lambda row: (
            str(row.get("chain") or ""),
            str(row.get("selection_rank_sha256") or ""),
            str(row.get("deployment_id") or ""),
        )
    )
    return normalized


def _validate_ordinary_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_file():
        raise AuthorityBridgeError(f"{label}_not_ordinary_file")
    return resolved


def _validate_report(report: Mapping[str, Any], projection_sha256: str, row_count: int) -> None:
    if report.get("schema_version") != "qualified_denominator_verification.v1":
        raise AuthorityBridgeError("verification_report_schema_invalid")
    for field in (
        "counter_authority",
        "global_integrity_valid",
        "exact_plan_targets_met",
        "production_targets_met",
        "plan_authority",
        "plan_valid",
    ):
        if report.get(field) is not True:
            raise AuthorityBridgeError(f"verification_report_{field}_false")
    if report.get("integrity_errors"):
        raise AuthorityBridgeError("verification_report_integrity_errors_present")
    if report.get("row_blockers"):
        raise AuthorityBridgeError("verification_report_row_blockers_present")
    expected_projection_sha256 = str(
        ((report.get("artifacts") or {}).get("verified_projection_sha256")) or ""
    )
    if expected_projection_sha256 != projection_sha256:
        raise AuthorityBridgeError("verified_projection_sha256_mismatch")
    if int(report.get("projection_row_count") or 0) != row_count:
        raise AuthorityBridgeError("verification_report_projection_row_count_mismatch")
    if int(report.get("selected_row_count") or 0) != row_count:
        raise AuthorityBridgeError("verification_report_selected_row_count_mismatch")


def _validate_final_seal(
    seal: Mapping[str, Any], report: Mapping[str, Any], projection: pd.DataFrame
) -> str:
    if seal.get("schema_version") != "qualified_denominator_final_seal.v1":
        raise AuthorityBridgeError("final_seal_schema_invalid")
    if str(seal.get("plan_sha256") or "") != str(report.get("plan_sha256") or ""):
        raise AuthorityBridgeError("final_seal_plan_sha256_mismatch")
    manifest = seal.get("manifest")
    if not isinstance(manifest, Mapping):
        raise AuthorityBridgeError("final_seal_manifest_missing")
    if manifest.get("schema_version") != "qualified_denominator_manifest.v1":
        raise AuthorityBridgeError("final_seal_manifest_schema_invalid")
    rows = manifest.get("rows")
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise AuthorityBridgeError("final_seal_manifest_rows_invalid")
    if int(manifest.get("row_count") or 0) != len(projection) or len(rows) != len(projection):
        raise AuthorityBridgeError("final_seal_manifest_row_count_mismatch")
    rows_sha256 = _canonical_sha256(_sorted_seal_rows(rows))
    if str(manifest.get("rows_sha256") or "") != rows_sha256:
        raise AuthorityBridgeError("final_seal_manifest_rows_sha256_mismatch")

    seal_rows = {str(row.get("deployment_id") or ""): row for row in rows}
    if len(seal_rows) != len(rows) or set(seal_rows) != set(projection["deployment_id"]):
        raise AuthorityBridgeError("final_seal_projection_identity_mismatch")
    lowercase_fields = {"chain", "contract_address", "qualification_status"}
    for projection_row in projection.to_dict("records"):
        sealed_row = seal_rows[str(projection_row["deployment_id"])]
        for field in _SEALED_ROW_BINDINGS:
            if _normalized(
                projection_row.get(field), lower=field in lowercase_fields
            ) != _normalized(sealed_row.get(field), lower=field in lowercase_fields):
                raise AuthorityBridgeError(f"final_seal_projection_{field}_mismatch")
    return rows_sha256


def build_control_denominator_authority_bridge(
    *,
    projection_path: Path,
    verification_report_path: Path,
    final_seal_path: Path,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Create an additive control-input projection from the sealed Recovery3 rows.

    The source files are read only. This bridge proves denominator authority and
    lineage; it deliberately does not enrich matching covariates or authorize
    candidate selection.
    """
    projection_path = _validate_ordinary_file(projection_path, "projection")
    verification_report_path = _validate_ordinary_file(
        verification_report_path, "verification_report"
    )
    final_seal_path = _validate_ordinary_file(final_seal_path, "final_seal")

    projection_sha256 = _sha256_file(projection_path)
    report_sha256 = _sha256_file(verification_report_path)
    seal_sha256 = _sha256_file(final_seal_path)
    projection = pd.read_csv(projection_path, dtype=str, keep_default_na=False)
    missing = sorted(_REQUIRED_PROJECTION_COLUMNS - set(projection.columns))
    if missing:
        raise AuthorityBridgeError(f"projection_missing_columns:{','.join(missing)}")
    if projection.duplicated(["chain", "contract_address"]).any():
        raise AuthorityBridgeError("projection_duplicate_chain_address")
    if not projection["counter_authority"].map(_normalize_bool).all():
        raise AuthorityBridgeError("projection_rows_not_counter_authorized")
    if not projection["qualification_status"].eq("VERIFIED").all():
        raise AuthorityBridgeError("projection_rows_not_verified")
    for field in ("source_record_sha256", "row_evidence_sha256"):
        if not projection[field].map(_is_sha256).all():
            raise AuthorityBridgeError(f"projection_{field}_invalid")

    report = _load_json(verification_report_path)
    _validate_report(report, projection_sha256, len(projection))
    seal = _load_json(final_seal_path)
    sealed_rows_sha256 = _validate_final_seal(seal, report, projection)

    per_chain = {
        str(chain): int(count)
        for chain, count in projection["chain"].value_counts().sort_index().items()
    }
    observed_counts = report.get("observed_counts") or {}
    if int(observed_counts.get("total") or 0) != len(projection):
        raise AuthorityBridgeError("verification_report_observed_total_mismatch")
    if observed_counts.get("per_chain") != per_chain:
        raise AuthorityBridgeError("verification_report_observed_per_chain_mismatch")

    bridged = projection.copy()
    # The final seal is the authority manifest for this additive projection.
    # Per-row source evidence remains independently bound by source_record_sha256
    # and row_evidence_sha256.
    bridged["source_manifest_sha256"] = seal_sha256
    bridged["authority_projection_sha256"] = projection_sha256
    bridged["authority_verification_report_sha256"] = report_sha256
    bridged["authority_final_seal_sha256"] = seal_sha256
    records_sha256 = _canonical_sha256(bridged.to_dict("records"))
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_denominator_authority_bridge.v1",
        "decision": "AUTHORITY_BRIDGE_VERIFIED",
        "selection_authorized": False,
        "selection_authorization_blocker": "matching_covariates_not_yet_enriched",
        "row_count": int(len(bridged)),
        "per_chain_rows": per_chain,
        "bridged_records_sha256": records_sha256,
        "sealed_manifest_rows_sha256": sealed_rows_sha256,
        "source_manifest_sha256_semantics": "sha256_of_recovery3_final_seal_file",
        "inputs": {
            "verified_projection": {
                "path": str(projection_path),
                "sha256": projection_sha256,
            },
            "verification_report": {
                "path": str(verification_report_path),
                "sha256": report_sha256,
            },
            "final_seal": {"path": str(final_seal_path), "sha256": seal_sha256},
        },
    }
    return bridged, manifest
