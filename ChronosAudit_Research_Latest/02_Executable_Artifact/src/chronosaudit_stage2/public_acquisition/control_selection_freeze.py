from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Mapping
from pathlib import Path

import pandas as pd

from .qualification import (
    build_control_candidates,
    make_control_row_sha256,
    verify_control_cohort_structure,
)


FREEZE_SCHEMA = "chronosaudit.stage2_control_selection_freeze.v1"
HORIZON_DECISION = "DYNAMIC_HORIZON_GATE_VERIFIED_NON_AUTHORIZING"
REQUIRED_AUTHORITY_BINDINGS = (
    "policy_sha256",
    "queue_sha256",
    "denominator_sha256",
    "pair_scope_sha256",
    "pair_feature_manifest_sha256",
    "horizon_sha256",
    "positive_authority_sha256",
)
OUTCOME_COLUMN_FRAGMENTS = (
    "outcome",
    "exploit",
    "incident",
    "adjudicat",
    "investigated_negative",
    "mechanism_separation",
)
UNKNOWN_TOKENS = {"", "nan", "none", "null", "na", "n/a", "unavailable", "unknown"}


class ControlSelectionFreezeError(ValueError):
    """Raised when the outcome-blind freeze boundary cannot be verified."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _json_safe(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if pd.isna(value):
        return None
    if hasattr(value, "item"):
        return value.item()
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _normalized_unknown(value: object) -> str:
    text = str(value or "").strip()
    return "unknown" if text.lower() in UNKNOWN_TOKENS else text


def _prepare_candidates(candidates: pd.DataFrame) -> pd.DataFrame:
    leaked = sorted(
        column
        for column in candidates.columns
        if any(fragment in column.lower() for fragment in OUTCOME_COLUMN_FRAGMENTS)
    )
    if leaked:
        raise ControlSelectionFreezeError(
            "pre_freeze_outcome_column:" + ",".join(leaked)
        )
    prepared = candidates.copy()
    for column in ("identity_group", "clone_family", "proxy_family", "protocol_family"):
        if column in prepared.columns:
            prepared[column] = prepared[column].map(_normalized_unknown)
    required_order = {"case_name", "chain", "contract_address", "deployment_time"}
    if required_order.issubset(prepared.columns):
        prepared["_normalized_chain"] = prepared["chain"].astype(str).str.strip().str.lower()
        prepared["_normalized_address"] = (
            prepared["contract_address"].astype(str).str.strip().str.lower()
        )
        prepared["_risk_entry_time"] = pd.to_datetime(
            prepared["deployment_time"], utc=True, errors="coerce"
        )
        if prepared["_risk_entry_time"].isna().any():
            raise ControlSelectionFreezeError("candidate_risk_entry_time_invalid")
        sort_columns = [
            "case_name", "_normalized_chain", "_normalized_address",
            "_risk_entry_time", "source_record_sha256",
        ]
        prepared = prepared.sort_values(sort_columns, kind="stable")
        prepared = prepared.drop_duplicates(
            ["case_name", "_normalized_chain", "_normalized_address"], keep="first"
        )
        prepared = prepared.drop(
            columns=["_normalized_chain", "_normalized_address", "_risk_entry_time"]
        ).reset_index(drop=True)
    return prepared


def _verify_cases(cases: pd.DataFrame, expected_case_count: int) -> pd.DataFrame:
    if expected_case_count <= 0:
        raise ControlSelectionFreezeError("expected_case_count_invalid")
    if "case_name" not in cases.columns:
        raise ControlSelectionFreezeError("case_name_missing")
    prepared = cases.copy()
    for column in ("identity_group", "clone_family", "proxy_family", "protocol_family"):
        if column in prepared.columns:
            prepared[column] = prepared[column].map(_normalized_unknown)
    if len(prepared) != expected_case_count:
        raise ControlSelectionFreezeError("positive_case_count_mismatch")
    if prepared["case_name"].astype(str).duplicated().any():
        raise ControlSelectionFreezeError("duplicate_positive_case_id")
    if {"chain", "target_contract_address"}.issubset(prepared.columns):
        identity = pd.DataFrame(
            {
                "chain": prepared["chain"].astype(str).str.strip().str.lower(),
                "address": prepared["target_contract_address"].astype(str).str.strip().str.lower(),
            }
        )
        if identity.duplicated().any():
            raise ControlSelectionFreezeError("reference_identity_dedup_v1_not_applied")
    if "first_qualifying_incident_time" in prepared.columns:
        incident = pd.to_datetime(
            prepared["first_qualifying_incident_time"], utc=True, errors="coerce"
        )
        risk_entry_column = (
            "frozen_risk_entry_time"
            if "frozen_risk_entry_time" in prepared.columns
            else "prediction_cutoff_time"
        )
        risk_entry = pd.to_datetime(prepared[risk_entry_column], utc=True, errors="coerce")
        if incident.isna().any() or risk_entry.isna().any() or not incident.gt(risk_entry).all():
            raise ControlSelectionFreezeError("first_incident_not_strictly_after_risk_entry")
    return prepared.sort_values(["case_name", "chain"], kind="stable").reset_index(drop=True)


def _verify_horizon(
    horizon_manifest: Mapping[str, object], authority_bindings: Mapping[str, str]
) -> None:
    if horizon_manifest.get("decision") != HORIZON_DECISION:
        raise ControlSelectionFreezeError("horizon_not_verified")
    for authority_flag in (
        "selection_authorized", "qualification_authorized", "counter_authority"
    ):
        if horizon_manifest.get(authority_flag) is not False:
            raise ControlSelectionFreezeError("horizon_authority_boundary_invalid")
    missing = [key for key in REQUIRED_AUTHORITY_BINDINGS if key not in authority_bindings]
    if missing:
        raise ControlSelectionFreezeError("authority_binding_missing:" + ",".join(missing))
    invalid = [key for key in REQUIRED_AUTHORITY_BINDINGS if not _is_sha256(authority_bindings[key])]
    if invalid:
        raise ControlSelectionFreezeError("authority_binding_invalid:" + ",".join(invalid))
    if (
        str(horizon_manifest.get("pair_feature_manifest_sha256", "")).lower()
        != authority_bindings["pair_feature_manifest_sha256"].lower()
    ):
        raise ControlSelectionFreezeError("pair_feature_binding_mismatch")
    if (
        str(horizon_manifest.get("dynamic_horizon_spec_sha256", "")).lower()
        != authority_bindings["horizon_sha256"].lower()
    ):
        raise ControlSelectionFreezeError("horizon_binding_mismatch")


def _verify_denominator_admission(
    admission: Mapping[str, object],
    authority_bindings: Mapping[str, str],
    *,
    expected_case_count: int,
    controls_per_positive: int,
) -> None:
    if admission.get("schema_version") != (
        "chronosaudit.denominator_expansion_admission_verification.v1"
    ):
        raise ControlSelectionFreezeError("denominator_admission_schema_invalid")
    if admission.get("decision") != "DENOMINATOR_EXPANSION_ADMISSION_VERIFIED":
        raise ControlSelectionFreezeError("denominator_admission_not_verified")
    if (
        admission.get("counter_authority") is not True
        or admission.get("denominator_qualifies") is not True
    ):
        raise ControlSelectionFreezeError("denominator_admission_not_authorizing")
    for flag in (
        "selection_authorized",
        "qualification_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if admission.get(flag) is not False:
            raise ControlSelectionFreezeError(
                f"denominator_admission_{flag}_invalid"
            )
    target = expected_case_count * controls_per_positive
    try:
        observed_case_count = int(admission.get("expected_case_count", -1))
        observed_controls = int(admission.get("controls_per_positive", -1))
        observed_target = int(admission.get("target_control_rows", -1))
        maximum = int(admission.get("maximum_assignable_controls", -1))
    except (TypeError, ValueError) as exc:
        raise ControlSelectionFreezeError(
            "denominator_admission_capacity_invalid"
        ) from exc
    if (
        observed_case_count != expected_case_count
        or observed_controls != controls_per_positive
        or observed_target != target
        or maximum < target
    ):
        raise ControlSelectionFreezeError("denominator_admission_capacity_invalid")
    if (
        str(admission.get("authorized_denominator_sha256", "")).lower()
        != str(authority_bindings.get("denominator_sha256", "")).lower()
    ):
        raise ControlSelectionFreezeError("denominator_admission_binding_mismatch")


def _initialize_output(output_root: Path) -> Path:
    root = Path(output_root)
    if root.exists() and any(root.iterdir()):
        raise ControlSelectionFreezeError("output_root_not_empty")
    root.mkdir(parents=True, exist_ok=True)
    return root


def build_frozen_control_cohort(
    *,
    cases: pd.DataFrame,
    candidates: pd.DataFrame,
    horizon_manifest: Mapping[str, object],
    denominator_admission_verification: Mapping[str, object],
    output_root: Path,
    authority_bindings: Mapping[str, str],
    controls_per_positive: int = 10,
    expected_case_count: int = 417,
) -> dict[str, object]:
    """Freeze an exact outcome-blind cohort or emit only a verified shortfall."""
    if controls_per_positive <= 0:
        raise ControlSelectionFreezeError("controls_per_positive_invalid")
    _verify_denominator_admission(
        denominator_admission_verification,
        authority_bindings,
        expected_case_count=expected_case_count,
        controls_per_positive=controls_per_positive,
    )
    _verify_horizon(horizon_manifest, authority_bindings)
    prepared_cases = _verify_cases(cases, expected_case_count)
    prepared_candidates = _prepare_candidates(candidates)
    root = _initialize_output(output_root)

    selected, audit = build_control_candidates(
        prepared_cases, prepared_candidates, controls_per_positive=controls_per_positive
    )
    expected_cases = prepared_cases["case_name"].astype(str).tolist()
    structure = verify_control_cohort_structure(
        selected,
        valid_column="candidate_row_valid",
        expected_case_names=expected_cases,
        controls_per_positive=controls_per_positive,
    )
    target_rows = expected_case_count * controls_per_positive
    max_allocated = int(structure.get("observed_valid_rows", 0))
    audit_records = json.loads(audit.to_json(orient="records", date_format="iso"))
    allocation_audit = {
        "algorithm": "deterministic_global_max_cardinality_chain_address_capacity_one_v1",
        "reference_identity_policy": "REFERENCE_IDENTITY_DEDUP_V1",
        "target_control_rows": target_rows,
        "max_allocated_rows": max_allocated,
        "structure": structure,
        "per_case": sorted(audit_records, key=lambda row: str(row.get("case_name", ""))),
    }
    allocation_hash = _canonical_sha256(allocation_audit)
    candidate_records = json.loads(
        prepared_candidates.sort_values(
            ["case_name", "chain", "contract_address", "deployment_time"], kind="stable"
        ).to_json(orient="records", date_format="iso")
    )
    base_manifest: dict[str, object] = {
        "schema_version": FREEZE_SCHEMA,
        "reference_identity_policy": "REFERENCE_IDENTITY_DEDUP_V1",
        "controls_per_positive": controls_per_positive,
        "expected_case_count": expected_case_count,
        "target_control_rows": target_rows,
        "max_allocated_rows": max_allocated,
        "authority_bindings": dict(sorted(authority_bindings.items())),
        "denominator_admission_verification_sha256": _canonical_sha256(
            denominator_admission_verification
        ),
        "horizon_decision": HORIZON_DECISION,
        "candidate_input_sha256": _canonical_sha256(candidate_records),
        "allocation_min_cut_audit": allocation_audit,
        "allocation_min_cut_audit_sha256": allocation_hash,
        "selection_frozen": bool(structure.get("passed", False)),
        "qualification_authorized": False,
        "counter_authority": False,
        "canonical_selected_controls": 0,
        "canonical_qualified_controls": 0,
    }

    result: dict[str, object]
    if not structure.get("passed", False):
        manifest = {
            **base_manifest,
            "status": "VERIFIED_SHORTFALL",
            "cohort_suppressed": True,
            "cohort_blockers": structure.get("cohort_blockers", []),
        }
        manifest["manifest_sha256"] = _canonical_sha256(manifest)
        manifest_path = root / "selection_shortfall_manifest.json"
        manifest_path.write_bytes(_canonical_bytes(manifest) + b"\n")
        result = {
            "status": "VERIFIED_SHORTFALL",
            "manifest_path": str(manifest_path),
            "target_control_rows": target_rows,
            "max_allocated_rows": max_allocated,
            "allocation_min_cut_audit_sha256": allocation_hash,
        }
    else:
        frozen = selected.sort_values(
            ["case_name", "control_rank", "chain", "contract_address"], kind="stable"
        ).reset_index(drop=True)
        frozen["frozen_candidate_sha256"] = frozen["control_row_sha256"]
        # Bind the stored row representation, not pandas' transient scalar
        # types, so the hash survives a CSV write/read verification cycle.
        frozen = pd.read_csv(
            io.StringIO(frozen.to_csv(index=False, lineterminator="\n")),
            keep_default_na=False,
        )
        frozen["control_row_sha256"] = frozen.apply(
            lambda row: make_control_row_sha256(row.to_dict()), axis=1
        )
        cohort_path = root / "frozen_control_cohort.csv"
        frozen.to_csv(cohort_path, index=False, lineterminator="\n")
        cohort_hash = _sha256_bytes(cohort_path.read_bytes())
        manifest = {
            **base_manifest,
            "status": "FROZEN_COMPLETE",
            "cohort_suppressed": False,
            "cohort_file": cohort_path.name,
            "cohort_sha256": cohort_hash,
            "frozen_candidate_hashes_sha256": _canonical_sha256(
                frozen["frozen_candidate_sha256"].astype(str).tolist()
            ),
        }
        manifest["manifest_sha256"] = _canonical_sha256(manifest)
        manifest_path = root / "frozen_control_cohort_manifest.json"
        manifest_path.write_bytes(_canonical_bytes(manifest) + b"\n")
        result = {
            "status": "FROZEN_COMPLETE",
            "manifest_path": str(manifest_path),
            "cohort_path": str(cohort_path),
            "target_control_rows": target_rows,
            "max_allocated_rows": max_allocated,
            "allocation_min_cut_audit_sha256": allocation_hash,
        }
    return result


def verify_frozen_control_cohort(manifest_path: Path) -> dict[str, object]:
    path = Path(manifest_path)
    if not path.is_file() or path.is_symlink():
        raise ControlSelectionFreezeError("manifest_not_ordinary_file")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != FREEZE_SCHEMA:
        raise ControlSelectionFreezeError("manifest_schema_invalid")
    expected_manifest_hash = str(manifest.get("manifest_sha256", ""))
    unsigned_manifest = dict(manifest)
    unsigned_manifest.pop("manifest_sha256", None)
    if expected_manifest_hash != _canonical_sha256(unsigned_manifest):
        raise ControlSelectionFreezeError("manifest_sha256_mismatch")
    if manifest.get("status") != "FROZEN_COMPLETE":
        return {
            "complete": False,
            "status": manifest.get("status"),
            "counter_authority": False,
        }
    cohort_path = path.parent / str(manifest.get("cohort_file", ""))
    if not cohort_path.is_file() or cohort_path.is_symlink():
        raise ControlSelectionFreezeError("cohort_not_ordinary_file")
    if _sha256_bytes(cohort_path.read_bytes()) != manifest.get("cohort_sha256"):
        raise ControlSelectionFreezeError("cohort_sha256_mismatch")
    cohort = pd.read_csv(cohort_path)
    expected_cases = sorted(cohort["case_name"].astype(str).unique().tolist())
    structure = verify_control_cohort_structure(
        cohort,
        valid_column="candidate_row_valid",
        expected_case_names=expected_cases,
        controls_per_positive=int(manifest["controls_per_positive"]),
    )
    if not structure.get("passed") or len(expected_cases) != int(manifest["expected_case_count"]):
        raise ControlSelectionFreezeError("frozen_cohort_structure_invalid")
    if manifest.get("counter_authority") is not False:
        raise ControlSelectionFreezeError("freeze_counter_authority_invalid")
    return {
        "complete": True,
        "status": "FROZEN_COMPLETE",
        "decision": "FROZEN_CONTROL_COHORT_VERIFIED_NON_AUTHORIZING",
        "target_control_rows": int(manifest["target_control_rows"]),
        "cohort_sha256": manifest["cohort_sha256"],
        "frozen_candidate_hashes_sha256": manifest[
            "frozen_candidate_hashes_sha256"
        ],
        "allocation_min_cut_audit_sha256": manifest[
            "allocation_min_cut_audit_sha256"
        ],
        "counter_authority": False,
    }


def replace_frozen_candidate(*args: object, **kwargs: object) -> None:
    del args, kwargs
    raise ControlSelectionFreezeError("post_freeze_replacement_forbidden")
