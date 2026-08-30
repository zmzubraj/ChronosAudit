from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

import pandas as pd


class ControlQualificationEvidenceError(ValueError):
    """Raised when a control qualification evidence batch is not auditable."""


CONTROL_QUALIFICATION_GATES = (
    "maturity",
    "censoring",
    "temporal",
    "lineage",
    "clone",
    "proxy",
    "protocol",
    "mechanism_separation",
)

_OUTCOME_DEPENDENT_GATES = {"maturity", "censoring", "mechanism_separation"}
_CHECK_SCHEMA = "chronosaudit.control_qualification_check.v1"
_EVIDENCE_SCHEMA = "chronosaudit.control_check_evidence.v1"
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_CHECK_FIELDS = (
    "schema_version",
    "case_name",
    "chain",
    "contract_address",
    "candidate_control_row_sha256",
    "gate",
    "check_status",
    "evidence_path",
    "evidence_sha256",
    "reviewer_identity",
    "reviewer_owner",
    "reviewer_kind",
    "reviewer_conflict_clear",
    "reviewer_confidence",
    "reviewed_at_utc",
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


def _as_bool(value: object) -> bool:
    if pd.isna(value):
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _require_columns(frame: pd.DataFrame, columns: tuple[str, ...], label: str) -> None:
    missing = sorted(set(columns) - set(frame.columns))
    if missing:
        raise ControlQualificationEvidenceError(f"{label}_missing_columns:{','.join(missing)}")


def _ordinary_directory(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlQualificationEvidenceError("evidence_root_not_ordinary_directory")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlQualificationEvidenceError("evidence_root_missing") from exc
    if not resolved.is_dir():
        raise ControlQualificationEvidenceError("evidence_root_not_ordinary_directory")
    return resolved


def _evidence_file(root: Path, value: object, label: str) -> tuple[Path, str]:
    relative_text = str(value or "").strip()
    relative = Path(relative_text)
    if not relative_text or relative.is_absolute():
        raise ControlQualificationEvidenceError(f"{label}_path_outside_evidence_root")
    candidate = root / relative
    if candidate.is_symlink():
        raise ControlQualificationEvidenceError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlQualificationEvidenceError(f"{label}_missing") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ControlQualificationEvidenceError(
            f"{label}_path_outside_evidence_root"
        ) from exc
    if not resolved.is_file():
        raise ControlQualificationEvidenceError(f"{label}_not_ordinary_file")
    return resolved, relative.as_posix()


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlQualificationEvidenceError("evidence_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlQualificationEvidenceError("evidence_root_invalid")
    return payload


def _candidate_key(row: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        str(row.get("case_name") or "").strip(),
        str(row.get("chain") or "").strip().lower(),
        str(row.get("contract_address") or "").strip().lower(),
    )


def _normalized_check_record(row: Mapping[str, object]) -> dict[str, object]:
    normalized = {field: row.get(field) for field in _CHECK_FIELDS}
    normalized["case_name"] = str(normalized["case_name"] or "").strip()
    normalized["chain"] = str(normalized["chain"] or "").strip().lower()
    normalized["contract_address"] = str(normalized["contract_address"] or "").strip().lower()
    for field in (
        "schema_version", "candidate_control_row_sha256", "gate", "check_status",
        "evidence_path", "evidence_sha256", "reviewer_identity", "reviewer_owner",
        "reviewer_kind", "reviewer_confidence", "reviewed_at_utc",
    ):
        normalized[field] = str(normalized[field] or "").strip()
    normalized["candidate_control_row_sha256"] = str(
        normalized["candidate_control_row_sha256"]
    ).lower()
    normalized["evidence_sha256"] = str(normalized["evidence_sha256"]).lower()
    normalized["gate"] = str(normalized["gate"]).lower()
    normalized["check_status"] = str(normalized["check_status"]).upper()
    normalized["reviewer_kind"] = str(normalized["reviewer_kind"]).upper()
    normalized["reviewer_conflict_clear"] = _as_bool(normalized["reviewer_conflict_clear"])
    normalized["reviewer_confidence"] = str(normalized["reviewer_confidence"]).lower()
    return normalized


def verify_control_qualification_evidence_batch(
    *,
    candidate_rows: pd.DataFrame,
    check_rows: pd.DataFrame,
    evidence_root: Path,
) -> dict[str, object]:
    """Verify eight semantic check records per candidate without authorizing counters."""
    _require_columns(
        candidate_rows,
        (
            "case_name", "chain", "contract_address", "candidate_status",
            "candidate_row_valid", "control_row_sha256",
        ),
        "candidate_rows",
    )
    _require_columns(check_rows, (*_CHECK_FIELDS, "evidence_record_sha256"), "check_rows")
    if candidate_rows.empty:
        raise ControlQualificationEvidenceError("candidate_rows_empty")
    root = _ordinary_directory(evidence_root)

    candidates: dict[tuple[str, str, str], str] = {}
    for raw in candidate_rows.to_dict("records"):
        key = _candidate_key(raw)
        if not key[0] or not key[1] or not _ADDRESS.fullmatch(key[2]):
            raise ControlQualificationEvidenceError("candidate_identity_invalid")
        if key in candidates:
            raise ControlQualificationEvidenceError("candidate_identity_duplicate")
        if str(raw.get("candidate_status")) not in {"CANDIDATE_CONTROL", "QUALIFIED_CONTROL"}:
            raise ControlQualificationEvidenceError("candidate_status_invalid")
        if not _as_bool(raw.get("candidate_row_valid")):
            raise ControlQualificationEvidenceError("candidate_row_not_valid")
        row_sha = str(raw.get("control_row_sha256") or "").strip().lower()
        if not _is_sha256(row_sha):
            raise ControlQualificationEvidenceError("candidate_control_row_sha256_invalid")
        candidates[key] = row_sha

    records: list[dict[str, object]] = []
    gates_by_candidate: dict[tuple[str, str, str], set[str]] = {
        key: set() for key in candidates
    }
    for raw in check_rows.to_dict("records"):
        record = _normalized_check_record(raw)
        key = _candidate_key(record)
        expected_candidate_sha = candidates.get(key)
        if expected_candidate_sha is None:
            raise ControlQualificationEvidenceError("check_candidate_unknown")
        gate = str(record["gate"])
        if gate not in CONTROL_QUALIFICATION_GATES or gate in gates_by_candidate[key]:
            raise ControlQualificationEvidenceError("gate_set_invalid")
        if record["schema_version"] != _CHECK_SCHEMA or record["check_status"] != "PASS":
            raise ControlQualificationEvidenceError("check_semantics_invalid")
        if record["candidate_control_row_sha256"] != expected_candidate_sha:
            raise ControlQualificationEvidenceError("candidate_control_row_sha256_mismatch")
        if not _is_sha256(record["evidence_sha256"]):
            raise ControlQualificationEvidenceError("evidence_sha256_invalid")
        expected_record_sha = str(raw.get("evidence_record_sha256") or "").strip().lower()
        if not _is_sha256(expected_record_sha) or _canonical_sha256(record) != expected_record_sha:
            raise ControlQualificationEvidenceError("evidence_record_sha256_mismatch")
        if not record["reviewer_identity"] or not record["reviewer_owner"]:
            raise ControlQualificationEvidenceError("reviewer_identity_invalid")
        if not record["reviewer_conflict_clear"]:
            raise ControlQualificationEvidenceError("reviewer_conflict_not_clear")
        if record["reviewer_confidence"] not in {"high", "very_high"}:
            raise ControlQualificationEvidenceError("reviewer_confidence_invalid")
        if not _UTC_SECONDS.fullmatch(str(record["reviewed_at_utc"])):
            raise ControlQualificationEvidenceError("reviewed_at_utc_invalid")
        if gate in _OUTCOME_DEPENDENT_GATES and record["reviewer_kind"] != "HUMAN":
            raise ControlQualificationEvidenceError("accountable_human_reviewer_required")
        if gate not in _OUTCOME_DEPENDENT_GATES and record["reviewer_kind"] not in {
            "HUMAN", "MECHANICAL",
        }:
            raise ControlQualificationEvidenceError("reviewer_kind_invalid")

        evidence_path, relative_path = _evidence_file(root, record["evidence_path"], "evidence")
        if _sha256_file(evidence_path) != record["evidence_sha256"]:
            raise ControlQualificationEvidenceError("evidence_sha256_mismatch")
        evidence = _load_json_object(evidence_path)
        binding = {
            "schema_version": _EVIDENCE_SCHEMA,
            "case_name": key[0],
            "chain": key[1],
            "contract_address": key[2],
            "candidate_control_row_sha256": expected_candidate_sha,
            "gate": gate,
            "result": "PASS",
        }
        if any(evidence.get(field) != value for field, value in binding.items()):
            raise ControlQualificationEvidenceError("evidence_binding_mismatch")
        if not str(evidence.get("decision_rule") or "").strip():
            raise ControlQualificationEvidenceError("evidence_decision_rule_missing")
        observations = evidence.get("observations")
        if not isinstance(observations, list) or not observations or not all(
            str(item or "").strip() for item in observations
        ):
            raise ControlQualificationEvidenceError("evidence_observations_invalid")
        source_sha = str(evidence.get("source_artifact_sha256") or "").strip().lower()
        if not _is_sha256(source_sha):
            raise ControlQualificationEvidenceError("source_artifact_sha256_invalid")
        source_path, source_relative = _evidence_file(
            root, evidence.get("source_artifact_path"), "source_artifact"
        )
        if _sha256_file(source_path) != source_sha:
            raise ControlQualificationEvidenceError("source_artifact_sha256_mismatch")

        gates_by_candidate[key].add(gate)
        records.append({
            **record,
            "evidence_path": relative_path,
            "source_artifact_path": source_relative,
            "evidence_record_sha256": expected_record_sha,
        })

    required_gates = set(CONTROL_QUALIFICATION_GATES)
    if any(gates != required_gates for gates in gates_by_candidate.values()):
        raise ControlQualificationEvidenceError("gate_set_invalid")

    ordered = sorted(
        records,
        key=lambda item: (
            str(item["case_name"]), str(item["chain"]),
            str(item["contract_address"]), CONTROL_QUALIFICATION_GATES.index(str(item["gate"])),
        ),
    )
    return {
        "schema_version": "chronosaudit.control_qualification_evidence_batch_review.v1",
        "decision": "QUALIFICATION_EVIDENCE_VERIFIED_NON_AUTHORIZING",
        "candidate_rows_verified": len(candidates),
        "check_rows_verified": len(ordered),
        "gate_counts": {
            gate: sum(1 for record in ordered if record["gate"] == gate)
            for gate in CONTROL_QUALIFICATION_GATES
        },
        "candidate_binding_sha256": _canonical_sha256(
            [
                {"case_name": key[0], "chain": key[1], "contract_address": key[2],
                 "control_row_sha256": candidates[key]}
                for key in sorted(candidates)
            ]
        ),
        "verified_check_records_sha256": _canonical_sha256(ordered),
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "accountable_signed_qualification_required": True,
        "blockers": [
            "accountable_signed_qualification_not_present",
            "canonical_candidate_import_not_performed",
            "qualified_control_counter_not_authorized",
        ],
    }
