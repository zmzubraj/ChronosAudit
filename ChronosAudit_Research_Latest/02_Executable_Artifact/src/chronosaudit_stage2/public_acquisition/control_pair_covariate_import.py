from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

import pandas as pd


class PairCovariateImportError(ValueError):
    """Raised when a pair-covariate evidence batch fails import verification."""


_SCOPE_REQUIRED = {
    "case_name",
    "chain",
    "control_address",
    "denominator_record_sha256",
    "required_covariate_cutoff_time",
    "pair_scope_record_sha256",
}

_EVIDENCE_REQUIRED = {
    "pair_scope_record_sha256",
    "case_name",
    "chain",
    "control_address",
    "denominator_record_sha256",
    "covariate_cutoff_time",
    "evidence_block_number",
    "evidence_block_timestamp",
    "code_size",
    "proxy_status",
    "source_verified_at_cutoff",
    "source_verification_basis",
    "identity_group",
    "clone_family",
    "proxy_family",
    "protocol_family",
    "runtime_code_evidence_sha256",
    "proxy_evidence_sha256",
    "source_verification_evidence_sha256",
    "protocol_evidence_sha256",
    "pair_covariate_record_sha256",
}

_RAW_EVIDENCE_HASH_COLUMNS = (
    "runtime_code_evidence_sha256",
    "proxy_evidence_sha256",
    "source_verification_evidence_sha256",
    "protocol_evidence_sha256",
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


def _normalize_bool(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y"}:
        return "true"
    if text in {"0", "false", "no", "n"}:
        return "false"
    raise PairCovariateImportError("source_verified_at_cutoff_invalid")


def _normalize_integer(value: object, label: str) -> str:
    text = str(value).strip()
    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]
    try:
        number = int(text)
    except (TypeError, ValueError) as exc:
        raise PairCovariateImportError(f"{label}_invalid") from exc
    if number < 0:
        raise PairCovariateImportError(f"{label}_invalid")
    return str(number)


def _normalize_time(value: object, label: str) -> str:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise PairCovariateImportError(f"{label}_invalid")
    return parsed.isoformat().replace("+00:00", "Z")


def _normalize_record(row: Mapping[str, object]) -> dict[str, str]:
    missing = sorted(_EVIDENCE_REQUIRED - set(row))
    if missing:
        raise PairCovariateImportError(
            f"evidence_missing_columns:{','.join(missing)}"
        )
    normalized: dict[str, str] = {}
    for field in sorted(_EVIDENCE_REQUIRED - {"pair_covariate_record_sha256"}):
        value = row.get(field)
        if field in {"evidence_block_number", "code_size"}:
            normalized[field] = _normalize_integer(value, field)
        elif field == "source_verified_at_cutoff":
            normalized[field] = _normalize_bool(value)
        elif field in {"covariate_cutoff_time", "evidence_block_timestamp"}:
            normalized[field] = _normalize_time(value, field)
        elif field in {
            "chain",
            "control_address",
            "denominator_record_sha256",
            "pair_scope_record_sha256",
            *_RAW_EVIDENCE_HASH_COLUMNS,
            "clone_family",
        }:
            normalized[field] = str(value or "").strip().lower()
        else:
            normalized[field] = str(value or "").strip()
        if not normalized[field]:
            raise PairCovariateImportError(f"{field}_empty")
    return normalized


def make_pair_covariate_record_sha256(row: Mapping[str, object]) -> str:
    return _canonical_sha256(_normalize_record(row))


def make_no_repeat_scope_sha256(pair_scope_hashes: Iterable[str]) -> str:
    normalized = sorted({str(value).strip().lower() for value in pair_scope_hashes})
    if not normalized or not all(_is_sha256(value) for value in normalized):
        raise PairCovariateImportError("no_repeat_scope_invalid")
    return _canonical_sha256(normalized)


def make_import_ledger_entry_sha256(entry: Mapping[str, object]) -> str:
    payload = {
        key: value for key, value in entry.items() if key != "entry_sha256"
    }
    return _canonical_sha256(payload)


def _ordinary_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise PairCovariateImportError(f"{label}_not_ordinary_file")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise PairCovariateImportError(f"{label}_not_ordinary_file")
    return resolved


def _load_object(path: Path, label: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PairCovariateImportError(f"{label}_root_not_object")
    return payload


def _safe_raw_file(root: Path, relative_value: object) -> Path:
    relative = Path(str(relative_value or ""))
    if relative.is_absolute():
        raise PairCovariateImportError("raw_receipt_path_absolute")
    candidate = root / relative
    if candidate.is_symlink():
        raise PairCovariateImportError("raw_receipt_not_ordinary_file")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PairCovariateImportError("raw_receipt_path_escape") from exc
    if not resolved.is_file():
        raise PairCovariateImportError("raw_receipt_not_ordinary_file")
    return resolved


def _validate_import_ledger(
    ledger: Mapping[str, object],
) -> tuple[set[str], set[str], set[str]]:
    if ledger.get("schema_version") != "chronosaudit.control_pair_import_ledger.v1":
        raise PairCovariateImportError("accepted_ledger_schema_invalid")
    if ledger.get("selection_authorized") is not False:
        raise PairCovariateImportError("accepted_ledger_selection_authorized_invalid")
    batches = ledger.get("accepted_batches")
    if not isinstance(batches, list):
        raise PairCovariateImportError("accepted_ledger_batches_invalid")
    pair_hashes: set[str] = set()
    batch_ids: set[str] = set()
    evidence_hashes: set[str] = set()
    previous_hash = "0" * 64
    for expected_sequence, batch in enumerate(batches, start=1):
        if not isinstance(batch, Mapping):
            raise PairCovariateImportError("accepted_ledger_batch_invalid")
        batch_id = str(batch.get("batch_id") or "").strip()
        manifest_hash = str(batch.get("batch_manifest_sha256") or "").strip().lower()
        evidence_hash = str(batch.get("evidence_csv_sha256") or "").strip().lower()
        verification_hash = str(
            batch.get("verification_report_sha256") or ""
        ).strip().lower()
        pair_scope_hash = str(batch.get("pair_scope_sha256") or "").strip().lower()
        no_repeat_hash = str(batch.get("no_repeat_scope_sha256") or "").strip().lower()
        verified_records_hash = str(
            batch.get("verified_records_sha256") or ""
        ).strip().lower()
        accepted = batch.get("pair_scope_record_sha256s")
        if (
            not batch_id
            or not _is_sha256(manifest_hash)
            or not _is_sha256(evidence_hash)
            or not _is_sha256(verification_hash)
            or not _is_sha256(pair_scope_hash)
            or not _is_sha256(no_repeat_hash)
            or not _is_sha256(verified_records_hash)
            or not isinstance(accepted, list)
            or not accepted
            or not all(_is_sha256(value) for value in accepted)
        ):
            raise PairCovariateImportError("accepted_ledger_batch_invalid")
        normalized_pairs = sorted(str(value).lower() for value in accepted)
        if len(set(normalized_pairs)) != len(normalized_pairs):
            raise PairCovariateImportError("accepted_ledger_pair_duplicate")
        if int(batch.get("sequence") or 0) != expected_sequence:
            raise PairCovariateImportError("accepted_ledger_sequence_invalid")
        if str(batch.get("previous_entry_sha256") or "").lower() != previous_hash:
            raise PairCovariateImportError("accepted_ledger_previous_hash_mismatch")
        if batch.get("selection_authorized") is not False:
            raise PairCovariateImportError("accepted_ledger_entry_authorization_invalid")
        accepted_at = _normalize_time(batch.get("accepted_at_utc"), "accepted_at_utc")
        if str(batch.get("accepted_at_utc")) != accepted_at:
            raise PairCovariateImportError("accepted_ledger_timestamp_not_canonical")
        entry_hash = str(batch.get("entry_sha256") or "").strip().lower()
        if not _is_sha256(entry_hash) or entry_hash != make_import_ledger_entry_sha256(batch):
            raise PairCovariateImportError("accepted_ledger_entry_hash_mismatch")
        if batch_id in batch_ids or evidence_hash in evidence_hashes:
            raise PairCovariateImportError("accepted_ledger_duplicate_batch")
        if set(normalized_pairs) & pair_hashes:
            raise PairCovariateImportError("accepted_ledger_pair_duplicate")
        batch_ids.add(batch_id)
        evidence_hashes.add(evidence_hash)
        pair_hashes.update(normalized_pairs)
        previous_hash = entry_hash
    expected_head = previous_hash
    if str(ledger.get("head_entry_sha256") or "").lower() != expected_head:
        raise PairCovariateImportError("accepted_ledger_head_hash_mismatch")
    if int(ledger.get("accepted_batch_count") or 0) != len(batches):
        raise PairCovariateImportError("accepted_ledger_batch_count_mismatch")
    if int(ledger.get("accepted_pair_count") or 0) != len(pair_hashes):
        raise PairCovariateImportError("accepted_ledger_pair_count_mismatch")
    return pair_hashes, batch_ids, evidence_hashes


def _accepted_pairs(ledger_path: Path | None) -> tuple[set[str], set[str], set[str]]:
    if ledger_path is None:
        return set(), set(), set()
    ledger_path = _ordinary_file(ledger_path, "accepted_ledger")
    ledger = _load_object(ledger_path, "accepted_ledger")
    return _validate_import_ledger(ledger)


def build_updated_import_ledger(
    *,
    verification_report_path: Path,
    batch_manifest_path: Path,
    evidence_csv_path: Path,
    accepted_at_utc: str,
    existing_ledger_path: Path | None = None,
) -> dict[str, object]:
    """Return a hash-chained ledger with one verified batch appended.

    This function does not write the ledger. The caller owns the explicit,
    atomic acceptance action.
    """
    verification_report_path = _ordinary_file(
        verification_report_path, "verification_report"
    )
    batch_manifest_path = _ordinary_file(batch_manifest_path, "batch_manifest")
    evidence_csv_path = _ordinary_file(evidence_csv_path, "evidence_csv")
    verification_sha256 = _sha256_file(verification_report_path)
    manifest_sha256 = _sha256_file(batch_manifest_path)
    evidence_sha256 = _sha256_file(evidence_csv_path)
    report = _load_object(verification_report_path, "verification_report")
    manifest = _load_object(batch_manifest_path, "batch_manifest")
    if report.get("schema_version") != (
        "chronosaudit.control_pair_covariate_import_verification.v1"
    ):
        raise PairCovariateImportError("verification_report_schema_invalid")
    if report.get("decision") != "PAIR_COVARIATE_IMPORT_VERIFIED":
        raise PairCovariateImportError("verification_report_decision_invalid")
    if report.get("selection_authorized") is not False:
        raise PairCovariateImportError("verification_report_authorization_invalid")
    if int(report.get("replayed_pair_records", -1)) != 0:
        raise PairCovariateImportError("verification_report_replay_invalid")
    report_inputs = report.get("inputs")
    if not isinstance(report_inputs, Mapping):
        raise PairCovariateImportError("verification_report_inputs_invalid")
    for field, observed in (
        ("batch_manifest_sha256", manifest_sha256),
        ("evidence_csv_sha256", evidence_sha256),
    ):
        if str(report_inputs.get(field) or "").lower() != observed:
            raise PairCovariateImportError(f"verification_report_{field}_mismatch")
    batch_id = str(manifest.get("batch_id") or "").strip()
    if not batch_id or batch_id != str(report.get("batch_id") or "").strip():
        raise PairCovariateImportError("verification_report_batch_id_mismatch")
    pair_scope_sha256 = str(
        report_inputs.get("pair_scope_sha256") or ""
    ).strip().lower()
    verified_records_sha256 = str(
        report.get("verified_records_sha256") or ""
    ).strip().lower()
    no_repeat_scope_sha256 = str(
        report.get("no_repeat_scope_sha256") or ""
    ).strip().lower()
    pair_hashes = report.get("pair_scope_record_sha256s")
    if (
        not _is_sha256(pair_scope_sha256)
        or not _is_sha256(verified_records_sha256)
        or not _is_sha256(no_repeat_scope_sha256)
        or not isinstance(pair_hashes, list)
        or not pair_hashes
        or not all(_is_sha256(value) for value in pair_hashes)
    ):
        raise PairCovariateImportError("verification_report_acceptance_fields_invalid")
    normalized_pairs = sorted(str(value).lower() for value in pair_hashes)
    evidence = pd.read_csv(
        evidence_csv_path, dtype=str, keep_default_na=False, low_memory=False
    )
    evidence_pairs = sorted(
        str(value).lower() for value in evidence["pair_scope_record_sha256"]
    )
    if normalized_pairs != evidence_pairs or int(report.get("verified_rows") or 0) != len(
        evidence
    ):
        raise PairCovariateImportError("verification_report_evidence_rows_mismatch")
    if make_no_repeat_scope_sha256(normalized_pairs) != no_repeat_scope_sha256:
        raise PairCovariateImportError("verification_report_no_repeat_scope_mismatch")

    if existing_ledger_path is None:
        ledger: dict[str, object] = {
            "schema_version": "chronosaudit.control_pair_import_ledger.v1",
            "selection_authorized": False,
            "accepted_batches": [],
            "accepted_batch_count": 0,
            "accepted_pair_count": 0,
            "head_entry_sha256": "0" * 64,
        }
        accepted_pairs: set[str] = set()
        accepted_batch_ids: set[str] = set()
        accepted_evidence_hashes: set[str] = set()
    else:
        existing_ledger_path = _ordinary_file(existing_ledger_path, "accepted_ledger")
        ledger = _load_object(existing_ledger_path, "accepted_ledger")
        accepted_pairs, accepted_batch_ids, accepted_evidence_hashes = (
            _validate_import_ledger(ledger)
        )
    if batch_id in accepted_batch_ids:
        raise PairCovariateImportError("batch_id_replay")
    if evidence_sha256 in accepted_evidence_hashes:
        raise PairCovariateImportError("evidence_csv_replay")
    if set(normalized_pairs) & accepted_pairs:
        raise PairCovariateImportError("pair_scope_replay")

    accepted_at = _normalize_time(accepted_at_utc, "accepted_at_utc")
    entry: dict[str, object] = {
        "sequence": len(ledger["accepted_batches"]) + 1,
        "accepted_at_utc": accepted_at,
        "batch_id": batch_id,
        "batch_manifest_sha256": manifest_sha256,
        "evidence_csv_sha256": evidence_sha256,
        "verification_report_sha256": verification_sha256,
        "pair_scope_sha256": pair_scope_sha256,
        "no_repeat_scope_sha256": no_repeat_scope_sha256,
        "verified_records_sha256": verified_records_sha256,
        "pair_scope_record_sha256s": normalized_pairs,
        "previous_entry_sha256": str(ledger["head_entry_sha256"]),
        "selection_authorized": False,
    }
    entry["entry_sha256"] = make_import_ledger_entry_sha256(entry)
    updated_batches = [*ledger["accepted_batches"], entry]
    updated: dict[str, object] = {
        "schema_version": "chronosaudit.control_pair_import_ledger.v1",
        "selection_authorized": False,
        "accepted_batches": updated_batches,
        "accepted_batch_count": len(updated_batches),
        "accepted_pair_count": len(accepted_pairs) + len(normalized_pairs),
        "head_entry_sha256": entry["entry_sha256"],
    }
    _validate_import_ledger(updated)
    return updated


def verify_control_pair_covariate_batch(
    *,
    pair_scope_path: Path,
    evidence_csv_path: Path,
    batch_manifest_path: Path,
    raw_evidence_root: Path,
    accepted_ledger_path: Path | None = None,
) -> tuple[pd.DataFrame, dict[str, object]]:
    pair_scope_path = _ordinary_file(pair_scope_path, "pair_scope")
    evidence_csv_path = _ordinary_file(evidence_csv_path, "evidence_csv")
    batch_manifest_path = _ordinary_file(batch_manifest_path, "batch_manifest")
    raw_root_candidate = raw_evidence_root.expanduser()
    if raw_root_candidate.is_symlink():
        raise PairCovariateImportError("raw_evidence_root_not_directory")
    raw_root = raw_root_candidate.resolve(strict=True)
    if not raw_root.is_dir():
        raise PairCovariateImportError("raw_evidence_root_not_directory")

    scope_sha256 = _sha256_file(pair_scope_path)
    evidence_sha256 = _sha256_file(evidence_csv_path)
    manifest_sha256 = _sha256_file(batch_manifest_path)
    manifest = _load_object(batch_manifest_path, "batch_manifest")
    if manifest.get("schema_version") != "chronosaudit.control_pair_covariate_batch.v1":
        raise PairCovariateImportError("batch_manifest_schema_invalid")
    batch_id = str(manifest.get("batch_id") or "").strip()
    if not batch_id:
        raise PairCovariateImportError("batch_id_empty")
    if manifest.get("selection_authorized") is not False:
        raise PairCovariateImportError("batch_manifest_selection_authorized_invalid")
    for label, observed in (
        ("pair_scope_sha256", scope_sha256),
        ("evidence_csv_sha256", evidence_sha256),
    ):
        if str(manifest.get(label) or "").lower() != observed:
            raise PairCovariateImportError(f"batch_manifest_{label}_mismatch")

    raw_manifest_path = _safe_raw_file(
        raw_root, manifest.get("raw_evidence_manifest_path")
    )
    raw_manifest_sha256 = _sha256_file(raw_manifest_path)
    if str(manifest.get("raw_evidence_manifest_sha256") or "").lower() != raw_manifest_sha256:
        raise PairCovariateImportError("raw_evidence_manifest_sha256_mismatch")
    raw_manifest = _load_object(raw_manifest_path, "raw_evidence_manifest")
    if raw_manifest.get("schema_version") != (
        "chronosaudit.control_pair_raw_evidence_manifest.v1"
    ):
        raise PairCovariateImportError("raw_evidence_manifest_schema_invalid")
    receipts = raw_manifest.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        raise PairCovariateImportError("raw_evidence_receipts_invalid")
    receipt_hashes: set[str] = set()
    receipt_paths: set[Path] = set()
    for receipt in receipts:
        if not isinstance(receipt, Mapping):
            raise PairCovariateImportError("raw_evidence_receipt_invalid")
        receipt_path = _safe_raw_file(raw_root, receipt.get("path"))
        expected = str(receipt.get("sha256") or "").strip().lower()
        if not _is_sha256(expected):
            raise PairCovariateImportError("raw_receipt_sha256_invalid")
        if receipt_path in receipt_paths:
            raise PairCovariateImportError("raw_receipt_path_duplicate")
        if _sha256_file(receipt_path) != expected:
            raise PairCovariateImportError("raw_receipt_sha256_mismatch")
        receipt_paths.add(receipt_path)
        receipt_hashes.add(expected)
    query_plan_sha256 = str(manifest.get("query_plan_sha256") or "").strip().lower()
    if not _is_sha256(query_plan_sha256) or query_plan_sha256 not in receipt_hashes:
        raise PairCovariateImportError("query_plan_receipt_missing")

    scope = pd.read_csv(pair_scope_path, dtype=str, keep_default_na=False, low_memory=False)
    evidence = pd.read_csv(
        evidence_csv_path, dtype=str, keep_default_na=False, low_memory=False
    )
    scope_missing = sorted(_SCOPE_REQUIRED - set(scope.columns))
    evidence_missing = sorted(_EVIDENCE_REQUIRED - set(evidence.columns))
    if scope_missing:
        raise PairCovariateImportError(
            f"pair_scope_missing_columns:{','.join(scope_missing)}"
        )
    if evidence_missing:
        raise PairCovariateImportError(
            f"evidence_missing_columns:{','.join(evidence_missing)}"
        )
    if scope["pair_scope_record_sha256"].duplicated().any():
        raise PairCovariateImportError("pair_scope_hash_duplicate")
    if evidence["pair_scope_record_sha256"].duplicated().any():
        raise PairCovariateImportError("evidence_pair_scope_hash_duplicate")
    if int(manifest.get("row_count") or -1) != len(evidence):
        raise PairCovariateImportError("batch_manifest_row_count_mismatch")

    scope_by_hash = scope.set_index("pair_scope_record_sha256")
    imported_pair_hashes = [
        str(value).strip().lower() for value in evidence["pair_scope_record_sha256"]
    ]
    if not imported_pair_hashes or not all(_is_sha256(value) for value in imported_pair_hashes):
        raise PairCovariateImportError("evidence_pair_scope_hash_invalid")
    if not set(imported_pair_hashes).issubset(
        {str(value).lower() for value in scope_by_hash.index}
    ):
        raise PairCovariateImportError("evidence_pair_outside_scope")
    expected_no_repeat = make_no_repeat_scope_sha256(imported_pair_hashes)
    if str(manifest.get("no_repeat_scope_sha256") or "").lower() != expected_no_repeat:
        raise PairCovariateImportError("no_repeat_scope_sha256_mismatch")

    accepted_pairs, accepted_batch_ids, accepted_evidence_hashes = _accepted_pairs(
        accepted_ledger_path
    )
    if batch_id in accepted_batch_ids:
        raise PairCovariateImportError("batch_id_replay")
    if evidence_sha256 in accepted_evidence_hashes:
        raise PairCovariateImportError("evidence_csv_replay")
    replayed = set(imported_pair_hashes) & accepted_pairs
    if replayed:
        raise PairCovariateImportError("pair_scope_replay")

    normalized_rows: list[dict[str, object]] = []
    scope_index = {str(value).lower(): value for value in scope_by_hash.index}
    for raw_row in evidence.to_dict("records"):
        normalized = _normalize_record(raw_row)
        pair_hash = normalized["pair_scope_record_sha256"]
        scope_row = scope_by_hash.loc[scope_index[pair_hash]]
        expected_bindings = {
            "case_name": str(scope_row["case_name"]).strip(),
            "chain": str(scope_row["chain"]).strip().lower(),
            "control_address": str(scope_row["control_address"]).strip().lower(),
            "denominator_record_sha256": str(
                scope_row["denominator_record_sha256"]
            ).strip().lower(),
            "covariate_cutoff_time": _normalize_time(
                scope_row["required_covariate_cutoff_time"],
                "required_covariate_cutoff_time",
            ),
        }
        for field, expected in expected_bindings.items():
            if normalized[field] != expected:
                label = (
                    "covariate_cutoff_mismatch"
                    if field == "covariate_cutoff_time"
                    else f"pair_binding_{field}_mismatch"
                )
                raise PairCovariateImportError(label)
        block_time = pd.to_datetime(
            normalized["evidence_block_timestamp"], utc=True, errors="raise"
        )
        cutoff = pd.to_datetime(
            normalized["covariate_cutoff_time"], utc=True, errors="raise"
        )
        if block_time > cutoff:
            raise PairCovariateImportError("evidence_block_after_cutoff")
        source_verified = normalized["source_verified_at_cutoff"] == "true"
        expected_basis = (
            "PUBLISHED_BY_CUTOFF" if source_verified else "NOT_PUBLISHED_BY_CUTOFF"
        )
        if normalized["source_verification_basis"] != expected_basis:
            raise PairCovariateImportError("source_verification_basis_mismatch")
        for field in _RAW_EVIDENCE_HASH_COLUMNS:
            evidence_hash = normalized[field]
            if not _is_sha256(evidence_hash) or evidence_hash not in receipt_hashes:
                raise PairCovariateImportError(f"{field}_receipt_missing")
        expected_record_hash = make_pair_covariate_record_sha256(raw_row)
        if str(raw_row.get("pair_covariate_record_sha256") or "").lower() != expected_record_hash:
            raise PairCovariateImportError("pair_covariate_record_sha256_mismatch")
        normalized["pair_covariate_record_sha256"] = expected_record_hash
        normalized_rows.append(normalized)

    verified = pd.DataFrame(normalized_rows)
    report: dict[str, object] = {
        "schema_version": "chronosaudit.control_pair_covariate_import_verification.v1",
        "decision": "PAIR_COVARIATE_IMPORT_VERIFIED",
        "selection_authorized": False,
        "selection_authorization_blocker": (
            "verified_batch_must_be_ledgered_and_full_pair_evidence_preflight_must_pass"
        ),
        "batch_id": batch_id,
        "verified_rows": int(len(verified)),
        "replayed_pair_records": 0,
        "raw_receipts_verified": int(len(receipt_paths)),
        "no_repeat_scope_sha256": expected_no_repeat,
        "pair_scope_record_sha256s": sorted(imported_pair_hashes),
        "inputs": {
            "pair_scope_sha256": scope_sha256,
            "evidence_csv_sha256": evidence_sha256,
            "batch_manifest_sha256": manifest_sha256,
            "raw_evidence_manifest_sha256": raw_manifest_sha256,
        },
        "verified_records_sha256": _canonical_sha256(
            verified.to_dict("records")
        ),
    }
    return verified, report


def verify_cutoff_safe_pair_feature_manifest(
    manifest_path: Path,
) -> dict[str, object]:
    """Verify the additive v2 pair-feature boundary without weakening v1 imports."""
    from chronosaudit_stage2.public_acquisition.control_pair_feature_projection import (
        ControlPairFeatureProjectionError,
        verify_pair_feature_projection,
    )

    try:
        report = verify_pair_feature_projection(manifest_path)
    except ControlPairFeatureProjectionError as exc:
        raise PairCovariateImportError(str(exc)) from exc
    manifest_file = _ordinary_file(manifest_path, "pair_feature_manifest")
    manifest = _load_object(manifest_file, "pair_feature_manifest")
    upstream = manifest.get("upstream_artifacts")
    if not isinstance(upstream, list):
        raise PairCovariateImportError("upstream_artifacts_invalid")
    labels = {
        str(artifact.get("label", ""))
        for artifact in upstream
        if isinstance(artifact, Mapping)
    }
    required = {
        "pair_scope",
        "denominator",
        "trace_results",
        "trace_checkpoint",
        "state_results",
        "state_checkpoint",
        "dynamic_horizon_spec",
    }
    missing = sorted(required - labels)
    if missing:
        raise PairCovariateImportError(
            f"required_upstream_missing:{','.join(missing)}"
        )
    if report.get("selection_authorized") is not False:
        raise PairCovariateImportError("pair_feature_authority_invalid")
    return {
        **report,
        "schema_version": "chronosaudit.control_pair_feature_import_verification.v2",
        "decision": "CUTOFF_SAFE_PAIR_FEATURE_IMPORT_VERIFIED_NON_AUTHORIZING",
        "required_upstream_labels": sorted(required),
    }
