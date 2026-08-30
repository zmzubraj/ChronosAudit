from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Mapping

from chronosaudit_stage2.public_acquisition.candidate_archive_qualification import (
    build_candidate_archive_run_plan,
)


PARENT_REPORT_FILENAME = "historical_snapshot_verification_report.json"
PARENT_PROJECTION_FILENAME = "historical_snapshot_verified_projection.csv"
CANDIDATE_REPORT_FILENAME = "candidate_archive_verification_report.json"
CANDIDATE_PROJECTION_FILENAME = "candidate_archive_verified_projection.csv"
REVISION_SLOT_FILENAME = "replacement_slots.csv"
REVISION_ORDER_FILENAME = "slot_candidate_order.csv"
MAPPING_FILENAME = "replacement_mapping.csv"
POPULATION_FILENAME = "revised_population.csv"
MANIFEST_FILENAME = "finalization_manifest.json"
CHECKSUM_FILENAME = "SHA256SUMS.txt"
VERIFICATION_INPUTS_FILENAME = "verification_inputs.json"
STRICT_STATUS = "HISTORICAL_SNAPSHOT_VERIFIED"
REQUIRED_QUOTAS = {"base": 3, "bsc": 38, "ethereum": 16}
REQUIRED_BLOCKER_CODE = "insufficient_incident_lead_time"
_SHA256 = hashlib.sha256

MAPPING_FIELDS = (
    "chain",
    "slot_case_id",
    "slot_case_name",
    "slot_target_contract_address",
    "slot_input_row_sha256",
    "slot_envelope_path",
    "slot_envelope_sha256",
    "candidate_id",
    "candidate_case_name",
    "candidate_target_contract_address",
    "candidate_incident_block",
    "candidate_exploit_tx_hash",
    "candidate_input_row_sha256",
    "candidate_source_sha256",
    "candidate_readme_sha256",
    "candidate_envelope_path",
    "candidate_envelope_sha256",
    "historical_envelope_path",
    "historical_envelope_sha256",
    "selection_rank_within_chain",
)

REVISED_EXTRA_FIELDS = (
    "population_role",
    "replaced_parent_slot_case_id",
    "parent_envelope_path",
    "parent_envelope_sha256",
    "parent_case_artifact_path",
    "parent_case_artifact_sha256",
    "candidate_envelope_path",
    "candidate_envelope_sha256",
    "historical_envelope_path",
    "historical_envelope_sha256",
    "replacement_selection_rank",
    "replacement_order_rule",
    "replacement_source_sha256",
    "replacement_readme_sha256",
    "replacement_incident_block",
    "replacement_exploit_tx_hash",
)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return _SHA256(_canonical_json_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    return _SHA256(path.read_bytes()).hexdigest()


def _csv_bool(value: bool) -> str:
    return "true" if value else "false"


def _validate_output_parent(output_dir: Path) -> None:
    if ".." in output_dir.parts:
        raise ValueError("finalization_output_parent_invalid")

    if output_dir.is_absolute():
        current = Path(output_dir.anchor)
        parts = output_dir.parts[1:]
    else:
        current = Path.cwd()
        parts = output_dir.parts

    for index, part in enumerate(parts):
        if part in ("", "."):
            continue
        current = current / part
        if current.is_symlink():
            raise ValueError("finalization_output_parent_invalid")
        if current.exists():
            is_leaf = index == len(parts) - 1
            if not current.is_dir():
                raise ValueError(
                    "finalization_output_exists" if is_leaf else "finalization_output_parent_invalid"
                )


def _safe_directory(path: str | Path, *, code: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_dir() or candidate.is_symlink():
        raise ValueError(code)
    return candidate.resolve()


def _safe_existing_file(root: Path, relative: str | Path, *, code: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(code)
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(code)
    resolved = current.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(code) from exc
    if not resolved.is_file():
        raise ValueError(code)
    return resolved


def _load_json(path: Path, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _read_csv(path: Path, *, code: str) -> tuple[list[str], list[dict[str, str]]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fields = list(reader.fieldnames or [])
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError(code) from exc
    if not fields:
        raise ValueError(code)
    return fields, rows


def _parse_sha256sums(path: Path, *, code: str) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(code) from exc
    values: dict[str, str] = {}
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ValueError(code)
        digest, name = parts
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError(code)
        base_name = Path(name).name
        if base_name in values:
            raise ValueError(code)
        values[base_name] = digest
    return values


def _validate_report_self_hash(report: Mapping[str, Any], *, code: str) -> None:
    expected = str(report.get("report_sha256") or "")
    actual = _sha256_json({key: value for key, value in report.items() if key != "report_sha256"})
    if expected != actual:
        raise ValueError(code)


def _parse_projection_row(row: Mapping[str, str]) -> dict[str, Any]:
    blockers = json.loads(str(row.get("scientific_blockers") or "[]"))
    if not isinstance(blockers, list):
        raise ValueError("candidate_projection_blockers_invalid")
    return {
        "candidate_id": str(row.get("candidate_id") or ""),
        "case_name": str(row.get("case_name") or ""),
        "chain": str(row.get("chain") or ""),
        "input_row_sha256": str(row.get("input_row_sha256") or ""),
        "candidate_envelope_path": str(row.get("candidate_envelope_path") or ""),
        "candidate_envelope_sha256": str(row.get("candidate_envelope_sha256") or ""),
        "historical_case_path": str(row.get("historical_case_path") or ""),
        "historical_case_sha256": str(row.get("historical_case_sha256") or ""),
        "eligible": str(row.get("eligible") or "").lower() == "true",
        "status": str(row.get("status") or ""),
        "scientific_blockers": [str(item) for item in blockers],
        "run_binding_sha256": str(row.get("run_binding_sha256") or ""),
    }


def _validated_parent_inputs(
    *,
    parent_run_root: Path,
    parent_report_root: Path,
) -> tuple[
    list[str],
    list[dict[str, str]],
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
    dict[str, Any],
    dict[str, Any],
    Path,
    Path,
]:
    manifest_path = _safe_existing_file(parent_run_root, "run_manifest.json", code="parent_manifest_invalid")
    blocker_path = _safe_existing_file(parent_run_root, "blocker_ledger.csv", code="parent_blocker_ledger_invalid")
    population_path = _safe_existing_file(parent_run_root, "frozen_inputs/temporal.csv", code="parent_population_invalid")
    report_path = _safe_existing_file(parent_report_root, PARENT_REPORT_FILENAME, code="parent_report_invalid")
    report = _load_json(report_path, code="parent_report_invalid")
    _validate_report_self_hash(report, code="parent_report_hash_invalid")
    projection_path = _safe_existing_file(
        parent_report_root,
        str(report.get("projection_path") or PARENT_PROJECTION_FILENAME),
        code="parent_projection_invalid",
    )
    if str(report.get("projection_sha256") or "") != _sha256_file(projection_path):
        raise ValueError("parent_projection_hash_invalid")
    if report.get("counter_authority") is not True:
        raise ValueError("parent_counter_authority_invalid")
    if list(report.get("integrity_errors") or []) != []:
        raise ValueError("parent_integrity_errors_present")
    if int(report.get("observed") or -1) != 360 or int(report.get("required") or -1) != 417:
        raise ValueError("parent_verification_counts_invalid")

    manifest = _load_json(manifest_path, code="parent_manifest_invalid")
    if str(manifest.get("binding", {}).get("run_id") or "") != "historical-snapshots-417-full-20260809":
        raise ValueError("parent_run_id_invalid")
    authoritative_input_hashes = dict(report.get("authoritative_input_hashes") or {})
    if authoritative_input_hashes.get("aggregate_hashes") != manifest.get("aggregate_hashes"):
        raise ValueError("parent_authoritative_hash_binding_invalid")

    population_fields, population_rows = _read_csv(population_path, code="parent_population_invalid")
    _, blocker_rows = _read_csv(blocker_path, code="parent_blocker_ledger_invalid")
    _, projection_rows = _read_csv(projection_path, code="parent_projection_invalid")
    if len(population_rows) != 417 or len(projection_rows) != 417:
        raise ValueError("parent_population_count_invalid")

    blocker_set = {
        (str(row.get("chain") or ""), str(row.get("case_id") or ""), str(row.get("code") or ""))
        for row in blocker_rows
    }
    report_blockers = {
        (
            str(item.get("chain") or ""),
            str(item.get("case_id") or ""),
            str(item.get("code") or ""),
        )
        for item in list(report.get("scientific_blockers") or [])
        if isinstance(item, Mapping)
    }
    if len(blocker_rows) != 57 or blocker_set != report_blockers:
        raise ValueError("parent_blocker_set_invalid")
    counts_by_chain: dict[str, int] = {}
    for chain, case_id, code in blocker_set:
        if code != REQUIRED_BLOCKER_CODE:
            raise ValueError("parent_blocker_code_invalid")
        counts_by_chain[chain] = counts_by_chain.get(chain, 0) + 1
    if counts_by_chain != REQUIRED_QUOTAS:
        raise ValueError("parent_blocker_quota_invalid")

    population_by_case_id = {str(row["case_id"]): row for row in population_rows}
    if len(population_by_case_id) != len(population_rows):
        raise ValueError("parent_case_id_duplicate")
    projection_by_case_id = {str(row["case_id"]): row for row in projection_rows}
    if set(population_by_case_id) != set(projection_by_case_id):
        raise ValueError("parent_projection_binding_invalid")
    retained_case_ids = [
        case_id
        for case_id, row in projection_by_case_id.items()
        if str(row.get("historical_snapshot_status") or "") == STRICT_STATUS
    ]
    if len(retained_case_ids) != 360:
        raise ValueError("parent_retained_count_invalid")

    return (
        population_fields,
        population_rows,
        population_by_case_id,
        projection_by_case_id,
        manifest,
        report,
        report_path,
        projection_path,
    )


def _validated_revision_inputs(
    revision_root: Path,
    *,
    blocked_case_ids: set[str],
) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]], Path, Path]:
    plan = build_candidate_archive_run_plan(revision_root)
    slots_path = _safe_existing_file(revision_root, REVISION_SLOT_FILENAME, code="revision_slots_invalid")
    order_path = _safe_existing_file(revision_root, REVISION_ORDER_FILENAME, code="revision_order_invalid")
    _, slot_rows = _read_csv(slots_path, code="revision_slots_invalid")
    _, order_rows = _read_csv(order_path, code="revision_order_invalid")
    slot_case_ids = {str(row.get("slot_case_id") or "") for row in slot_rows}
    if len(slot_rows) != 57 or slot_case_ids != blocked_case_ids:
        raise ValueError("revision_slot_binding_invalid")
    for row in slot_rows:
        if str(row.get("blocker_code") or "") != REQUIRED_BLOCKER_CODE:
            raise ValueError("revision_slot_blocker_invalid")
        chain = str(row.get("chain") or "")
        if chain not in REQUIRED_QUOTAS:
            raise ValueError("revision_slot_chain_invalid")
    counts_by_chain: dict[str, int] = {}
    for row in slot_rows:
        chain = str(row["chain"])
        counts_by_chain[chain] = counts_by_chain.get(chain, 0) + 1
    if counts_by_chain != REQUIRED_QUOTAS:
        raise ValueError("revision_slot_quota_invalid")

    for row in order_rows:
        if str(row.get("slot_case_id") or "") not in slot_case_ids:
            raise ValueError("revision_order_slot_unknown")
        chain = str(row.get("chain") or "")
        if chain not in REQUIRED_QUOTAS:
            raise ValueError("revision_order_chain_invalid")
        if not str(row.get("global_rank") or "").isdigit() or int(str(row["global_rank"])) <= 0:
            raise ValueError("revision_order_rank_invalid")
    return plan, slot_rows, order_rows, slots_path, order_path


def _validated_candidate_inputs(
    *,
    candidate_run_root: Path,
    candidate_report_root: Path,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], Path, Path, Path]:
    checksum_path = _safe_existing_file(candidate_report_root, CHECKSUM_FILENAME, code="candidate_checksums_invalid")
    checksums = _parse_sha256sums(checksum_path, code="candidate_checksums_invalid")
    expected_checksum_names = {
        CANDIDATE_REPORT_FILENAME,
        CANDIDATE_PROJECTION_FILENAME,
        VERIFICATION_INPUTS_FILENAME,
    }
    if set(checksums) != expected_checksum_names:
        raise ValueError("candidate_checksums_invalid")
    report_path = _safe_existing_file(candidate_report_root, CANDIDATE_REPORT_FILENAME, code="candidate_report_invalid")
    projection_path = _safe_existing_file(
        candidate_report_root,
        CANDIDATE_PROJECTION_FILENAME,
        code="candidate_projection_invalid",
    )
    verification_inputs_path = _safe_existing_file(
        candidate_report_root,
        VERIFICATION_INPUTS_FILENAME,
        code="candidate_verification_inputs_invalid",
    )
    for name, path in (
        (CANDIDATE_REPORT_FILENAME, report_path),
        (CANDIDATE_PROJECTION_FILENAME, projection_path),
        (VERIFICATION_INPUTS_FILENAME, verification_inputs_path),
    ):
        if checksums.get(name) != _sha256_file(path):
            raise ValueError(f"candidate_checksum_mismatch:{name}")
    report = _load_json(report_path, code="candidate_report_invalid")
    _validate_report_self_hash(report, code="candidate_report_hash_invalid")
    if report.get("counter_authority") is not True:
        raise ValueError("candidate_counter_authority_invalid")
    if list(report.get("integrity_errors") or []) != []:
        raise ValueError("candidate_integrity_errors_present")
    report_rows = list(report.get("rows") or [])
    if len(report_rows) != 145:
        raise ValueError("candidate_report_count_invalid")
    _, projection_rows = _read_csv(projection_path, code="candidate_projection_invalid")
    if len(projection_rows) != 145:
        raise ValueError("candidate_projection_count_invalid")

    projection_by_id = {row["candidate_id"]: _parse_projection_row(row) for row in projection_rows}
    if len(projection_by_id) != len(projection_rows):
        raise ValueError("candidate_projection_duplicate")
    report_by_id = {
        str(row.get("candidate_id") or ""): row
        for row in report_rows
        if isinstance(row, Mapping)
    }
    if set(projection_by_id) != set(report_by_id):
        raise ValueError("candidate_projection_binding_invalid")
    plan_ids = {str(item["candidate_id"]) for item in list(plan.get("ordered_candidates") or [])}
    if set(projection_by_id) != plan_ids:
        raise ValueError("candidate_plan_binding_invalid")

    for candidate_id, projection_row in projection_by_id.items():
        report_row = report_by_id[candidate_id]
        normalized = {
            "candidate_id": candidate_id,
            "case_name": str(report_row.get("case_name") or ""),
            "chain": str(report_row.get("chain") or ""),
            "input_row_sha256": str(report_row.get("input_row_sha256") or ""),
            "candidate_envelope_path": str(report_row.get("candidate_envelope_path") or ""),
            "candidate_envelope_sha256": str(report_row.get("candidate_envelope_sha256") or ""),
            "historical_case_path": str(report_row.get("historical_case_path") or ""),
            "historical_case_sha256": str(report_row.get("historical_case_sha256") or ""),
            "eligible": bool(report_row.get("eligible")),
            "status": str(report_row.get("status") or ""),
            "scientific_blockers": [str(item) for item in list(report_row.get("scientific_blockers") or [])],
            "run_binding_sha256": str(report_row.get("run_binding_sha256") or ""),
        }
        if normalized != projection_row:
            raise ValueError("candidate_projection_report_mismatch")

    manifest_path = _safe_existing_file(candidate_run_root, "run_manifest.json", code="candidate_run_manifest_invalid")
    manifest = _load_json(manifest_path, code="candidate_run_manifest_invalid")
    qualification_result_path = _safe_existing_file(
        candidate_run_root,
        "qualification_result.json",
        code="candidate_qualification_result_invalid",
    )
    if manifest.get("revision_input_hashes") != plan.get("revision_input_hashes"):
        raise ValueError("candidate_revision_hashes_invalid")
    verification_inputs = _load_json(
        verification_inputs_path,
        code="candidate_verification_inputs_invalid",
    )
    expected_inputs = {
        "schema_version": "candidate_archive_verification_inputs.v1",
        "run_manifest_sha256": _sha256_file(manifest_path),
        "qualification_result_sha256": _sha256_file(qualification_result_path),
        "run_binding_sha256": str(manifest.get("binding_sha256") or ""),
        "revision_input_hashes": dict(plan.get("revision_input_hashes") or {}),
    }
    if verification_inputs != expected_inputs:
        raise ValueError("candidate_verification_inputs_mismatch")
    if dict(report.get("authoritative_input_hashes") or {}) != {
        "run_manifest_sha256": expected_inputs["run_manifest_sha256"],
        "qualification_result_sha256": expected_inputs["qualification_result_sha256"],
        "run_binding_sha256": expected_inputs["run_binding_sha256"],
        "revision_input_hashes": expected_inputs["revision_input_hashes"],
    }:
        raise ValueError("candidate_authoritative_inputs_mismatch")

    return report, projection_by_id, report_path, projection_path, manifest_path


def _select_candidate_ids_by_chain(
    *,
    order_rows: list[dict[str, str]],
    candidate_rows_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, list[str]]:
    selected: dict[str, list[str]] = {}
    for chain, quota in REQUIRED_QUOTAS.items():
        chosen: list[str] = []
        seen: set[str] = set()
        ordered_candidates = sorted(
            [row for row in order_rows if str(row.get("chain") or "") == chain],
            key=lambda row: (int(str(row.get("global_rank") or "0")), str(row.get("slot_case_id") or ""), str(row.get("candidate_id") or "")),
        )
        for order_row in ordered_candidates:
            candidate_id = str(order_row.get("candidate_id") or "")
            if candidate_id in seen:
                continue
            seen.add(candidate_id)
            if candidate_id not in candidate_rows_by_id:
                continue
            row = candidate_rows_by_id[candidate_id]
            if row["eligible"] is True:
                chosen.append(candidate_id)
                if len(chosen) == quota:
                    break
        if len(chosen) != quota:
            raise ValueError(f"candidate_quota_unfilled:{chain}")
        selected[chain] = chosen
    return selected


def _load_selected_candidate_artifacts(
    *,
    candidate_run_root: Path,
    candidate_id: str,
    row: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate_path = _safe_existing_file(
        candidate_run_root,
        str(row["candidate_envelope_path"]),
        code="candidate_envelope_path_invalid",
    )
    candidate_payload = _load_json(candidate_path, code="candidate_envelope_invalid")
    if str(candidate_payload.get("candidate_id") or "") != candidate_id:
        raise ValueError("candidate_envelope_binding_invalid")
    if str(candidate_payload.get("envelope_sha256") or "") != str(row["candidate_envelope_sha256"]):
        raise ValueError("candidate_envelope_hash_invalid")

    historical_path_text = str(row["historical_case_path"] or "")
    if not historical_path_text:
        raise ValueError("candidate_historical_case_missing")
    historical_path = _safe_existing_file(
        candidate_run_root,
        historical_path_text,
        code="candidate_historical_path_invalid",
    )
    if _sha256_file(historical_path) != str(row["historical_case_sha256"]):
        raise ValueError("candidate_historical_hash_invalid")
    historical_payload = _load_json(historical_path, code="candidate_historical_invalid")
    if str(historical_payload.get("case_id") or "") != candidate_id:
        raise ValueError("candidate_historical_binding_invalid")
    if historical_payload.get("strict_snapshot_closed") is not True:
        raise ValueError("candidate_historical_not_closed")
    return candidate_payload, historical_payload


def _build_mapping_rows(
    *,
    slot_rows: list[dict[str, str]],
    selected_by_chain: Mapping[str, list[str]],
    plan_by_id: Mapping[str, Mapping[str, Any]],
    candidate_rows_by_id: Mapping[str, Mapping[str, Any]],
    population_by_case_id: Mapping[str, Mapping[str, str]],
    parent_projection_by_case_id: Mapping[str, Mapping[str, str]],
    parent_addresses: set[tuple[str, str]],
    parent_case_ids: set[str],
    parent_txs: set[tuple[str, str]],
    candidate_run_root: Path,
) -> tuple[list[dict[str, str]], dict[str, dict[str, str]]]:
    selected_addresses: set[tuple[str, str]] = set()
    selected_txs: set[tuple[str, str]] = set()
    mapping_rows: list[dict[str, str]] = []
    replacement_by_slot: dict[str, dict[str, str]] = {}

    for chain in sorted(REQUIRED_QUOTAS):
        chain_slots = sorted(
            [row for row in slot_rows if row["chain"] == chain],
            key=lambda item: item["slot_case_id"],
        )
        selected_ids = list(selected_by_chain[chain])
        if len(chain_slots) != len(selected_ids):
            raise ValueError(f"selection_quota_mismatch:{chain}")
        for index, (slot, candidate_id) in enumerate(zip(chain_slots, selected_ids), start=1):
            candidate = dict(plan_by_id[candidate_id])
            row = candidate_rows_by_id[candidate_id]
            if row["eligible"] is not True:
                raise ValueError("selected_candidate_not_eligible")
            if candidate_id in parent_case_ids:
                raise ValueError("selected_candidate_case_id_collision")
            address_key = (chain, str(candidate["target_contract_address"]).lower())
            if address_key in selected_addresses or address_key in parent_addresses:
                raise ValueError("selected_candidate_address_collision")
            selected_addresses.add(address_key)
            tx_key = (chain, str(candidate["exploit_tx_hash"]).lower())
            if tx_key in selected_txs or tx_key in parent_txs:
                raise ValueError("selected_candidate_tx_collision")
            selected_txs.add(tx_key)
            if str(candidate["chain"]) != chain:
                raise ValueError("selected_candidate_chain_mismatch")

            candidate_payload, historical_payload = _load_selected_candidate_artifacts(
                candidate_run_root=candidate_run_root,
                candidate_id=candidate_id,
                row=row,
            )
            parent_row = dict(population_by_case_id[str(slot["slot_case_id"])])
            parent_projection = dict(parent_projection_by_case_id[str(slot["slot_case_id"])])
            mapping = {
                "chain": chain,
                "slot_case_id": str(slot["slot_case_id"]),
                "slot_case_name": str(parent_row.get("incident_name") or parent_row.get("case_name") or ""),
                "slot_target_contract_address": str(parent_row.get("target_contract_address") or ""),
                "slot_input_row_sha256": str(parent_projection.get("input_row_sha256") or ""),
                "slot_envelope_path": str(parent_projection.get("envelope_path") or ""),
                "slot_envelope_sha256": str(parent_projection.get("envelope_sha256") or ""),
                "candidate_id": candidate_id,
                "candidate_case_name": str(candidate["case_name"]),
                "candidate_target_contract_address": str(candidate["target_contract_address"]),
                "candidate_incident_block": str(candidate["incident_block"]),
                "candidate_exploit_tx_hash": str(candidate["exploit_tx_hash"]),
                "candidate_input_row_sha256": str(candidate["input_row_sha256"]),
                "candidate_source_sha256": str(candidate["source_sha256"]),
                "candidate_readme_sha256": str(candidate["readme_sha256"]),
                "candidate_envelope_path": str(row["candidate_envelope_path"]),
                "candidate_envelope_sha256": str(row["candidate_envelope_sha256"]),
                "historical_envelope_path": str(row["historical_case_path"]),
                "historical_envelope_sha256": str(row["historical_case_sha256"]),
                "selection_rank_within_chain": str(index),
            }
            mapping_rows.append(mapping)

            strict = dict(historical_payload.get("strict_snapshot") or {})
            revised = {key: "" for key in parent_row.keys()}
            revised.update(
                {
                    "case_name": str(candidate["case_name"]),
                    "task_source": "defihacklabs-temporal-replacement-finalization",
                    "chain": chain,
                    "fork_block_number": str(candidate["incident_block"]),
                    "target_contract_address": str(candidate["target_contract_address"]).lower(),
                    "evm_version": "",
                    "case_id": candidate_id,
                    "incident_date": str(candidate.get("incident_date") or ""),
                    "incident_name": str(candidate["case_name"]),
                    "mechanism_raw": "replacement_candidate",
                    "incident_contract_path": "",
                    "incident_chain": chain,
                    "source_url": "",
                    "source_status": "replacement_candidate_historical_snapshot_verified",
                    "source_snapshot_sha256": str(candidate["source_sha256"]),
                    "incident_record_sha256": str(candidate["input_row_sha256"]),
                    "incident_reference_urls": "[]",
                    "incident_tx_hashes": json.dumps([str(candidate["exploit_tx_hash"])], separators=(",", ":")),
                    "incident_loss_text": "",
                    "match_method": "frozen_chain_global_order_finalization",
                    "incident_metadata_present": "True",
                    "benchmark_fork_anchor_present": "True",
                    "deployment_block": str(strict.get("deployment_block") or ""),
                    "prediction_cutoff_block": str(strict.get("prediction_cutoff_block") or ""),
                    "incident_block_or_time": str(strict.get("incident_block") or candidate["incident_block"]),
                    "source_availability_time": "",
                    "runtime_bytecode_hash_at_cutoff": str(
                        ((strict.get("snapshot") or {}).get("runtime_bytecode_sha256")) or ""
                    ),
                    "outcome_adjudication_id": "",
                    "temporal_certification": "replacement_candidate_selected",
                    "admissibility_reason_codes": "[]",
                    "population_role": "replacement",
                    "replaced_parent_slot_case_id": str(slot["slot_case_id"]),
                    "parent_envelope_path": str(parent_projection.get("envelope_path") or ""),
                    "parent_envelope_sha256": str(parent_projection.get("envelope_sha256") or ""),
                    "parent_case_artifact_path": str(parent_projection.get("case_artifact_path") or ""),
                    "parent_case_artifact_sha256": str(parent_projection.get("case_artifact_sha256") or ""),
                    "candidate_envelope_path": str(row["candidate_envelope_path"]),
                    "candidate_envelope_sha256": str(row["candidate_envelope_sha256"]),
                    "historical_envelope_path": str(row["historical_case_path"]),
                    "historical_envelope_sha256": str(row["historical_case_sha256"]),
                    "replacement_selection_rank": str(index),
                    "replacement_order_rule": "first_eligible_unique_from_frozen_chain_global_order",
                    "replacement_source_sha256": str(candidate["source_sha256"]),
                    "replacement_readme_sha256": str(candidate["readme_sha256"]),
                    "replacement_incident_block": str(candidate["incident_block"]),
                    "replacement_exploit_tx_hash": str(candidate["exploit_tx_hash"]),
                }
            )
            replacement_by_slot[str(slot["slot_case_id"])] = revised
    return mapping_rows, replacement_by_slot


def _build_revised_population_rows(
    *,
    population_rows: list[dict[str, str]],
    parent_projection_by_case_id: Mapping[str, Mapping[str, str]],
    replacement_by_slot: Mapping[str, Mapping[str, str]],
) -> list[dict[str, str]]:
    revised_rows: list[dict[str, str]] = []
    for row in population_rows:
        case_id = str(row["case_id"])
        if case_id in replacement_by_slot:
            revised_rows.append(dict(replacement_by_slot[case_id]))
            continue
        projection = dict(parent_projection_by_case_id[case_id])
        retained = {**row}
        retained.update(
            {
                "population_role": "retained",
                "replaced_parent_slot_case_id": "",
                "parent_envelope_path": str(projection.get("envelope_path") or ""),
                "parent_envelope_sha256": str(projection.get("envelope_sha256") or ""),
                "parent_case_artifact_path": str(projection.get("case_artifact_path") or ""),
                "parent_case_artifact_sha256": str(projection.get("case_artifact_sha256") or ""),
                "candidate_envelope_path": "",
                "candidate_envelope_sha256": "",
                "historical_envelope_path": "",
                "historical_envelope_sha256": "",
                "replacement_selection_rank": "",
                "replacement_order_rule": "",
                "replacement_source_sha256": "",
                "replacement_readme_sha256": "",
                "replacement_incident_block": "",
                "replacement_exploit_tx_hash": "",
            }
        )
        revised_rows.append(retained)
    return revised_rows


def _write_outputs(
    output_dir: Path,
    *,
    mapping_rows: list[dict[str, str]],
    revised_population_rows: list[dict[str, str]],
    revised_population_fields: list[str],
    manifest: dict[str, Any],
) -> None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    try:
        with (stage / MAPPING_FILENAME).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(MAPPING_FIELDS))
            writer.writeheader()
            for row in mapping_rows:
                writer.writerow(row)
        with (stage / POPULATION_FILENAME).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=revised_population_fields)
            writer.writeheader()
            for row in revised_population_rows:
                writer.writerow(row)
        manifest_payload = dict(manifest)
        manifest_payload["output_hashes"] = {
            MAPPING_FILENAME: _sha256_file(stage / MAPPING_FILENAME),
            POPULATION_FILENAME: _sha256_file(stage / POPULATION_FILENAME),
        }
        manifest_payload["manifest_sha256"] = _sha256_json(
            {key: value for key, value in manifest_payload.items() if key != "manifest_sha256"}
        )
        (stage / MANIFEST_FILENAME).write_bytes(_canonical_json_bytes(manifest_payload) + b"\n")
        checksum_lines = [
            f"{_sha256_file(stage / name)}  {name}"
            for name in (MAPPING_FILENAME, POPULATION_FILENAME, MANIFEST_FILENAME)
        ]
        (stage / CHECKSUM_FILENAME).write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        if output_dir.exists():
            if any(output_dir.iterdir()):
                raise ValueError("finalization_output_exists")
            output_dir.rmdir()
        os.replace(stage, output_dir)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def finalize_historical_snapshot_replacements(
    *,
    parent_run_root: str | Path,
    parent_report_root: str | Path,
    revision_root: str | Path,
    candidate_run_root: str | Path,
    candidate_report_root: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    parent_run = _safe_directory(parent_run_root, code="parent_run_root_invalid")
    parent_report = _safe_directory(parent_report_root, code="parent_report_root_invalid")
    revision = _safe_directory(revision_root, code="revision_root_invalid")
    candidate_run = _safe_directory(candidate_run_root, code="candidate_run_root_invalid")
    candidate_report = _safe_directory(candidate_report_root, code="candidate_report_root_invalid")
    output_input = Path(output_dir).expanduser()
    _validate_output_parent(output_input)
    output = output_input.resolve(strict=False)

    (
        population_fields,
        population_rows,
        population_by_case_id,
        parent_projection_by_case_id,
        parent_manifest,
        parent_report_payload,
        parent_report_path,
        parent_projection_path,
    ) = _validated_parent_inputs(
        parent_run_root=parent_run,
        parent_report_root=parent_report,
    )
    blocked_case_ids = {
        case_id
        for case_id, row in parent_projection_by_case_id.items()
        if str(row.get("historical_snapshot_status") or "") != STRICT_STATUS
    }
    plan, slot_rows, order_rows, revision_slots_path, revision_order_path = _validated_revision_inputs(
        revision,
        blocked_case_ids=blocked_case_ids,
    )
    candidate_report_payload, candidate_rows_by_id, candidate_report_path, candidate_projection_path, candidate_manifest_path = _validated_candidate_inputs(
        candidate_run_root=candidate_run,
        candidate_report_root=candidate_report,
        plan=plan,
    )

    selected_by_chain = _select_candidate_ids_by_chain(
        order_rows=order_rows,
        candidate_rows_by_id=candidate_rows_by_id,
    )
    plan_by_id = {
        str(item["candidate_id"]): dict(item)
        for item in list(plan.get("ordered_candidates") or [])
    }
    parent_addresses = {
        (str(row["chain"]), str(row["target_contract_address"]).lower())
        for row in population_rows
    }
    parent_case_ids = {str(row["case_id"]) for row in population_rows}
    parent_txs: set[tuple[str, str]] = set()
    for row in population_rows:
        try:
            transactions = json.loads(str(row.get("incident_tx_hashes") or "[]"))
        except json.JSONDecodeError as exc:
            raise ValueError("parent_incident_tx_invalid") from exc
        if isinstance(transactions, list):
            for tx in transactions:
                if isinstance(tx, str) and tx:
                    parent_txs.add((str(row["chain"]), tx.lower()))

    mapping_rows, replacement_by_slot = _build_mapping_rows(
        slot_rows=slot_rows,
        selected_by_chain=selected_by_chain,
        plan_by_id=plan_by_id,
        candidate_rows_by_id=candidate_rows_by_id,
        population_by_case_id=population_by_case_id,
        parent_projection_by_case_id=parent_projection_by_case_id,
        parent_addresses=parent_addresses,
        parent_case_ids=parent_case_ids,
        parent_txs=parent_txs,
        candidate_run_root=candidate_run,
    )
    revised_population_fields = list(population_fields) + list(REVISED_EXTRA_FIELDS)
    revised_population_rows = _build_revised_population_rows(
        population_rows=population_rows,
        parent_projection_by_case_id=parent_projection_by_case_id,
        replacement_by_slot=replacement_by_slot,
    )
    if len(mapping_rows) != 57 or len(revised_population_rows) != 417:
        raise ValueError("finalized_population_count_invalid")

    retained_case_ids = [
        str(row["case_id"])
        for row in revised_population_rows
        if str(row.get("population_role") or "") == "retained"
    ]
    manifest = {
        "schema_version": "historical_snapshot_replacement_finalization.v1",
        "order_rule": "first eligible unique candidates from frozen chain-global order; bind to sorted slots within chain",
        "slot_quotas": dict(REQUIRED_QUOTAS),
        "selected_candidate_ids_by_chain": dict(selected_by_chain),
        "retained_case_ids": retained_case_ids,
        "input_artifacts": {
            "parent_run_manifest": {
                "path": str(parent_run / "run_manifest.json"),
                "sha256": _sha256_file(parent_run / "run_manifest.json"),
            },
            "parent_report": {
                "path": str(parent_report_path),
                "sha256": _sha256_file(parent_report_path),
                "report_sha256": str(parent_report_payload["report_sha256"]),
            },
            "parent_projection": {
                "path": str(parent_projection_path),
                "sha256": _sha256_file(parent_projection_path),
            },
            "revision_slots": {
                "path": str(revision_slots_path),
                "sha256": _sha256_file(revision_slots_path),
            },
            "revision_order": {
                "path": str(revision_order_path),
                "sha256": _sha256_file(revision_order_path),
            },
            "revision_input_hashes": dict(plan.get("revision_input_hashes") or {}),
            "candidate_run_manifest": {
                "path": str(candidate_manifest_path),
                "sha256": _sha256_file(candidate_manifest_path),
            },
            "candidate_report": {
                "path": str(candidate_report_path),
                "sha256": _sha256_file(candidate_report_path),
                "report_sha256": str(candidate_report_payload["report_sha256"]),
            },
            "candidate_projection": {
                "path": str(candidate_projection_path),
                "sha256": _sha256_file(candidate_projection_path),
            },
        },
        "counts": {
            "replacement_count": len(mapping_rows),
            "retained_count": len(retained_case_ids),
            "revised_population_count": len(revised_population_rows),
        },
        "authoritative_bindings": {
            "parent_binding_sha256": str(parent_manifest.get("binding_sha256") or ""),
            "candidate_binding_sha256": str(candidate_report_payload["rows"][0]["run_binding_sha256"]) if candidate_report_payload.get("rows") else "",
        },
    }
    _write_outputs(
        output,
        mapping_rows=mapping_rows,
        revised_population_rows=revised_population_rows,
        revised_population_fields=revised_population_fields,
        manifest=manifest,
    )
    return _load_json(output / MANIFEST_FILENAME, code="finalization_manifest_invalid")


__all__ = ["finalize_historical_snapshot_replacements"]
