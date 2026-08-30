from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path


class ControlStagedStateProjectionError(ValueError):
    """Raised when staged cutoff-state evidence cannot be joined losslessly."""


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
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
        raise ControlStagedStateProjectionError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlStagedStateProjectionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlStagedStateProjectionError(f"{label}_not_ordinary")
    return resolved


def _load_results(path: Path, label: str) -> tuple[Path, dict[str, object], list[dict[str, object]]]:
    file = _ordinary(path, label)
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlStagedStateProjectionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "stage2_control_cutoff_state_results.v1":
        raise ControlStagedStateProjectionError(f"{label}_schema_invalid")
    material = {key: value for key, value in payload.items() if key != "results_sha256"}
    if payload.get("results_sha256") != _canonical_sha(material):
        raise ControlStagedStateProjectionError(f"{label}_self_hash_invalid")
    rows = payload.get("targets")
    try:
        count = int(payload.get("target_count", -1))
    except (TypeError, ValueError) as exc:
        raise ControlStagedStateProjectionError(f"{label}_incomplete") from exc
    if (
        not isinstance(rows, list)
        or not all(isinstance(row, dict) for row in rows)
        or len(rows) != count
        or payload.get("processed_target_count") != count
        or payload.get("completed_target_count") != count
        or payload.get("dispositions") != {"complete": count}
    ):
        raise ControlStagedStateProjectionError(f"{label}_incomplete")
    for row in rows:
        row_material = {key: value for key, value in row.items() if key not in {"result_sha256", "disposition"}}
        if row.get("result_sha256") != _canonical_sha(row_material):
            raise ControlStagedStateProjectionError(f"{label[:-1]}_self_hash_invalid")
    return file, payload, rows


def _raw_hashes(*rows: Mapping[str, object]) -> list[str]:
    hashes: set[str] = set()
    for row in rows:
        values = row.get("raw_evidence_hashes")
        if not isinstance(values, list) or not values:
            raise ControlStagedStateProjectionError("raw_evidence_hashes_invalid")
        for value in values:
            text = str(value).lower()
            if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
                raise ControlStagedStateProjectionError("raw_evidence_hash_invalid")
            hashes.add(text)
    return sorted(hashes)


def project_staged_state_results(
    *,
    base_state_results_path: Path,
    derived_state_results_path: Path,
    beacon_implementation_results_path: Path | None,
) -> dict[str, object]:
    base_file, base_payload, base_rows = _load_results(base_state_results_path, "base_state_results")
    derived_file, derived_payload, derived_rows = _load_results(derived_state_results_path, "derived_state_results")
    phase3: tuple[Path, dict[str, object], list[dict[str, object]]] | None = None
    if beacon_implementation_results_path is not None:
        phase3 = _load_results(beacon_implementation_results_path, "beacon_implementation_results")

    derived_by_key: dict[tuple[str, str], dict[str, object]] = {}
    for row in derived_rows:
        if row.get("schema_version") != "stage2_control_derived_state_result.v1":
            raise ControlStagedStateProjectionError("derived_state_result_schema_invalid")
        key = (str(row.get("base_state_result_sha256", "")), str(row.get("derived_role", "")))
        if not all(key) or key in derived_by_key:
            raise ControlStagedStateProjectionError("derived_state_result_identity_invalid")
        derived_by_key[key] = row
    phase3_by_source: dict[str, dict[str, object]] = {}
    if phase3 is not None:
        for row in phase3[2]:
            if row.get("schema_version") != "stage2_control_beacon_implementation_result.v1":
                raise ControlStagedStateProjectionError("beacon_implementation_result_schema_invalid")
            source = str(row.get("derived_state_result_sha256", ""))
            if not source or source in phase3_by_source:
                raise ControlStagedStateProjectionError("beacon_implementation_result_identity_invalid")
            phase3_by_source[source] = row

    projections: list[dict[str, object]] = []
    used_derived: set[str] = set()
    used_phase3: set[str] = set()
    for base in base_rows:
        if base.get("schema_version") != "stage2_control_base_state_result.v1":
            raise ControlStagedStateProjectionError("base_state_result_schema_invalid")
        base_sha = str(base["result_sha256"])
        signals = [
            ("eip1967_implementation", "direct_implementation_runtime_code", base.get("direct_implementation_address")),
            ("eip1967_beacon", "beacon_implementation_call", base.get("beacon_address")),
            ("eip1167", "eip1167_target_runtime_code", base.get("eip1167_target")),
        ]
        active = [signal for signal in signals if signal[2]]
        if len(active) > 1:
            raise ControlStagedStateProjectionError("proxy_signal_conflict")
        implementation_address: object = None
        implementation_code_hash: object = None
        joined_rows: list[Mapping[str, object]] = [base]
        proxy_family = "unknown"
        if active:
            proxy_family, role, source_address = active[0]
            derived = derived_by_key.get((base_sha, role))
            if derived is None:
                raise ControlStagedStateProjectionError("derived_state_result_missing")
            used_derived.add(str(derived["result_sha256"]))
            joined_rows.append(derived)
            if role == "beacon_implementation_call":
                implementation_address = derived.get("beacon_implementation_address")
                if not implementation_address:
                    raise ControlStagedStateProjectionError("beacon_implementation_address_missing")
                phase3_row = phase3_by_source.get(str(derived["result_sha256"]))
                if phase3_row is None:
                    raise ControlStagedStateProjectionError("beacon_implementation_result_missing")
                used_phase3.add(str(phase3_row["result_sha256"]))
                joined_rows.append(phase3_row)
                implementation_code_hash = phase3_row.get("runtime_code_hash")
            else:
                implementation_address = source_address
                implementation_code_hash = derived.get("runtime_code_hash")
            if not implementation_code_hash:
                raise ControlStagedStateProjectionError("implementation_code_hash_missing")
        clone_family = implementation_code_hash or base.get("metadata_stripped_code_hash") or base.get("runtime_code_hash")
        raw_hashes = _raw_hashes(*joined_rows)
        row: dict[str, object] = {
            "schema_version": "stage2_control_cutoff_state_result.v1",
            "status": "complete",
            "phase": "STAGED_CUTOFF_STATE_PROJECTION_V1",
            "target_id": base["target_id"],
            "case_id": base["case_id"],
            "chain": base["chain"],
            "chain_address": base["chain_address"],
            "identity_group": base["identity_group"],
            "cutoff_timestamp": base["cutoff_timestamp"],
            "evidence_block_number": base["evidence_block_number"],
            "evidence_block_hash": base["evidence_block_hash"],
            "evidence_block_timestamp": base.get("evidence_block_timestamp"),
            "next_block_number": base["next_block_number"],
            "next_block_hash": base["next_block_hash"],
            "next_block_timestamp": base.get("next_block_timestamp"),
            "provider_agreement": True,
            "provider_families": base["provider_families"],
            "eip1898_pinned": True,
            "runtime_code_size": base["runtime_code_size"],
            "runtime_code_hash": base["runtime_code_hash"],
            "metadata_stripped_code_hash": base["metadata_stripped_code_hash"],
            "proxy_status": "proxy" if active else "unknown",
            "proxy_family": proxy_family,
            "implementation_address": implementation_address,
            "implementation_code_hash": implementation_code_hash,
            "clone_family": clone_family,
            "pair_scope_record_sha256": base["pair_scope_record_sha256"],
            "denominator_record_sha256": base["denominator_record_sha256"],
            "deployment_result_sha256": base["deployment_result_sha256"],
            "base_state_result_sha256": base_sha,
            "derived_state_result_sha256s": sorted(
                str(joined["result_sha256"])
                for joined in joined_rows[1:]
                if joined.get("schema_version") == "stage2_control_derived_state_result.v1"
            ),
            "beacon_implementation_result_sha256s": sorted(
                str(joined["result_sha256"])
                for joined in joined_rows[1:]
                if joined.get("schema_version") == "stage2_control_beacon_implementation_result.v1"
            ),
            "raw_evidence_hashes": raw_hashes,
            "field_statuses": {
                "runtime_code": "observable",
                "eip1967_implementation": "observable",
                "eip1967_beacon": "observable",
                "eip1967_admin": "observable",
                "beacon_implementation": "observable" if base.get("beacon_address") else "unavailable",
                "eip1167_target": "observable" if base.get("eip1167_target") else "unavailable",
                "implementation_runtime_code": "observable" if active else "unavailable",
                "proxy_classification": "observable" if active else "unavailable",
            },
            "selection_authorized": False,
            "qualification_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
        row["result_sha256"] = _canonical_sha(row)
        projections.append(row)

    expected_derived = {str(row["result_sha256"]) for row in derived_rows}
    if used_derived != expected_derived:
        raise ControlStagedStateProjectionError("derived_state_result_membership_mismatch")
    expected_phase3 = {str(row["result_sha256"]) for row in (phase3[2] if phase3 else [])}
    if used_phase3 != expected_phase3:
        raise ControlStagedStateProjectionError("beacon_implementation_result_membership_mismatch")
    projections.sort(key=lambda row: str(row["target_id"]))
    output: dict[str, object] = {
        "schema_version": "stage2_control_staged_cutoff_state_results.v1",
        "decision": "STAGED_CUTOFF_STATE_PROJECTED_NON_AUTHORIZING",
        "base_state_results_file_sha256": _file_sha(base_file),
        "base_state_results_sha256": base_payload["results_sha256"],
        "derived_state_results_file_sha256": _file_sha(derived_file),
        "derived_state_results_sha256": derived_payload["results_sha256"],
        "beacon_implementation_results_file_sha256": _file_sha(phase3[0]) if phase3 else None,
        "beacon_implementation_results_sha256": phase3[1]["results_sha256"] if phase3 else None,
        "target_count": len(projections),
        "complete": len(projections) == len(base_rows),
        "targets": projections,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["projection_sha256"] = _canonical_sha(output)
    return output
