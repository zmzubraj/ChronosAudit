from __future__ import annotations

import csv
import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Mapping

from .historical_snapshot_run import (
    FULL_CASE_TARGET,
    _atomic_write_csv,
    _atomic_write_text,
    _canonical_json_bytes,
    _frozen_input_path,
    _frozen_inputs_hash,
    _historical_snapshot_closure_report,
    _load_existing_preparation_manifest,
    _load_schema,
    _load_yaml,
    _portable_path,
    _scan_receipt_manifest,
    _selected_cases_from_binding,
    _sha256_file,
    _sha256_json,
    _stable_case_mapping,
    _validate_frozen_input_entries,
    _validate_receipt_observation_paths,
    _validate_snapshot_case_envelope_hashes,
    _validate_transition_proof_hashes,
    load_canonical_snapshot_population,
)
from .strict_snapshot import (
    STRICT_HISTORICAL_STATUS,
    snapshot_counter_projection,
    validate_strict_historical_snapshot,
)

REPORT_FILENAME = "historical_snapshot_verification_report.json"
PROJECTION_FILENAME = "historical_snapshot_verified_projection.csv"
QUALIFICATION_FIELDS = [
    "case_id",
    "case_name",
    "chain",
    "input_row_sha256",
    "envelope_path",
    "envelope_sha256",
    "status",
    "candidate_closed",
    "resumed",
    "quarantined",
    "retried",
    "counter_authority",
]
PROJECTION_FIELDS = [
    "case_id",
    "case_name",
    "chain",
    "input_row_sha256",
    "envelope_path",
    "envelope_sha256",
    "counter_authority",
    "historical_snapshot_status",
    "historical_snapshot_source_receipt_sha256",
    "historical_snapshot_identity_receipt_sha256",
    "historical_snapshot_source_provider_family",
    "historical_snapshot_identity_provider_family",
    "historical_snapshot_schema_valid",
    "historical_snapshot_hash_bound",
    "case_artifact_path",
    "case_artifact_sha256",
]
NON_SCIENTIFIC_METADATA_FIELDS = ["resumed", "quarantined", "retried"]
_EXPECTED_AGGREGATE_KEYS = {
    "rpc_receipt_manifest",
    "provider_identity_verification",
    "historical_snapshot_closure_report",
    "case_qualification",
    "blocker_ledger",
}
_EXPECTED_AGGREGATE_PATHS = {
    "rpc_receipt_manifest": "rpc_receipt_manifest.json",
    "provider_identity_verification": "provider_identity_verification.json",
    "historical_snapshot_closure_report": "historical_snapshot_closure_report.json",
    "case_qualification": "case_qualification.csv",
    "blocker_ledger": "blocker_ledger.csv",
}
_FROZEN_ENTRY_DEFAULT_PATHS = {
    "queue": "frozen_inputs/queue.csv",
    "temporal": "frozen_inputs/temporal.csv",
    "policy": "frozen_inputs/policy.yaml",
}


def _csv_bool(value: bool) -> str:
    return "true" if value else "false"


def _safe_run_root(run_root: str | Path) -> Path:
    path = Path(run_root).expanduser()
    if not path.exists() or not path.is_dir():
        raise ValueError("run_root_invalid")
    if path.is_symlink():
        raise ValueError("run_root_symlink")
    return path.resolve(strict=False)


def _safe_artifact_path(run_root: Path, relative_path: str) -> Path:
    candidate = run_root / relative_path
    if candidate.is_symlink():
        raise ValueError("path_symlink")
    resolved = candidate.resolve(strict=False)
    root_resolved = run_root.resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("path_escape") from exc
    return resolved


def _safe_output_root(output_path: str | Path) -> Path:
    candidate = Path(output_path).expanduser()
    if candidate.exists() and candidate.is_symlink():
        raise ValueError("output_path_symlink")
    return candidate.resolve(strict=False)


def _load_json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_csv_rows(path: Path, *, expected_fields: list[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected_fields:
            raise ValueError("csv_columns_mismatch")
        return list(reader)


def _is_sha256_hex(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _load_json_or_error(path: Path, *, missing_code: str, malformed_code: str) -> tuple[dict[str, Any], str | None]:
    if path is None:
        return {}, missing_code
    try:
        return _load_json_file(path), None
    except FileNotFoundError:
        return {}, missing_code
    except (JSONDecodeError, UnicodeDecodeError, OSError, ValueError):
        return {}, malformed_code


def _load_csv_or_error(
    path: Path,
    *,
    expected_fields: list[str],
    missing_code: str,
    malformed_code: str,
) -> tuple[list[dict[str, str]], str | None]:
    if path is None:
        return [], missing_code
    try:
        return _load_csv_rows(path, expected_fields=expected_fields), None
    except FileNotFoundError:
        return [], missing_code
    except (UnicodeDecodeError, OSError, ValueError):
        return [], malformed_code


def _fallback_frozen_entry(name: str) -> dict[str, Any]:
    return {"name": name, "frozen_path": _FROZEN_ENTRY_DEFAULT_PATHS[name]}


def _required_frozen_entry(
    entries: list[dict[str, Any]],
    *,
    name: str,
    integrity_errors: list[str],
) -> dict[str, Any]:
    for entry in entries:
        if entry.get("name") == name:
            return dict(entry)
    integrity_errors.append(f"frozen_required_entry_missing:{name}")
    return _fallback_frozen_entry(name)


def _resolved_required_frozen_path(
    root: Path,
    *,
    entry: Mapping[str, Any],
    name: str,
    integrity_errors: list[str],
) -> Path | None:
    relative_path = str(entry.get("frozen_path") or _FROZEN_ENTRY_DEFAULT_PATHS[name])
    try:
        path = _safe_artifact_path(root, relative_path)
    except ValueError as exc:
        integrity_errors.append(f"frozen_input_path_invalid:{name}:{exc}")
        return None
    if not path.exists() or not path.is_file():
        integrity_errors.append(f"frozen_input_missing:{name}")
        return None
    return path


def _aggregate_artifact_path(
    root: Path,
    *,
    aggregate_paths: Mapping[str, Any],
    name: str,
    integrity_errors: list[str],
) -> Path | None:
    relative_path = str(aggregate_paths.get(name) or _EXPECTED_AGGREGATE_PATHS[name])
    try:
        return _safe_artifact_path(root, relative_path)
    except ValueError as exc:
        integrity_errors.append(f"aggregate_path_invalid:{name}")
        try:
            return _safe_artifact_path(root, _EXPECTED_AGGREGATE_PATHS[name])
        except ValueError as fallback_exc:
            integrity_errors.append(f"aggregate_fallback_invalid:{name}:{fallback_exc}")
            return None


def _load_yaml_or_error(path: Path | None, *, missing_code: str, malformed_code: str) -> tuple[dict[str, Any], str | None]:
    if path is None:
        return {}, missing_code
    try:
        return dict(_load_yaml(path) or {}), None
    except FileNotFoundError:
        return {}, missing_code
    except (UnicodeDecodeError, OSError, ValueError):
        return {}, malformed_code


def _safe_optional_path(
    root: Path,
    *,
    relative_path: str,
    invalid_code: str,
    integrity_errors: list[str],
) -> Path | None:
    try:
        return _safe_artifact_path(root, relative_path)
    except ValueError:
        integrity_errors.append(invalid_code)
        return None


def _blank_projection_row(case: Mapping[str, Any]) -> dict[str, str]:
    return {
        "case_id": str(case["case_id"]),
        "case_name": str(case["case_name"]),
        "chain": str(case["chain"]),
        "input_row_sha256": str(case["input_row_sha256"]),
        "envelope_path": "",
        "envelope_sha256": "",
        "counter_authority": "false",
        "historical_snapshot_status": "",
        "historical_snapshot_source_receipt_sha256": "",
        "historical_snapshot_identity_receipt_sha256": "",
        "historical_snapshot_source_provider_family": "",
        "historical_snapshot_identity_provider_family": "",
        "historical_snapshot_schema_valid": "false",
        "historical_snapshot_hash_bound": "false",
        "case_artifact_path": "",
        "case_artifact_sha256": "",
    }


def _blank_qualification_row(case: Mapping[str, Any]) -> dict[str, str]:
    return {
        "case_id": str(case["case_id"]),
        "case_name": str(case["case_name"]),
        "chain": str(case["chain"]),
        "input_row_sha256": str(case["input_row_sha256"]),
        "envelope_path": f"cases/{case['case_id']}.json",
        "envelope_sha256": "",
        "status": "PARTIAL",
        "candidate_closed": "false",
        "resumed": "false",
        "quarantined": "false",
        "retried": "false",
        "counter_authority": "false",
    }


def _provider_report_hash(report: Mapping[str, Any]) -> str:
    return _sha256_json(
        {
            "schema_version": report["schema_version"],
            "complete": report["complete"],
            "chain_count": report["chain_count"],
            "errors": report["errors"],
            "chains": report["chains"],
        }
    )


def _provider_record_identity(
    *,
    chain: str,
    provider_id: str,
    family: str,
    identity: str,
    endpoint_template_sha256: str,
) -> dict[str, str]:
    evidence = {
        "chain": chain,
        "provider_id": provider_id,
        "provider_identity_id": identity,
        "endpoint_template_sha256": endpoint_template_sha256,
        "verified_operator_family": family,
    }
    return {
        "chain": chain,
        "provider_id": provider_id,
        "verified_operator_family": family,
        "public_endpoint_identity_id": identity,
        "public_endpoint_identity_sha256": _sha256_json(identity),
        "endpoint_template_sha256": endpoint_template_sha256,
        "identity_evidence_sha256": _sha256_json(evidence),
    }


def _validate_provider_report(
    report: Mapping[str, Any],
    *,
    selected_cases: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    if report.get("schema_version") != "historical_snapshot_provider_identity_verification.v1":
        errors.append("provider_report_schema_invalid")
    if report.get("report_sha256") != _provider_report_hash(report):
        errors.append("provider_report_self_hash_mismatch")
    chain_list = [
        dict(entry)
        for entry in report.get("chains", [])
        if isinstance(entry, Mapping) and str(entry.get("chain") or "").strip()
    ]
    chain_names = [str(entry.get("chain") or "") for entry in chain_list]
    if len(set(chain_names)) != len(chain_names):
        errors.append("provider_report_duplicate_chain")
    selected_chains = sorted({str(case["chain"]) for case in selected_cases})
    chain_entries = {
        str(entry.get("chain") or ""): dict(entry)
        for entry in chain_list
    }
    if sorted(chain_entries) != selected_chains:
        errors.append("provider_report_chain_coverage_mismatch")
    validated: dict[str, dict[str, Any]] = {}
    all_error_tokens: set[str] = set()
    for chain in selected_chains:
        entry = chain_entries.get(chain)
        if entry is None:
            continue
        providers = entry.get("providers", [])
        if not isinstance(providers, list) or not providers:
            errors.append("provider_report_incomplete")
            continue
        families: set[str] = set()
        expected_errors: set[str] = set()
        provider_keys: set[tuple[str, str]] = set()
        normalized_providers: list[dict[str, str]] = []
        for provider in providers:
            if not isinstance(provider, Mapping):
                expected_errors.add("incomplete_identity")
                continue
            provider_id = str(provider.get("provider_id") or "").strip()
            family = str(provider.get("verified_operator_family") or "").strip()
            identity = str(provider.get("public_endpoint_identity_id") or "").strip()
            endpoint_sha = str(provider.get("endpoint_template_sha256") or "").strip().lower()
            if not provider_id or not family or not identity or not _is_sha256_hex(endpoint_sha):
                expected_errors.add("incomplete_identity")
                if endpoint_sha and not _is_sha256_hex(endpoint_sha):
                    errors.append("provider_report_sha256_invalid")
                continue
            normalized = _provider_record_identity(
                chain=chain,
                provider_id=provider_id,
                family=family,
                identity=identity,
                endpoint_template_sha256=endpoint_sha,
            )
            if not _is_sha256_hex(provider.get("public_endpoint_identity_sha256")):
                errors.append("provider_report_sha256_invalid")
            if not _is_sha256_hex(provider.get("identity_evidence_sha256")):
                errors.append("provider_report_sha256_invalid")
            if str(provider.get("public_endpoint_identity_sha256") or "") != normalized["public_endpoint_identity_sha256"]:
                expected_errors.add("incomplete_identity")
            if str(provider.get("identity_evidence_sha256") or "") != normalized["identity_evidence_sha256"]:
                expected_errors.add("incomplete_identity")
            provider_key = (provider_id, identity)
            if provider_key in provider_keys:
                errors.append("provider_report_duplicate_provider_identity")
            families.add(family)
            provider_keys.add(provider_key)
            normalized_providers.append(normalized)
        if len(families) < 2:
            expected_errors.add("same_family")
        expected_error_list = sorted(expected_errors)
        if expected_error_list != list(entry.get("errors") or []):
            errors.append("provider_report_errors_mismatch")
        if bool(entry.get("complete")) != (not expected_error_list):
            errors.append("provider_report_complete_mismatch")
        if int(entry.get("provider_count") or 0) != len(normalized_providers):
            errors.append("provider_report_count_mismatch")
        if sorted(entry.get("verified_operator_families") or []) != sorted(families):
            errors.append("provider_report_family_index_mismatch")
        all_error_tokens.update(expected_error_list)
        validated[chain] = {
            "complete": not expected_error_list,
            "providers": normalized_providers,
            "provider_keys": provider_keys,
            "families": sorted(families),
            "errors": expected_error_list,
        }
    if sorted(all_error_tokens) != list(report.get("errors") or []):
        errors.append("provider_report_global_errors_mismatch")
    if bool(report.get("complete")) != (not all_error_tokens and bool(validated)):
        errors.append("provider_report_global_complete_mismatch")
    return validated, errors


def _snapshot_provider_records(snapshot_provider_identity: Mapping[str, Any], *, chain: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for family_entry in snapshot_provider_identity.get("families", []) or []:
        if not isinstance(family_entry, Mapping):
            continue
        family = str(family_entry.get("family_id") or "").strip()
        endpoint_sha = str(family_entry.get("endpoint_template_sha256") or "").strip().lower()
        for evidence in family_entry.get("evidence", []) or []:
            if not isinstance(evidence, Mapping):
                continue
            provider_id = str(evidence.get("provider_id") or "").strip()
            identity = str(evidence.get("provider_identity") or "").strip()
            endpoint_value = str(
                evidence.get("endpoint_template_sha256")
                or endpoint_sha
            ).strip().lower()
            if not provider_id or not family or not identity or not _is_sha256_hex(endpoint_value):
                continue
            records.append(
                _provider_record_identity(
                    chain=chain,
                    provider_id=provider_id,
                    family=family,
                    identity=identity,
                    endpoint_template_sha256=endpoint_value,
                )
            )
    return records


def _validate_operational_metadata(
    actual_rows: list[dict[str, str]],
    *,
    manifest_summary: Mapping[str, Any],
    closure_report: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    for field in NON_SCIENTIFIC_METADATA_FIELDS:
        values = [row[field] for row in actual_rows]
        if any(value not in {"true", "false"} for value in values):
            errors.append(f"operational_metadata_{field}_encoding_invalid")
    counts = {
        "reused_case_count": sum(1 for row in actual_rows if row["resumed"] == "true"),
        "quarantined_case_count": sum(1 for row in actual_rows if row["quarantined"] == "true"),
        "retried_case_count": sum(1 for row in actual_rows if row["retried"] == "true"),
    }
    for key, observed in counts.items():
        if int(manifest_summary.get(key) or 0) != observed:
            errors.append(f"summary_{key}_mismatch")
        if int(closure_report.get(key) or 0) != observed:
            errors.append(f"closure_{key}_mismatch")
    return errors


def _selected_case_result(
    *,
    run_root: Path,
    case: Mapping[str, Any],
    frozen_policy: Mapping[str, Any],
    provider_index_by_chain: Mapping[str, dict[str, Any]],
    strict_schema: Mapping[str, Any],
) -> tuple[dict[str, str], list[str], dict[str, str]]:
    projection = _blank_projection_row(case)
    qualification = _blank_qualification_row(case)
    blockers: set[str] = set()
    case_id = str(case["case_id"])
    envelope_relpath = f"cases/{case_id}.json"
    case_path = _safe_artifact_path(run_root, envelope_relpath)
    if not case_path.exists() or not case_path.is_file():
        blockers.add("case_artifact_missing")
        return qualification, sorted(blockers), projection

    envelope = _load_json_file(case_path)
    envelope_file_sha = _sha256_file(case_path)
    projection["envelope_path"] = envelope_relpath
    projection["envelope_sha256"] = str(envelope.get("envelope_sha256") or "")
    projection["case_artifact_path"] = envelope_relpath
    projection["case_artifact_sha256"] = envelope_file_sha
    qualification["envelope_sha256"] = str(envelope.get("envelope_sha256") or "")
    qualification["status"] = str(envelope.get("status") or "PARTIAL")

    if not _validate_snapshot_case_envelope_hashes(envelope):
        blockers.add("case_envelope_hash_mismatch")
        return qualification, sorted(blockers), projection
    if envelope.get("case_path") != f"{case_id}.json":
        blockers.add("case_path_mismatch")
    chain = str(case["chain"])
    if str(envelope.get("case_id") or "").strip() != case_id:
        blockers.add("case_envelope_binding_mismatch")
    for key, expected in (
        ("case_name", str(case["case_name"])),
        ("chain", chain),
        ("address", str(case["address"]).lower()),
        ("incident_block", int(case["incident_block"])),
    ):
        if key in envelope and envelope.get(key) is not None:
            actual = envelope.get(key)
            if key == "address":
                actual = str(actual).strip().lower()
            elif key == "chain":
                actual = str(actual).strip().lower()
            elif key == "incident_block":
                actual = int(actual)
            else:
                actual = str(actual)
            if actual != expected:
                blockers.add("case_envelope_binding_mismatch")
                break
    envelope_case_input = dict(envelope.get("case_input") or {})
    # Compare canonical encodings because pandas represents missing numeric
    # values as NaN, and NaN is intentionally unequal to itself in Python.
    if _sha256_json(envelope_case_input) != _sha256_json(dict(case)):
        blockers.add("case_input_hash_mismatch")
    if envelope.get("case_input_sha256") != _sha256_json(envelope_case_input):
        blockers.add("case_input_hash_mismatch")
    if dict(envelope.get("policy_input") or {}) != dict(frozen_policy):
        blockers.add("policy_input_mismatch")
    if envelope.get("policy_sha256") != _sha256_json(frozen_policy):
        blockers.add("policy_hash_mismatch")
    transition = dict(envelope.get("transition_proof") or {})
    if not _validate_transition_proof_hashes(transition):
        blockers.add("transition_proof_hash_mismatch")
    receipt_root = _safe_artifact_path(run_root, "rpc_receipts")
    persisted_status = str(envelope.get("status") or "PARTIAL")
    strict_snapshot = dict(envelope.get("strict_snapshot") or {})
    provider_identity = dict(strict_snapshot.get("provider_identity") or {})
    provider_chain = provider_index_by_chain.get(chain, {})
    expected_records = _snapshot_provider_records(provider_identity, chain=chain)
    actual_provider_records = {
        tuple(
            provider[field]
            for field in (
                "provider_id",
                "verified_operator_family",
                "public_endpoint_identity_id",
                "endpoint_template_sha256",
                "identity_evidence_sha256",
            )
        )
        for provider in provider_chain.get("providers", [])
    }
    if not provider_chain or not provider_chain.get("complete"):
        blockers.add("provider_identity_incomplete")
    for record in expected_records:
        key = (
            record["provider_id"],
            record["verified_operator_family"],
            record["public_endpoint_identity_id"],
            record["endpoint_template_sha256"],
            record["identity_evidence_sha256"],
        )
        if key not in actual_provider_records:
            blockers.add("provider_identity_hash_mismatch")
            break

    if (
        envelope.get("strict_snapshot_closed") is True
        and persisted_status == "VERIFIED"
        and not list(envelope.get("blockers") or [])
    ):
        if not _validate_receipt_paths_for_run_root(
            snapshot_transition_observations(transition),
            receipt_root=receipt_root,
        ):
            blockers.add("receipt_binding_invalid")
        validation_snapshot = _relocatable_strict_snapshot(strict_snapshot, receipt_root=receipt_root)
        validation = validate_strict_historical_snapshot(
            validation_snapshot,
            schema=dict(strict_schema),
            receipt_root=receipt_root,
            provider_identity=provider_identity,
        )
        if not validation.ok:
            blockers.update(validation.errors)
        else:
            counter = snapshot_counter_projection(
                strict_snapshot,
                case_artifact_path=envelope_relpath,
                case_artifact_sha256=envelope_file_sha,
            )
            if counter["historical_snapshot_status"] != STRICT_HISTORICAL_STATUS:
                blockers.add("strict_counter_projection_invalid")
            else:
                projection.update(
                    {
                        "counter_authority": "true",
                        "historical_snapshot_status": counter["historical_snapshot_status"],
                        "historical_snapshot_source_receipt_sha256": str(
                            counter["historical_snapshot_source_receipt_sha256"]
                        ),
                        "historical_snapshot_identity_receipt_sha256": str(
                            counter["historical_snapshot_identity_receipt_sha256"]
                        ),
                        "historical_snapshot_source_provider_family": str(
                            counter["historical_snapshot_source_provider_family"]
                        ),
                        "historical_snapshot_identity_provider_family": str(
                            counter["historical_snapshot_identity_provider_family"]
                        ),
                        "historical_snapshot_schema_valid": "true",
                        "historical_snapshot_hash_bound": "true",
                    }
                )
    else:
        blockers.update(str(code).strip() for code in (envelope.get("blockers") or []) if str(code).strip())

    candidate_closed = not blockers and projection["historical_snapshot_status"] == STRICT_HISTORICAL_STATUS
    qualification["status"] = "VERIFIED" if candidate_closed else persisted_status
    qualification["candidate_closed"] = _csv_bool(candidate_closed)
    return qualification, sorted(blockers), projection


def snapshot_transition_observations(transition: Mapping[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    proof = dict(transition.get("proof") or {})
    for category in ("headers", "code"):
        category_payload = dict(proof.get(category) or {})
        for item in category_payload.values():
            if not isinstance(item, Mapping):
                continue
            for observation in item.get("observations", []) or []:
                if isinstance(observation, Mapping):
                    observations.append(dict(observation))
    search = dict(transition.get("search") or {})
    for observation in search.get("observations", []) or []:
        if isinstance(observation, Mapping):
            observations.append(dict(observation))
    return observations


def _receipt_path_matches_expected_layout(raw_response_path: Any, *, receipt_sha256: str) -> bool:
    digest = str(receipt_sha256 or "").strip().lower()
    if not _is_sha256_hex(digest):
        return False
    parts = Path(str(raw_response_path or "")).parts[-3:]
    return list(parts) == ["rpc_receipts", digest[:2], f"{digest}.json"]


def _rewrite_observation_paths_to_run_root(value: Any, *, receipt_root: Path) -> Any:
    if isinstance(value, dict):
        updated = {
            key: _rewrite_observation_paths_to_run_root(item, receipt_root=receipt_root)
            for key, item in value.items()
        }
        digest = str(updated.get("response_sha256") or "").strip().lower()
        if digest and "raw_response_path" in updated:
            updated["raw_response_path"] = str(
                _safe_artifact_path(receipt_root.parent, f"rpc_receipts/{digest[:2]}/{digest}.json")
            )
        return updated
    if isinstance(value, list):
        return [_rewrite_observation_paths_to_run_root(item, receipt_root=receipt_root) for item in value]
    return value


def _relocatable_strict_snapshot(snapshot: Mapping[str, Any], *, receipt_root: Path) -> dict[str, Any]:
    """Rebase receipt locations only after validating the persisted self-hash."""
    original = dict(snapshot)
    excluded = (
        "strict_snapshot_validation",
        "artifact_sha256_without_self_hash",
        "artifact_sha256",
        "cached_artifact_reused",
        "status",
        "blocked_reason",
    )
    hash_payload = dict(original)
    for key in excluded:
        hash_payload.pop(key, None)
    with_inner = dict(hash_payload)
    with_inner["artifact_sha256_without_self_hash"] = original.get("artifact_sha256_without_self_hash")
    if (
        original.get("artifact_sha256_without_self_hash") != _sha256_json(hash_payload)
        or original.get("artifact_sha256") != _sha256_json(with_inner)
    ):
        return original

    rebased = _rewrite_observation_paths_to_run_root(original, receipt_root=receipt_root)
    rebased_payload = dict(rebased)
    for key in excluded:
        rebased_payload.pop(key, None)
    rebased["artifact_sha256_without_self_hash"] = _sha256_json(rebased_payload)
    rebased_with_inner = dict(rebased_payload)
    rebased_with_inner["artifact_sha256_without_self_hash"] = rebased["artifact_sha256_without_self_hash"]
    rebased["artifact_sha256"] = _sha256_json(rebased_with_inner)
    return rebased


def _validate_receipt_paths_for_run_root(
    observations: list[dict[str, Any]],
    *,
    receipt_root: Path,
) -> bool:
    for observation in observations:
        digest = str(observation.get("response_sha256") or "").strip().lower()
        if not _receipt_path_matches_expected_layout(observation.get("raw_response_path"), receipt_sha256=digest):
            return False
        path = receipt_root / digest[:2] / f"{digest}.json"
        if path.is_symlink() or not path.is_file() or _sha256_file(path) != digest:
            return False
    return True


def _zero_projection(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    zeroed: list[dict[str, str]] = []
    for row in rows:
        updated = dict(row)
        for field in (
            "historical_snapshot_status",
            "historical_snapshot_source_receipt_sha256",
            "historical_snapshot_identity_receipt_sha256",
            "historical_snapshot_source_provider_family",
            "historical_snapshot_identity_provider_family",
            "case_artifact_path",
            "case_artifact_sha256",
        ):
            updated[field] = ""
        updated["historical_snapshot_schema_valid"] = "false"
        updated["historical_snapshot_hash_bound"] = "false"
        zeroed.append(updated)
    return zeroed


def verify_historical_snapshot_run(run_root: str | Path, *, output_path: str | Path | None = None) -> dict[str, Any]:
    root = _safe_run_root(run_root)
    output_root = root if output_path is None else _safe_output_root(output_path)
    output_root.mkdir(parents=True, exist_ok=True)

    integrity_errors: list[str] = []
    scientific_blockers: list[dict[str, str]] = []
    strict_schema = _load_schema("strict_historical_snapshot.schema.json")

    manifest_path = _safe_optional_path(
        root,
        relative_path="run_manifest.json",
        invalid_code="run_manifest_path_invalid",
        integrity_errors=integrity_errors,
    )
    manifest, run_manifest_error = _load_json_or_error(
        manifest_path,
        missing_code="run_manifest_missing",
        malformed_code="run_manifest_invalid",
    )
    if run_manifest_error is not None:
        integrity_errors.append(run_manifest_error)
        manifest = {}
    binding = dict(manifest.get("binding") or {})
    frozen_section = dict(manifest.get("frozen_inputs") or {})
    frozen_entries = list(frozen_section.get("entries") or [])
    manifest_summary = dict(manifest.get("summary") or {})
    if manifest and manifest.get("schema_version") != "historical_snapshot_run.v1":
        integrity_errors.append("run_manifest_schema_invalid")
    if manifest and manifest.get("binding_sha256") != _sha256_json(binding):
        integrity_errors.append("run_manifest_binding_hash_mismatch")
    if frozen_section.get("manifest_path") != "frozen_inputs/manifest.json":
        integrity_errors.append("frozen_manifest_path_mismatch")
    frozen_manifest_path = _safe_optional_path(
        root,
        relative_path="frozen_inputs/manifest.json",
        invalid_code="frozen_manifest_path_invalid",
        integrity_errors=integrity_errors,
    )
    frozen_manifest, frozen_manifest_error = _load_json_or_error(
        frozen_manifest_path,
        missing_code="frozen_manifest_missing",
        malformed_code="frozen_manifest_invalid",
    )
    if frozen_manifest_error is not None:
        integrity_errors.append(frozen_manifest_error)
        frozen_manifest = {}
    if frozen_manifest.get("entries") != frozen_entries:
        integrity_errors.append("frozen_manifest_entries_mismatch")
    if _frozen_inputs_hash(frozen_entries) != frozen_manifest.get("entries_sha256"):
        integrity_errors.append("frozen_manifest_hash_mismatch")
    aggregate_paths = dict(manifest.get("aggregate_paths") or {})
    aggregate_hashes = dict(manifest.get("aggregate_hashes") or {})
    if manifest and aggregate_paths != _EXPECTED_AGGREGATE_PATHS:
        integrity_errors.append("run_manifest_aggregate_paths_mismatch")
    if manifest and set(aggregate_hashes) != _EXPECTED_AGGREGATE_KEYS:
        integrity_errors.append("run_manifest_aggregate_hashes_mismatch")
    for name, relpath in aggregate_paths.items():
        try:
            path = _safe_artifact_path(root, str(relpath))
        except ValueError:
            integrity_errors.append(f"aggregate_path_invalid:{name}")
            continue
        if not path.exists():
            integrity_errors.append(f"aggregate_missing:{name}")
            continue
        if aggregate_hashes.get(name) != _sha256_file(path):
            integrity_errors.append(f"aggregate_hash_mismatch:{name}")
    authoritative = {
        "binding_sha256": manifest.get("binding_sha256"),
        "frozen_inputs_sha256": _frozen_inputs_hash(frozen_entries),
        "aggregate_paths": aggregate_paths,
        "aggregate_hashes": aggregate_hashes,
        "summary": manifest_summary,
    }
    if manifest and manifest.get("authoritative_sha256") != _sha256_json(authoritative):
        integrity_errors.append("run_manifest_authoritative_hash_mismatch")

    queue_entry = _required_frozen_entry(
        frozen_entries,
        name="queue",
        integrity_errors=integrity_errors,
    )
    temporal_entry = _required_frozen_entry(
        frozen_entries,
        name="temporal",
        integrity_errors=integrity_errors,
    )
    policy_entry = _required_frozen_entry(
        frozen_entries,
        name="policy",
        integrity_errors=integrity_errors,
    )
    queue_path = _resolved_required_frozen_path(
        root,
        entry=queue_entry,
        name="queue",
        integrity_errors=integrity_errors,
    )
    temporal_path = _resolved_required_frozen_path(
        root,
        entry=temporal_entry,
        name="temporal",
        integrity_errors=integrity_errors,
    )
    policy_path = _resolved_required_frozen_path(
        root,
        entry=policy_entry,
        name="policy",
        integrity_errors=integrity_errors,
    )
    if queue_path is not None and temporal_path is not None and policy_path is not None:
        try:
            _validate_frozen_input_entries(root, frozen_entries)
        except ValueError:
            integrity_errors.append("frozen_input_hash_mismatch")

    population = None
    if queue_path is not None and temporal_path is not None:
        try:
            population = load_canonical_snapshot_population(queue_path, temporal_path)
        except Exception:
            integrity_errors.append("canonical_population_unavailable")
    else:
        integrity_errors.append("canonical_population_unavailable")

    if population is not None:
        if len(population) != FULL_CASE_TARGET:
            integrity_errors.append("canonical_population_count_mismatch")
        if len(set(population["case_id"].astype(str))) != FULL_CASE_TARGET:
            integrity_errors.append("canonical_population_duplicate_case_id")
        try:
            selected_cases = [
                _stable_case_mapping(case)
                for case in _selected_cases_from_binding(population, binding=binding)
            ]
        except ValueError:
            integrity_errors.append("selected_binding_invalid")
            selected_cases = []
        projection_rows: list[dict[str, str]] = [
            _blank_projection_row(_stable_case_mapping(case))
            for case in population.to_dict(orient="records")
        ]
    else:
        selected_cases = []
        projection_rows = []
    selected_by_id = {str(case["case_id"]): dict(case) for case in selected_cases}
    frozen_policy, frozen_policy_error = _load_yaml_or_error(
        policy_path,
        missing_code="frozen_policy_missing",
        malformed_code="frozen_policy_invalid",
    )
    if frozen_policy_error is not None:
        integrity_errors.append(frozen_policy_error)

    actual_qualification_rows, qualification_error = _load_csv_or_error(
        _aggregate_artifact_path(
            root,
            aggregate_paths=aggregate_paths,
            name="case_qualification",
            integrity_errors=integrity_errors,
        ),
        expected_fields=QUALIFICATION_FIELDS,
        missing_code="case_qualification_missing",
        malformed_code="case_qualification_invalid",
    )
    if qualification_error is not None:
        integrity_errors.append(qualification_error)
    actual_blocker_rows, blocker_error = _load_csv_or_error(
        _aggregate_artifact_path(
            root,
            aggregate_paths=aggregate_paths,
            name="blocker_ledger",
            integrity_errors=integrity_errors,
        ),
        expected_fields=["chain", "case_id", "code"],
        missing_code="blocker_ledger_missing",
        malformed_code="blocker_ledger_invalid",
    )
    if blocker_error is not None:
        integrity_errors.append(blocker_error)
    actual_receipt_manifest, receipt_manifest_error = _load_json_or_error(
        _aggregate_artifact_path(
            root,
            aggregate_paths=aggregate_paths,
            name="rpc_receipt_manifest",
            integrity_errors=integrity_errors,
        ),
        missing_code="receipt_manifest_missing",
        malformed_code="receipt_manifest_invalid",
    )
    if receipt_manifest_error is not None:
        integrity_errors.append(receipt_manifest_error)
    actual_provider_report, provider_report_load_error = _load_json_or_error(
        _aggregate_artifact_path(
            root,
            aggregate_paths=aggregate_paths,
            name="provider_identity_verification",
            integrity_errors=integrity_errors,
        ),
        missing_code="provider_report_missing",
        malformed_code="provider_report_invalid",
    )
    if provider_report_load_error is not None:
        integrity_errors.append(provider_report_load_error)
    actual_closure_report, closure_report_error = _load_json_or_error(
        _aggregate_artifact_path(
            root,
            aggregate_paths=aggregate_paths,
            name="historical_snapshot_closure_report",
            integrity_errors=integrity_errors,
        ),
        missing_code="closure_report_missing",
        malformed_code="closure_report_invalid",
    )
    if closure_report_error is not None:
        integrity_errors.append(closure_report_error)

    try:
        receipt_root = _safe_artifact_path(root, "rpc_receipts")
        receipt_manifest, receipt_case_blockers = _scan_receipt_manifest(
            root,
            receipt_root=receipt_root,
            selected_cases=selected_cases,
        )
    except ValueError:
        integrity_errors.append("receipt_root_invalid")
        receipt_manifest = {}
        receipt_case_blockers = {}
    if receipt_manifest != actual_receipt_manifest:
        integrity_errors.append("receipt_manifest_mismatch")
    if provider_report_load_error is None:
        provider_index_by_chain, provider_report_errors = _validate_provider_report(
            actual_provider_report,
            selected_cases=selected_cases,
        )
        integrity_errors.extend(provider_report_errors)
    else:
        provider_index_by_chain = {}

    expected_qualification_rows: list[dict[str, str]] = []
    expected_blocker_rows: list[dict[str, str]] = []
    for raw_case in ([] if population is None else population.to_dict(orient="records")):
        case = _stable_case_mapping(raw_case)
        case_id = str(case["case_id"])
        if case_id not in selected_by_id:
            continue
        qualification_row, blockers, projection_row = _selected_case_result(
            run_root=root,
            case=selected_by_id[case_id],
            frozen_policy=frozen_policy,
            provider_index_by_chain=provider_index_by_chain,
            strict_schema=strict_schema,
        )
        for code in receipt_case_blockers.get(case_id, []):
            if code not in blockers:
                blockers.append(code)
        qualification_row["candidate_closed"] = _csv_bool(not blockers and projection_row["historical_snapshot_status"] == STRICT_HISTORICAL_STATUS)
        if blockers:
            projection_row = _blank_projection_row(case)
            projection_row["envelope_path"] = qualification_row["envelope_path"]
            projection_row["envelope_sha256"] = qualification_row["envelope_sha256"]
        expected_qualification_rows.append(qualification_row)
        for code in sorted(set(blockers)):
            expected_blocker_rows.append(
                {"chain": qualification_row["chain"], "case_id": case_id, "code": code}
            )
            scientific_blockers.append({"chain": qualification_row["chain"], "case_id": case_id, "code": code})
            if code in {"case_envelope_binding_mismatch", "case_input_hash_mismatch", "receipt_binding_invalid"} and code not in integrity_errors:
                integrity_errors.append(code)
        for index, existing in enumerate(projection_rows):
            if existing["case_id"] == case_id:
                projection_rows[index] = projection_row
                break

    expected_qualification_rows.sort(key=lambda row: row["case_id"])
    expected_blocker_rows.sort(key=lambda row: (row["chain"], row["case_id"], row["code"]))

    if population is not None:
        if len(actual_qualification_rows) != len(expected_qualification_rows):
            integrity_errors.append("case_qualification_count_mismatch")
        else:
            for actual, expected in zip(actual_qualification_rows, expected_qualification_rows, strict=True):
                for field in ("case_id", "case_name", "chain", "input_row_sha256", "envelope_path", "envelope_sha256", "status", "candidate_closed", "counter_authority"):
                    if actual[field] != expected[field]:
                        integrity_errors.append(f"case_qualification_{field}_mismatch")
                        break
        if actual_blocker_rows != expected_blocker_rows:
            integrity_errors.append("blocker_ledger_mismatch")
        integrity_errors.extend(
            _validate_operational_metadata(
                actual_qualification_rows,
                manifest_summary=manifest_summary,
                closure_report=actual_closure_report,
            )
        )

        if binding.get("population"):
            expected_closure_report = _historical_snapshot_closure_report(
                binding=binding,
                qualification_rows=actual_qualification_rows,
                blocker_rows=expected_blocker_rows,
                receipt_manifest=actual_receipt_manifest,
                provider_report=actual_provider_report,
            )
            if expected_closure_report != actual_closure_report:
                integrity_errors.append("closure_report_mismatch")
        else:
            integrity_errors.append("closure_report_unverifiable")

    if integrity_errors:
        projection_rows = _zero_projection(projection_rows)
        scientific_blockers = []

    observed = sum(1 for row in projection_rows if row["historical_snapshot_status"] == STRICT_HISTORICAL_STATUS)
    passed = not integrity_errors and observed == FULL_CASE_TARGET

    _atomic_write_csv(
        output_root / PROJECTION_FILENAME,
        projection_rows,
        fieldnames=PROJECTION_FIELDS,
    )
    projection_sha256 = _sha256_file(output_root / PROJECTION_FILENAME)
    report: dict[str, Any] = {
        "schema_version": "historical_snapshot_verification_report.v1",
        "required": FULL_CASE_TARGET,
        "observed": observed,
        "passed": passed,
        "selected_case_count": len(selected_cases),
        "counter_authority": not bool(integrity_errors),
        "authoritative_input_hashes": {
            "binding_sha256": str(manifest.get("binding_sha256") or ""),
            "frozen_inputs_sha256": _frozen_inputs_hash(frozen_entries),
            "aggregate_hashes": dict(aggregate_hashes),
        },
        "projection_path": PROJECTION_FILENAME,
        "projection_sha256": projection_sha256,
        "integrity_errors": sorted(dict.fromkeys(integrity_errors)),
        "scientific_blockers": sorted(
            scientific_blockers,
            key=lambda item: (item["chain"], item["case_id"], item["code"]),
        ),
        "operational_metadata": {
            "independently_derived": False,
            "verified_via_manifest_binding_only": list(NON_SCIENTIFIC_METADATA_FIELDS),
        },
        "chain_counts": {
            "verified_by_chain": {
                chain: sum(
                    1
                    for row in projection_rows
                    if row["chain"] == chain and row["historical_snapshot_status"] == STRICT_HISTORICAL_STATUS
                )
                for chain in sorted({row["chain"] for row in projection_rows})
            }
        },
    }
    report["report_sha256"] = _sha256_json({k: v for k, v in report.items() if k != "report_sha256"})
    _atomic_write_text(
        output_root / REPORT_FILENAME,
        _canonical_json_bytes(report).decode("utf-8"),
    )
    return report
