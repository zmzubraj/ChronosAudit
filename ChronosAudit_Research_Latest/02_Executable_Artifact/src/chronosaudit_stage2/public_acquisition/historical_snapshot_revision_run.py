from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from chronosaudit_stage2.public_acquisition.historical_snapshot_run import (
    _atomic_write_text,
    _canonical_json_bytes,
    _collect_receipt_references,
    _seal_snapshot_case_envelope,
    _sha256_json,
    execute_historical_snapshot_cases,
    prepare_historical_snapshot_run,
)
from chronosaudit_stage2.public_acquisition.strict_snapshot import (
    _load_schema,
    _seal_strict_snapshot_artifact,
)


QUEUE_FIELDS = ("case_name", "chain", "target_contract_address", "fork_block_number", "required_queries")
REQUIRED_QUOTAS = {"base": 3, "bsc": 38, "ethereum": 16}
REQUIRED_QUERY_TEXT = "eth_getCode@fork; EIP-1967 slots@fork; beacon/diamond resolution; deployment tx"
CANDIDATE_REPORT_FILES = {
    "candidate_archive_verification_report.json",
    "candidate_archive_verified_projection.csv",
    "verification_inputs.json",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_revision_case_id(case_name: str, chain: str, address: str, incident_block: int) -> str:
    material = f"{str(case_name).strip()}|{str(chain).strip().lower()}|{str(address).strip().lower()}|{int(incident_block)}"
    return "ca2-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _safe_root(value: str | Path, *, code: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_dir() or path.is_symlink():
        raise ValueError(code)
    resolved = path.resolve()
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    for part in path.parts[1:] if path.is_absolute() else path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(code)
    return resolved


def _validate_output_path(path: Path, *, parent_code: str, occupied_code: str) -> None:
    if ".." in path.parts:
        raise ValueError(parent_code)
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for index, part in enumerate(parts):
        if part in ("", "."):
            continue
        current = current / part
        if current.is_symlink():
            raise ValueError(parent_code)
        if current.exists() and not current.is_dir():
            raise ValueError(occupied_code if index == len(parts) - 1 else parent_code)


def _safe_file(root: Path, relative: str, *, code: str) -> Path:
    rel = Path(str(relative))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(code)
    current = root
    for part in rel.parts:
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


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    if not fields:
        raise ValueError("revision_csv_invalid")
    return fields, rows


def _write_csv(path: Path, fields: list[str] | tuple[str, ...], rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        writer.writerows(rows)


def _load_json(path: Path, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _validate_self_hash(payload: Mapping[str, Any], field: str, *, code: str) -> None:
    expected = str(payload.get(field) or "")
    actual = hashlib.sha256(
        _canonical_json({key: value for key, value in payload.items() if key != field}).encode("utf-8")
    ).hexdigest()
    if expected != actual:
        raise ValueError(code)


def _validate_checksums(root: Path, names: set[str]) -> None:
    checksum_path = _safe_file(root, "SHA256SUMS.txt", code="finalization_checksums_invalid")
    parsed: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2 or Path(parts[1]).name != parts[1]:
            raise ValueError("finalization_checksums_invalid")
        parsed[parts[1]] = parts[0]
    if set(parsed) != names:
        raise ValueError("finalization_checksums_invalid")
    for name, digest in parsed.items():
        path = _safe_file(root, name, code="finalization_artifact_invalid")
        if _sha256_file(path) != digest:
            raise ValueError(f"finalization_checksum_mismatch:{name}")


def _parse_checksums(path: Path, *, code: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2 or Path(parts[1]).name != parts[1] or len(parts[0]) != 64:
            raise ValueError(code)
        parsed[parts[1]] = parts[0]
    return parsed


def _validated_source_packages(
    *,
    parent: Path,
    parent_report: Path,
    candidate: Path,
    candidate_report: Path,
    finalization_manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, str]]]:
    inputs = dict(finalization_manifest.get("input_artifacts") or {})
    authority = dict(finalization_manifest.get("authoritative_bindings") or {})

    parent_manifest_path = _safe_file(parent, "run_manifest.json", code="parent_manifest_invalid")
    parent_report_path = _safe_file(
        parent_report,
        "historical_snapshot_verification_report.json",
        code="parent_report_invalid",
    )
    parent_payload = _load_json(parent_report_path, code="parent_report_invalid")
    _validate_self_hash(parent_payload, "report_sha256", code="parent_report_hash_invalid")
    parent_projection_path = _safe_file(
        parent_report,
        str(parent_payload.get("projection_path") or "historical_snapshot_verified_projection.csv"),
        code="parent_projection_invalid",
    )
    if str(parent_payload.get("projection_sha256") or "") != _sha256_file(parent_projection_path):
        raise ValueError("parent_projection_hash_invalid")
    parent_manifest = _load_json(parent_manifest_path, code="parent_manifest_invalid")
    if str(parent_payload.get("authoritative_input_hashes", {}).get("binding_sha256") or "") != str(
        parent_manifest.get("binding_sha256") or ""
    ):
        raise ValueError("parent_authoritative_hash_binding_invalid")
    if parent_payload.get("authoritative_input_hashes", {}).get("aggregate_hashes") != parent_manifest.get(
        "aggregate_hashes"
    ):
        raise ValueError("parent_authoritative_hash_binding_invalid")
    if str(authority.get("parent_binding_sha256") or "") != str(parent_manifest.get("binding_sha256") or ""):
        raise ValueError("parent_finalization_binding_mismatch")

    candidate_manifest_path = _safe_file(candidate, "run_manifest.json", code="candidate_run_manifest_invalid")
    candidate_result_path = _safe_file(
        candidate, "qualification_result.json", code="candidate_qualification_result_invalid"
    )
    candidate_manifest = _load_json(candidate_manifest_path, code="candidate_run_manifest_invalid")
    checksum_path = _safe_file(candidate_report, "SHA256SUMS.txt", code="candidate_checksums_invalid")
    checksums = _parse_checksums(checksum_path, code="candidate_checksums_invalid")
    if set(checksums) != CANDIDATE_REPORT_FILES:
        raise ValueError("candidate_checksums_invalid")
    candidate_paths = {
        name: _safe_file(candidate_report, name, code="candidate_report_package_invalid")
        for name in CANDIDATE_REPORT_FILES
    }
    for name, path in candidate_paths.items():
        if checksums[name] != _sha256_file(path):
            raise ValueError(f"candidate_checksum_mismatch:{name}")
    candidate_payload = _load_json(
        candidate_paths["candidate_archive_verification_report.json"],
        code="candidate_report_invalid",
    )
    _validate_self_hash(candidate_payload, "report_sha256", code="candidate_report_hash_invalid")
    verification_inputs = _load_json(
        candidate_paths["verification_inputs.json"],
        code="candidate_verification_inputs_invalid",
    )
    expected_verification_inputs = {
        "schema_version": "candidate_archive_verification_inputs.v1",
        "run_manifest_sha256": _sha256_file(candidate_manifest_path),
        "qualification_result_sha256": _sha256_file(candidate_result_path),
        "run_binding_sha256": str(candidate_manifest.get("binding_sha256") or ""),
        "revision_input_hashes": dict(candidate_manifest.get("revision_input_hashes") or {}),
    }
    if verification_inputs != expected_verification_inputs:
        raise ValueError("candidate_verification_inputs_mismatch")
    if dict(candidate_payload.get("authoritative_input_hashes") or {}) != {
        key: expected_verification_inputs[key]
        for key in (
            "run_manifest_sha256",
            "qualification_result_sha256",
            "run_binding_sha256",
            "revision_input_hashes",
        )
    }:
        raise ValueError("candidate_authoritative_inputs_mismatch")
    if str(authority.get("candidate_binding_sha256") or "") != str(candidate_manifest.get("binding_sha256") or ""):
        raise ValueError("candidate_finalization_binding_mismatch")

    exact_hashes = {
        "parent_run_manifest": (_sha256_file(parent_manifest_path), inputs.get("parent_run_manifest")),
        "parent_verification_report": (_sha256_file(parent_report_path), inputs.get("parent_report")),
        "parent_verified_projection": (_sha256_file(parent_projection_path), inputs.get("parent_projection")),
        "candidate_run_manifest": (_sha256_file(candidate_manifest_path), inputs.get("candidate_run_manifest")),
        "candidate_verification_report": (
            _sha256_file(candidate_paths["candidate_archive_verification_report.json"]),
            inputs.get("candidate_report"),
        ),
        "candidate_verified_projection": (
            _sha256_file(candidate_paths["candidate_archive_verified_projection.csv"]),
            inputs.get("candidate_projection"),
        ),
    }
    parent_run_id = str(parent_manifest.get("binding", {}).get("run_id") or "")
    candidate_run_id = str(candidate_manifest.get("run_id") or "")
    if not parent_run_id or not candidate_run_id:
        raise ValueError("source_run_identity_missing")
    portable_ids = {
        "parent_run_manifest": f"chronosaudit://historical-snapshot-run/{parent_run_id}/run_manifest.json",
        "parent_verification_report": f"chronosaudit://historical-snapshot-verification/{parent_run_id}/historical_snapshot_verification_report.json",
        "parent_verified_projection": f"chronosaudit://historical-snapshot-verification/{parent_run_id}/historical_snapshot_verified_projection.csv",
        "candidate_run_manifest": f"chronosaudit://candidate-archive-run/{candidate_run_id}/run_manifest.json",
        "candidate_verification_report": f"chronosaudit://candidate-archive-verification/{candidate_run_id}/candidate_archive_verification_report.json",
        "candidate_verified_projection": f"chronosaudit://candidate-archive-verification/{candidate_run_id}/candidate_archive_verified_projection.csv",
    }
    source_bindings: dict[str, dict[str, str]] = {}
    for logical_id, (digest, finalization_binding) in exact_hashes.items():
        if not isinstance(finalization_binding, Mapping) or str(finalization_binding.get("sha256") or "") != digest:
            raise ValueError(f"finalization_source_hash_mismatch:{logical_id}")
        source_bindings[logical_id] = {"logical_id": portable_ids[logical_id], "sha256": digest}
    source_bindings["candidate_verification_inputs"] = {
        "logical_id": f"chronosaudit://candidate-archive-verification/{candidate_run_id}/verification_inputs.json",
        "sha256": _sha256_file(candidate_paths["verification_inputs.json"]),
    }
    source_bindings["candidate_report_checksums"] = {
        "logical_id": f"chronosaudit://candidate-archive-verification/{candidate_run_id}/SHA256SUMS.txt",
        "sha256": _sha256_file(checksum_path),
    }
    return parent_payload, candidate_payload, source_bindings


def derive_revised_inputs(
    finalization_root: str | Path,
    *,
    output_root: str | Path,
    source_bindings: Mapping[str, Mapping[str, str]] | None = None,
) -> tuple[Path, Path, Path]:
    final_root = _safe_root(finalization_root, code="finalization_root_invalid")
    output = Path(output_root).expanduser()
    _validate_output_path(
        output,
        parent_code="revision_input_output_parent_invalid",
        occupied_code="revision_input_output_occupied",
    )
    if output.exists() and (output.is_symlink() or (output.is_dir() and any(output.iterdir())) or not output.is_dir()):
        raise ValueError("revision_input_output_occupied")
    output.mkdir(parents=True, exist_ok=True)
    _validate_checksums(
        final_root,
        {"replacement_mapping.csv", "revised_population.csv", "finalization_manifest.json"},
    )
    manifest = _load_json(
        _safe_file(final_root, "finalization_manifest.json", code="finalization_manifest_invalid"),
        code="finalization_manifest_invalid",
    )
    _validate_self_hash(manifest, "manifest_sha256", code="finalization_manifest_hash_invalid")
    if manifest.get("schema_version") != "historical_snapshot_replacement_finalization.v1":
        raise ValueError("finalization_manifest_schema_invalid")
    if dict(manifest.get("counts") or {}) != {
        "replacement_count": 57,
        "retained_count": 360,
        "revised_population_count": 417,
    }:
        raise ValueError("finalization_counts_invalid")
    fields, rows = _read_csv(
        _safe_file(final_root, "revised_population.csv", code="revised_population_invalid")
    )
    if len(rows) != 417:
        raise ValueError("revised_population_count_invalid")
    roles = {"retained": 0, "replacement": 0}
    temporal_rows: list[dict[str, str]] = []
    queue_rows: list[dict[str, str]] = []
    provenance_rows: list[dict[str, str]] = []
    temporal_fields = list(fields)
    for extra in ("candidate_id", "source_case_id", "source_artifact_path", "source_artifact_sha256"):
        if extra not in temporal_fields:
            temporal_fields.append(extra)
    for raw in rows:
        row = dict(raw)
        role = str(row.get("population_role") or "")
        if role not in roles:
            raise ValueError("revised_population_role_invalid")
        roles[role] += 1
        original_id = str(row.get("case_id") or "")
        canonical_id = canonical_revision_case_id(
            row["case_name"], row["chain"], row["target_contract_address"], int(row["fork_block_number"])
        )
        if role == "retained" and canonical_id != original_id:
            raise ValueError("retained_case_id_drift")
        row["candidate_id"] = original_id if role == "replacement" else ""
        row["source_case_id"] = original_id
        if role == "retained":
            row["source_artifact_path"] = str(row.get("parent_case_artifact_path") or "")
            row["source_artifact_sha256"] = str(row.get("parent_case_artifact_sha256") or "")
        else:
            row["source_artifact_path"] = str(row.get("historical_envelope_path") or "")
            row["source_artifact_sha256"] = str(row.get("historical_envelope_sha256") or "")
        row["case_id"] = canonical_id
        temporal_rows.append({field: str(row.get(field) or "") for field in temporal_fields})
        queue_rows.append(
            {
                "case_name": row["case_name"],
                "chain": row["chain"],
                "target_contract_address": row["target_contract_address"],
                "fork_block_number": row["fork_block_number"],
                "required_queries": REQUIRED_QUERY_TEXT,
            }
        )
        provenance_rows.append(
            {
                "case_id": canonical_id,
                "population_role": role,
                "source_case_id": original_id,
                "source_artifact_path": row["source_artifact_path"],
                "source_artifact_sha256": row["source_artifact_sha256"],
                "replaced_parent_slot_case_id": str(row.get("replaced_parent_slot_case_id") or ""),
            }
        )
    if roles != {"retained": 360, "replacement": 57}:
        raise ValueError("revised_population_role_counts_invalid")
    case_ids = [row["case_id"] for row in temporal_rows]
    if len(set(case_ids)) != 417:
        raise ValueError("revised_population_case_id_duplicate")
    queue_path = output / "queue.csv"
    temporal_path = output / "temporal.csv"
    provenance_path = output / "source_provenance.json"
    _write_csv(queue_path, QUEUE_FIELDS, queue_rows)
    _write_csv(temporal_path, temporal_fields, temporal_rows)
    provenance = {
        "schema_version": "historical_snapshot_revision_sources.v1",
        "finalization_manifest_sha256": _sha256_file(final_root / "finalization_manifest.json"),
        "replacement_mapping_sha256": _sha256_file(final_root / "replacement_mapping.csv"),
        "revised_population_sha256": _sha256_file(final_root / "revised_population.csv"),
        "source_bindings": {
            str(name): {"logical_id": str(value.get("logical_id") or ""), "sha256": str(value.get("sha256") or "")}
            for name, value in sorted((source_bindings or {}).items())
        },
        "case_count": len(provenance_rows),
        "cases": sorted(provenance_rows, key=lambda item: item["case_id"]),
    }
    provenance["provenance_sha256"] = hashlib.sha256(_canonical_json(provenance).encode("utf-8")).hexdigest()
    provenance_path.write_text(json.dumps(provenance, indent=2, sort_keys=True), encoding="utf-8")
    return queue_path, temporal_path, provenance_path


def _rebase_receipt_paths(value: Any, *, receipt_root: Path) -> Any:
    if isinstance(value, dict):
        updated = {key: _rebase_receipt_paths(item, receipt_root=receipt_root) for key, item in value.items()}
        digest = str(updated.get("response_sha256") or "").strip().lower()
        if digest and "raw_response_path" in updated:
            updated["raw_response_path"] = str(receipt_root / digest[:2] / f"{digest}.json")
        return updated
    if isinstance(value, list):
        return [_rebase_receipt_paths(item, receipt_root=receipt_root) for item in value]
    return value


def _reseal_transition(value: Mapping[str, Any], *, receipt_root: Path) -> dict[str, Any]:
    transition = dict(_rebase_receipt_paths(dict(value), receipt_root=receipt_root))
    transition.pop("proof_sha256_without_self_hash", None)
    transition.pop("proof_sha256", None)
    transition["proof_sha256_without_self_hash"] = _sha256_json(transition)
    outer = dict(transition)
    transition["proof_sha256"] = _sha256_json(outer)
    return transition


def _provider_objects(provider_report: Mapping[str, Any]) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = {}
    for chain_row in list(provider_report.get("chains") or []):
        chain = str(chain_row.get("chain") or "")
        values: list[Any] = []
        for row in list(chain_row.get("providers") or []):
            values.append(
                SimpleNamespace(
                    provider_id=str(row.get("provider_id") or ""),
                    provider_family=str(row.get("verified_operator_family") or ""),
                    public_endpoint_id=str(row.get("public_endpoint_identity_id") or ""),
                    provider_identity_evidence={
                        "endpoint_template_sha256": str(row.get("endpoint_template_sha256") or "")
                    },
                )
            )
        result[chain] = values
    return result


def assemble_historical_snapshot_revision(
    *,
    parent_run_root: str | Path,
    parent_report_root: str | Path,
    candidate_run_root: str | Path,
    candidate_report_root: str | Path,
    finalization_root: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    parent = _safe_root(parent_run_root, code="parent_run_invalid")
    parent_report = _safe_root(parent_report_root, code="parent_report_invalid")
    candidate = _safe_root(candidate_run_root, code="candidate_run_invalid")
    candidate_report = _safe_root(candidate_report_root, code="candidate_report_invalid")
    final_root = _safe_root(finalization_root, code="finalization_root_invalid")
    output = Path(output_dir).expanduser()
    _validate_output_path(
        output,
        parent_code="revision_output_parent_invalid",
        occupied_code="revision_output_occupied",
    )
    if output.exists():
        raise ValueError("revision_output_occupied")
    finalization_manifest = _load_json(
        _safe_file(final_root, "finalization_manifest.json", code="finalization_manifest_invalid"),
        code="finalization_manifest_invalid",
    )
    _validate_self_hash(finalization_manifest, "manifest_sha256", code="finalization_manifest_hash_invalid")
    parent_verification, candidate_verification, source_bindings = _validated_source_packages(
        parent=parent,
        parent_report=parent_report,
        candidate=candidate,
        candidate_report=candidate_report,
        finalization_manifest=finalization_manifest,
    )
    if not parent_verification.get("counter_authority") or int(parent_verification.get("observed") or -1) != 360:
        raise ValueError("parent_counter_authority_invalid")
    if list(parent_verification.get("integrity_errors") or []):
        raise ValueError("parent_integrity_errors_present")
    if not candidate_verification.get("counter_authority") or int(candidate_verification.get("eligible_count") or -1) < 57:
        raise ValueError("candidate_counter_authority_invalid")
    if list(candidate_verification.get("integrity_errors") or []):
        raise ValueError("candidate_integrity_errors_present")

    _, revised_rows = _read_csv(_safe_file(final_root, "revised_population.csv", code="revised_population_invalid"))
    temp_parent = output.parent
    temp_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=str(temp_parent)))
    try:
        input_root = staging / "derived_inputs"
        queue_path, temporal_path, provenance_path = derive_revised_inputs(
            final_root,
            output_root=input_root,
            source_bindings=source_bindings,
        )
        prepared = prepare_historical_snapshot_run(
            queue_path,
            temporal_path,
            policy_path=parent / "frozen_inputs/policy.yaml",
            provider_template_path=parent / "frozen_inputs/provider_template.yaml",
            incident_input_path=provenance_path,
            output_root=staging,
            revision="assembled",
            run_id=output.name,
        )
        run_root = Path(prepared["run_root"])
        source_by_final_id: dict[str, tuple[Path, Path, str]] = {}
        for row in revised_rows:
            final_id = canonical_revision_case_id(
                row["case_name"], row["chain"], row["target_contract_address"], int(row["fork_block_number"])
            )
            role = str(row["population_role"])
            if role == "retained":
                source_path = _safe_file(parent, row["parent_case_artifact_path"], code="parent_case_artifact_invalid")
                source_receipts = parent / "rpc_receipts"
                expected_sha = row["parent_case_artifact_sha256"]
            else:
                source_path = _safe_file(candidate, row["historical_envelope_path"], code="candidate_case_artifact_invalid")
                source_receipts = source_path.parent / "receipts"
                expected_sha = row["historical_envelope_sha256"]
            if _sha256_file(source_path) != expected_sha:
                raise ValueError("source_case_artifact_hash_mismatch")
            source_by_final_id[final_id] = (source_path, source_receipts, role)
        if len(source_by_final_id) != 417:
            raise ValueError("source_case_membership_invalid")

        parent_provider_report = _load_json(
            _safe_file(parent, "provider_identity_verification.json", code="parent_provider_report_invalid"),
            code="parent_provider_report_invalid",
        )
        providers_by_chain = _provider_objects(parent_provider_report)

        def resolver(chain: str, _receipt_root: Path) -> list[Any]:
            return list(providers_by_chain.get(chain, []))

        def importer(
            case: dict[str, Any],
            *,
            providers: list[Any],
            policy: dict[str, Any],
            receipt_root: Path,
            case_root: Path,
            resume: bool,
            **_kwargs: Any,
        ) -> dict[str, Any]:
            del providers, resume
            source_path, source_receipts, _role = source_by_final_id[str(case["case_id"])]
            source = _load_json(source_path, code="source_case_artifact_invalid")
            for reference in _collect_receipt_references(source):
                digest = str(reference.get("response_sha256") or "").strip().lower()
                if len(digest) != 64:
                    raise ValueError("source_receipt_digest_invalid")
                receipt = _safe_file(
                    source_receipts,
                    f"{digest[:2]}/{digest}.json",
                    code="source_receipt_missing",
                )
                payload = receipt.read_bytes()
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise ValueError("source_receipt_hash_mismatch")
                destination = receipt_root / digest[:2] / f"{digest}.json"
                if destination.exists() and destination.read_bytes() != payload:
                    raise ValueError("receipt_digest_collision")
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    destination.write_bytes(payload)
            transition = _reseal_transition(dict(source.get("transition_proof") or {}), receipt_root=receipt_root)
            strict = dict(_rebase_receipt_paths(dict(source.get("strict_snapshot") or {}), receipt_root=receipt_root))
            strict.update(
                {
                    "case_id": case["case_id"],
                    "case_name": case["case_name"],
                    "chain": case["chain"],
                    "address": str(case["address"]).lower(),
                    "case_input": dict(case),
                    "case_input_sha256": _sha256_json(case),
                }
            )
            for key in (
                "strict_snapshot_validation",
                "artifact_sha256_without_self_hash",
                "artifact_sha256",
                "cached_artifact_reused",
            ):
                strict.pop(key, None)
            strict = _seal_strict_snapshot_artifact(
                strict,
                schema=_load_schema("strict_historical_snapshot.schema.json"),
                receipt_root=receipt_root,
                provider_identity=dict(strict.get("provider_identity") or {}),
                include_runtime_status=True,
            )
            if strict.get("strict_snapshot_closed") is not True:
                raise ValueError("imported_strict_snapshot_not_closed")
            envelope = {
                "case_id": str(case["case_id"]),
                "case_input": dict(case),
                "case_input_sha256": _sha256_json(case),
                # The outer case envelope is governed by the revised run's
                # frozen policy. Candidate strict artifacts may carry a
                # narrower acquisition-policy material internally, but the
                # historical run verifier requires this outer binding to the
                # exact frozen policy bytes for every case.
                "policy_input": dict(policy),
                "policy_sha256": _sha256_json(policy),
                "transition_proof": transition,
                "transition_proof_sha256": transition["proof_sha256"],
                "strict_snapshot": strict,
                "strict_snapshot_sha256": _sha256_json(strict),
                "strict_snapshot_closed": True,
                "status": "VERIFIED",
                "blockers": [],
                "case_path": f"{case['case_id']}.json",
                "receipt_root": "rpc_receipts",
            }
            sealed = _seal_snapshot_case_envelope(envelope)
            _atomic_write_text(case_root / f"{case['case_id']}.json", json.dumps(sealed, indent=2, sort_keys=True))
            return sealed

        execution = execute_historical_snapshot_cases(
            prepared,
            provider_resolver=resolver,
            case_executor=importer,
            max_workers=1,
            resume=False,
        )
        if execution["summary"]["candidate_closed_count"] != 417:
            raise ValueError("assembled_case_count_not_closed")
        output.parent.mkdir(parents=True, exist_ok=True)
        os.replace(run_root, output)
        return {
            "schema_version": "historical_snapshot_revision_assembly.v1",
            "run_root": str(output.resolve()),
            "retained_count": 360,
            "replacement_count": 57,
            "assembled_count": 417,
            "run_manifest_sha256": _sha256_file(output / "run_manifest.json"),
        }
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
