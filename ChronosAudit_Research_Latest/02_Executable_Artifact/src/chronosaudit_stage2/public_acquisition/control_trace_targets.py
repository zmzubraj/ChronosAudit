from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path


class ControlTraceTargetError(ValueError):
    """Raised when the frozen unresolved trace scope is inconsistent."""


_FALSE_AUTHORITY_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_TRACE_METHODS = (
    "trace_transaction",
    "debug_traceTransaction",
    "trace_block",
    "debug_traceBlockByNumber",
)
_EFFECTIVE_MANIFEST_FALSE_AUTHORITY_FLAGS = (
    "rpc_authorized",
    "denominator_admission_authorized",
    "selection_authorized",
    "qualification_authorized",
    "counter_authority",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
    "independent_review_established",
    "r5_authorized",
    "release_authorized",
    "publication_authorized",
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlTraceTargetError(f"{label}_not_ordinary")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlTraceTargetError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlTraceTargetError(f"{label}_not_ordinary")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlTraceTargetError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlTraceTargetError(f"{label}_root_invalid")
    return payload


def _read_csv(path: Path, label: str) -> tuple[list[str], list[dict[str, str]]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or [])
            rows = [dict(row) for row in reader]
    except UnicodeDecodeError as exc:
        raise ControlTraceTargetError(f"{label}_csv_invalid") from exc
    if not fieldnames:
        raise ControlTraceTargetError(f"{label}_csv_invalid")
    return fieldnames, rows


def build_effective_trace_target_identities(
    *,
    sources: Sequence[tuple[Path, Path]],
) -> dict[str, object]:
    """Freeze unresolved trace identities from terminal effective overlays.

    Each input binds one self-hashed effective-reconciliation manifest to its
    exact COMPLETE CSV and then revalidates every candidate result file. The
    output deliberately grants no RPC, admission, selection, or counter power.
    """
    if not sources:
        raise ControlTraceTargetError("effective_sources_empty")

    source_bindings: list[dict[str, object]] = []
    targets: list[dict[str, object]] = []
    seen_assignments: set[str] = set()
    seen_chain_addresses: set[str] = set()
    chain_counts: Counter[str] = Counter()
    required_columns = {
        "case_name",
        "chain",
        "control_address",
        "reserve_assignment_sha256",
        "effective_status",
        "source_index",
        "source_run_binding_sha256",
        "source_event_sha256",
        "result_sha256",
        "result_file_sha256",
        "result_path",
    }

    for reconciliation_index, (manifest_input, complete_input) in enumerate(sources):
        manifest_path = _ordinary(
            manifest_input, f"effective_manifest_{reconciliation_index}"
        )
        complete_path = _ordinary(
            complete_input, f"effective_complete_{reconciliation_index}"
        )
        manifest = _load(manifest_path, f"effective_manifest_{reconciliation_index}")
        manifest_material = {
            key: value for key, value in manifest.items() if key != "manifest_sha256"
        }
        if (
            manifest.get("schema_version")
            != "chronosaudit.control_candidate_effective_reconciliation.v1"
            or manifest.get("decision")
            != "EFFECTIVE_ACQUISITION_TERMINAL_RECONCILIATION_VERIFIED"
            or manifest.get("manifest_sha256") != _canonical_sha(manifest_material)
        ):
            raise ControlTraceTargetError("effective_manifest_binding_invalid")
        for flag in _EFFECTIVE_MANIFEST_FALSE_AUTHORITY_FLAGS:
            if manifest.get(flag) is not False:
                raise ControlTraceTargetError(f"effective_manifest_{flag}_invalid")
        if int(manifest.get("effective_unresolved_count", -1)) != 0:
            raise ControlTraceTargetError("effective_manifest_unresolved")
        try:
            declared_complete_path = _ordinary(
                Path(str(manifest.get("complete_output_path", ""))),
                f"effective_manifest_complete_{reconciliation_index}",
            )
        except (TypeError, ValueError) as exc:
            raise ControlTraceTargetError("effective_manifest_complete_path_invalid") from exc
        if declared_complete_path != complete_path:
            raise ControlTraceTargetError("effective_manifest_complete_path_mismatch")
        if manifest.get("complete_output_sha256") != _file_sha(complete_path):
            raise ControlTraceTargetError("effective_manifest_complete_hash_mismatch")

        fieldnames, rows = _read_csv(
            complete_path, f"effective_complete_{reconciliation_index}"
        )
        if not required_columns.issubset(fieldnames):
            raise ControlTraceTargetError("effective_complete_columns_invalid")
        if (
            len(rows) != int(manifest.get("effective_complete_count", -1))
            or manifest.get("complete_records_sha256") != _canonical_sha(rows)
        ):
            raise ControlTraceTargetError("effective_complete_records_mismatch")

        declared_sources = manifest.get("source_bindings")
        if (
            not isinstance(declared_sources, list)
            or len(declared_sources) != int(manifest.get("source_run_count", -1))
            or not all(isinstance(row, Mapping) for row in declared_sources)
        ):
            raise ControlTraceTargetError("effective_manifest_sources_invalid")
        runs_by_index: dict[int, str] = {}
        for source in declared_sources:
            try:
                source_index = int(source.get("source_index", -1))
            except (TypeError, ValueError) as exc:
                raise ControlTraceTargetError("effective_manifest_source_index_invalid") from exc
            run_binding = str(source.get("run_binding_sha256", ""))
            if (
                source_index < 0
                or source_index in runs_by_index
                or len(run_binding) != 64
            ):
                raise ControlTraceTargetError("effective_manifest_source_binding_invalid")
            runs_by_index[source_index] = run_binding

        source_trace_count = 0
        for row_index, row in enumerate(rows):
            assignment = str(row.get("reserve_assignment_sha256", "")).lower()
            chain = str(row.get("chain", "")).strip().lower()
            address = str(row.get("control_address", "")).strip().lower()
            case_id = str(row.get("case_name", "")).strip()
            try:
                source_index = int(row.get("source_index", -1))
            except (TypeError, ValueError) as exc:
                raise ControlTraceTargetError("effective_row_source_index_invalid") from exc
            if (
                row.get("effective_status") != "COMPLETE"
                or len(assignment) != 64
                or not chain
                or len(address) != 42
                or not case_id
                or source_index not in runs_by_index
                or row.get("source_run_binding_sha256") != runs_by_index[source_index]
                or len(str(row.get("source_event_sha256", ""))) != 64
            ):
                raise ControlTraceTargetError(f"effective_row_binding_invalid:{row_index}")
            if assignment in seen_assignments:
                raise ControlTraceTargetError("trace_target_duplicate")
            seen_assignments.add(assignment)

            result_path = _ordinary(
                Path(str(row.get("result_path", ""))),
                f"effective_result_{reconciliation_index}_{row_index}",
            )
            if row.get("result_file_sha256") != _file_sha(result_path):
                raise ControlTraceTargetError("effective_result_file_hash_mismatch")
            result = _load(
                result_path, f"effective_result_{reconciliation_index}_{row_index}"
            )
            result_material = {
                key: value for key, value in result.items() if key != "result_sha256"
            }
            if (
                result.get("schema_version")
                != "chronosaudit.control_candidate_rpc_acquisition_result.v1"
                or result.get("result_sha256") != _canonical_sha(result_material)
                or result.get("result_sha256") != row.get("result_sha256")
                or result.get("run_binding_sha256")
                != row.get("source_run_binding_sha256")
                or result.get("reserve_assignment_sha256") != assignment
                or str(result.get("case_name", "")).lower() != case_id.lower()
                or str(result.get("chain", "")).lower() != chain
                or str(result.get("control_address", "")).lower() != address
            ):
                raise ControlTraceTargetError("effective_result_binding_invalid")
            for flag in (
                "selection_authorized",
                "stage_promotion_authorized",
                "recovery3_mutation_authorized",
            ):
                if result.get(flag) is not False:
                    raise ControlTraceTargetError(f"effective_result_{flag}_invalid")

            chain_address = f"{chain}:{address}"
            if chain_address in seen_chain_addresses:
                raise ControlTraceTargetError("trace_chain_address_duplicate")
            seen_chain_addresses.add(chain_address)
            creation_type = result.get("creation_type")
            if creation_type == "TOP_LEVEL_CREATE_RECEIPT_PROVEN":
                if (
                    result.get("rpc_classification_complete") is not True
                    or result.get("provider_consensus") is not True
                    or result.get("temporal_pre_cutoff") is not True
                ):
                    raise ControlTraceTargetError("effective_receipt_candidate_invalid")
                continue
            if creation_type != "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED":
                raise ControlTraceTargetError("effective_creation_type_invalid")
            if (
                result.get("rpc_classification_complete") is not False
                or result.get("trace_proof") is not False
                or result.get("provider_consensus") is not True
                or result.get("temporal_pre_cutoff") is not True
            ):
                raise ControlTraceTargetError("effective_trace_candidate_invalid")

            target = {
                "target_id": f"trace-{assignment}",
                "case_id": case_id,
                "chain": chain,
                "chain_address": chain_address,
                "transaction_hash": str(result.get("creation_tx_hash", "")).lower(),
                "block_number": int(result.get("deployment_block", -1)),
                "block_hash": str(result.get("deployment_block_hash", "")).lower(),
                "reserve_assignment_sha256": assignment,
                "reserve_record_sha256": result["result_sha256"],
                "reserve_record_file_sha256": _file_sha(result_path),
                "source_reconciliation_index": reconciliation_index,
                "source_reconciliation_manifest_file_sha256": _file_sha(manifest_path),
                "source_complete_file_sha256": _file_sha(complete_path),
            }
            if (
                len(str(target["transaction_hash"])) != 66
                or int(target["block_number"]) < 0
                or len(str(target["block_hash"])) != 66
            ):
                raise ControlTraceTargetError("effective_trace_identity_invalid")
            targets.append(target)
            source_trace_count += 1
            chain_counts[chain] += 1

        source_bindings.append(
            {
                "source_reconciliation_index": reconciliation_index,
                "manifest_path": str(manifest_path),
                "manifest_file_sha256": _file_sha(manifest_path),
                "manifest_sha256": manifest["manifest_sha256"],
                "complete_output_path": str(complete_path),
                "complete_output_sha256": _file_sha(complete_path),
                "complete_records_sha256": manifest["complete_records_sha256"],
                "complete_count": len(rows),
                "trace_required_count": source_trace_count,
            }
        )

    targets.sort(key=lambda row: str(row["target_id"]))
    output: dict[str, object] = {
        "schema_version": "stage2_control_trace_target_identities.v1",
        "source_reconciliation_count": len(source_bindings),
        "source_reconciliations": source_bindings,
        "target_count": len(targets),
        "chain_target_counts": dict(sorted(chain_counts.items())),
        "targets": targets,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["target_identities_sha256"] = _canonical_sha(output)
    return output


def build_trace_target_identities(
    *,
    acquisition_summary_path: Path,
    signature_verification_path: Path,
    acquisition_ledger_path: Path,
    candidate_root: Path,
) -> dict[str, object]:
    """Freeze the exact unresolved trace identities without adding RPC authority."""
    summary_path = _ordinary(acquisition_summary_path, "acquisition_summary")
    summary = _load(summary_path, "acquisition_summary")
    if summary.get("schema_version") != (
        "chronosaudit.control_candidate_rpc_acquisition_summary.v1"
    ):
        raise ControlTraceTargetError("summary_schema_invalid")
    stored_summary_sha = summary.get("summary_sha256")
    material = {
        key: value for key, value in summary.items() if key != "summary_sha256"
    }
    if stored_summary_sha != _canonical_sha(material):
        raise ControlTraceTargetError("summary_self_hash_invalid")
    for flag in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if summary.get(flag) is not False:
            raise ControlTraceTargetError(f"summary_{flag}_invalid")

    verification_path = _ordinary(
        signature_verification_path, "signature_verification"
    )
    verification = _load(verification_path, "signature_verification")
    if verification.get("decision") != (
        "LOCAL_TEST_CHECKPOINT_SIGNATURE_VERIFIED_NON_AUTHORIZING"
    ):
        raise ControlTraceTargetError("signature_verification_decision_invalid")
    if verification.get("summary_sha256") != _file_sha(summary_path):
        raise ControlTraceTargetError("signature_verification_summary_mismatch")
    for flag in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if verification.get(flag) is not False:
            raise ControlTraceTargetError(f"signature_{flag}_invalid")

    ledger_path = _ordinary(acquisition_ledger_path, "acquisition_ledger")
    completed: dict[str, str] = {}
    previous = "0" * 64
    try:
        ledger_lines = ledger_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ControlTraceTargetError("acquisition_ledger_invalid") from exc
    for index, line in enumerate(ledger_lines):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlTraceTargetError("acquisition_ledger_invalid") from exc
        if not isinstance(event, dict):
            raise ControlTraceTargetError("acquisition_ledger_invalid")
        stored_event_sha = event.pop("event_sha256", None)
        if (
            event.get("previous_event_sha256") != previous
            or stored_event_sha != _canonical_sha(event)
        ):
            raise ControlTraceTargetError(f"acquisition_ledger_chain_invalid:{index}")
        previous = str(stored_event_sha)
        if event.get("status") != "COMPLETE":
            continue
        assignment = str(event.get("reserve_assignment_sha256", ""))
        result_sha = str(event.get("result_sha256", ""))
        if not assignment or not result_sha or assignment in completed:
            raise ControlTraceTargetError("acquisition_ledger_complete_invalid")
        completed[assignment] = result_sha
    if len(completed) != int(summary.get("completed_count", -1)):
        raise ControlTraceTargetError("acquisition_ledger_completed_count_mismatch")

    root = candidate_root.expanduser()
    if root.is_symlink():
        raise ControlTraceTargetError("candidate_root_symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ControlTraceTargetError("candidate_root_not_directory")

    targets: list[dict[str, object]] = []
    for assignment in sorted(completed):
        path = root / f"{assignment}.json"
        if path.is_symlink() or not path.is_file():
            raise ControlTraceTargetError("candidate_record_not_ordinary")
        row = _load(path, "candidate_record")
        if row.get("schema_version") != (
            "chronosaudit.control_candidate_rpc_acquisition_result.v1"
        ):
            raise ControlTraceTargetError("candidate_schema_invalid")
        stored_result_sha = row.get("result_sha256")
        result_material = {
            key: value for key, value in row.items() if key != "result_sha256"
        }
        if stored_result_sha != _canonical_sha(result_material):
            raise ControlTraceTargetError("candidate_self_hash_invalid")
        if stored_result_sha != completed[assignment]:
            raise ControlTraceTargetError("candidate_ledger_hash_mismatch")
        if row.get("reserve_assignment_sha256") != assignment:
            raise ControlTraceTargetError("candidate_ledger_identity_mismatch")
        if row.get("run_binding_sha256") != summary.get("run_binding_sha256"):
            raise ControlTraceTargetError("candidate_run_binding_mismatch")
        if row.get("creation_type") != (
            "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED"
        ):
            continue
        if row.get("rpc_classification_complete") is not False:
            raise ControlTraceTargetError("trace_candidate_already_classified")
        if row.get("trace_proof") is not False:
            raise ControlTraceTargetError("trace_candidate_proof_invalid")
        if row.get("provider_consensus") is not True:
            raise ControlTraceTargetError("trace_candidate_consensus_missing")
        if row.get("temporal_pre_cutoff") is not True:
            raise ControlTraceTargetError("trace_candidate_temporal_invalid")
        for flag in (
            "selection_authorized",
            "stage_promotion_authorized",
            "recovery3_mutation_authorized",
        ):
            if row.get(flag) is not False:
                raise ControlTraceTargetError(f"candidate_{flag}_invalid")

        reserve_sha = str(row.get("reserve_assignment_sha256", ""))
        chain = str(row.get("chain", "")).strip().lower()
        address = str(row.get("control_address", "")).strip().lower()
        case_id = str(row.get("case_name", "")).strip()
        if (
            len(reserve_sha) != 64
            or not chain
            or len(address) != 42
            or not case_id
        ):
            raise ControlTraceTargetError("trace_candidate_identity_invalid")
        targets.append(
            {
                "target_id": f"trace-{reserve_sha}",
                "case_id": case_id,
                "chain": chain,
                "chain_address": f"{chain}:{address}",
                "transaction_hash": str(row["creation_tx_hash"]).lower(),
                "block_number": int(row["deployment_block"]),
                "block_hash": str(row["deployment_block_hash"]).lower(),
                "reserve_assignment_sha256": reserve_sha,
                "reserve_record_sha256": stored_result_sha,
                "reserve_record_file_sha256": _file_sha(path),
            }
        )

    targets.sort(key=lambda row: str(row["target_id"]))
    expected = int(summary.get("trace_required_count", -1))
    if len(targets) != expected:
        raise ControlTraceTargetError("trace_target_count_mismatch")
    ids = [str(row["target_id"]) for row in targets]
    addresses = [str(row["chain_address"]) for row in targets]
    if len(ids) != len(set(ids)):
        raise ControlTraceTargetError("trace_target_duplicate")
    if len(addresses) != len(set(addresses)):
        raise ControlTraceTargetError("trace_chain_address_duplicate")

    output: dict[str, object] = {
        "schema_version": "stage2_control_trace_target_identities.v1",
        "acquisition_summary_file_sha256": _file_sha(summary_path),
        "acquisition_summary_sha256": stored_summary_sha,
        "signature_verification_file_sha256": _file_sha(verification_path),
        "acquisition_ledger_file_sha256": _file_sha(ledger_path),
        "run_binding_sha256": summary["run_binding_sha256"],
        "target_count": len(targets),
        "targets": targets,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["target_identities_sha256"] = _canonical_sha(output)
    return output


def _require_false_authority(payload: Mapping[str, object], label: str) -> None:
    for flag in _FALSE_AUTHORITY_FLAGS:
        if payload.get(flag) is not False:
            raise ControlTraceTargetError(f"{label}_{flag}_invalid")


def _trace_params(method: str, target: Mapping[str, object]) -> list[object]:
    transaction_hash = str(target.get("transaction_hash", "")).strip().lower()
    block_number = target.get("block_number")
    if len(transaction_hash) != 66:
        raise ControlTraceTargetError("trace_target_transaction_hash_invalid")
    if method == "trace_transaction":
        return [transaction_hash]
    if method == "debug_traceTransaction":
        return [transaction_hash, {"tracer": "callTracer", "timeout": "120s"}]
    if not isinstance(block_number, int) or block_number < 0:
        raise ControlTraceTargetError("trace_target_block_number_invalid")
    if method == "trace_block":
        return [hex(block_number)]
    if method == "debug_traceBlockByNumber":
        return [hex(block_number), {"tracer": "callTracer", "timeout": "120s"}]
    raise ControlTraceTargetError("trace_method_invalid")


def materialize_trace_targets(
    *,
    target_identities_path: Path,
    capability_report_path: Path,
    capability_verification_path: Path,
) -> dict[str, object]:
    """Bind frozen trace identities to exact observed provider calls.

    The result remains non-authorizing even when the capability verifier was
    registry-bound. A separately signed activation must revalidate the provider
    registry, call scopes, request ceiling, and activation window before any RPC.
    """
    identities_path = _ordinary(target_identities_path, "target_identities")
    identities = _load(identities_path, "target_identities")
    if identities.get("schema_version") != "stage2_control_trace_target_identities.v1":
        raise ControlTraceTargetError("target_identities_schema_invalid")
    identities_material = {
        key: value
        for key, value in identities.items()
        if key != "target_identities_sha256"
    }
    if identities.get("target_identities_sha256") != _canonical_sha(
        identities_material
    ):
        raise ControlTraceTargetError("target_identities_self_hash_invalid")
    _require_false_authority(identities, "target_identities")
    identity_rows = identities.get("targets")
    if (
        not isinstance(identity_rows, list)
        or len(identity_rows) != identities.get("target_count")
        or not identity_rows
        or not all(isinstance(row, Mapping) for row in identity_rows)
    ):
        raise ControlTraceTargetError("target_identities_count_invalid")
    target_ids = [str(row.get("target_id", "")) for row in identity_rows]
    if any(not value for value in target_ids) or len(target_ids) != len(set(target_ids)):
        raise ControlTraceTargetError("trace_target_duplicate")

    report_path = _ordinary(capability_report_path, "capability_report")
    report = _load(report_path, "capability_report")
    if report.get("schema_version") != "stage2_control_trace_state_capability.v1":
        raise ControlTraceTargetError("capability_report_schema_invalid")
    report_material = {
        key: value for key, value in report.items() if key != "report_sha256"
    }
    if report.get("report_sha256") != _canonical_sha(report_material):
        raise ControlTraceTargetError("capability_report_self_hash_invalid")
    if report.get("complete") is not True or report.get("errors") != []:
        raise ControlTraceTargetError("capability_report_not_complete")
    _require_false_authority(report, "capability_report")

    verification_path = _ordinary(
        capability_verification_path, "capability_verification"
    )
    verification = _load(verification_path, "capability_verification")
    if verification.get("schema_version") != (
        "stage2_control_trace_state_capability_verification.v1"
    ):
        raise ControlTraceTargetError("capability_verification_schema_invalid")
    verification_material = {
        key: value
        for key, value in verification.items()
        if key != "verification_sha256"
    }
    if verification.get("verification_sha256") != _canonical_sha(
        verification_material
    ):
        raise ControlTraceTargetError("capability_verification_self_hash_invalid")
    if verification.get("complete") is not True or verification.get("errors") != []:
        raise ControlTraceTargetError("capability_verification_not_complete")
    if (
        verification.get("report_sha256") != report.get("report_sha256")
        or verification.get("report_file_sha256") != _file_sha(report_path)
    ):
        raise ControlTraceTargetError("capability_verification_report_mismatch")
    _require_false_authority(verification, "capability_verification")

    chain_rows = report.get("chains")
    if (
        not isinstance(chain_rows, list)
        or len(chain_rows) != report.get("chain_count")
        or not chain_rows
    ):
        raise ControlTraceTargetError("capability_chain_count_invalid")
    providers_by_chain: dict[str, list[dict[str, object]]] = {}
    for chain_row in chain_rows:
        if not isinstance(chain_row, Mapping) or chain_row.get("complete") is not True:
            raise ControlTraceTargetError("capability_chain_invalid")
        chain = str(chain_row.get("chain", "")).strip().lower()
        provider_rows = chain_row.get("providers")
        if (
            not chain
            or chain in providers_by_chain
            or not isinstance(provider_rows, list)
            or len(provider_rows) != 2
            or not all(isinstance(row, Mapping) for row in provider_rows)
        ):
            raise ControlTraceTargetError("capability_provider_count_invalid")
        normalized: list[dict[str, object]] = []
        families: set[str] = set()
        provider_ids: set[str] = set()
        for provider_row in provider_rows:
            provider_id = str(provider_row.get("provider_id", "")).strip()
            family = str(provider_row.get("provider_family", "")).strip().lower()
            method = str(provider_row.get("trace_method", "")).strip()
            if (
                not provider_id
                or provider_id in provider_ids
                or not family
                or family == "unverified"
                or method not in _TRACE_METHODS
                or provider_row.get("known_creation_recovered") is not True
            ):
                raise ControlTraceTargetError("capability_provider_invalid")
            provider_ids.add(provider_id)
            families.add(family)
            normalized.append({
                "provider_id": provider_id,
                "operator_family": family,
                "method": method,
            })
        if len(families) != 2:
            raise ControlTraceTargetError("provider_family_independence")
        declared_families = {
            str(value).strip().lower()
            for value in chain_row.get("verified_operator_families", [])
        }
        if declared_families != families:
            raise ControlTraceTargetError("capability_family_set_mismatch")
        providers_by_chain[chain] = sorted(
            normalized, key=lambda row: str(row["provider_id"])
        )

    identity_chains = {
        str(row.get("chain", "")).strip().lower() for row in identity_rows
    }
    if not identity_chains or identity_chains != set(providers_by_chain):
        raise ControlTraceTargetError("capability_identity_chain_scope_mismatch")

    targets: list[dict[str, object]] = []
    for identity in identity_rows:
        target = dict(identity)
        chain = str(target.get("chain", "")).strip().lower()
        target["calls"] = [
            {
                **provider,
                "params": _trace_params(str(provider["method"]), target),
            }
            for provider in providers_by_chain[chain]
        ]
        targets.append(target)
    targets.sort(key=lambda row: str(row["target_id"]))

    output: dict[str, object] = {
        "schema_version": "stage2_control_trace_targets.v1",
        "target_identities_file_sha256": _file_sha(identities_path),
        "target_identities_sha256": identities["target_identities_sha256"],
        "capability_report_file_sha256": _file_sha(report_path),
        "capability_report_sha256": report["report_sha256"],
        "capability_verification_file_sha256": _file_sha(verification_path),
        "capability_verification_sha256": verification["verification_sha256"],
        "provider_registry_verified": verification.get("provider_registry_verified") is True,
        "target_count": len(targets),
        "rpc_call_count": sum(len(target["calls"]) for target in targets),
        "targets": targets,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output["trace_targets_sha256"] = _canonical_sha(output)
    return output
