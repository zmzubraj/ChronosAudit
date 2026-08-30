from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .control_trace_acquisition import (
    _parse_creation_set,
    reverify_trace_activation_for_execution,
    verify_trace_checkpoint_signature,
)
from .control_trace_retry_overlay_approval import (
    APPROVED_SPEC_SHA256,
    verify_trace_retry_overlay_spec_approval,
)


class ControlTraceRetryOverlayError(ValueError):
    """Raised when source evidence or a retry overlay fails closed."""


FALSE_AUTHORITY = {
    "rpc_authorized": False,
    "denominator_admission_authorized": False,
    "selection_authorized": False,
    "qualification_authorized": False,
    "counter_authority": False,
    "stage_promotion_authorized": False,
    "recovery3_mutation_authorized": False,
    "independent_review_established": False,
    "r5_authorized": False,
    "release_authorized": False,
    "publication_authorized": False,
}


@dataclass(frozen=True)
class TraceSourceRoot:
    checkpoint_path: Path
    signature_path: Path
    allowed_signers_path: Path
    expected_principal: str


@dataclass(frozen=True)
class CompleteTraceEvidence:
    target_id: str
    source_key: str
    checkpoint_file_sha256: str
    record: dict[str, object]


@dataclass(frozen=True)
class VerifiedTraceSourceRoot:
    source_key: str
    checkpoint_file_sha256: str
    checkpoint_sha256: str
    checkpoint_status: str
    processed_target_count: int
    completed_target_count: int
    request_count: int
    complete_evidence: tuple[CompleteTraceEvidence, ...]
    manifest: dict[str, object]


@dataclass(frozen=True)
class CanonicalCompleteTrace:
    target_id: str
    canonical_source_key: str
    canonical_record: dict[str, object]
    agreeing_sources: tuple[CompleteTraceEvidence, ...]


@dataclass(frozen=True)
class CompleteSourceUnion:
    completed_by_target: dict[str, CanonicalCompleteTrace]
    duplicate_agreement_count: int


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
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
        raise ControlTraceRetryOverlayError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlTraceRetryOverlayError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlTraceRetryOverlayError(f"{label}_not_ordinary_file")
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        value = json.loads(ordinary.read_text(encoding="utf-8"))
    except PermissionError as exc:
        raise ControlTraceRetryOverlayError(f"{label}_unreadable") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlTraceRetryOverlayError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise ControlTraceRetryOverlayError(f"{label}_root_invalid")
    return value


def _self_hash(payload: Mapping[str, object], field: str, label: str) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _canonical_sha(material):
        raise ControlTraceRetryOverlayError(f"{label}_self_hash_invalid")


def _require_false(payload: Mapping[str, object], label: str) -> None:
    for field in FALSE_AUTHORITY:
        if field in payload and payload.get(field) is not False:
            raise ControlTraceRetryOverlayError(f"{label}_{field}_invalid")


def _confined_child(root: Path, relative_value: object, label: str) -> Path:
    relative = Path(str(relative_value or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ControlTraceRetryOverlayError(f"{label}_path_escape")
    candidate = root / relative
    child = _ordinary(candidate, label)
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise ControlTraceRetryOverlayError(f"{label}_path_escape") from exc
    return child


def _load_original_targets(path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    payload = _load(path, "original_targets")
    if payload.get("schema_version") != "stage2_control_trace_targets.v1":
        raise ControlTraceRetryOverlayError("original_targets_schema_invalid")
    _self_hash(payload, "trace_targets_sha256", "original_targets")
    _require_false(payload, "original_targets")
    if payload.get("rpc_authorized") is not False:
        raise ControlTraceRetryOverlayError("original_targets_rpc_authorized_invalid")
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        raise ControlTraceRetryOverlayError("original_targets_invalid")
    typed = [dict(row) for row in rows]
    ids = [str(row.get("target_id", "")) for row in typed]
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        raise ControlTraceRetryOverlayError("original_target_identity_invalid")
    if ids != sorted(ids):
        raise ControlTraceRetryOverlayError("original_target_order_invalid")
    if payload.get("target_count") != len(typed) or payload.get("rpc_call_count") != 2 * len(typed):
        raise ControlTraceRetryOverlayError("original_target_count_invalid")
    return payload, typed


def _complete_semantics(row: Mapping[str, object]) -> tuple[object, ...]:
    creation = row.get("creation_set")
    if not isinstance(creation, list):
        raise ControlTraceRetryOverlayError("complete_creation_set_invalid")
    return (
        row.get("target_sha256"),
        row.get("case_id"),
        row.get("chain"),
        row.get("chain_address"),
        row.get("transaction_hash"),
        row.get("block_number"),
        row.get("block_hash"),
        row.get("reserve_record_sha256"),
        row.get("creation_set_sha256"),
        tuple(tuple(value) for value in creation),
    )


def _validate_activation(
    *,
    request_path: Path,
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    verification_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> tuple[dict[str, object], dict[str, object]]:
    request = _load(request_path, "activation_request")
    stored = _load(verification_path, "activation_verification")
    try:
        reverified = reverify_trace_activation_for_execution(
            activation_verification_path=verification_path,
            request=request,
            approval_path=approval_path,
            signature_path=signature_path,
            allowed_signers_path=allowed_signers_path,
            expected_principal=expected_principal,
            verification_time_utc=verification_time_utc,
        )
    except Exception as exc:
        raise ControlTraceRetryOverlayError("activation_reverification_failed") from exc
    if stored != reverified:
        raise ControlTraceRetryOverlayError("activation_reverification_mismatch")
    return request, reverified


def _event_rows(path: Path) -> list[dict[str, object]]:
    ledger = _ordinary(path, "source_event_ledger")
    rows: list[dict[str, object]] = []
    try:
        lines = ledger.read_text(encoding="utf-8").splitlines()
    except PermissionError as exc:
        raise ControlTraceRetryOverlayError("source_event_ledger_unreadable") from exc
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ControlTraceRetryOverlayError("source_event_json_invalid") from exc
        if not isinstance(value, dict):
            raise ControlTraceRetryOverlayError("source_event_invalid")
        rows.append(value)
    return rows


def verify_trace_source_root(
    *,
    source: TraceSourceRoot,
    original_targets_path: Path,
    activation_request_path: Path,
    activation_approval_path: Path,
    activation_signature_path: Path,
    activation_allowed_signers_path: Path,
    activation_verification_path: Path,
    activation_expected_principal: str,
    verification_time_utc: str = "2026-08-25T00:00:00Z",
    retry_reconstruction_inputs: Mapping[str, object] | None = None,
) -> VerifiedTraceSourceRoot:
    targets_file = _ordinary(original_targets_path, "original_targets")
    raw_target_payload = _load(targets_file, "execution_targets")
    if raw_target_payload.get("schema_version") == "stage2_control_trace_targets.v1":
        _, targets = _load_original_targets(targets_file)
    elif raw_target_payload.get("schema_version") == "stage2_control_trace_retry_targets.v1":
        if retry_reconstruction_inputs is None:
            raise ControlTraceRetryOverlayError("trace_retry_targets_invalid")
        verification = verify_trace_retry_targets(
            artifact_path=targets_file,
            **dict(retry_reconstruction_inputs),
        )
        if verification.get("decision") != "TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING":
            raise ControlTraceRetryOverlayError("trace_retry_targets_invalid")
        retry_rows = raw_target_payload.get("targets")
        if not isinstance(retry_rows, list) or not all(isinstance(row, dict) for row in retry_rows):
            raise ControlTraceRetryOverlayError("trace_retry_targets_invalid")
        targets = [dict(row) for row in retry_rows]
    else:
        raise ControlTraceRetryOverlayError("execution_targets_schema_invalid")
    targets_by_id = {str(row["target_id"]): row for row in targets}
    request, activation = _validate_activation(
        request_path=activation_request_path,
        approval_path=activation_approval_path,
        signature_path=activation_signature_path,
        allowed_signers_path=activation_allowed_signers_path,
        verification_path=activation_verification_path,
        expected_principal=activation_expected_principal,
        verification_time_utc=verification_time_utc,
    )
    if activation.get("trace_targets_sha256") != _file_sha(targets_file):
        raise ControlTraceRetryOverlayError("activation_target_mismatch")
    checkpoint_file = _ordinary(source.checkpoint_path, "source_checkpoint")
    checkpoint = _load(checkpoint_file, "source_checkpoint")
    if checkpoint.get("schema_version") != "stage2_control_trace_acquisition_checkpoint.v1":
        raise ControlTraceRetryOverlayError("source_checkpoint_schema_invalid")
    _self_hash(checkpoint, "checkpoint_sha256", "source_checkpoint")
    _require_false(checkpoint, "source_checkpoint")
    try:
        checkpoint_verification = verify_trace_checkpoint_signature(
            checkpoint_path=checkpoint_file,
            signature_path=source.signature_path,
            allowed_signers_path=source.allowed_signers_path,
            expected_principal=source.expected_principal,
        )
    except Exception as exc:
        raise ControlTraceRetryOverlayError("source_checkpoint_signature_invalid") from exc
    if checkpoint_verification.get("complete") is not True:
        raise ControlTraceRetryOverlayError("source_checkpoint_signature_invalid")
    if checkpoint.get("trace_targets_sha256") != _file_sha(targets_file):
        raise ControlTraceRetryOverlayError("source_target_binding_invalid")
    if checkpoint.get("activation_verification_sha256") != activation.get("verification_sha256"):
        raise ControlTraceRetryOverlayError("source_activation_binding_invalid")
    if checkpoint.get("target_count") != len(targets):
        raise ControlTraceRetryOverlayError("source_target_count_invalid")

    root = checkpoint_file.parent.resolve(strict=True)
    results_path = _confined_child(root, checkpoint.get("normalized_results_path"), "source_results")
    ledger_path = _confined_child(root, checkpoint.get("event_ledger_path"), "source_event_ledger")
    if _file_sha(results_path) != checkpoint.get("normalized_results_sha256"):
        raise ControlTraceRetryOverlayError("source_results_hash_invalid")
    if _file_sha(ledger_path) != checkpoint.get("event_ledger_sha256"):
        raise ControlTraceRetryOverlayError("source_event_ledger_hash_invalid")
    results = _load(results_path, "source_results")
    if results.get("schema_version") != "stage2_control_trace_acquisition_results.v1":
        raise ControlTraceRetryOverlayError("source_results_schema_invalid")
    _self_hash(results, "results_sha256", "source_results")
    _require_false(results, "source_results")
    rows = results.get("targets")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ControlTraceRetryOverlayError("source_results_invalid")
    processed_ids = [str(row.get("target_id", "")) for row in rows]
    original_ids = [str(row["target_id"]) for row in targets]
    if processed_ids != original_ids[: len(processed_ids)]:
        raise ControlTraceRetryOverlayError("source_processed_prefix_invalid")
    if processed_ids != checkpoint.get("processed_target_ids"):
        raise ControlTraceRetryOverlayError("source_processed_ids_invalid")
    if len(rows) != checkpoint.get("processed_target_count") or len(rows) != results.get("processed_target_count"):
        raise ControlTraceRetryOverlayError("source_processed_count_invalid")

    events = _event_rows(ledger_path)
    if len(events) != checkpoint.get("request_count"):
        raise ControlTraceRetryOverlayError("source_event_count_invalid")
    previous: str | None = None
    scopes = request.get("rpc_call_scopes")
    if not isinstance(scopes, list):
        raise ControlTraceRetryOverlayError("source_activation_scopes_invalid")
    scopes_by_hash = {
        str(scope.get("call_scope_sha256")): scope
        for scope in scopes
        if isinstance(scope, Mapping)
    }
    events_by_target: dict[str, list[dict[str, object]]] = {}
    for expected_sequence, event in enumerate(events, 1):
        if event.get("schema_version") != "stage2_control_trace_acquisition_event.v1":
            raise ControlTraceRetryOverlayError("source_event_schema_invalid")
        material = {key: value for key, value in event.items() if key != "event_sha256"}
        if event.get("event_sha256") != _canonical_sha(material):
            raise ControlTraceRetryOverlayError("source_event_self_hash_invalid")
        if event.get("sequence") != expected_sequence or event.get("previous_event_sha256") != previous:
            raise ControlTraceRetryOverlayError("source_event_chain_invalid")
        previous = str(event["event_sha256"])
        target_id = str(event.get("target_id", ""))
        target = targets_by_id.get(target_id)
        if target is None or event.get("target_sha256") != _canonical_sha(target):
            raise ControlTraceRetryOverlayError("source_event_target_invalid")
        if event.get("activation_verification_sha256") != activation.get("verification_sha256"):
            raise ControlTraceRetryOverlayError("source_event_activation_invalid")
        scope = scopes_by_hash.get(str(event.get("call_scope_sha256", "")))
        if scope is None:
            raise ControlTraceRetryOverlayError("source_event_scope_invalid")
        for field in ("target_id", "provider_id", "operator_family", "method", "params_sha256"):
            if event.get(field) != scope.get(field):
                raise ControlTraceRetryOverlayError("source_event_scope_invalid")
        request_file = _confined_child(root, event.get("request_path"), "source_raw_request")
        response_file = _confined_child(root, event.get("response_path"), "source_raw_response")
        if _file_sha(request_file) != event.get("request_sha256") or _file_sha(response_file) != event.get("response_sha256"):
            raise ControlTraceRetryOverlayError("source_raw_hash_invalid")
        raw_request = _load(request_file, "source_raw_request")
        raw_response = _load(response_file, "source_raw_response")
        if (
            raw_request.get("sequence") != expected_sequence
            or raw_request.get("target_id") != target_id
            or raw_request.get("provider_id") != event.get("provider_id")
            or raw_request.get("method") != event.get("method")
            or raw_request.get("params") != scope.get("params")
            or raw_request.get("call_scope_sha256") != event.get("call_scope_sha256")
            or raw_response.get("sequence") != expected_sequence
            or raw_response.get("provider_id") != event.get("provider_id")
            or raw_response.get("method") != event.get("method")
            or raw_response.get("params") != scope.get("params")
        ):
            raise ControlTraceRetryOverlayError("source_raw_semantics_invalid")
        if event.get("disposition") == "complete":
            if raw_response.get("error") is not None:
                raise ControlTraceRetryOverlayError("source_complete_response_invalid")
            try:
                creation = _parse_creation_set(
                    target=target,
                    method=str(event["method"]),
                    result=raw_response.get("result"),
                )
            except Exception as exc:
                raise ControlTraceRetryOverlayError("source_complete_response_invalid") from exc
            if event.get("normalized_creation_set_sha256") != _canonical_sha(creation):
                raise ControlTraceRetryOverlayError("source_complete_creation_hash_invalid")
        events_by_target.setdefault(target_id, []).append(event)
    if previous != checkpoint.get("event_tip_sha256"):
        raise ControlTraceRetryOverlayError("source_event_tip_invalid")
    if checkpoint.get("used_sequences") != list(range(1, len(events) + 1)):
        raise ControlTraceRetryOverlayError("source_used_sequences_invalid")

    completed: list[CompleteTraceEvidence] = []
    complete_ids: list[str] = []
    for row in rows:
        _self_hash(row, "record_sha256", "source_result")
        target_id = str(row.get("target_id", ""))
        target = targets_by_id[target_id]
        if row.get("target_sha256") != _canonical_sha(target):
            raise ControlTraceRetryOverlayError("source_result_target_invalid")
        for field in (
            "case_id", "chain", "chain_address", "transaction_hash", "block_number",
            "block_hash", "reserve_record_sha256",
        ):
            if row.get(field) != target.get(field):
                raise ControlTraceRetryOverlayError("source_result_target_invalid")
        if row.get("disposition") != "complete":
            continue
        provider_ids = row.get("provider_ids")
        families = row.get("operator_families")
        if (
            not isinstance(provider_ids, list) or len(provider_ids) != 2
            or len(set(map(str, provider_ids))) != 2
            or not isinstance(families, list) or len(families) != 2
            or len(set(map(str, families))) != 2
        ):
            raise ControlTraceRetryOverlayError("source_complete_independence_invalid")
        terminal = [event for event in events_by_target.get(target_id, []) if event.get("disposition") == "complete"]
        if (
            len(terminal) != 2
            or {str(event["provider_id"]) for event in terminal} != set(map(str, provider_ids))
            or {str(event["operator_family"]) for event in terminal} != set(map(str, families))
            or {str(event["normalized_creation_set_sha256"]) for event in terminal}
            != {str(row.get("creation_set_sha256"))}
        ):
            raise ControlTraceRetryOverlayError("source_complete_event_proof_invalid")
        creation = row.get("creation_set")
        if not isinstance(creation, list) or row.get("creation_set_sha256") != _canonical_sha(tuple(tuple(value) for value in creation)):
            raise ControlTraceRetryOverlayError("source_complete_creation_set_invalid")
        address = str(row.get("chain_address", "")).split(":", 1)[-1].lower()
        if address not in {str(value[1]).lower() for value in creation if isinstance(value, list) and len(value) > 1}:
            raise ControlTraceRetryOverlayError("source_complete_candidate_missing")
        complete_ids.append(target_id)
        completed.append(CompleteTraceEvidence(
            target_id=target_id,
            source_key=_file_sha(checkpoint_file),
            checkpoint_file_sha256=_file_sha(checkpoint_file),
            record=dict(row),
        ))
    if complete_ids != checkpoint.get("completed_target_ids"):
        raise ControlTraceRetryOverlayError("source_completed_ids_invalid")
    if len(completed) != checkpoint.get("completed_target_count") or len(completed) != results.get("completed_target_count"):
        raise ControlTraceRetryOverlayError("source_completed_count_invalid")

    checkpoint_file_sha = _file_sha(checkpoint_file)
    manifest: dict[str, object] = {
        "source_key": checkpoint_file_sha,
        "checkpoint_path": str(source.checkpoint_path),
        "checkpoint_file_sha256": checkpoint_file_sha,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "checkpoint_signature_sha256": _file_sha(_ordinary(source.signature_path, "source_signature")),
        "checkpoint_allowed_signers_sha256": _file_sha(_ordinary(source.allowed_signers_path, "source_allowed_signers")),
        "checkpoint_signer_principal": source.expected_principal,
        "checkpoint_status": checkpoint["status"],
        "processed_target_count": len(rows),
        "completed_target_count": len(completed),
        "request_count": len(events),
        "normalized_results_file_sha256": _file_sha(results_path),
        "event_ledger_file_sha256": _file_sha(ledger_path),
        "event_tip_sha256": previous,
        "cryptographically_reverified": True,
        "raw_receipts_reverified": True,
        **FALSE_AUTHORITY,
    }
    manifest["source_manifest_sha256"] = _canonical_sha(manifest)
    return VerifiedTraceSourceRoot(
        source_key=checkpoint_file_sha,
        checkpoint_file_sha256=checkpoint_file_sha,
        checkpoint_sha256=str(checkpoint["checkpoint_sha256"]),
        checkpoint_status=str(checkpoint["status"]),
        processed_target_count=len(rows),
        completed_target_count=len(completed),
        request_count=len(events),
        complete_evidence=tuple(completed),
        manifest=manifest,
    )


def build_complete_source_union(sources: Sequence[VerifiedTraceSourceRoot]) -> CompleteSourceUnion:
    if not sources:
        raise ControlTraceRetryOverlayError("source_roots_empty")
    grouped: dict[str, list[CompleteTraceEvidence]] = {}
    for source in sources:
        for evidence in source.complete_evidence:
            grouped.setdefault(evidence.target_id, []).append(evidence)
    completed: dict[str, CanonicalCompleteTrace] = {}
    duplicate_count = 0
    for target_id, evidence_rows in grouped.items():
        semantics = {_complete_semantics(value.record) for value in evidence_rows}
        if len(semantics) != 1:
            raise ControlTraceRetryOverlayError("complete_source_conflict")
        ordered = tuple(sorted(
            evidence_rows,
            key=lambda value: (value.checkpoint_file_sha256, str(value.record.get("record_sha256", ""))),
        ))
        duplicate_count += len(ordered) - 1
        completed[target_id] = CanonicalCompleteTrace(
            target_id=target_id,
            canonical_source_key=ordered[0].source_key,
            canonical_record=dict(ordered[0].record),
            agreeing_sources=ordered,
        )
    return CompleteSourceUnion(
        completed_by_target=dict(sorted(completed.items())),
        duplicate_agreement_count=duplicate_count,
    )


def build_retry_targets_from_verified_sources(
    *,
    original_targets: Sequence[dict[str, object]],
    original_targets_file_sha256: str,
    original_targets_sha256: str,
    activation_verification_file_sha256: str,
    activation_verification_sha256: str,
    spec_approval_record_sha256: str,
    sources: Sequence[VerifiedTraceSourceRoot],
    union: CompleteSourceUnion,
) -> dict[str, object]:
    by_id = {str(row["target_id"]): dict(row) for row in original_targets}
    complete_ids = sorted(union.completed_by_target)
    if not set(complete_ids) <= set(by_id):
        raise ControlTraceRetryOverlayError("source_complete_outside_original")
    unresolved_ids = sorted(set(by_id) - set(complete_ids))
    provenance: list[dict[str, object]] = []
    for target_id in complete_ids:
        chosen = union.completed_by_target[target_id]
        provenance.append({
            "target_id": target_id,
            "target_sha256": chosen.canonical_record["target_sha256"],
            "creation_set_sha256": chosen.canonical_record["creation_set_sha256"],
            "record_sha256": chosen.canonical_record["record_sha256"],
            "canonical_source_key": chosen.canonical_source_key,
            "agreeing_source_keys": [value.source_key for value in chosen.agreeing_sources],
        })
    artifact: dict[str, object] = {
        "schema_version": "stage2_control_trace_retry_targets.v1",
        "decision": "TRACE_RETRY_TARGETS_FROZEN_NON_AUTHORIZING",
        "approved_specification_sha256": APPROVED_SPEC_SHA256,
        "spec_approval_record_sha256": spec_approval_record_sha256,
        "original_trace_targets_file_sha256": original_targets_file_sha256,
        "original_trace_targets_sha256": original_targets_sha256,
        "original_activation_verification_file_sha256": activation_verification_file_sha256,
        "original_activation_verification_sha256": activation_verification_sha256,
        "source_roots": [dict(source.manifest) for source in sorted(sources, key=lambda item: item.source_key)],
        "original_target_count": len(by_id),
        "source_complete_count": len(complete_ids),
        "duplicate_agreement_count": union.duplicate_agreement_count,
        "unresolved_count": len(unresolved_ids),
        "rpc_call_count": len(unresolved_ids) * 2,
        "source_complete_targets": provenance,
        "targets": [by_id[target_id] for target_id in unresolved_ids],
        **FALSE_AUTHORITY,
    }
    artifact["retry_targets_sha256"] = _canonical_sha(artifact)
    verify_retry_target_payload(artifact)
    return artifact


def verify_retry_target_payload(payload: Mapping[str, object]) -> None:
    if payload.get("schema_version") != "stage2_control_trace_retry_targets.v1":
        raise ControlTraceRetryOverlayError("retry_targets_schema_invalid")
    _self_hash(payload, "retry_targets_sha256", "retry_targets")
    _require_false(payload, "retry_targets")
    if payload.get("approved_specification_sha256") != APPROVED_SPEC_SHA256:
        raise ControlTraceRetryOverlayError("retry_specification_invalid")
    targets = payload.get("targets")
    complete = payload.get("source_complete_targets")
    if not isinstance(targets, list) or not all(isinstance(row, Mapping) for row in targets):
        raise ControlTraceRetryOverlayError("retry_targets_invalid")
    if not isinstance(complete, list) or not all(isinstance(row, Mapping) for row in complete):
        raise ControlTraceRetryOverlayError("retry_complete_provenance_invalid")
    retry_ids = [str(row.get("target_id", "")) for row in targets]
    complete_ids = [str(row.get("target_id", "")) for row in complete]
    if set(retry_ids) & set(complete_ids):
        raise ControlTraceRetryOverlayError("retry_contains_source_complete")
    if retry_ids != sorted(retry_ids) or complete_ids != sorted(complete_ids):
        raise ControlTraceRetryOverlayError("retry_target_order_invalid")
    if len(retry_ids) != len(set(retry_ids)) or len(complete_ids) != len(set(complete_ids)):
        raise ControlTraceRetryOverlayError("retry_target_duplicate")
    if payload.get("source_complete_count") != len(complete_ids) or payload.get("unresolved_count") != len(retry_ids):
        raise ControlTraceRetryOverlayError("retry_count_invalid")
    if payload.get("original_target_count") != len(complete_ids) + len(retry_ids):
        raise ControlTraceRetryOverlayError("retry_partition_invalid")
    if payload.get("rpc_call_count") != 2 * len(retry_ids):
        raise ControlTraceRetryOverlayError("retry_call_count_invalid")


def build_trace_retry_targets(
    *,
    specification_path: Path,
    spec_approval_path: Path,
    original_targets_path: Path,
    activation_request_path: Path,
    activation_approval_path: Path,
    activation_signature_path: Path,
    activation_allowed_signers_path: Path,
    activation_verification_path: Path,
    activation_expected_principal: str,
    sources: Sequence[TraceSourceRoot],
    verification_time_utc: str = "2026-08-25T00:00:00Z",
) -> dict[str, object]:
    approval_verification = verify_trace_retry_overlay_spec_approval(
        approval_path=spec_approval_path,
        specification_path=specification_path,
    )
    approval = _load(spec_approval_path, "spec_approval")
    if approval_verification.get("verified") is not True:
        raise ControlTraceRetryOverlayError("spec_approval_invalid")
    targets_file = _ordinary(original_targets_path, "original_targets")
    target_payload, targets = _load_original_targets(targets_file)
    _, activation = _validate_activation(
        request_path=activation_request_path,
        approval_path=activation_approval_path,
        signature_path=activation_signature_path,
        allowed_signers_path=activation_allowed_signers_path,
        verification_path=activation_verification_path,
        expected_principal=activation_expected_principal,
        verification_time_utc=verification_time_utc,
    )
    verified_sources = [
        verify_trace_source_root(
            source=source,
            original_targets_path=targets_file,
            activation_request_path=activation_request_path,
            activation_approval_path=activation_approval_path,
            activation_signature_path=activation_signature_path,
            activation_allowed_signers_path=activation_allowed_signers_path,
            activation_verification_path=activation_verification_path,
            activation_expected_principal=activation_expected_principal,
            verification_time_utc=verification_time_utc,
        )
        for source in sources
    ]
    union = build_complete_source_union(verified_sources)
    return build_retry_targets_from_verified_sources(
        original_targets=targets,
        original_targets_file_sha256=_file_sha(targets_file),
        original_targets_sha256=str(target_payload["trace_targets_sha256"]),
        activation_verification_file_sha256=_file_sha(_ordinary(activation_verification_path, "activation_verification")),
        activation_verification_sha256=str(activation["verification_sha256"]),
        spec_approval_record_sha256=str(approval["record_sha256"]),
        sources=verified_sources,
        union=union,
    )


def verify_trace_retry_targets(
    *, artifact_path: Path, **reconstruction_inputs: Any
) -> dict[str, object]:
    artifact_file = _ordinary(artifact_path, "retry_targets")
    supplied = _load(artifact_file, "retry_targets")
    verify_retry_target_payload(supplied)
    rebuilt = build_trace_retry_targets(**reconstruction_inputs)
    if supplied != rebuilt:
        raise ControlTraceRetryOverlayError("retry_reconstruction_mismatch")
    report: dict[str, object] = {
        "schema_version": "stage2_control_trace_retry_targets_verification.v1",
        "decision": "TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING",
        "verified": True,
        "retry_targets_file_sha256": _file_sha(artifact_file),
        "retry_targets_sha256": supplied["retry_targets_sha256"],
        "original_target_count": supplied["original_target_count"],
        "source_complete_count": supplied["source_complete_count"],
        "duplicate_agreement_count": supplied["duplicate_agreement_count"],
        "unresolved_count": supplied["unresolved_count"],
        "rpc_call_count": supplied["rpc_call_count"],
        **FALSE_AUTHORITY,
    }
    report["verification_sha256"] = _canonical_sha(report)
    return report


def build_completion_overlay_from_verified(
    *,
    original_targets: Sequence[dict[str, object]],
    source_union: CompleteSourceUnion,
    retry_source: VerifiedTraceSourceRoot,
    retry_targets_payload: Mapping[str, object],
    retry_targets_file_sha256: str,
    retry_targets_verification_sha256: str,
) -> dict[str, object]:
    verify_retry_target_payload(retry_targets_payload)
    if retry_source.checkpoint_status != "COMPLETE":
        raise ControlTraceRetryOverlayError("retry_root_not_complete")
    original_by_id = {str(row["target_id"]): dict(row) for row in original_targets}
    retry_ids = [str(row["target_id"]) for row in retry_targets_payload["targets"]]  # type: ignore[index]
    source_ids = set(source_union.completed_by_target)
    if source_ids & set(retry_ids):
        raise ControlTraceRetryOverlayError("overlay_partition_overlap")
    if source_ids | set(retry_ids) != set(original_by_id):
        raise ControlTraceRetryOverlayError("overlay_partition_incomplete")
    retry_complete = {value.target_id: value for value in retry_source.complete_evidence}
    if set(retry_complete) != set(retry_ids):
        raise ControlTraceRetryOverlayError("retry_root_not_complete")

    rows: list[dict[str, object]] = []
    for target_id in sorted(original_by_id):
        target = original_by_id[target_id]
        if target_id in source_union.completed_by_target:
            chosen = source_union.completed_by_target[target_id]
            record = dict(chosen.canonical_record)
            origin = "IMMUTABLE_SOURCE_ROOT"
            provenance = [
                {
                    "source_key": value.source_key,
                    "checkpoint_file_sha256": value.checkpoint_file_sha256,
                    "record_sha256": value.record["record_sha256"],
                }
                for value in chosen.agreeing_sources
            ]
        else:
            evidence = retry_complete[target_id]
            record = dict(evidence.record)
            origin = "FRESH_RETRY_ROOT"
            provenance = [{
                "source_key": evidence.source_key,
                "checkpoint_file_sha256": evidence.checkpoint_file_sha256,
                "record_sha256": evidence.record["record_sha256"],
            }]
        if record.get("target_sha256") != _canonical_sha(target):
            raise ControlTraceRetryOverlayError("overlay_target_substitution")
        overlay_row: dict[str, object] = {
            **record,
            "evidence_origin": origin,
            "agreeing_source_provenance": provenance,
        }
        overlay_row["overlay_record_sha256"] = _canonical_sha(overlay_row)
        rows.append(overlay_row)
    artifact: dict[str, object] = {
        "schema_version": "stage2_control_trace_completion_overlay.v1",
        "decision": "COMPLETE_NON_AUTHORIZING",
        "approved_specification_sha256": APPROVED_SPEC_SHA256,
        "original_target_count": len(original_by_id),
        "source_complete_count": len(source_ids),
        "retry_target_count": len(retry_ids),
        "completed_target_count": len(rows),
        "retry_targets_file_sha256": retry_targets_file_sha256,
        "retry_targets_sha256": retry_targets_payload["retry_targets_sha256"],
        "retry_targets_verification_sha256": retry_targets_verification_sha256,
        "retry_checkpoint_file_sha256": retry_source.checkpoint_file_sha256,
        "retry_checkpoint_sha256": retry_source.checkpoint_sha256,
        "targets": rows,
        **FALSE_AUTHORITY,
    }
    artifact["overlay_sha256"] = _canonical_sha(artifact)
    verify_completion_overlay_payload(artifact)
    return artifact


def verify_completion_overlay_payload(payload: Mapping[str, object]) -> None:
    if payload.get("schema_version") != "stage2_control_trace_completion_overlay.v1":
        raise ControlTraceRetryOverlayError("overlay_schema_invalid")
    if payload.get("decision") != "COMPLETE_NON_AUTHORIZING":
        raise ControlTraceRetryOverlayError("overlay_not_complete")
    _self_hash(payload, "overlay_sha256", "overlay")
    _require_false(payload, "overlay")
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows or not all(isinstance(row, Mapping) for row in rows):
        raise ControlTraceRetryOverlayError("overlay_targets_invalid")
    ids = [str(row.get("target_id", "")) for row in rows]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ControlTraceRetryOverlayError("overlay_target_identity_invalid")
    if payload.get("completed_target_count") != len(rows) or payload.get("original_target_count") != len(rows):
        raise ControlTraceRetryOverlayError("overlay_count_invalid")
    if payload.get("source_complete_count", 0) + payload.get("retry_target_count", 0) != len(rows):
        raise ControlTraceRetryOverlayError("overlay_partition_invalid")
    for row in rows:
        material = {key: value for key, value in row.items() if key != "overlay_record_sha256"}
        if row.get("overlay_record_sha256") != _canonical_sha(material):
            raise ControlTraceRetryOverlayError("overlay_record_self_hash_invalid")
        base = {
            key: value
            for key, value in row.items()
            if key not in {"evidence_origin", "agreeing_source_provenance", "overlay_record_sha256"}
        }
        _self_hash(base, "record_sha256", "overlay_trace_record")
        if row.get("disposition") != "complete" or row.get("evidence_origin") not in {
            "IMMUTABLE_SOURCE_ROOT", "FRESH_RETRY_ROOT"
        }:
            raise ControlTraceRetryOverlayError("overlay_record_invalid")


def build_trace_completion_overlay(
    *,
    retry_targets_path: Path,
    retry_targets_verification_path: Path,
    retry_reconstruction_inputs: Mapping[str, object],
    retry_activation_request_path: Path,
    retry_activation_approval_path: Path,
    retry_activation_signature_path: Path,
    retry_activation_allowed_signers_path: Path,
    retry_activation_verification_path: Path,
    retry_activation_expected_principal: str,
    retry_source: TraceSourceRoot,
    retry_verification_time_utc: str,
) -> dict[str, object]:
    verification = verify_trace_retry_targets(
        artifact_path=retry_targets_path,
        **dict(retry_reconstruction_inputs),
    )
    stored_verification = _load(retry_targets_verification_path, "retry_targets_verification")
    if stored_verification != verification:
        raise ControlTraceRetryOverlayError("retry_targets_verification_mismatch")
    original_targets_path = Path(retry_reconstruction_inputs["original_targets_path"])
    _, original_targets = _load_original_targets(original_targets_path)
    source_specs = retry_reconstruction_inputs.get("sources")
    if not isinstance(source_specs, Sequence):
        raise ControlTraceRetryOverlayError("source_roots_invalid")
    source_verified = [
        verify_trace_source_root(
            source=source,
            original_targets_path=original_targets_path,
            activation_request_path=Path(retry_reconstruction_inputs["activation_request_path"]),
            activation_approval_path=Path(retry_reconstruction_inputs["activation_approval_path"]),
            activation_signature_path=Path(retry_reconstruction_inputs["activation_signature_path"]),
            activation_allowed_signers_path=Path(retry_reconstruction_inputs["activation_allowed_signers_path"]),
            activation_verification_path=Path(retry_reconstruction_inputs["activation_verification_path"]),
            activation_expected_principal=str(retry_reconstruction_inputs["activation_expected_principal"]),
        )
        for source in source_specs
        if isinstance(source, TraceSourceRoot)
    ]
    if len(source_verified) != len(source_specs):
        raise ControlTraceRetryOverlayError("source_roots_invalid")
    source_union = build_complete_source_union(source_verified)
    retry_verified = verify_trace_source_root(
        source=retry_source,
        original_targets_path=retry_targets_path,
        activation_request_path=retry_activation_request_path,
        activation_approval_path=retry_activation_approval_path,
        activation_signature_path=retry_activation_signature_path,
        activation_allowed_signers_path=retry_activation_allowed_signers_path,
        activation_verification_path=retry_activation_verification_path,
        activation_expected_principal=retry_activation_expected_principal,
        verification_time_utc=retry_verification_time_utc,
        retry_reconstruction_inputs=retry_reconstruction_inputs,
    )
    retry_payload = _load(retry_targets_path, "retry_targets")
    return build_completion_overlay_from_verified(
        original_targets=original_targets,
        source_union=source_union,
        retry_source=retry_verified,
        retry_targets_payload=retry_payload,
        retry_targets_file_sha256=_file_sha(_ordinary(retry_targets_path, "retry_targets")),
        retry_targets_verification_sha256=str(verification["verification_sha256"]),
    )


def verify_trace_completion_overlay(
    *, overlay_path: Path, **reconstruction_inputs: Any
) -> dict[str, object]:
    overlay_file = _ordinary(overlay_path, "overlay")
    supplied = _load(overlay_file, "overlay")
    verify_completion_overlay_payload(supplied)
    rebuilt = build_trace_completion_overlay(**reconstruction_inputs)
    if supplied != rebuilt:
        raise ControlTraceRetryOverlayError("overlay_reconstruction_mismatch")
    report: dict[str, object] = {
        "schema_version": "stage2_control_trace_completion_overlay_verification.v1",
        "decision": "COMPLETE_NON_AUTHORIZING",
        "verified": True,
        "overlay_file_sha256": _file_sha(overlay_file),
        "overlay_sha256": supplied["overlay_sha256"],
        "completed_target_count": supplied["completed_target_count"],
        **FALSE_AUTHORITY,
    }
    report["verification_sha256"] = _canonical_sha(report)
    return report
