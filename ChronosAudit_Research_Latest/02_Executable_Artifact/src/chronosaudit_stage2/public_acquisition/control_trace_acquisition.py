from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
import subprocess
from typing import Any

from chronosaudit_stage2.deployment_stream import (
    canonical_creation_set,
    creations_from_geth_calltracer,
    creations_from_parity_traces,
)
from chronosaudit_stage2.onchain import ProviderObservation

from .control_trace_state_activation import (
    authorize_rpc_call,
    verify_trace_state_activation,
)


TRACE_RUN_SCHEMA = "stage2_control_trace_acquisition_run.v1"
TRACE_EVENT_SCHEMA = "stage2_control_trace_acquisition_event.v1"
TRACE_RESULTS_SCHEMA = "stage2_control_trace_acquisition_results.v1"
TRACE_CHECKPOINT_SCHEMA = "stage2_control_trace_acquisition_checkpoint.v1"
TRACE_SUMMARY_SCHEMA = "stage2_control_trace_acquisition_summary.v1"
CHECKPOINT_NAMESPACE = "chronosaudit-stage2-control-trace-acquisition-local-test-v1"
_TRANSIENT_MARKERS = (
    "rate",
    "limit",
    "timeout",
    "temporar",
    "internal error",
    "precondition failure",
)
_UNSUPPORTED_MARKERS = ("unsupported", "method not found", "not implemented")


class ControlTraceAcquisitionError(ValueError):
    """Raised when a trace run violates its frozen activation or resume binding."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_checkpoint_payload(checkpoint: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(checkpoint)) + "\n").encode("utf-8")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlTraceAcquisitionError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlTraceAcquisitionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlTraceAcquisitionError(f"{label}_not_ordinary_file")
    return resolved


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlTraceAcquisitionError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _append_event(path: Path, event: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlTraceAcquisitionError("event_ledger_symlink")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(dict(event)) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _load_json(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlTraceAcquisitionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlTraceAcquisitionError(f"{label}_root_invalid")
    return payload


def reverify_trace_activation_for_execution(
    *,
    activation_verification_path: Path,
    request: Mapping[str, object],
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    """Cryptographically reverify the exact activation immediately before RPC."""
    stored = _load_json(
        activation_verification_path, "activation_verification"
    )
    reverified = verify_trace_state_activation(
        request=request,
        approval_path=approval_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_signers_path,
        expected_principal=expected_principal,
        verification_time_utc=verification_time_utc,
    )
    if stored != reverified:
        raise ControlTraceAcquisitionError(
            "activation_cryptographic_reverification_mismatch"
        )
    return reverified


def _validate_activation(activation: Mapping[str, object], trace_targets_sha256: str) -> None:
    if activation.get("schema_version") != (
        "stage2_control_trace_state_activation_verification.v1"
    ):
        raise ControlTraceAcquisitionError("activation_schema_invalid")
    if activation.get("decision") != "TRACE_STATE_RPC_ACTIVATION_VERIFIED":
        raise ControlTraceAcquisitionError("activation_not_verified")
    material = {
        key: value for key, value in activation.items()
        if key != "verification_sha256"
    }
    if activation.get("verification_sha256") != _canonical_sha(material):
        raise ControlTraceAcquisitionError("activation_self_hash_invalid")
    if activation.get("rpc_authorized") is not True:
        raise ControlTraceAcquisitionError("rpc_not_authorized")
    for flag in (
        "acquisition_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if activation.get(flag) is not False:
            raise ControlTraceAcquisitionError(f"activation_{flag}_invalid")
    if activation.get("trace_targets_sha256") != trace_targets_sha256:
        raise ControlTraceAcquisitionError("trace_targets_hash_mismatch")
    scopes = activation.get("rpc_call_scopes")
    if not isinstance(scopes, list) or not scopes:
        raise ControlTraceAcquisitionError("rpc_call_scopes_invalid")
    if activation.get("unmaterialized_state_calls_authorized") is not False:
        raise ControlTraceAcquisitionError(
            "unmaterialized_state_calls_authorized_invalid"
        )
    if activation.get("activation_stage") == "TRACE_ONLY_PRE_STATE_DERIVATION":
        if (
            activation.get("state_target_count") != 0
            or activation.get("state_targets_sha256") is not None
            or any(
                not isinstance(scope, Mapping)
                or scope.get("target_type") != "trace"
                for scope in scopes
            )
        ):
            raise ControlTraceAcquisitionError("trace_only_scope_invalid")
    trace_scopes = [
        scope for scope in scopes
        if isinstance(scope, Mapping) and scope.get("target_type") == "trace"
    ]
    by_target: dict[str, set[str]] = {}
    for scope in trace_scopes:
        by_target.setdefault(str(scope.get("target_id", "")), set()).add(
            str(scope.get("operator_family", ""))
        )
    if not by_target or any(
        "" in families or "unverified" in families or len(families) < 2
        for families in by_target.values()
    ):
        raise ControlTraceAcquisitionError("provider_family_independence")


def _target_rows(
    path: Path,
    *,
    retry_reconstruction_inputs: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = _load_json(path, "trace_targets")
    schema = payload.get("schema_version")
    if schema != "stage2_control_trace_targets.v1":
        if (
            schema == "stage2_control_trace_retry_targets.v1"
            and retry_reconstruction_inputs is not None
        ):
            try:
                from .control_trace_retry_overlay import verify_trace_retry_targets

                verification = verify_trace_retry_targets(
                    artifact_path=path,
                    **dict(retry_reconstruction_inputs),
                )
            except Exception as exc:
                raise ControlTraceAcquisitionError(
                    "trace_retry_targets_invalid"
                ) from exc
            if verification.get("decision") != (
                "TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING"
            ):
                raise ControlTraceAcquisitionError(
                    "trace_retry_targets_invalid"
                )
        else:
            raise ControlTraceAcquisitionError("trace_targets_schema_invalid")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets or not all(
        isinstance(target, dict) for target in targets
    ):
        raise ControlTraceAcquisitionError("trace_targets_invalid")
    ids = [str(target.get("target_id", "")) for target in targets]
    if any(not target_id for target_id in ids) or len(ids) != len(set(ids)):
        raise ControlTraceAcquisitionError("trace_target_identity_invalid")
    return sorted(targets, key=lambda row: str(row["target_id"]))


def _scope_for_target(
    activation: Mapping[str, object], target_id: str
) -> list[dict[str, object]]:
    scopes = [
        dict(scope)
        for scope in activation["rpc_call_scopes"]
        if isinstance(scope, Mapping)
        and scope.get("target_type") == "trace"
        and scope.get("target_id") == target_id
    ]
    families = {str(scope.get("operator_family", "")) for scope in scopes}
    if len(families) < 2 or "unverified" in families or "" in families:
        raise ControlTraceAcquisitionError("provider_family_independence")
    return sorted(scopes, key=lambda row: (str(row["provider_id"]), str(row["method"])))


def _persist_raw(
    raw_root: Path,
    *,
    sequence: int,
    kind: str,
    provider_id: str,
    method: str,
    payload: Mapping[str, object],
) -> tuple[str, str]:
    safe_provider = "".join(character if character.isalnum() or character in "_.-" else "_"
                            for character in provider_id)
    safe_method = "".join(character if character.isalnum() or character in "_.-" else "_"
                          for character in method)
    path = raw_root / f"{sequence:06d}-{safe_provider}-{safe_method}-{kind}.json"
    _atomic_json(path, payload)
    return path.relative_to(raw_root.parent).as_posix(), _sha(path)


def _parse_creation_set(
    *, target: Mapping[str, object], method: str, result: object
) -> tuple[tuple[object, ...], ...]:
    chain = str(target["chain"])
    block_number = int(target["block_number"])
    block_hash = str(target["block_hash"])
    transaction_hash = str(target["transaction_hash"])
    if method in {"trace_transaction", "trace_block"}:
        if not isinstance(result, list):
            raise ControlTraceAcquisitionError("malformed_response")
        records = creations_from_parity_traces(
            chain, block_number, block_hash, result
        )
    elif method == "debug_traceTransaction":
        if not isinstance(result, dict):
            raise ControlTraceAcquisitionError("malformed_response")
        records = creations_from_geth_calltracer(
            chain,
            block_number,
            block_hash,
            [{"txHash": transaction_hash, "result": result}],
        )
    elif method == "debug_traceBlockByNumber":
        if not isinstance(result, list):
            raise ControlTraceAcquisitionError("malformed_response")
        records = creations_from_geth_calltracer(
            chain, block_number, block_hash, result
        )
    else:
        raise ControlTraceAcquisitionError("method_not_activated")
    return canonical_creation_set(records)


def _event(
    *,
    previous_event_sha256: str | None,
    sequence: int,
    activation_sha256: str,
    target: Mapping[str, object],
    scope: Mapping[str, object],
    request_path: str,
    request_sha256: str,
    response_path: str,
    response_sha256: str,
    normalized_creation_set_sha256: str | None,
    disposition: str,
) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": TRACE_EVENT_SCHEMA,
        "previous_event_sha256": previous_event_sha256,
        "sequence": sequence,
        "activation_verification_sha256": activation_sha256,
        "target_id": target["target_id"],
        "target_sha256": _canonical_sha(target),
        "provider_id": scope["provider_id"],
        "operator_family": scope["operator_family"],
        "method": scope["method"],
        "params_sha256": scope["params_sha256"],
        "call_scope_sha256": scope["call_scope_sha256"],
        "request_path": request_path,
        "request_sha256": request_sha256,
        "response_path": response_path,
        "response_sha256": response_sha256,
        "normalized_creation_set_sha256": normalized_creation_set_sha256,
        "disposition": disposition,
    }
    event["event_sha256"] = _canonical_sha(event)
    return event


def _persist_progress(
    *,
    output: Path,
    ledger_path: Path,
    activation_sha: str,
    target_sha: str,
    target_count: int,
    target_results: list[dict[str, object]],
    request_count: int,
    used_sequences: set[int],
    previous_event_sha: str | None,
) -> tuple[dict[str, object], dict[str, object], dict[str, int], str]:
    completed = sum(row["disposition"] == "complete" for row in target_results)
    dispositions = dict(sorted(Counter(str(row["disposition"]) for row in target_results).items()))
    results: dict[str, object] = {
        "schema_version": TRACE_RESULTS_SCHEMA,
        "activation_verification_sha256": activation_sha,
        "trace_targets_sha256": target_sha,
        "target_count": target_count,
        "processed_target_count": len(target_results),
        "completed_target_count": completed,
        "dispositions": dispositions,
        "targets": target_results,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    results["results_sha256"] = _canonical_sha(results)
    results_path = output / "normalized-trace-results.json"
    _atomic_json(results_path, results)
    if len(target_results) < target_count:
        status = "IN_PROGRESS_NON_AUTHORIZING"
    elif completed == target_count:
        status = "COMPLETE"
    else:
        status = "PARTIAL_NON_AUTHORIZING"
    checkpoint: dict[str, object] = {
        "schema_version": TRACE_CHECKPOINT_SCHEMA,
        "status": status,
        "activation_verification_sha256": activation_sha,
        "trace_targets_sha256": target_sha,
        "target_count": target_count,
        "processed_target_count": len(target_results),
        "completed_target_count": completed,
        "processed_target_ids": [row["target_id"] for row in target_results],
        "completed_target_ids": [
            row["target_id"] for row in target_results if row["disposition"] == "complete"
        ],
        "request_count": request_count,
        "used_sequences": sorted(used_sequences),
        "event_tip_sha256": previous_event_sha,
        "event_ledger_path": ledger_path.relative_to(output).as_posix(),
        "event_ledger_sha256": _sha(ledger_path),
        "normalized_results_path": results_path.relative_to(output).as_posix(),
        "normalized_results_sha256": _sha(results_path),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    checkpoint["checkpoint_sha256"] = _canonical_sha(checkpoint)
    _atomic_json(output / "checkpoint.json", checkpoint)
    return results, checkpoint, dispositions, status


def execute_control_trace_acquisition(
    *,
    activation: Mapping[str, object],
    unresolved_trace_path: Path,
    output_root: Path,
    transport: Callable[[str, str, list[object]], ProviderObservation],
    now_utc: str,
    retry_reconstruction_inputs: Mapping[str, object] | None = None,
    _resume_checkpoint: Mapping[str, object] | None = None,
    _existing_results: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Execute exact activated trace calls and emit non-authorizing evidence."""
    target_file = _ordinary(unresolved_trace_path, "trace_targets")
    target_sha = _sha(target_file)
    _validate_activation(activation, target_sha)
    targets = _target_rows(
        target_file,
        retry_reconstruction_inputs=retry_reconstruction_inputs,
    )
    output = output_root.expanduser()
    if output.is_symlink():
        raise ControlTraceAcquisitionError("output_root_symlink")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    ledger_path = output / "trace-events.jsonl"
    if ledger_path.exists() and _resume_checkpoint is None:
        raise ControlTraceAcquisitionError("existing_run_requires_resume")
    raw_root = output / "raw"
    raw_root.mkdir(exist_ok=_resume_checkpoint is not None)

    if _resume_checkpoint is None:
        used_sequences: set[int] = set()
        request_count = 0
        sequence = 0
        previous_event_sha: str | None = None
        target_results: list[dict[str, object]] = []
    else:
        used_sequences = {int(value) for value in _resume_checkpoint["used_sequences"]}
        request_count = int(_resume_checkpoint["request_count"])
        sequence = max(used_sequences, default=0)
        previous_event_sha = str(_resume_checkpoint.get("event_tip_sha256") or "") or None
        existing_rows = (_existing_results or {}).get("targets")
        if not isinstance(existing_rows, list) or not all(isinstance(row, dict) for row in existing_rows):
            raise ControlTraceAcquisitionError("resume_results_invalid")
        target_results = [dict(row) for row in existing_rows]
    processed_target_ids = {str(row["target_id"]) for row in target_results}
    retry_limit = int(activation.get("retry_limit", 0))
    activation_sha = str(activation.get("verification_sha256", ""))
    for target in targets:
        target_id = str(target["target_id"])
        if target_id in processed_target_ids:
            continue
        scopes = _scope_for_target(activation, target_id)
        expected_calls = target.get("calls")
        if not isinstance(expected_calls, list) or len(expected_calls) != len(scopes):
            raise ControlTraceAcquisitionError("target_scope_count_mismatch")
        provider_sets: list[tuple[dict[str, object], tuple[tuple[object, ...], ...]]] = []
        terminal_disposition: str | None = None
        for scope in scopes:
            observation: ProviderObservation | None = None
            normalized: tuple[tuple[object, ...], ...] | None = None
            call_disposition = "malformed_response"
            for attempt in range(retry_limit + 1):
                sequence += 1
                authorization = authorize_rpc_call(
                    activation,
                    target_id=target_id,
                    chain=str(target["chain"]),
                    provider_id=str(scope["provider_id"]),
                    method=str(scope["method"]),
                    params=list(scope["params"]),
                    sequence_number=sequence,
                    used_sequences=used_sequences,
                    requests_used=request_count,
                    now_utc=now_utc,
                )
                used_sequences.add(sequence)
                request_count += 1
                request_payload = {
                    "schema_version": "stage2_control_trace_rpc_request.v1",
                    "sequence": sequence,
                    "target_id": target_id,
                    "provider_id": scope["provider_id"],
                    "method": scope["method"],
                    "params": scope["params"],
                    "call_scope_sha256": authorization["call_scope_sha256"],
                }
                request_path, request_sha = _persist_raw(
                    raw_root,
                    sequence=sequence,
                    kind="request",
                    provider_id=str(scope["provider_id"]),
                    method=str(scope["method"]),
                    payload=request_payload,
                )
                observation = transport(
                    str(scope["provider_id"]),
                    str(scope["method"]),
                    list(scope["params"]),
                )
                if not isinstance(observation, ProviderObservation):
                    raise ControlTraceAcquisitionError("provider_observation_invalid")
                response_payload = {
                    "schema_version": "stage2_control_trace_rpc_response.v1",
                    "sequence": sequence,
                    "provider_id": observation.provider_id,
                    "method": observation.method,
                    "params": observation.params,
                    "result": observation.result,
                    "error": observation.error,
                    "observed_at_unix": observation.observed_at_unix,
                    "observed_at_utc": observation.observed_at_utc,
                    "http_status": observation.http_status,
                    "attempt": attempt + 1,
                    "transport_request_sha256": observation.request_sha256,
                    "transport_response_sha256": observation.response_sha256,
                }
                response_path, response_sha = _persist_raw(
                    raw_root,
                    sequence=sequence,
                    kind="response",
                    provider_id=str(scope["provider_id"]),
                    method=str(scope["method"]),
                    payload=response_payload,
                )
                if observation.error is None:
                    try:
                        normalized = _parse_creation_set(
                            target=target,
                            method=str(scope["method"]),
                            result=observation.result,
                        )
                        call_disposition = "complete"
                    except ControlTraceAcquisitionError:
                        call_disposition = "malformed_response"
                    should_retry = False
                else:
                    lowered = observation.error.lower()
                    call_disposition = (
                        "method_unsupported"
                        if any(marker in lowered for marker in _UNSUPPORTED_MARKERS)
                        else "retry_exhausted"
                    )
                    should_retry = (
                        attempt < retry_limit
                        and any(marker in lowered for marker in _TRANSIENT_MARKERS)
                    )
                normalized_sha = _canonical_sha(normalized) if normalized is not None else None
                event = _event(
                    previous_event_sha256=previous_event_sha,
                    sequence=sequence,
                    activation_sha256=activation_sha,
                    target=target,
                    scope=scope,
                    request_path=request_path,
                    request_sha256=request_sha,
                    response_path=response_path,
                    response_sha256=response_sha,
                    normalized_creation_set_sha256=normalized_sha,
                    disposition=("retrying" if should_retry else call_disposition),
                )
                _append_event(ledger_path, event)
                previous_event_sha = str(event["event_sha256"])
                if not should_retry:
                    break
            if call_disposition != "complete" or normalized is None:
                terminal_disposition = call_disposition
                break
            provider_sets.append((scope, normalized))

        if terminal_disposition is None:
            semantic_sets = {value for _, value in provider_sets}
            if len(semantic_sets) != 1:
                terminal_disposition = "trace_disagreement"
            else:
                agreed = next(iter(semantic_sets))
                address = str(target["chain_address"]).split(":", 1)[-1].lower()
                if address not in {str(row[1]).lower() for row in agreed}:
                    terminal_disposition = "candidate_missing"
                else:
                    terminal_disposition = "complete"
        agreed_set = (
            provider_sets[0][1]
            if terminal_disposition == "complete" and provider_sets
            else ()
        )
        row: dict[str, object] = {
            "target_id": target_id,
            "case_id": target["case_id"],
            "chain": target["chain"],
            "chain_address": target["chain_address"],
            "transaction_hash": target["transaction_hash"],
            "block_number": target["block_number"],
            "block_hash": target["block_hash"],
            "reserve_record_sha256": target["reserve_record_sha256"],
            "target_sha256": _canonical_sha(target),
            "provider_ids": [scope["provider_id"] for scope, _ in provider_sets],
            "operator_families": [scope["operator_family"] for scope, _ in provider_sets],
            "creation_set": [list(value) for value in agreed_set],
            "creation_set_sha256": _canonical_sha(agreed_set),
            "disposition": terminal_disposition,
        }
        row["record_sha256"] = _canonical_sha(row)
        target_results.append(row)
        _, _, _, _ = _persist_progress(
            output=output,
            ledger_path=ledger_path,
            activation_sha=activation_sha,
            target_sha=target_sha,
            target_count=len(targets),
            target_results=target_results,
            request_count=request_count,
            used_sequences=used_sequences,
            previous_event_sha=previous_event_sha,
        )

    results, checkpoint, dispositions, status = _persist_progress(
        output=output,
        ledger_path=ledger_path,
        activation_sha=activation_sha,
        target_sha=target_sha,
        target_count=len(targets),
        target_results=target_results,
        request_count=request_count,
        used_sequences=used_sequences,
        previous_event_sha=previous_event_sha,
    )
    completed = int(results["completed_target_count"])
    results_path = output / "normalized-trace-results.json"
    checkpoint_path = output / "checkpoint.json"
    summary: dict[str, object] = {
        "schema_version": TRACE_SUMMARY_SCHEMA,
        "status": status,
        "target_count": len(targets),
        "completed_target_count": completed,
        "dispositions": dispositions,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _canonical_sha(summary)
    summary_path = output / "summary.json"
    _atomic_json(summary_path, summary)
    return {
        **summary,
        "normalized_results_path": str(results_path),
        "event_ledger_path": str(ledger_path),
        "checkpoint_path": str(checkpoint_path),
        "summary_path": str(summary_path),
    }


def _resolved_child(root: Path, relative_value: object, label: str) -> Path:
    relative = Path(str(relative_value or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ControlTraceAcquisitionError("resume_path_escape")
    child = _ordinary(root / relative, label)
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise ControlTraceAcquisitionError("resume_path_escape") from exc
    return child


def resume_trace_acquisition(
    checkpoint_path: Path,
    *,
    transport: Callable[[str, str, list[object]], ProviderObservation],
    activation: Mapping[str, object] | None = None,
    unresolved_trace_path: Path | None = None,
    now_utc: str | None = None,
    retry_reconstruction_inputs: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Validate a checkpoint before skipping or continuing any target."""
    checkpoint_file = _ordinary(checkpoint_path, "checkpoint")
    checkpoint = _load_json(checkpoint_file, "checkpoint")
    if checkpoint.get("schema_version") != TRACE_CHECKPOINT_SCHEMA:
        raise ControlTraceAcquisitionError("checkpoint_schema_invalid")
    material = {key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"}
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(material):
        raise ControlTraceAcquisitionError("checkpoint_self_hash_invalid")
    root = checkpoint_file.parent.resolve(strict=True)
    results_path = _resolved_child(
        root, checkpoint.get("normalized_results_path"), "normalized_results"
    )
    ledger_path = _resolved_child(root, checkpoint.get("event_ledger_path"), "event_ledger")
    if (
        _sha(results_path) != checkpoint.get("normalized_results_sha256")
        or _sha(ledger_path) != checkpoint.get("event_ledger_sha256")
    ):
        raise ControlTraceAcquisitionError("resume_hash_mismatch")
    if checkpoint.get("status") == "COMPLETE":
        return {
            "status": "COMPLETE",
            "target_count": checkpoint["target_count"],
            "completed_target_count": checkpoint["completed_target_count"],
            "normalized_results_path": str(results_path),
            "event_ledger_path": str(ledger_path),
            "checkpoint_path": str(checkpoint_file),
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
    if checkpoint.get("status") == "PARTIAL_NON_AUTHORIZING":
        return {
            "status": "PARTIAL_NON_AUTHORIZING",
            "target_count": checkpoint["target_count"],
            "completed_target_count": checkpoint["completed_target_count"],
            "normalized_results_path": str(results_path),
            "event_ledger_path": str(ledger_path),
            "checkpoint_path": str(checkpoint_file),
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        }
    if activation is None or unresolved_trace_path is None or now_utc is None:
        raise ControlTraceAcquisitionError("resume_inputs_required")
    results = _load_json(results_path, "normalized_results")
    return execute_control_trace_acquisition(
        activation=activation,
        unresolved_trace_path=unresolved_trace_path,
        output_root=root,
        transport=transport,
        now_utc=now_utc,
        retry_reconstruction_inputs=retry_reconstruction_inputs,
        _resume_checkpoint=checkpoint,
        _existing_results=results,
    )


def verify_trace_checkpoint_signature(
    *,
    checkpoint_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
) -> dict[str, object]:
    """Verify the purpose-specific local-test signature on one checkpoint."""
    checkpoint_file = _ordinary(checkpoint_path, "checkpoint")
    signature_file = _ordinary(signature_path, "signature")
    allowed_signers_file = _ordinary(allowed_signers_path, "allowed_signers")
    checkpoint = _load_json(checkpoint_file, "checkpoint")
    if checkpoint.get("schema_version") != TRACE_CHECKPOINT_SCHEMA:
        raise ControlTraceAcquisitionError("checkpoint_schema_invalid")
    material = {
        key: value for key, value in checkpoint.items()
        if key != "checkpoint_sha256"
    }
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(material):
        raise ControlTraceAcquisitionError("checkpoint_self_hash_invalid")
    for flag in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if checkpoint.get(flag) is not False:
            raise ControlTraceAcquisitionError(f"checkpoint_{flag}_invalid")
    principal = expected_principal.strip()
    if not principal:
        raise ControlTraceAcquisitionError("signer_principal_invalid")
    verification = subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed_signers_file),
            "-I",
            principal,
            "-n",
            CHECKPOINT_NAMESPACE,
            "-s",
            str(signature_file),
        ],
        input=canonical_checkpoint_payload(checkpoint),
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise ControlTraceAcquisitionError("checkpoint_signature_invalid")
    result: dict[str, object] = {
        "schema_version": "stage2_control_trace_acquisition_checkpoint_verification.v1",
        "complete": True,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "checkpoint_file_sha256": _sha(checkpoint_file),
        "signature_sha256": _sha(signature_file),
        "allowed_signers_sha256": _sha(allowed_signers_file),
        "signature_namespace": CHECKPOINT_NAMESPACE,
        "signer_principal": principal,
        "status": checkpoint["status"],
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "identity_binding_limit": "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY",
        "errors": [],
    }
    result["verification_sha256"] = _canonical_sha(result)
    return result
