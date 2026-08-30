from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_activation import (
    authorize_boundary_rpc_call,
)


RESULT_SCHEMA = "stage2_control_cutoff_boundary_result.v1"
RESULTS_SCHEMA = "stage2_control_cutoff_boundary_results.v1"
CHECKPOINT_SCHEMA = "stage2_control_cutoff_boundary_checkpoint.v1"


class ControlCutoffBoundaryResolutionError(ValueError):
    """Raised when a dual-provider cutoff bracket cannot be proven."""


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


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCutoffBoundaryResolutionError("raw_output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _cutoff_epoch(value: object) -> int:
    try:
        parsed = datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ControlCutoffBoundaryResolutionError("cutoff_timestamp_invalid") from exc
    return int(parsed.timestamp())


def _validate_target(target: Mapping[str, object]) -> None:
    if target.get("schema_version") != (
        "stage2_control_cutoff_boundary_requirement.v1"
    ):
        raise ControlCutoffBoundaryResolutionError("target_schema_invalid")
    material = {key: value for key, value in target.items() if key != "target_sha256"}
    if target.get("target_sha256") != _canonical_sha(material):
        raise ControlCutoffBoundaryResolutionError("target_self_hash_invalid")
    for field in (
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if target.get(field) is not False:
            raise ControlCutoffBoundaryResolutionError(f"target_{field}_invalid")
    if target.get("search_algorithm") != "DETERMINISTIC_INTEGER_BINARY_SEARCH_V1":
        raise ControlCutoffBoundaryResolutionError("search_algorithm_invalid")
    try:
        lower = int(target.get("lower_bound_block", -1))
        upper = int(target.get("upper_bound_block", -1))
        maximum = int(target.get("maximum_block_header_queries_per_provider", -1))
    except (TypeError, ValueError) as exc:
        raise ControlCutoffBoundaryResolutionError("target_range_invalid") from exc
    if lower < 0 or upper <= lower or maximum <= 0:
        raise ControlCutoffBoundaryResolutionError("target_range_invalid")
    _cutoff_epoch(target.get("cutoff_timestamp"))


def _header(value: object, expected_number: int) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ControlCutoffBoundaryResolutionError("block_header_malformed")
    try:
        number = int(str(value["number"]), 16)
        timestamp = int(str(value["timestamp"]), 16)
        block_hash = str(value["hash"]).strip().lower()
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlCutoffBoundaryResolutionError("block_header_malformed") from exc
    if (
        number != expected_number
        or timestamp < 0
        or len(block_hash) != 66
        or not block_hash.startswith("0x")
        or any(character not in "0123456789abcdef" for character in block_hash[2:])
    ):
        raise ControlCutoffBoundaryResolutionError("block_header_malformed")
    return {"number": number, "hash": block_hash, "timestamp": timestamp}


def resolve_cutoff_boundary(
    *,
    target: Mapping[str, object],
    providers: list[object],
    activation: Mapping[str, object],
    raw_root: str | Path,
    now_utc: str,
    run_state: dict[str, object] | None = None,
    provider_min_intervals: Mapping[str, float] | None = None,
) -> dict[str, object]:
    """Resolve one cutoff bracket by deterministic search on two families.

    This produces evidence only. It grants no selection, qualification, counter,
    stage-promotion, or Recovery3 authority.
    """
    _validate_target(target)
    if len(providers) != 2:
        raise ControlCutoffBoundaryResolutionError("provider_count_invalid")
    provider_ids = [str(getattr(provider, "provider_id", "")).strip() for provider in providers]
    families = [
        str(getattr(provider, "provider_family", "")).strip().lower()
        for provider in providers
    ]
    if (
        any(not value for value in provider_ids + families)
        or len(set(provider_ids)) != 2
        or len(set(families)) != 2
        or "unverified" in families
    ):
        raise ControlCutoffBoundaryResolutionError("provider_family_independence")
    intervals: dict[str, float] = {}
    for provider_id, raw_interval in dict(provider_min_intervals or {}).items():
        if str(provider_id) not in provider_ids:
            continue
        try:
            interval = float(raw_interval)
        except (TypeError, ValueError) as exc:
            raise ControlCutoffBoundaryResolutionError(
                "provider_min_interval_invalid"
            ) from exc
        if interval < 0 or interval > 5:
            raise ControlCutoffBoundaryResolutionError(
                "provider_min_interval_invalid"
            )
        if interval > 0:
            intervals[str(provider_id)] = interval

    scopes = activation.get("range_scopes")
    target_id = str(target["target_id"])
    chain = str(target["chain"]).strip().lower()
    if not isinstance(scopes, list):
        raise ControlCutoffBoundaryResolutionError("activation_scopes_invalid")
    target_scopes = [
        scope
        for scope in scopes
        if isinstance(scope, Mapping)
        and scope.get("target_id") == target_id
        and scope.get("chain") == chain
    ]
    scope_bindings = {
        (str(scope.get("provider_id", "")), str(scope.get("operator_family", "")).lower())
        for scope in target_scopes
    }
    if (
        len(target_scopes) != 2
        or scope_bindings != set(zip(provider_ids, families, strict=True))
        or any(scope.get("target_sha256") != target["target_sha256"] for scope in target_scopes)
    ):
        raise ControlCutoffBoundaryResolutionError("activation_scope_mismatch")

    root = Path(raw_root).expanduser().resolve(strict=False)
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise ControlCutoffBoundaryResolutionError("raw_root_invalid")
    root.mkdir(parents=True, exist_ok=True)
    cutoff = _cutoff_epoch(target["cutoff_timestamp"])
    lower = int(target["lower_bound_block"])
    upper = int(target["upper_bound_block"])
    if run_state is None:
        run_state = {
            "sequence": 0,
            "requests_used": 0,
            "used_sequences": set(),
            "scope_requests_used": {},
            "request_evidence": [],
        }
    used_sequences = run_state.get("used_sequences")
    scope_counts = run_state.get("scope_requests_used")
    request_evidence = run_state.get("request_evidence")
    if (
        not isinstance(used_sequences, set)
        or not isinstance(scope_counts, dict)
        or not isinstance(request_evidence, list)
    ):
        raise ControlCutoffBoundaryResolutionError("run_state_invalid")
    raw_evidence: list[dict[str, object]] = []
    provider_results: list[dict[str, object]] = []

    for provider in providers:
        provider_id = str(provider.provider_id)
        family = str(provider.provider_family).lower()
        low = lower
        high = upper
        best: dict[str, object] | None = None
        cache: dict[int, dict[str, object]] = {}
        matching_scope = next(
            scope
            for scope in target_scopes
            if scope.get("provider_id") == provider_id
        )
        scope_sha = str(matching_scope["range_scope_sha256"])

        def fetch(number: int) -> dict[str, object]:
            if number in cache:
                return cache[number]
            params: list[object] = [hex(number), False]
            sequence = int(run_state["sequence"]) + 1
            requests_used = int(run_state["requests_used"])
            scope_requests_used = int(scope_counts.get(scope_sha, 0))
            authorization = authorize_boundary_rpc_call(
                activation,
                target_id=target_id,
                chain=chain,
                provider_id=provider_id,
                method="eth_getBlockByNumber",
                params=params,
                sequence_number=sequence,
                used_sequences=used_sequences,
                requests_used=requests_used,
                scope_requests_used=scope_requests_used,
                now_utc=now_utc,
            )
            interval = intervals.get(provider_id, 0.0)
            if interval > 0:
                time.sleep(interval)
            observation = provider.call("eth_getBlockByNumber", params)
            envelope = {
                "schema_version": "stage2_control_cutoff_boundary_raw_rpc.v1",
                "sequence_number": sequence,
                "authorization": authorization,
                "target_id": target_id,
                "chain": chain,
                "provider_id": provider_id,
                "operator_family": family,
                "method": "eth_getBlockByNumber",
                "params": params,
                "result": observation.result,
                "observed_at_unix": observation.observed_at_unix,
                "error": observation.error,
            }
            safe_provider = "".join(
                character if character.isalnum() or character in "_.-" else "_"
                for character in provider_id
            )
            path = root / f"{sequence:06d}-{safe_provider}-{number}.json"
            _atomic_json(path, envelope)
            digest = _file_sha(path)
            evidence_record = {
                "sequence_number": sequence,
                "target_id": target_id,
                "provider_id": provider_id,
                "block_number": number,
                "path": str(path),
                "sha256": digest,
                "succeeded": observation.error is None,
            }
            raw_evidence.append(evidence_record)
            request_evidence.append(evidence_record)
            used_sequences.add(sequence)
            run_state["sequence"] = sequence
            run_state["requests_used"] = requests_used + 1
            scope_counts[scope_sha] = scope_requests_used + 1
            if observation.error is not None:
                raise ControlCutoffBoundaryResolutionError("provider_error")
            header = _header(observation.result, number)
            cache[number] = header
            return header

        while low <= high:
            middle = (low + high) // 2
            current = fetch(middle)
            if int(current["timestamp"]) <= cutoff:
                best = current
                low = middle + 1
            else:
                high = middle - 1
        if best is None or int(best["number"]) >= upper:
            raise ControlCutoffBoundaryResolutionError("cutoff_not_bracketed")
        next_header = fetch(int(best["number"]) + 1)
        if (
            int(best["timestamp"]) > cutoff
            or int(next_header["timestamp"]) <= cutoff
            or int(next_header["number"]) != int(best["number"]) + 1
        ):
            raise ControlCutoffBoundaryResolutionError("cutoff_not_bracketed")
        provider_results.append(
            {
                "provider_id": provider_id,
                "operator_family": family,
                "evidence_block": best,
                "next_block": next_header,
                "block_header_query_count": int(scope_counts.get(scope_sha, 0)),
            }
        )

    semantic = [
        {
            "evidence_block": result["evidence_block"],
            "next_block": result["next_block"],
        }
        for result in provider_results
    ]
    if semantic[0] != semantic[1]:
        raise ControlCutoffBoundaryResolutionError("provider_boundary_disagreement")
    evidence_block = semantic[0]["evidence_block"]
    next_block = semantic[0]["next_block"]
    result: dict[str, object] = {
        "schema_version": RESULT_SCHEMA,
        "target_id": target_id,
        "target_sha256": target["target_sha256"],
        "case_id": target["case_id"],
        "chain": chain,
        "cutoff_timestamp": target["cutoff_timestamp"],
        "evidence_block_number": evidence_block["number"],
        "evidence_block_hash": evidence_block["hash"],
        "evidence_block_timestamp": evidence_block["timestamp"],
        "next_block_number": next_block["number"],
        "next_block_hash": next_block["hash"],
        "next_block_timestamp": next_block["timestamp"],
        "pair_scope_record_count": target["pair_scope_record_count"],
        "pair_scope_record_sha256s": target["pair_scope_record_sha256s"],
        "provider_results": provider_results,
        "raw_evidence": raw_evidence,
        "raw_evidence_count": len(raw_evidence),
        "provider_agreement": True,
        "disposition": "complete",
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["result_sha256"] = _canonical_sha(result)
    return result


def _load_json(path: Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ControlCutoffBoundaryResolutionError(f"{label}_not_ordinary")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCutoffBoundaryResolutionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCutoffBoundaryResolutionError(f"{label}_root_invalid")
    return payload


def _requirements(path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    if path.is_symlink() or not path.is_file():
        raise ControlCutoffBoundaryResolutionError("requirements_not_ordinary")
    payload = _load_json(path, "requirements")
    if payload.get("schema_version") != "stage2_control_cutoff_boundary_requirements.v1":
        raise ControlCutoffBoundaryResolutionError("requirements_schema_invalid")
    material = {key: value for key, value in payload.items() if key != "requirements_sha256"}
    if payload.get("requirements_sha256") != _canonical_sha(material):
        raise ControlCutoffBoundaryResolutionError("requirements_self_hash_invalid")
    if payload.get("complete") is not True or payload.get("rpc_authorized") is not False:
        raise ControlCutoffBoundaryResolutionError("requirements_status_invalid")
    for flag in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if payload.get(flag) is not False:
            raise ControlCutoffBoundaryResolutionError(f"requirements_{flag}_invalid")
    targets = payload.get("targets")
    if (
        not isinstance(targets, list)
        or not targets
        or len(targets) != payload.get("boundary_target_count")
        or not all(isinstance(target, dict) for target in targets)
    ):
        raise ControlCutoffBoundaryResolutionError("requirements_targets_invalid")
    for target in targets:
        _validate_target(target)
    ordered = sorted(targets, key=lambda target: str(target["target_id"]))
    if len({str(target["target_id"]) for target in ordered}) != len(ordered):
        raise ControlCutoffBoundaryResolutionError("target_duplicate")
    return payload, ordered


def _validate_batch_activation(
    activation: Mapping[str, object], requirements_path: Path, requirements: Mapping[str, object]
) -> None:
    if activation.get("schema_version") != (
        "stage2_control_cutoff_boundary_activation_verification.v1"
    ) or activation.get("decision") != "CUTOFF_BOUNDARY_RPC_ACTIVATION_VERIFIED":
        raise ControlCutoffBoundaryResolutionError("activation_not_verified")
    material = {
        key: value for key, value in activation.items() if key != "verification_sha256"
    }
    if activation.get("verification_sha256") != _canonical_sha(material):
        raise ControlCutoffBoundaryResolutionError("activation_self_hash_invalid")
    if (
        activation.get("rpc_authorized") is not True
        or activation.get("requirements_file_sha256") != _file_sha(requirements_path)
        or activation.get("requirements_sha256") != requirements.get("requirements_sha256")
    ):
        raise ControlCutoffBoundaryResolutionError("activation_binding_invalid")
    for flag in (
        "acquisition_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if activation.get(flag) is not False:
            raise ControlCutoffBoundaryResolutionError(f"activation_{flag}_invalid")


def _persist_batch(
    *,
    output: Path,
    requirements_path: Path,
    requirements: Mapping[str, object],
    activation: Mapping[str, object],
    target_count: int,
    target_results: list[dict[str, object]],
    run_state: Mapping[str, object],
    last_failure: Mapping[str, object] | None = None,
) -> dict[str, object]:
    completed = sum(row.get("disposition") == "complete" for row in target_results)
    complete = len(target_results) == target_count and completed == target_count
    results: dict[str, object] = {
        "schema_version": RESULTS_SCHEMA,
        "requirements_file_sha256": _file_sha(requirements_path),
        "requirements_sha256": requirements["requirements_sha256"],
        "activation_verification_sha256": activation["verification_sha256"],
        "target_count": target_count,
        "processed_target_count": len(target_results),
        "completed_target_count": completed,
        "complete": complete,
        "targets": target_results,
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    if last_failure is not None:
        results["last_failure"] = dict(last_failure)
    results["results_sha256"] = _canonical_sha(results)
    results_path = output / "cutoff-boundary-results.json"
    _atomic_json(results_path, results)
    status = (
        "PARTIAL_NON_AUTHORIZING"
        if last_failure is not None
        else "COMPLETE_NON_AUTHORIZING"
        if complete
        else "IN_PROGRESS_NON_AUTHORIZING"
        if len(target_results) < target_count
        else "PARTIAL_NON_AUTHORIZING"
    )
    request_evidence = list(run_state["request_evidence"])
    checkpoint: dict[str, object] = {
        "schema_version": CHECKPOINT_SCHEMA,
        "status": status,
        "requirements_file_sha256": _file_sha(requirements_path),
        "requirements_sha256": requirements["requirements_sha256"],
        "activation_verification_sha256": activation["verification_sha256"],
        "target_count": target_count,
        "processed_target_count": len(target_results),
        "completed_target_count": completed,
        "processed_target_ids": [row["target_id"] for row in target_results],
        "sequence": int(run_state["sequence"]),
        "request_count": int(run_state["requests_used"]),
        "used_sequences": sorted(run_state["used_sequences"]),
        "scope_requests_used": dict(sorted(run_state["scope_requests_used"].items())),
        "request_evidence_count": len(request_evidence),
        "request_evidence": request_evidence,
        "results_file_sha256": _file_sha(results_path),
        "results_sha256": results["results_sha256"],
        "counter_authority": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    if last_failure is not None:
        checkpoint["last_failure"] = dict(last_failure)
    checkpoint["checkpoint_sha256"] = _canonical_sha(checkpoint)
    checkpoint_path = output / "checkpoint.json"
    _atomic_json(checkpoint_path, checkpoint)
    summary: dict[str, object] = {
        "status": status,
        "target_count": target_count,
        "processed_target_count": len(target_results),
        "completed_target_count": completed,
        "request_count": int(run_state["requests_used"]),
        "results_path": str(results_path),
        "checkpoint_path": str(checkpoint_path),
        "results_sha256": results["results_sha256"],
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "counter_authority": False,
        "selection_authorized": False,
    }
    if last_failure is not None:
        summary["last_failure"] = dict(last_failure)
    return summary


def _process_targets(
    *,
    targets: list[dict[str, object]],
    start_index: int,
    stop_index: int,
    activation: Mapping[str, object],
    providers_by_id: Mapping[str, object],
    output: Path,
    now_utc: str,
    run_state: dict[str, object],
    target_results: list[dict[str, object]],
    provider_min_intervals: Mapping[str, float] | None,
) -> None:
    scopes = activation.get("range_scopes")
    if not isinstance(scopes, list):
        raise ControlCutoffBoundaryResolutionError("activation_scopes_invalid")
    for target in targets[start_index:stop_index]:
        target_id = str(target["target_id"])
        target_scopes = [
            scope
            for scope in scopes
            if isinstance(scope, Mapping) and scope.get("target_id") == target_id
        ]
        provider_ids = sorted({str(scope.get("provider_id", "")) for scope in target_scopes})
        if len(provider_ids) != 2 or any(provider_id not in providers_by_id for provider_id in provider_ids):
            raise ControlCutoffBoundaryResolutionError("provider_binding_missing")
        providers = [providers_by_id[provider_id] for provider_id in provider_ids]
        target_raw = output / "raw" / str(target["target_sha256"])
        result = resolve_cutoff_boundary(
            target=target,
            providers=providers,
            activation=activation,
            raw_root=target_raw,
            now_utc=now_utc,
            run_state=run_state,
            provider_min_intervals=provider_min_intervals,
        )
        target_results.append(result)


def execute_cutoff_boundary_batch(
    *,
    requirements_path: Path,
    activation: Mapping[str, object],
    providers_by_id: Mapping[str, object],
    output_root: Path,
    now_utc: str,
    max_targets: int | None = None,
    provider_min_intervals: Mapping[str, float] | None = None,
) -> dict[str, object]:
    requirements_file = requirements_path.expanduser().resolve(strict=True)
    requirements, targets = _requirements(requirements_file)
    _validate_batch_activation(activation, requirements_file, requirements)
    if set(provider_min_intervals or {}) - set(providers_by_id):
        raise ControlCutoffBoundaryResolutionError(
            "provider_min_interval_provider_invalid"
        )
    output = output_root.expanduser()
    if output.is_symlink():
        raise ControlCutoffBoundaryResolutionError("output_root_symlink")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    if (output / "checkpoint.json").exists():
        raise ControlCutoffBoundaryResolutionError("existing_run_requires_resume")
    if max_targets is not None and max_targets <= 0:
        raise ControlCutoffBoundaryResolutionError("max_targets_invalid")
    stop = len(targets) if max_targets is None else min(len(targets), max_targets)
    run_state: dict[str, object] = {
        "sequence": 0,
        "requests_used": 0,
        "used_sequences": set(),
        "scope_requests_used": {},
        "request_evidence": [],
    }
    target_results: list[dict[str, object]] = []
    last_failure: dict[str, object] | None = None
    try:
        _process_targets(
            targets=targets,
            start_index=0,
            stop_index=stop,
            activation=activation,
            providers_by_id=providers_by_id,
            output=output,
            now_utc=now_utc,
            run_state=run_state,
            target_results=target_results,
            provider_min_intervals=provider_min_intervals,
        )
    except ControlCutoffBoundaryResolutionError as exc:
        failed_index = len(target_results)
        if failed_index >= len(targets):
            raise
        last_failure = {
            "error_code": str(exc),
            "target_id": str(targets[failed_index]["target_id"]),
        }
    return _persist_batch(
        output=output,
        requirements_path=requirements_file,
        requirements=requirements,
        activation=activation,
        target_count=len(targets),
        target_results=target_results,
        run_state=run_state,
        last_failure=last_failure,
    )


def resume_cutoff_boundary_batch(
    *,
    requirements_path: Path,
    activation: Mapping[str, object],
    providers_by_id: Mapping[str, object],
    output_root: Path,
    now_utc: str,
    max_targets: int | None = None,
    provider_min_intervals: Mapping[str, float] | None = None,
) -> dict[str, object]:
    requirements_file = requirements_path.expanduser().resolve(strict=True)
    requirements, targets = _requirements(requirements_file)
    _validate_batch_activation(activation, requirements_file, requirements)
    if set(provider_min_intervals or {}) - set(providers_by_id):
        raise ControlCutoffBoundaryResolutionError(
            "provider_min_interval_provider_invalid"
        )
    output = output_root.expanduser().resolve(strict=True)
    checkpoint_path = output / "checkpoint.json"
    results_path = output / "cutoff-boundary-results.json"
    checkpoint = _load_json(checkpoint_path, "checkpoint")
    results = _load_json(results_path, "results")
    if checkpoint.get("schema_version") != CHECKPOINT_SCHEMA:
        raise ControlCutoffBoundaryResolutionError("checkpoint_schema_invalid")
    checkpoint_material = {
        key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"
    }
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(checkpoint_material):
        raise ControlCutoffBoundaryResolutionError("checkpoint_self_hash_invalid")
    if results.get("schema_version") != RESULTS_SCHEMA:
        raise ControlCutoffBoundaryResolutionError("results_schema_invalid")
    results_material = {key: value for key, value in results.items() if key != "results_sha256"}
    if results.get("results_sha256") != _canonical_sha(results_material):
        raise ControlCutoffBoundaryResolutionError("results_self_hash_invalid")
    if (
        checkpoint.get("results_file_sha256") != _file_sha(results_path)
        or checkpoint.get("results_sha256") != results.get("results_sha256")
        or checkpoint.get("requirements_file_sha256") != _file_sha(requirements_file)
        or checkpoint.get("requirements_sha256") != requirements.get("requirements_sha256")
        or checkpoint.get("activation_verification_sha256") != activation.get("verification_sha256")
    ):
        raise ControlCutoffBoundaryResolutionError("resume_binding_invalid")
    target_results = results.get("targets")
    if not isinstance(target_results, list):
        raise ControlCutoffBoundaryResolutionError("resume_results_invalid")
    processed_ids = [str(row.get("target_id", "")) for row in target_results if isinstance(row, Mapping)]
    expected_prefix = [str(target["target_id"]) for target in targets[: len(processed_ids)]]
    if processed_ids != expected_prefix or checkpoint.get("processed_target_ids") != processed_ids:
        raise ControlCutoffBoundaryResolutionError("resume_target_prefix_invalid")
    used_sequences = checkpoint.get("used_sequences")
    scope_requests_used = checkpoint.get("scope_requests_used")
    request_evidence = checkpoint.get("request_evidence")
    if (
        not isinstance(used_sequences, list)
        or not isinstance(scope_requests_used, dict)
        or not isinstance(request_evidence, list)
        or checkpoint.get("request_evidence_count") != len(request_evidence)
    ):
        raise ControlCutoffBoundaryResolutionError("resume_run_state_invalid")
    evidence_sequences: list[int] = []
    evidence_paths: set[str] = set()
    for row in request_evidence:
        if not isinstance(row, Mapping):
            raise ControlCutoffBoundaryResolutionError("resume_request_evidence_invalid")
        try:
            sequence = int(row["sequence_number"])
            evidence_path = Path(str(row["path"])).expanduser().resolve(strict=True)
        except (KeyError, TypeError, ValueError, OSError) as exc:
            raise ControlCutoffBoundaryResolutionError(
                "resume_request_evidence_invalid"
            ) from exc
        if (
            evidence_path.is_symlink()
            or not evidence_path.is_file()
            or row.get("sha256") != _file_sha(evidence_path)
            or str(evidence_path) in evidence_paths
        ):
            raise ControlCutoffBoundaryResolutionError(
                "resume_request_evidence_invalid"
            )
        evidence_sequences.append(sequence)
        evidence_paths.add(str(evidence_path))
    if (
        sorted(evidence_sequences) != sorted(int(value) for value in used_sequences)
        or len(evidence_sequences) != int(checkpoint.get("request_count", -1))
    ):
        raise ControlCutoffBoundaryResolutionError("resume_request_evidence_invalid")
    run_state: dict[str, object] = {
        "sequence": int(checkpoint.get("sequence", -1)),
        "requests_used": int(checkpoint.get("request_count", -1)),
        "used_sequences": {int(value) for value in used_sequences},
        "scope_requests_used": {str(key): int(value) for key, value in scope_requests_used.items()},
        "request_evidence": request_evidence,
    }
    remaining = len(targets) - len(target_results)
    if max_targets is not None and max_targets <= 0:
        raise ControlCutoffBoundaryResolutionError("max_targets_invalid")
    count = remaining if max_targets is None else min(remaining, max_targets)
    last_failure: dict[str, object] | None = None
    try:
        _process_targets(
            targets=targets,
            start_index=len(target_results),
            stop_index=len(target_results) + count,
            activation=activation,
            providers_by_id=providers_by_id,
            output=output,
            now_utc=now_utc,
            run_state=run_state,
            target_results=target_results,
            provider_min_intervals=provider_min_intervals,
        )
    except ControlCutoffBoundaryResolutionError as exc:
        failed_index = len(target_results)
        if failed_index >= len(targets):
            raise
        last_failure = {
            "error_code": str(exc),
            "target_id": str(targets[failed_index]["target_id"]),
        }
    return _persist_batch(
        output=output,
        requirements_path=requirements_file,
        requirements=requirements,
        activation=activation,
        target_count=len(targets),
        target_results=target_results,
        run_state=run_state,
        last_failure=last_failure,
    )
