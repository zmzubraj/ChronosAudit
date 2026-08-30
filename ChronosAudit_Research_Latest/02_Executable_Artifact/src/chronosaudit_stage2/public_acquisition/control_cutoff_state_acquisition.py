from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from chronosaudit_stage2.onchain import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    ProviderObservation,
    canonical_block_selector,
    historical_identity_snapshot,
    is_eip1167_minimal_proxy,
    normalize_hex,
    provider_consensus,
    storage_word_to_address,
    strip_solidity_metadata,
)
from chronosaudit_stage2.public_acquisition.control_base_state_activation import (
    authorize_base_state_rpc_call,
)
from chronosaudit_stage2.public_acquisition.control_trace_state_activation import (
    authorize_rpc_call,
)


STATE_RUN_SCHEMA = "stage2_control_cutoff_state_acquisition_run.v1"
STATE_RESULT_SCHEMA = "stage2_control_cutoff_state_result.v1"
STATE_RESULTS_SCHEMA = "stage2_control_cutoff_state_results.v1"
STATE_EVENT_SCHEMA = "stage2_control_cutoff_state_acquisition_event.v1"
STATE_CHECKPOINT_SCHEMA = "stage2_control_cutoff_state_acquisition_checkpoint.v1"
STATE_SUMMARY_SCHEMA = "stage2_control_cutoff_state_acquisition_summary.v1"
CHECKPOINT_NAMESPACE = "chronosaudit-stage2-control-cutoff-state-acquisition-local-test-v1"
_TRANSIENT_ERROR_MARKERS = (
    "timeout",
    "timed out",
    "temporar",
    "rate",
    "limit",
    "connection",
    "reset",
    "unavailable",
    "precondition failure",
    "internal error",
)


class ControlCutoffStateAcquisitionError(ValueError):
    """A frozen cutoff-state target could not be reconstructed safely."""


@dataclass(frozen=True)
class CutoffStateTarget:
    target_id: str
    case_id: str
    chain: str
    chain_address: str
    cutoff_timestamp: int
    evidence_block_number: int
    evidence_block_hash: str
    next_block_number: int
    next_block_hash: str
    pair_scope_record_sha256: str
    denominator_record_sha256: str
    deployment_result_sha256: str


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _consensus_failure_disposition(
    result: Mapping[str, object], *, field: str, disagreement: str
) -> str:
    observations = result.get("observations")
    if isinstance(observations, list) and any(
        isinstance(row, Mapping) and row.get("error") is not None
        for row in observations
    ):
        return f"{field}_provider_error"
    if result.get("normalization_errors"):
        return f"{field}_normalization_error"
    return disagreement


def canonical_checkpoint_payload(checkpoint: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(checkpoint)) + "\n").encode("utf-8")


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCutoffStateAcquisitionError("raw_output_symlink")
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


class _RecordingProvider:
    def __init__(self, provider: object, raw_root: Path, evidence: list[dict[str, str]]) -> None:
        self._provider = provider
        self._raw_root = raw_root
        self._evidence = evidence
        self.provider_id = str(getattr(provider, "provider_id", ""))
        self.provider_family = str(getattr(provider, "provider_family", ""))

    def call(self, method: str, params: list[Any]) -> ProviderObservation:
        observation = self._provider.call(method, params)
        if getattr(self._provider, "_manages_raw_evidence", False):
            raw_path = Path(str(observation.raw_response_path or ""))
            if (
                observation.response_sha256 is None
                or not raw_path.is_file()
                or raw_path.is_symlink()
                or _file_sha(raw_path) != observation.response_sha256
            ):
                raise ControlCutoffStateAcquisitionError("managed_raw_evidence_invalid")
            self._evidence.append(
                {"path": raw_path.name, "sha256": observation.response_sha256}
            )
            return observation
        sequence = len(self._evidence) + 1
        envelope = {
            "schema_version": "stage2_control_cutoff_state_raw_rpc.v1",
            "sequence": sequence,
            "provider_id": self.provider_id,
            "operator_family": self.provider_family,
            "method": method,
            "params": params,
            "result": observation.result,
            "error": observation.error,
            "observed_at_unix": observation.observed_at_unix,
            "observed_at_utc": observation.observed_at_utc,
        }
        safe_provider = "".join(
            character if character.isalnum() or character in "_.-" else "_"
            for character in self.provider_id
        )
        path = self._raw_root / f"{sequence:06d}-{safe_provider}-{method}.json"
        _atomic_json(path, envelope)
        digest = _file_sha(path)
        self._evidence.append({"path": path.name, "sha256": digest})
        return ProviderObservation(
            provider_id=self.provider_id,
            method=observation.method,
            params=observation.params,
            result=observation.result,
            observed_at_unix=observation.observed_at_unix,
            error=observation.error,
            response_sha256=digest,
            provider_family=self.provider_family,
            request_sha256=observation.request_sha256,
            raw_response_path=str(path),
            http_status=observation.http_status,
            attempt=observation.attempt,
            observed_at_utc=observation.observed_at_utc,
        )


def _normalize_timestamped_block(value: Any) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("malformed block header")
    try:
        number = int(str(value["number"]), 16)
        block_hash = normalize_hex(str(value["hash"]))
        timestamp = int(str(value["timestamp"]), 16)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("malformed block header") from exc
    if len(block_hash) != 66:
        raise ValueError("malformed block hash")
    return {"number": number, "hash": block_hash, "timestamp": timestamp}


def _require_consensus(result: dict[str, Any], error: str) -> dict[str, object]:
    if result.get("status") != "consensus" or not isinstance(result.get("value"), dict):
        raise ControlCutoffStateAcquisitionError(error)
    return dict(result["value"])


def _code_hash(code: str) -> str:
    normalized = normalize_hex(code)
    return hashlib.sha256(bytes.fromhex(normalized[2:])).hexdigest()


def _address_from_chain_address(target: CutoffStateTarget) -> str:
    try:
        chain, address = target.chain_address.split(":", 1)
    except ValueError as exc:
        raise ControlCutoffStateAcquisitionError("chain_address_invalid") from exc
    normalized = normalize_hex(address)
    if chain.lower() != target.chain.lower() or len(normalized) != 42:
        raise ControlCutoffStateAcquisitionError("chain_address_invalid")
    return normalized


def acquire_cutoff_state(
    *,
    target: CutoffStateTarget,
    providers: list[object],
    raw_root: str | Path,
) -> dict[str, object]:
    """Reconstruct one target's identity at the last canonical block at cutoff.

    This helper is evidence production only. It does not select or qualify a
    control and it never converts a provider/read failure into an UNKNOWN value.
    """
    families = {
        str(getattr(provider, "provider_family", "")).strip().lower()
        for provider in providers
    }
    if "" in families or "unverified" in families or len(families) < 2:
        raise ControlCutoffStateAcquisitionError("provider_family_independence")
    if target.next_block_number != target.evidence_block_number + 1:
        raise ControlCutoffStateAcquisitionError("cutoff_block_bracket_not_adjacent")

    address = _address_from_chain_address(target)
    evidence: list[dict[str, str]] = []
    recording = [
        _RecordingProvider(provider, Path(raw_root), evidence) for provider in providers
    ]
    evidence_block = _require_consensus(
        provider_consensus(
            recording,
            "eth_getBlockByNumber",
            [hex(target.evidence_block_number), False],
            _normalize_timestamped_block,
            require_distinct_provider_families=True,
        ),
        "evidence_block_disagreement",
    )
    next_block = _require_consensus(
        provider_consensus(
            recording,
            "eth_getBlockByNumber",
            [hex(target.next_block_number), False],
            _normalize_timestamped_block,
            require_distinct_provider_families=True,
        ),
        "next_block_disagreement",
    )
    if (
        evidence_block["number"] != target.evidence_block_number
        or evidence_block["hash"] != normalize_hex(target.evidence_block_hash)
    ):
        raise ControlCutoffStateAcquisitionError("evidence_block_target_mismatch")
    if (
        next_block["number"] != target.next_block_number
        or next_block["hash"] != normalize_hex(target.next_block_hash)
    ):
        raise ControlCutoffStateAcquisitionError("next_block_target_mismatch")
    if not (
        int(evidence_block["timestamp"]) <= target.cutoff_timestamp
        < int(next_block["timestamp"])
    ):
        raise ControlCutoffStateAcquisitionError("cutoff_block_bracket_invalid")

    snapshot = historical_identity_snapshot(
        address,
        target.evidence_block_number,
        recording,
        strict_provider_families=True,
        agreed_block_hash=str(evidence_block["hash"]),
    )
    if snapshot.get("status") != "complete":
        raise ControlCutoffStateAcquisitionError("historical_identity_disputed")
    if snapshot.get("canonical_block_hash") != evidence_block["hash"]:
        raise ControlCutoffStateAcquisitionError("snapshot_block_hash_mismatch")

    target_code = snapshot.get("code", {}).get("value")
    if not isinstance(target_code, str):
        raise ControlCutoffStateAcquisitionError("runtime_code_unavailable")
    implementation_address: str | None = None
    proxy_family = "none"
    if snapshot.get("implementation", {}).get("value"):
        implementation_address = str(snapshot["implementation"]["value"]).lower()
        proxy_family = "eip1967_implementation"
    elif snapshot.get("beacon_implementation", {}).get("value"):
        implementation_address = str(snapshot["beacon_implementation"]["value"]).lower()
        proxy_family = "eip1967_beacon"
    elif snapshot.get("eip1167_target"):
        implementation_address = str(snapshot["eip1167_target"]).lower()
        proxy_family = "eip1167"

    implementation_code_hash: str | None = None
    if implementation_address is not None:
        implementation_code = provider_consensus(
            recording,
            "eth_getCode",
            [implementation_address, canonical_block_selector(str(evidence_block["hash"]))],
            normalize_hex,
            require_distinct_provider_families=True,
        )
        if implementation_code.get("status") != "consensus" or not isinstance(
            implementation_code.get("value"), str
        ):
            raise ControlCutoffStateAcquisitionError("implementation_code_disagreement")
        implementation_code_hash = _code_hash(str(implementation_code["value"]))

    result: dict[str, object] = {
        "schema_version": STATE_RESULT_SCHEMA,
        "status": "complete",
        "target_id": target.target_id,
        "case_id": target.case_id,
        "chain": target.chain.lower(),
        "chain_address": target.chain_address.lower(),
        "identity_group": target.chain_address.lower(),
        "cutoff_timestamp": target.cutoff_timestamp,
        "evidence_block_number": target.evidence_block_number,
        "evidence_block_hash": evidence_block["hash"],
        "evidence_block_timestamp": evidence_block["timestamp"],
        "next_block_number": target.next_block_number,
        "next_block_hash": next_block["hash"],
        "next_block_timestamp": next_block["timestamp"],
        "provider_agreement": True,
        "provider_families": sorted(families),
        "eip1898_pinned": True,
        "runtime_code_size": len(bytes.fromhex(normalize_hex(target_code)[2:])),
        "runtime_code_hash": _code_hash(target_code),
        "metadata_stripped_code_hash": snapshot.get("metadata_stripped_bytecode_sha256"),
        # Absence of recognized EIP-1967/EIP-1167 signals cannot rule out a
        # non-standard delegate mechanism. Preserve that epistemic boundary.
        "proxy_status": "proxy" if implementation_address else "unknown",
        "proxy_family": proxy_family if implementation_address else "unknown",
        "implementation_address": implementation_address,
        "implementation_code_hash": implementation_code_hash,
        "clone_family": implementation_code_hash
        or snapshot.get("metadata_stripped_bytecode_sha256")
        or _code_hash(target_code),
        "pair_scope_record_sha256": target.pair_scope_record_sha256,
        "denominator_record_sha256": target.denominator_record_sha256,
        "deployment_result_sha256": target.deployment_result_sha256,
        "raw_evidence_hashes": [item["sha256"] for item in evidence],
        "raw_evidence": evidence,
        "field_statuses": {
            "runtime_code": "observable",
            "eip1967_implementation": "observable",
            "eip1967_beacon": "observable",
            "eip1967_admin": "observable",
            "beacon_implementation": (
                "observable" if snapshot.get("beacon", {}).get("value") else "unavailable"
            ),
            "eip1167_target": (
                "observable" if snapshot.get("eip1167_target") else "unavailable"
            ),
            "implementation_runtime_code": (
                "observable" if implementation_address else "unavailable"
            ),
            "proxy_classification": "observable" if implementation_address else "unavailable",
        },
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["result_sha256"] = _canonical_sha(result)
    return result


def acquire_base_state(
    *,
    target: CutoffStateTarget,
    providers: list[object],
    raw_root: str | Path,
) -> dict[str, object]:
    """Acquire only Phase 1 fixed-address reads at the agreed cutoff block."""
    families = {
        str(getattr(provider, "provider_family", "")).strip().lower()
        for provider in providers
    }
    if "" in families or "unverified" in families or len(families) < 2:
        raise ControlCutoffStateAcquisitionError("provider_family_independence")
    if target.next_block_number != target.evidence_block_number + 1:
        raise ControlCutoffStateAcquisitionError("cutoff_block_bracket_not_adjacent")
    address = _address_from_chain_address(target)
    evidence: list[dict[str, str]] = []
    recording = [
        _RecordingProvider(provider, Path(raw_root), evidence) for provider in providers
    ]
    evidence_block = _require_consensus(
        provider_consensus(
            recording,
            "eth_getBlockByNumber",
            [hex(target.evidence_block_number), False],
            _normalize_timestamped_block,
            require_distinct_provider_families=True,
        ),
        "evidence_block_disagreement",
    )
    next_block = _require_consensus(
        provider_consensus(
            recording,
            "eth_getBlockByNumber",
            [hex(target.next_block_number), False],
            _normalize_timestamped_block,
            require_distinct_provider_families=True,
        ),
        "next_block_disagreement",
    )
    if (
        evidence_block["number"] != target.evidence_block_number
        or evidence_block["hash"] != normalize_hex(target.evidence_block_hash)
        or next_block["number"] != target.next_block_number
        or next_block["hash"] != normalize_hex(target.next_block_hash)
    ):
        raise ControlCutoffStateAcquisitionError("cutoff_block_target_mismatch")
    if not (
        int(evidence_block["timestamp"]) <= target.cutoff_timestamp
        < int(next_block["timestamp"])
    ):
        raise ControlCutoffStateAcquisitionError("cutoff_block_bracket_invalid")
    selector = canonical_block_selector(str(evidence_block["hash"]))
    code = provider_consensus(
        recording,
        "eth_getCode",
        [address, selector],
        normalize_hex,
        require_distinct_provider_families=True,
    )
    slots = {
        "direct_implementation_address": EIP1967_IMPLEMENTATION_SLOT,
        "beacon_address": EIP1967_BEACON_SLOT,
        "admin_address": EIP1967_ADMIN_SLOT,
    }
    slot_results = {
        field: provider_consensus(
            recording,
            "eth_getStorageAt",
            [address, slot, selector],
            storage_word_to_address,
            require_distinct_provider_families=True,
        )
        for field, slot in slots.items()
    }
    if code.get("status") != "consensus" or not isinstance(code.get("value"), str):
        raise ControlCutoffStateAcquisitionError(
            _consensus_failure_disposition(
                code,
                field="runtime_code",
                disagreement="runtime_code_disagreement",
            )
        )
    failed_slots = [
        result
        for result in slot_results.values()
        if result.get("status") != "consensus"
    ]
    if failed_slots:
        dispositions = {
            _consensus_failure_disposition(
                result,
                field="fixed_slot",
                disagreement="fixed_slot_disagreement",
            )
            for result in failed_slots
        }
        disposition = (
            "fixed_slot_provider_error"
            if "fixed_slot_provider_error" in dispositions
            else sorted(dispositions)[0]
        )
        raise ControlCutoffStateAcquisitionError(disposition)
    normalized_code = normalize_hex(str(code["value"]))
    stripped, metadata_status = strip_solidity_metadata(normalized_code)
    eip1167_target = is_eip1167_minimal_proxy(normalized_code)
    result: dict[str, object] = {
        "schema_version": "stage2_control_base_state_result.v1",
        "status": "complete",
        "phase": "FIXED_ADDRESS_BASE_STATE_DISCOVERY_ONLY",
        "target_id": target.target_id,
        "case_id": target.case_id,
        "chain": target.chain.lower(),
        "chain_address": target.chain_address.lower(),
        "identity_group": target.chain_address.lower(),
        "cutoff_timestamp": target.cutoff_timestamp,
        "evidence_block_number": target.evidence_block_number,
        "evidence_block_hash": evidence_block["hash"],
        "evidence_block_timestamp": evidence_block["timestamp"],
        "next_block_number": target.next_block_number,
        "next_block_hash": next_block["hash"],
        "next_block_timestamp": next_block["timestamp"],
        "provider_agreement": True,
        "provider_families": sorted(families),
        "eip1898_pinned": True,
        "runtime_code_size": len(bytes.fromhex(normalized_code[2:])),
        "runtime_code_hash": _code_hash(normalized_code),
        "metadata_stripped_code_hash": hashlib.sha256(
            bytes.fromhex(stripped[2:])
        ).hexdigest(),
        "metadata_status": metadata_status,
        **{field: slot_results[field].get("value") for field in slots},
        "eip1167_target": eip1167_target,
        "pair_scope_record_sha256": target.pair_scope_record_sha256,
        "denominator_record_sha256": target.denominator_record_sha256,
        "deployment_result_sha256": target.deployment_result_sha256,
        "raw_evidence_hashes": [item["sha256"] for item in evidence],
        "raw_evidence": evidence,
        "derived_address_reads_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["result_sha256"] = _canonical_sha(result)
    return result


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlCutoffStateAcquisitionError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCutoffStateAcquisitionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCutoffStateAcquisitionError(f"{label}_not_ordinary_file")
    return resolved


def _load_json(path: Path, label: str) -> dict[str, object]:
    ordinary = _ordinary(path, label)
    try:
        payload = json.loads(ordinary.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCutoffStateAcquisitionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCutoffStateAcquisitionError(f"{label}_root_invalid")
    return payload


def _append_event(path: Path, event: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlCutoffStateAcquisitionError("event_ledger_symlink")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(dict(event)) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _relative_raw_path(path: Path, output: Path) -> str:
    resolved = path.resolve(strict=True)
    try:
        return resolved.relative_to(output).as_posix()
    except ValueError as exc:
        raise ControlCutoffStateAcquisitionError("raw_path_escape") from exc


def _validate_activation(activation: Mapping[str, object], target_sha256: str) -> None:
    schema = activation.get("schema_version")
    base_phase = schema == "stage2_control_base_state_activation_verification.v1"
    if not base_phase and schema != "stage2_control_trace_state_activation_verification.v1":
        raise ControlCutoffStateAcquisitionError("activation_schema_invalid")
    expected_decision = (
        "BASE_STATE_RPC_ACTIVATION_VERIFIED"
        if base_phase
        else "TRACE_STATE_RPC_ACTIVATION_VERIFIED"
    )
    if activation.get("decision") != expected_decision:
        raise ControlCutoffStateAcquisitionError("activation_not_verified")
    material = {
        key: value for key, value in activation.items() if key != "verification_sha256"
    }
    if activation.get("verification_sha256") != _canonical_sha(material):
        raise ControlCutoffStateAcquisitionError("activation_self_hash_invalid")
    if activation.get("rpc_authorized") is not True:
        raise ControlCutoffStateAcquisitionError("rpc_not_authorized")
    for flag in (
        "acquisition_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if activation.get(flag) is not False:
            raise ControlCutoffStateAcquisitionError(f"activation_{flag}_invalid")
    if base_phase and activation.get("derived_address_reads_authorized") is not False:
        raise ControlCutoffStateAcquisitionError("derived_address_reads_authorized")
    target_hash_field = (
        "base_state_targets_file_sha256" if base_phase else "state_targets_sha256"
    )
    if activation.get(target_hash_field) != target_sha256:
        raise ControlCutoffStateAcquisitionError("state_targets_hash_mismatch")


def _state_targets(path: Path) -> list[dict[str, object]]:
    payload = _load_json(path, "state_targets")
    if payload.get("schema_version") not in {
        "stage2_control_state_targets.v1",
        "stage2_control_base_state_targets.v1",
    }:
        raise ControlCutoffStateAcquisitionError("state_targets_schema_invalid")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets or not all(
        isinstance(target, dict) for target in targets
    ):
        raise ControlCutoffStateAcquisitionError("state_targets_invalid")
    target_ids = [str(target.get("target_id", "")) for target in targets]
    if any(not target_id for target_id in target_ids) or len(target_ids) != len(set(target_ids)):
        raise ControlCutoffStateAcquisitionError("state_target_identity_invalid")
    return sorted(targets, key=lambda row: str(row["target_id"]))


class _ActivatedProvider:
    _manages_raw_evidence = True

    def __init__(
        self,
        *,
        provider_id: str,
        provider_family: str,
        target: Mapping[str, object],
        activation: Mapping[str, object],
        transport: Callable[[str, str, list[object]], ProviderObservation],
        now_utc: str,
        output: Path,
        raw_root: Path,
        ledger_path: Path,
        run_state: dict[str, object],
    ) -> None:
        self.provider_id = provider_id
        self.provider_family = provider_family
        self._target = target
        self._activation = activation
        self._transport = transport
        self._now_utc = now_utc
        self._output = output
        self._raw_root = raw_root
        self._ledger_path = ledger_path
        self._run_state = run_state

    def call(self, method: str, params: list[Any]) -> ProviderObservation:
        used_sequences = self._run_state["used_sequences"]
        if not isinstance(used_sequences, set):
            raise ControlCutoffStateAcquisitionError("run_state_invalid")
        authorizer = (
            authorize_base_state_rpc_call
            if self._activation.get("schema_version")
            == "stage2_control_base_state_activation_verification.v1"
            else authorize_rpc_call
        )
        retry_limit = int(self._activation.get("retry_limit", 0))
        for attempt in range(retry_limit + 1):
            sequence = int(self._run_state["sequence"]) + 1
            authorization = authorizer(
                self._activation,
                target_id=str(self._target["target_id"]),
                chain=str(self._target["chain"]),
                provider_id=self.provider_id,
                method=method,
                params=list(params),
                sequence_number=sequence,
                used_sequences=used_sequences,
                requests_used=int(self._run_state["request_count"]),
                now_utc=self._now_utc,
            )
            used_sequences.add(sequence)
            self._run_state["sequence"] = sequence
            self._run_state["request_count"] = int(self._run_state["request_count"]) + 1
            request = {
                "schema_version": "stage2_control_cutoff_state_rpc_request.v1",
                "sequence": sequence,
                "target_id": self._target["target_id"],
                "provider_id": self.provider_id,
                "operator_family": self.provider_family,
                "method": method,
                "params": params,
                "attempt": attempt + 1,
                "call_scope_sha256": authorization["call_scope_sha256"],
            }
            request_path = self._raw_root / (
                f"{sequence:06d}-{self.provider_id}-{method}-request.json"
            )
            _atomic_json(request_path, request)
            request_sha = _file_sha(request_path)
            observation = self._transport(self.provider_id, method, list(params))
            if not isinstance(observation, ProviderObservation):
                raise ControlCutoffStateAcquisitionError("provider_observation_invalid")
            response = {
                "schema_version": "stage2_control_cutoff_state_rpc_response.v1",
                "sequence": sequence,
                "target_id": self._target["target_id"],
                "provider_id": self.provider_id,
                "operator_family": self.provider_family,
                "method": method,
                "params": params,
                "attempt": attempt + 1,
                "result": observation.result,
                "error": observation.error,
                "observed_at_unix": observation.observed_at_unix,
                "observed_at_utc": observation.observed_at_utc,
                "http_status": observation.http_status,
                "transport_request_sha256": observation.request_sha256,
                "transport_response_sha256": observation.response_sha256,
            }
            response_path = self._raw_root / (
                f"{sequence:06d}-{self.provider_id}-{method}-response.json"
            )
            _atomic_json(response_path, response)
            response_sha = _file_sha(response_path)
            lowered_error = str(observation.error or "").lower()
            should_retry = (
                observation.error is not None
                and attempt < retry_limit
                and any(marker in lowered_error for marker in _TRANSIENT_ERROR_MARKERS)
            )
            event: dict[str, object] = {
                "schema_version": STATE_EVENT_SCHEMA,
                "previous_event_sha256": self._run_state.get("event_tip_sha256"),
                "sequence": sequence,
                "activation_verification_sha256": self._activation["verification_sha256"],
                "target_id": self._target["target_id"],
                "target_sha256": _canonical_sha(self._target),
                "provider_id": self.provider_id,
                "operator_family": self.provider_family,
                "method": method,
                "params_sha256": _canonical_sha(params),
                "call_scope_sha256": authorization["call_scope_sha256"],
                "request_path": _relative_raw_path(request_path, self._output),
                "request_sha256": request_sha,
                "response_path": _relative_raw_path(response_path, self._output),
                "response_sha256": response_sha,
                "disposition": (
                    "retrying"
                    if should_retry
                    else "complete" if observation.error is None else "provider_error"
                ),
            }
            event["event_sha256"] = _canonical_sha(event)
            _append_event(self._ledger_path, event)
            self._run_state["event_tip_sha256"] = event["event_sha256"]
            recorded = ProviderObservation(
                provider_id=self.provider_id,
                method=method,
                params=list(params),
                result=observation.result,
                observed_at_unix=observation.observed_at_unix,
                error=observation.error,
                response_sha256=response_sha,
                provider_family=self.provider_family,
                request_sha256=request_sha,
                raw_response_path=str(response_path),
                http_status=observation.http_status,
                attempt=attempt + 1,
                observed_at_utc=observation.observed_at_utc,
            )
            if not should_retry:
                return recorded
        raise ControlCutoffStateAcquisitionError("retry_loop_invalid")


def _persist_batch_progress(
    *,
    output: Path,
    ledger_path: Path,
    activation_sha256: str,
    targets_sha256: str,
    target_count: int,
    target_results: list[dict[str, object]],
    run_state: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], str]:
    completed = sum(row.get("disposition") == "complete" for row in target_results)
    dispositions = dict(sorted(Counter(str(row["disposition"]) for row in target_results).items()))
    results: dict[str, object] = {
        "schema_version": STATE_RESULTS_SCHEMA,
        "activation_verification_sha256": activation_sha256,
        "state_targets_sha256": targets_sha256,
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
    results_path = output / "normalized-cutoff-state-results.json"
    _atomic_json(results_path, results)
    status = (
        "IN_PROGRESS_NON_AUTHORIZING"
        if len(target_results) < target_count
        else "COMPLETE"
        if completed == target_count
        else "PARTIAL_NON_AUTHORIZING"
    )
    checkpoint: dict[str, object] = {
        "schema_version": STATE_CHECKPOINT_SCHEMA,
        "status": status,
        "activation_verification_sha256": activation_sha256,
        "state_targets_sha256": targets_sha256,
        "target_count": target_count,
        "processed_target_count": len(target_results),
        "completed_target_count": completed,
        "processed_target_ids": [row["target_id"] for row in target_results],
        "completed_target_ids": [
            row["target_id"] for row in target_results if row.get("disposition") == "complete"
        ],
        "request_count": int(run_state["request_count"]),
        "used_sequences": sorted(run_state["used_sequences"]),
        "event_tip_sha256": run_state.get("event_tip_sha256"),
        "event_ledger_path": ledger_path.relative_to(output).as_posix(),
        "event_ledger_sha256": _file_sha(ledger_path),
        "normalized_results_path": results_path.relative_to(output).as_posix(),
        "normalized_results_sha256": _file_sha(results_path),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    checkpoint["checkpoint_sha256"] = _canonical_sha(checkpoint)
    _atomic_json(output / "checkpoint.json", checkpoint)
    return results, checkpoint, status


def execute_control_cutoff_state_acquisition(
    *,
    activation: Mapping[str, object],
    state_targets_path: Path,
    output_root: Path,
    transport: Callable[[str, str, list[object]], ProviderObservation],
    now_utc: str,
) -> dict[str, object]:
    """Execute exact activated cutoff-state calls and checkpoint target results."""
    targets_file = _ordinary(state_targets_path, "state_targets")
    targets_sha = _file_sha(targets_file)
    _validate_activation(activation, targets_sha)
    targets = _state_targets(targets_file)
    output = output_root.expanduser()
    if output.is_symlink():
        raise ControlCutoffStateAcquisitionError("output_root_symlink")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    ledger_path = output / "cutoff-state-events.jsonl"
    if ledger_path.exists():
        raise ControlCutoffStateAcquisitionError("existing_run_requires_resume")
    raw_root = output / "raw"
    raw_root.mkdir()
    run_state: dict[str, object] = {
        "sequence": 0,
        "request_count": 0,
        "used_sequences": set(),
        "event_tip_sha256": None,
    }
    target_results: list[dict[str, object]] = []
    activation_sha = str(activation["verification_sha256"])
    base_phase = activation.get("schema_version") == (
        "stage2_control_base_state_activation_verification.v1"
    )
    target_type = "base_state" if base_phase else "state"
    for target_row in targets:
        scopes = [
            scope for scope in activation["rpc_call_scopes"]
            if isinstance(scope, Mapping)
            and scope.get("target_type") == target_type
            and scope.get("target_id") == target_row["target_id"]
        ]
        families = {
            str(scope.get("operator_family", "")) for scope in scopes
        }
        if "" in families or "unverified" in families or len(families) < 2:
            raise ControlCutoffStateAcquisitionError("provider_family_independence")
        provider_bindings: dict[str, str] = {}
        for scope in scopes:
            provider_id = str(scope["provider_id"])
            family = str(scope["operator_family"])
            if provider_id in provider_bindings and provider_bindings[provider_id] != family:
                raise ControlCutoffStateAcquisitionError("provider_family_binding_conflict")
            provider_bindings[provider_id] = family
        target_values = {
            field: target_row[field]
            for field in CutoffStateTarget.__dataclass_fields__
        }
        if base_phase:
            try:
                target_values["cutoff_timestamp"] = int(
                    target_row["cutoff_timestamp_unix"]
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ControlCutoffStateAcquisitionError(
                    "cutoff_timestamp_unix_invalid"
                ) from exc
        target = CutoffStateTarget(**target_values)
        activated_providers = [
            _ActivatedProvider(
                provider_id=provider_id,
                provider_family=family,
                target=target_row,
                activation=activation,
                transport=transport,
                now_utc=now_utc,
                output=output,
                raw_root=raw_root,
                ledger_path=ledger_path,
                run_state=run_state,
            )
            for provider_id, family in sorted(provider_bindings.items())
        ]
        try:
            operation = acquire_base_state if base_phase else acquire_cutoff_state
            projection = operation(
                target=target, providers=activated_providers, raw_root=raw_root
            )
            row = {**projection, "disposition": "complete"}
        except (ControlCutoffStateAcquisitionError, ValueError) as exc:
            row = {
                "target_id": target.target_id,
                "case_id": target.case_id,
                "chain": target.chain,
                "chain_address": target.chain_address,
                "target_sha256": _canonical_sha(target_row),
                "disposition": str(exc),
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            }
            row["record_sha256"] = _canonical_sha(row)
        target_results.append(row)
        _persist_batch_progress(
            output=output,
            ledger_path=ledger_path,
            activation_sha256=activation_sha,
            targets_sha256=targets_sha,
            target_count=len(targets),
            target_results=target_results,
            run_state=run_state,
        )
    results, checkpoint, status = _persist_batch_progress(
        output=output,
        ledger_path=ledger_path,
        activation_sha256=activation_sha,
        targets_sha256=targets_sha,
        target_count=len(targets),
        target_results=target_results,
        run_state=run_state,
    )
    summary: dict[str, object] = {
        "schema_version": STATE_SUMMARY_SCHEMA,
        "status": status,
        "target_count": len(targets),
        "completed_target_count": results["completed_target_count"],
        "dispositions": results["dispositions"],
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
        "normalized_results_path": str(output / "normalized-cutoff-state-results.json"),
        "event_ledger_path": str(ledger_path),
        "checkpoint_path": str(output / "checkpoint.json"),
        "summary_path": str(summary_path),
    }


def _resolved_child(root: Path, relative_value: object, label: str) -> Path:
    relative = Path(str(relative_value or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ControlCutoffStateAcquisitionError("resume_path_escape")
    child = _ordinary(root / relative, label)
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise ControlCutoffStateAcquisitionError("resume_path_escape") from exc
    return child


def resume_cutoff_state_acquisition(
    checkpoint_path: Path,
    *,
    transport: Callable[[str, str, list[object]], ProviderObservation],
) -> dict[str, object]:
    """Re-hash a terminal checkpoint before returning without network access."""
    checkpoint_file = _ordinary(checkpoint_path, "checkpoint")
    checkpoint = _load_json(checkpoint_file, "checkpoint")
    if checkpoint.get("schema_version") != STATE_CHECKPOINT_SCHEMA:
        raise ControlCutoffStateAcquisitionError("checkpoint_schema_invalid")
    material = {
        key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"
    }
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(material):
        raise ControlCutoffStateAcquisitionError("checkpoint_self_hash_invalid")
    root = checkpoint_file.parent.resolve(strict=True)
    results_path = _resolved_child(
        root, checkpoint.get("normalized_results_path"), "normalized_results"
    )
    ledger_path = _resolved_child(root, checkpoint.get("event_ledger_path"), "event_ledger")
    if (
        _file_sha(results_path) != checkpoint.get("normalized_results_sha256")
        or _file_sha(ledger_path) != checkpoint.get("event_ledger_sha256")
    ):
        raise ControlCutoffStateAcquisitionError("resume_hash_mismatch")
    status = str(checkpoint.get("status"))
    if status not in {"COMPLETE", "PARTIAL_NON_AUTHORIZING"}:
        raise ControlCutoffStateAcquisitionError("resume_inputs_required")
    return {
        "status": status,
        "target_count": checkpoint["target_count"],
        "completed_target_count": checkpoint["completed_target_count"],
        "normalized_results_path": str(results_path),
        "event_ledger_path": str(ledger_path),
        "checkpoint_path": str(checkpoint_file),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def verify_cutoff_state_checkpoint_signature(
    *,
    checkpoint_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
) -> dict[str, object]:
    checkpoint_file = _ordinary(checkpoint_path, "checkpoint")
    signature_file = _ordinary(signature_path, "signature")
    allowed_signers_file = _ordinary(allowed_signers_path, "allowed_signers")
    checkpoint = _load_json(checkpoint_file, "checkpoint")
    if checkpoint.get("schema_version") != STATE_CHECKPOINT_SCHEMA:
        raise ControlCutoffStateAcquisitionError("checkpoint_schema_invalid")
    material = {
        key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"
    }
    if checkpoint.get("checkpoint_sha256") != _canonical_sha(material):
        raise ControlCutoffStateAcquisitionError("checkpoint_self_hash_invalid")
    for flag in (
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        if checkpoint.get(flag) is not False:
            raise ControlCutoffStateAcquisitionError(f"checkpoint_{flag}_invalid")
    principal = expected_principal.strip()
    if not principal:
        raise ControlCutoffStateAcquisitionError("signer_principal_invalid")
    verification = subprocess.run(
        [
            "/usr/bin/ssh-keygen", "-Y", "verify",
            "-f", str(allowed_signers_file),
            "-I", principal,
            "-n", CHECKPOINT_NAMESPACE,
            "-s", str(signature_file),
        ],
        input=canonical_checkpoint_payload(checkpoint),
        capture_output=True,
        check=False,
    )
    if verification.returncode != 0:
        raise ControlCutoffStateAcquisitionError("checkpoint_signature_invalid")
    result: dict[str, object] = {
        "schema_version": "stage2_control_cutoff_state_checkpoint_verification.v1",
        "complete": True,
        "checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "checkpoint_file_sha256": _file_sha(checkpoint_file),
        "signature_sha256": _file_sha(signature_file),
        "allowed_signers_sha256": _file_sha(allowed_signers_file),
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
