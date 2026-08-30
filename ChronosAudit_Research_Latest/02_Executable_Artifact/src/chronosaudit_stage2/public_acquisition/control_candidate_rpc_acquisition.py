from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .providers import ProviderRegistry


class ControlCandidateRpcAcquisitionError(ValueError):
    """Raised when an activated candidate-RPC run is unsafe or inconsistent."""


Transport = Callable[[str, str, list[object]], Mapping[str, object]]
_ACTIVATION_SCHEMA = "chronosaudit.control_candidate_rpc_activation_verification.v1"
_EVENT_SCHEMA = "chronosaudit.control_candidate_rpc_acquisition_event.v1"
_REQUEST_EVENT_SCHEMA = "chronosaudit.control_candidate_rpc_request_event.v1"
_RESULT_SCHEMA = "chronosaudit.control_candidate_rpc_acquisition_result.v1"
_ALLOWED_METHODS = {"eth_chainId", "eth_getTransactionReceipt", "eth_getBlockByHash"}
_CHAIN_IDS = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha(value: object) -> str:
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
        raise ControlCandidateRpcAcquisitionError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlCandidateRpcAcquisitionError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlCandidateRpcAcquisitionError(f"{label}_not_ordinary_file")
    return resolved


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlCandidateRpcAcquisitionError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlCandidateRpcAcquisitionError(f"{label}_root_invalid")
    return payload


def _hex_int(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ControlCandidateRpcAcquisitionError(f"{label}_invalid")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise ControlCandidateRpcAcquisitionError(f"{label}_invalid") from exc


def _iso_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_transport(endpoint: str, method: str, params: list[object]) -> Mapping[str, object]:
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    request = Request(
        endpoint,
        data=_canonical_bytes(body),
        headers={"content-type": "application/json", "user-agent": "ChronosAudit-local-test/1"},
        method="POST",
    )
    with urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ControlCandidateRpcAcquisitionError("rpc_response_root_invalid")
    return payload


def _read_queue(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ControlCandidateRpcAcquisitionError("queue_empty")
    return rows


def _round_robin_by_case(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Interleave cases while preserving each case's frozen reserve order."""
    case_order: list[str] = []
    grouped: dict[str, deque[dict[str, str]]] = {}
    for row in rows:
        case_name = row["case_name"]
        if case_name not in grouped:
            grouped[case_name] = deque()
            case_order.append(case_name)
        grouped[case_name].append(row)
    ordered: list[dict[str, str]] = []
    while grouped:
        for case_name in list(case_order):
            case_rows = grouped.get(case_name)
            if case_rows is None:
                continue
            ordered.append(case_rows.popleft())
            if not case_rows:
                del grouped[case_name]
    return ordered


@dataclass(frozen=True)
class _RuntimeProvider:
    provider_id: str
    chain: str
    endpoint: str
    operator_family: str
    public_endpoint_id: str


def _providers_by_chain(
    registry: ProviderRegistry, required_chains: set[str]
) -> dict[str, list[_RuntimeProvider]]:
    result: dict[str, list[object]] = {}
    if not required_chains or not required_chains.issubset(_CHAIN_IDS):
        raise ControlCandidateRpcAcquisitionError("queue_chain_scope_invalid")
    for chain in sorted(required_chains):
        records = registry.providers_for_chain(chain, verified_only=True)
        if len(records) != 2 or len({item.operator_family for item in records}) != 2:
            raise ControlCandidateRpcAcquisitionError(f"provider_pair_invalid:{chain}")
        try:
            result[chain] = sorted(
                [
                    _RuntimeProvider(
                        provider_id=record.provider_id,
                        chain=record.chain,
                        endpoint=record.resolved_endpoint(),
                        operator_family=record.operator_family,
                        public_endpoint_id=record.public_endpoint_id,
                    )
                    for record in records
                ],
                key=lambda item: item.provider_id,
            )
        except ValueError as exc:
            raise ControlCandidateRpcAcquisitionError(
                f"provider_runtime_binding_invalid:{chain}"
            ) from exc
    return result


def prepare_control_candidate_rpc_acquisition(
    *,
    activation_path: Path,
    activation_request_path: Path,
    queue_path: Path,
    provider_registry_path: Path,
    output_root: Path,
) -> dict[str, object]:
    activation_file = _ordinary(activation_path, "activation")
    activation_request_file = _ordinary(activation_request_path, "activation_request")
    queue_file = _ordinary(queue_path, "queue")
    registry_file = _ordinary(provider_registry_path, "provider_registry")
    activation = _load_json(activation_file, "activation")
    activation_request = _load_json(activation_request_file, "activation_request")
    if activation.get("schema_version") != _ACTIVATION_SCHEMA or activation.get("decision") != "RPC_ACTIVATION_VERIFIED":
        raise ControlCandidateRpcAcquisitionError("activation_not_verified")
    if activation.get("rpc_authorized") is not True:
        raise ControlCandidateRpcAcquisitionError("rpc_not_authorized")
    for field in ("acquisition_authorized", "selection_authorized", "stage_promotion_authorized", "recovery3_mutation_authorized"):
        if activation.get(field) is not False:
            raise ControlCandidateRpcAcquisitionError(f"activation_{field}_invalid")
    if activation.get("hash_chained_no_repeat_ledger_required") is not True:
        raise ControlCandidateRpcAcquisitionError("activation_ledger_requirement_invalid")
    if _file_sha(queue_file) != activation.get("queue_sha256"):
        raise ControlCandidateRpcAcquisitionError("queue_sha256_mismatch")
    request_body = dict(activation_request)
    request_sha = request_body.pop("request_sha256", None)
    if request_sha != _sha(request_body) or request_sha != activation.get("request_sha256"):
        raise ControlCandidateRpcAcquisitionError("activation_request_sha256_mismatch")
    if _file_sha(registry_file) != activation_request.get("provider_registry_sha256"):
        raise ControlCandidateRpcAcquisitionError("provider_registry_sha256_mismatch")
    rows = _read_queue(queue_file)
    if len(rows) != activation.get("queue_row_count"):
        raise ControlCandidateRpcAcquisitionError("queue_row_count_mismatch")
    if set(activation_request.get("rpc_methods") or []) != _ALLOWED_METHODS:
        raise ControlCandidateRpcAcquisitionError("activation_method_scope_invalid")
    registry = ProviderRegistry.from_path(registry_file)
    required_chains = {str(row.get("chain") or "").strip().lower() for row in rows}
    pairs = _providers_by_chain(registry, required_chains)
    actual_bindings = sorted((provider.chain, provider.provider_id, provider.operator_family, provider.public_endpoint_id) for pair in pairs.values() for provider in pair)
    approved_bindings = sorted(
        (
            str(item["chain"]),
            str(item["provider_id"]),
            str(item["operator_family"]),
            str(item["public_endpoint_identity_id"]),
        )
        for item in activation.get("provider_bindings", [])
        if isinstance(item, Mapping) and str(item.get("chain") or "") in required_chains
    )
    if actual_bindings != approved_bindings:
        raise ControlCandidateRpcAcquisitionError("provider_binding_mismatch")
    root = output_root.expanduser().resolve(strict=False)
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "run_manifest.json"
    manifest_body = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_run.v2",
        "activation_sha256": _file_sha(activation_file),
        "activation_request_file_sha256": _file_sha(activation_request_file),
        "activation_request_sha256": request_sha,
        "queue_sha256": _file_sha(queue_file),
        "provider_registry_sha256": _file_sha(registry_file),
        "queue_row_count": len(rows),
        "maximum_rpc_requests": activation["maximum_rpc_requests"],
        "request_receipt_ledger_required": True,
        "transport_retries_within_activation": 0,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest = dict(manifest_body)
    manifest["run_binding_sha256"] = _sha(manifest_body)
    if manifest_path.exists():
        if _load_json(manifest_path, "run_manifest") != manifest:
            raise ControlCandidateRpcAcquisitionError("resume_binding_mismatch")
    else:
        _atomic_json(manifest_path, manifest)
    return {"root": root, "manifest": manifest, "rows": rows, "providers": pairs}


def _store_rpc(root: Path, provider_id: str, method: str, params: list[object], response: Mapping[str, object]) -> dict[str, str]:
    envelope = {"provider_id": provider_id, "request": {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, "response": dict(response)}
    digest = _sha(envelope)
    path = root / "rpc" / digest[:2] / f"{digest}.json"
    if path.exists():
        if _file_sha(path) != hashlib.sha256((json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")).hexdigest():
            raise ControlCandidateRpcAcquisitionError("rpc_cache_hash_mismatch")
    else:
        _atomic_json(path, envelope)
    return {"rpc_envelope_sha256": digest, "rpc_envelope_path": str(path)}


def _request_error_code(exc: BaseException) -> str:
    if isinstance(exc, HTTPError):
        return f"http_{exc.code}"
    return type(exc).__name__


class _RequestRecorder:
    def __init__(self, *, root: Path, maximum: int, transport: Transport):
        self.root = root
        self.maximum = int(maximum)
        self.transport = transport
        self.ledger = root / "request-events.jsonl"
        self.count = 0
        self.previous = "0" * 64
        self.candidate_scope_ids: set[str] = set()
        if self.maximum < 0:
            raise ControlCandidateRpcAcquisitionError("maximum_rpc_requests_invalid")
        if self.ledger.exists():
            for index, line in enumerate(self.ledger.read_text(encoding="utf-8").splitlines()):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ControlCandidateRpcAcquisitionError(
                        f"request_ledger_json_invalid:{index}"
                    ) from exc
                stored = event.pop("event_sha256", None)
                if (
                    event.get("schema_version") != _REQUEST_EVENT_SCHEMA
                    or event.get("previous_event_sha256") != self.previous
                    or event.get("request_sequence") != index + 1
                    or stored != _sha(event)
                ):
                    raise ControlCandidateRpcAcquisitionError(
                        f"request_ledger_chain_invalid:{index}"
                    )
                self.previous = str(stored)
                self.count += 1
                if event.get("scope_kind") == "candidate":
                    self.candidate_scope_ids.add(str(event.get("scope_id") or ""))
        if self.count > self.maximum:
            raise ControlCandidateRpcAcquisitionError("request_budget_already_exceeded")

    @property
    def remaining(self) -> int:
        return self.maximum - self.count

    def _append(self, payload: dict[str, object]) -> None:
        event = {
            "schema_version": _REQUEST_EVENT_SCHEMA,
            "previous_event_sha256": self.previous,
            "request_sequence": self.count + 1,
            **payload,
        }
        event["event_sha256"] = _sha(event)
        with self.ledger.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.count += 1
        self.previous = str(event["event_sha256"])
        if event.get("scope_kind") == "candidate":
            self.candidate_scope_ids.add(str(event.get("scope_id") or ""))

    def call(
        self,
        *,
        provider: object,
        method: str,
        params: list[object],
        scope_kind: str,
        scope_id: str,
    ) -> tuple[object, dict[str, str]]:
        if self.remaining <= 0:
            raise ControlCandidateRpcAcquisitionError("request_budget_exhausted")
        common: dict[str, object] = {
            "scope_kind": scope_kind,
            "scope_id": scope_id,
            "provider_id": provider.provider_id,
            "method": method,
            "params_sha256": _sha(params),
        }
        try:
            response = self.transport(provider.endpoint, method, params)
        except BaseException as exc:
            self._append(
                {
                    **common,
                    "disposition": "TRANSPORT_ERROR",
                    "error_code": _request_error_code(exc),
                }
            )
            raise
        evidence = _store_rpc(self.root, provider.provider_id, method, params, response)
        invalid = response.get("error") is not None or "result" not in response or response.get("result") is None
        self._append(
            {
                **common,
                "disposition": "RPC_ERROR" if invalid else "SUCCESS",
                **evidence,
            }
        )
        if invalid:
            raise ControlCandidateRpcAcquisitionError(
                f"rpc_result_invalid:{provider.provider_id}:{method}"
            )
        return response["result"], evidence


def _append_event(ledger: Path, payload: dict[str, object], previous: str) -> str:
    event = {"schema_version": _EVENT_SCHEMA, "previous_event_sha256": previous, **payload}
    event["event_sha256"] = _sha(event)
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return str(event["event_sha256"])


def _completed(ledger: Path) -> tuple[set[str], set[str], set[str], Counter[str], str]:
    completed: set[str] = set()
    rejected: set[str] = set()
    partial: set[str] = set()
    status_counts: Counter[str] = Counter()
    previous = "0" * 64
    if not ledger.exists():
        return completed, rejected, partial, status_counts, previous
    for index, line in enumerate(ledger.read_text(encoding="utf-8").splitlines()):
        event = json.loads(line)
        stored = event.pop("event_sha256", None)
        if event.get("previous_event_sha256") != previous or stored != _sha(event):
            raise ControlCandidateRpcAcquisitionError(f"ledger_chain_invalid:{index}")
        previous = str(stored)
        status = str(event.get("status") or "")
        status_counts[status] += 1
        if status == "COMPLETE":
            completed.add(str(event["reserve_assignment_sha256"]))
        elif status == "TERMINAL_REJECTED":
            rejected.add(str(event["reserve_assignment_sha256"]))
        elif status == "PARTIAL":
            partial.add(str(event["reserve_assignment_sha256"]))
    if (completed & rejected) or (completed & partial) or (rejected & partial):
        raise ControlCandidateRpcAcquisitionError("assignment_terminal_status_conflict")
    return completed, rejected, partial, status_counts, previous


def execute_control_candidate_rpc_acquisition(
    prepared: Mapping[str, object],
    *,
    transport: Transport = default_transport,
    max_candidates: int | None = None,
    max_workers: int = 1,
) -> dict[str, object]:
    if int(max_workers) != 1:
        raise ControlCandidateRpcAcquisitionError(
            "max_workers_must_equal_one_for_deterministic_request_ledger"
        )
    root = Path(prepared["root"])
    rows = list(prepared["rows"])
    pairs = prepared["providers"]
    ledger = root / "events.jsonl"
    completed, rejected, partial, status_counts, previous = _completed(ledger)
    recorder = _RequestRecorder(
        root=root,
        maximum=int(prepared["manifest"]["maximum_rpc_requests"]),
        transport=transport,
    )
    orphaned_request_scopes = sorted(
        recorder.candidate_scope_ids - completed - rejected - partial
    )
    for assignment in orphaned_request_scopes:
        previous = _append_event(
            ledger,
            {
                "reserve_assignment_sha256": assignment,
                "status": "PARTIAL",
                "error_code": "interrupted_request_scope_detected_on_resume",
            },
            previous,
        )
        partial.add(assignment)
        status_counts["PARTIAL"] += 1
    chain_evidence: dict[str, list[dict[str, str]]] = {}
    for chain, providers in pairs.items():
        observations = []
        for provider in providers:
            cache_path = root / "chain_identity" / f"{provider.provider_id}.json"
            if cache_path.exists():
                cached = _load_json(cache_path, "chain_identity")
                if cached.get("chain") != chain or cached.get("provider_id") != provider.provider_id or cached.get("chain_id") != _CHAIN_IDS[chain]:
                    raise ControlCandidateRpcAcquisitionError(f"chain_identity_cache_invalid:{provider.provider_id}")
                evidence = {
                    "rpc_envelope_sha256": str(cached["rpc_envelope_sha256"]),
                    "rpc_envelope_path": str(cached["rpc_envelope_path"]),
                }
            else:
                result, evidence = recorder.call(
                    provider=provider,
                    method="eth_chainId",
                    params=[],
                    scope_kind="chain_identity",
                    scope_id=f"{chain}:{provider.provider_id}",
                )
                if _hex_int(result, "chain_id") != _CHAIN_IDS[chain]:
                    raise ControlCandidateRpcAcquisitionError(f"chain_id_mismatch:{provider.provider_id}")
                _atomic_json(cache_path, {"chain": chain, "provider_id": provider.provider_id, "chain_id": _CHAIN_IDS[chain], **evidence})
            observations.append({"provider_id": provider.provider_id, **evidence})
        chain_evidence[chain] = observations
    pending = _round_robin_by_case(
        [
            row for row in rows
            if row["reserve_assignment_sha256"] not in completed
            and row["reserve_assignment_sha256"] not in rejected
            and row["reserve_assignment_sha256"] not in partial
        ]
    )
    unresolved_before_budget = len(pending)
    candidate_budget = recorder.remaining // 4
    pending = pending[:candidate_budget]
    if max_candidates is not None:
        pending = pending[: max(0, int(max_candidates))]
    new_complete = 0
    new_partial = 0
    new_rejected = 0

    def acquire(row: dict[str, str]) -> dict[str, object]:
        assignment = row["reserve_assignment_sha256"]
        candidate_path = root / "candidates" / f"{assignment}.json"
        try:
            normalized_receipts = []
            observations = []
            for provider in pairs[row["chain"]]:
                receipt, receipt_evidence = recorder.call(
                    provider=provider,
                    method="eth_getTransactionReceipt",
                    params=[row["creation_tx_hash"]],
                    scope_kind="candidate",
                    scope_id=assignment,
                )
                if not isinstance(receipt, Mapping):
                    raise ControlCandidateRpcAcquisitionError("receipt_invalid")
                block_hash = str(receipt.get("blockHash") or "").lower()
                block_number = _hex_int(receipt.get("blockNumber"), "receipt_block_number")
                block, block_evidence = recorder.call(
                    provider=provider,
                    method="eth_getBlockByHash",
                    params=[block_hash, False],
                    scope_kind="candidate",
                    scope_id=assignment,
                )
                if not isinstance(block, Mapping):
                    raise ControlCandidateRpcAcquisitionError("block_invalid")
                timestamp = _hex_int(block.get("timestamp"), "block_timestamp")
                normalized = {
                    "block_hash": block_hash,
                    "block_number": block_number,
                    "block_timestamp": timestamp,
                    "contract_address": str(receipt.get("contractAddress") or "").lower(),
                    "transaction_hash": str(receipt.get("transactionHash") or "").lower(),
                    "status": _hex_int(receipt.get("status"), "receipt_status"),
                }
                if _hex_int(block.get("number"), "block_number") != block_number or str(block.get("hash") or "").lower() != block_hash:
                    raise ControlCandidateRpcAcquisitionError("receipt_block_mismatch")
                normalized_receipts.append(normalized)
                observations.append({"provider_id": provider.provider_id, "operator_family": provider.operator_family, **receipt_evidence, "block_rpc_envelope_sha256": block_evidence["rpc_envelope_sha256"], "block_rpc_envelope_path": block_evidence["rpc_envelope_path"]})
            if len({_sha(item) for item in normalized_receipts}) != 1:
                raise ControlCandidateRpcAcquisitionError("provider_disagreement")
            agreed = normalized_receipts[0]
            if agreed["transaction_hash"] != row["creation_tx_hash"].lower() or agreed["block_number"] != int(row["deployment_block"]):
                raise ControlCandidateRpcAcquisitionError("queue_deployment_binding_mismatch")
            target = row["control_address"].lower()
            contract_address = agreed["contract_address"]
            if contract_address and contract_address != target:
                rejection = {
                    "schema_version": _RESULT_SCHEMA,
                    "run_binding_sha256": prepared["manifest"]["run_binding_sha256"],
                    "reserve_assignment_sha256": assignment,
                    "case_name": row["case_name"],
                    "chain": row["chain"],
                    "control_address": target,
                    "creation_tx_hash": row["creation_tx_hash"].lower(),
                    "rejection_reason": "top_level_contract_address_mismatch",
                    "observed_contract_address": contract_address,
                    "provider_consensus": True,
                    "provider_observations": observations,
                    "selection_authorized": False,
                    "stage_promotion_authorized": False,
                    "recovery3_mutation_authorized": False,
                }
                rejection["result_sha256"] = _sha(rejection)
                _atomic_json(candidate_path, rejection)
                return {
                    "reserve_assignment_sha256": assignment,
                    "status": "TERMINAL_REJECTED",
                    "error_code": rejection["rejection_reason"],
                    "result_sha256": rejection["result_sha256"],
                    "result_path": str(candidate_path),
                }
            creation_type = "TOP_LEVEL_CREATE_RECEIPT_PROVEN" if contract_address == target else "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED"
            deployment_time = _iso_utc(int(agreed["block_timestamp"]))
            cutoff = datetime.strptime(row["positive_prediction_cutoff_time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            deployment_dt = datetime.fromtimestamp(int(agreed["block_timestamp"]), timezone.utc)
            temporal_pre_cutoff = deployment_dt < cutoff
            result = {
                "schema_version": _RESULT_SCHEMA,
                "run_binding_sha256": prepared["manifest"]["run_binding_sha256"],
                "reserve_assignment_sha256": assignment,
                "case_name": row["case_name"],
                "chain": row["chain"],
                "control_address": target,
                "creation_tx_hash": row["creation_tx_hash"].lower(),
                "deployment_block": agreed["block_number"],
                "deployment_block_hash": agreed["block_hash"],
                "control_deployment_time": deployment_time,
                "deployment_distance_seconds": int((deployment_dt - cutoff).total_seconds()),
                "temporal_pre_cutoff": temporal_pre_cutoff,
                "creation_type": creation_type,
                "trace_proof": False,
                "provider_consensus": True,
                "provider_observations": observations,
                "rpc_classification_complete": temporal_pre_cutoff and creation_type == "TOP_LEVEL_CREATE_RECEIPT_PROVEN",
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            }
            result["result_sha256"] = _sha(result)
            _atomic_json(candidate_path, result)
            return {"reserve_assignment_sha256": assignment, "status": "COMPLETE", "result_sha256": result["result_sha256"], "result_path": str(candidate_path)}
        except Exception as exc:
            return {"reserve_assignment_sha256": assignment, "status": "PARTIAL", "error_code": str(exc)}

    for outcome in map(acquire, pending):
        previous = _append_event(ledger, outcome, previous)
        status_counts[str(outcome["status"])] += 1
        assignment = str(outcome["reserve_assignment_sha256"])
        if outcome["status"] == "COMPLETE":
            completed.add(assignment)
            new_complete += 1
        elif outcome["status"] == "TERMINAL_REJECTED":
            rejected.add(assignment)
            new_rejected += 1
        else:
            new_partial += 1
            partial.add(assignment)
    completed_cases: set[str] = set()
    rpc_classification_complete_count = 0
    trace_required_count = 0
    for assignment in completed:
        result_path = root / "candidates" / f"{assignment}.json"
        result = _load_json(result_path, "candidate_result")
        stored_result_sha = result.pop("result_sha256", None)
        if stored_result_sha != _sha(result):
            raise ControlCandidateRpcAcquisitionError(
                f"candidate_result_sha256_invalid:{assignment}"
            )
        completed_cases.add(str(result.get("case_name") or ""))
        if result.get("rpc_classification_complete") is True:
            rpc_classification_complete_count += 1
        if result.get("creation_type") == "INTERNAL_OR_FACTORY_CREATE_UNRESOLVED_TRACE_REQUIRED":
            trace_required_count += 1
    summary = {
        "schema_version": "chronosaudit.control_candidate_rpc_acquisition_summary.v1",
        "run_binding_sha256": prepared["manifest"]["run_binding_sha256"],
        "queue_row_count": len(rows),
        "completed_count": len(completed),
        "completed_case_count": len(completed_cases),
        "rpc_classification_complete_count": rpc_classification_complete_count,
        "trace_required_count": trace_required_count,
        "ledger_status_counts": dict(sorted(status_counts.items())),
        "terminal_rejected_count": len(rejected),
        "remaining_count": len(rows) - len(completed) - len(rejected),
        "activation_attempted_count": len(completed) + len(rejected) + len(partial),
        "retry_required_count": len(partial),
        "new_complete_count": new_complete,
        "new_terminal_rejected_count": new_rejected,
        "new_partial_count": new_partial,
        "request_count": recorder.count,
        "remaining_request_budget": recorder.remaining,
        "request_budget_exhausted": unresolved_before_budget > candidate_budget,
        "request_ledger_sha256": _file_sha(recorder.ledger),
        "request_ledger_terminal_hash": recorder.previous,
        "chain_identity_evidence": chain_evidence,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    summary["summary_sha256"] = _sha(summary)
    _atomic_json(root / "summary.json", summary)
    return summary
