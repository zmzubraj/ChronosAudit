from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from chronosaudit_stage2.deployment_stream import (
    canonical_creation_set,
    creations_from_geth_calltracer,
    creations_from_parity_traces,
    trace_transaction_backend,
)
from chronosaudit_stage2.onchain import (
    BEACON_IMPLEMENTATION_SELECTOR,
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    ProviderObservation,
)

from .providers import ProviderRegistry


SCHEMA_VERSION = "stage2_control_trace_state_capability.v1"
VERIFIER_SCHEMA_VERSION = "stage2_control_trace_state_capability_verification.v1"
REQUIRED_METHODS = (
    "eth_chainId",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getTransactionReceipt",
    "eth_getCode",
    "eth_getStorageAt",
)
TRACE_METHODS = (
    "trace_transaction",
    "debug_traceTransaction",
    "trace_block",
    "debug_traceBlockByNumber",
)
_FALSE_AUTHORITY_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


class ControlTraceStateCapabilityError(ValueError):
    """Raised when historical trace/state capability is not proven."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlTraceStateCapabilityError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlTraceStateCapabilityError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlTraceStateCapabilityError(f"{label}_not_ordinary_file")
    return resolved


def _prepare_raw_root(raw_root: Path) -> Path:
    candidate = raw_root.expanduser()
    if candidate.is_symlink():
        raise ControlTraceStateCapabilityError("raw_root_symlink")
    candidate.mkdir(parents=True, exist_ok=True)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ControlTraceStateCapabilityError("raw_root_not_directory")
    return resolved


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ControlTraceStateCapabilityError("raw_evidence_symlink")
    data = (_canonical_json(dict(payload)) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _int_quantity(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ControlTraceStateCapabilityError(f"{label}_invalid")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise ControlTraceStateCapabilityError(f"{label}_invalid") from exc


def _lower_hex(value: object, label: str, length: int | None = None) -> str:
    text = str(value or "").strip().lower()
    if not text.startswith("0x"):
        raise ControlTraceStateCapabilityError(f"{label}_invalid")
    if length is not None and len(text) != length:
        raise ControlTraceStateCapabilityError(f"{label}_invalid")
    if any(character not in "0123456789abcdef" for character in text[2:]):
        raise ControlTraceStateCapabilityError(f"{label}_invalid")
    return text


class _EvidenceRecorder:
    def __init__(self, raw_root: Path) -> None:
        self.raw_root = _prepare_raw_root(raw_root)
        self.entries: list[dict[str, object]] = []
        self.sequence = 0

    def call(self, provider: Any, method: str, params: list[object]) -> ProviderObservation:
        observation = provider.call(method, params)
        if not isinstance(observation, ProviderObservation):
            raise ControlTraceStateCapabilityError("provider_observation_invalid")
        self.sequence += 1
        safe_provider = _SAFE_NAME.sub("_", str(provider.provider_id))
        safe_method = _SAFE_NAME.sub("_", method)
        prefix = f"{self.sequence:05d}-{safe_provider}-{safe_method}"
        request = {
            "schema_version": "stage2_control_trace_state_capability_request.v1",
            "provider_id": str(provider.provider_id),
            "provider_family": str(getattr(provider, "provider_family", "unverified")),
            "method": method,
            "params": params,
        }
        response = {
            "schema_version": "stage2_control_trace_state_capability_response.v1",
            "provider_id": observation.provider_id,
            "provider_family": str(getattr(provider, "provider_family", "unverified")),
            "method": observation.method,
            "params": observation.params,
            "result": observation.result,
            "error": observation.error,
            "observed_at_unix": observation.observed_at_unix,
            "observed_at_utc": observation.observed_at_utc,
            "http_status": observation.http_status,
            "attempt": observation.attempt,
            "transport_request_sha256": observation.request_sha256,
            "transport_response_sha256": observation.response_sha256,
        }
        for kind, payload in (("request", request), ("response", response)):
            path = self.raw_root / f"{prefix}-{kind}.json"
            _atomic_write(path, payload)
            self.entries.append(
                {
                    "sequence": self.sequence,
                    "kind": kind,
                    "provider_id": str(provider.provider_id),
                    "method": method,
                    "path": path.relative_to(self.raw_root).as_posix(),
                    "sha256": _sha(path),
                }
            )
        return observation


def _successful(observation: ProviderObservation, method: str) -> object:
    if observation.error is not None:
        raise ControlTraceStateCapabilityError(f"rpc_error:{method}")
    return observation.result


def _provider_fixture_result(
    *,
    provider: Any,
    fixture: Mapping[str, object],
    recorder: _EvidenceRecorder,
) -> dict[str, object]:
    provider_id = str(getattr(provider, "provider_id", "")).strip()
    family = str(getattr(provider, "provider_family", "")).strip().lower()
    if not provider_id:
        raise ControlTraceStateCapabilityError("provider_id_missing")
    if not family or family == "unverified":
        raise ControlTraceStateCapabilityError("provider_family_unverified")

    expected_chain_id = _lower_hex(fixture.get("chain_id"), "fixture_chain_id")
    chain_id = _lower_hex(
        _successful(recorder.call(provider, "eth_chainId", []), "eth_chainId"),
        "observed_chain_id",
    )
    if chain_id != expected_chain_id:
        raise ControlTraceStateCapabilityError("chain_id_mismatch")

    block_number = int(fixture["block_number"])
    block_hash = _lower_hex(fixture.get("block_hash"), "fixture_block_hash", 66)
    by_number = _successful(
        recorder.call(provider, "eth_getBlockByNumber", [hex(block_number), False]),
        "eth_getBlockByNumber",
    )
    by_hash = _successful(
        recorder.call(provider, "eth_getBlockByHash", [block_hash, False]),
        "eth_getBlockByHash",
    )
    if not isinstance(by_number, Mapping) or not isinstance(by_hash, Mapping):
        raise ControlTraceStateCapabilityError("historical_block_invalid")
    number_semantic = (
        _int_quantity(by_number.get("number"), "block_number"),
        _lower_hex(by_number.get("hash"), "block_hash", 66),
        _int_quantity(by_number.get("timestamp"), "block_timestamp"),
    )
    hash_semantic = (
        _int_quantity(by_hash.get("number"), "block_number"),
        _lower_hex(by_hash.get("hash"), "block_hash", 66),
        _int_quantity(by_hash.get("timestamp"), "block_timestamp"),
    )
    if number_semantic != hash_semantic or number_semantic[:2] != (block_number, block_hash):
        raise ControlTraceStateCapabilityError("historical_block_mismatch")

    transaction_hash = _lower_hex(
        fixture.get("transaction_hash"), "fixture_transaction_hash", 66
    )
    receipt = _successful(
        recorder.call(provider, "eth_getTransactionReceipt", [transaction_hash]),
        "eth_getTransactionReceipt",
    )
    if not isinstance(receipt, Mapping):
        raise ControlTraceStateCapabilityError("receipt_invalid")
    if (
        _lower_hex(receipt.get("transactionHash"), "receipt_transaction_hash", 66)
        != transaction_hash
        or _lower_hex(receipt.get("blockHash"), "receipt_block_hash", 66)
        != block_hash
        or _int_quantity(receipt.get("blockNumber"), "receipt_block_number")
        != block_number
    ):
        raise ControlTraceStateCapabilityError("receipt_block_mismatch")

    trace_method, trace_payload, _, trace_error = trace_transaction_backend(
        _RecordedProvider(provider, recorder), transaction_hash
    )
    if trace_method is None:
        raise ControlTraceStateCapabilityError(
            f"trace_method_unsupported:{_canonical_json(trace_error)}"
        )
    if trace_method == "trace_transaction":
        records = creations_from_parity_traces(
            str(fixture["chain"]), block_number, block_hash, trace_payload
        )
    else:
        records = creations_from_geth_calltracer(
            str(fixture["chain"]),
            block_number,
            block_hash,
            [{"txHash": transaction_hash, "result": trace_payload}],
        )
    creation_set = canonical_creation_set(records)
    created_address = _lower_hex(
        fixture.get("created_address"), "fixture_created_address", 42
    )
    if created_address not in {row[1] for row in creation_set}:
        raise ControlTraceStateCapabilityError("known_creation_missing")

    selector = {"blockHash": block_hash, "requireCanonical": True}
    code = _successful(
        recorder.call(provider, "eth_getCode", [created_address, selector]),
        "eth_getCode",
    )
    code = _lower_hex(code, "historical_code")
    slots: dict[str, str] = {}
    for name, slot in (
        ("implementation", EIP1967_IMPLEMENTATION_SLOT),
        ("beacon", EIP1967_BEACON_SLOT),
        ("admin", EIP1967_ADMIN_SLOT),
    ):
        value = _successful(
            recorder.call(provider, "eth_getStorageAt", [created_address, slot, selector]),
            "eth_getStorageAt",
        )
        slots[name] = _lower_hex(value, f"{name}_slot", 66)

    beacon_result: str | None = None
    beacon_address = fixture.get("beacon_address")
    if beacon_address:
        normalized_beacon = _lower_hex(beacon_address, "fixture_beacon_address", 42)
        beacon_result = _lower_hex(
            _successful(
                recorder.call(
                    provider,
                    "eth_call",
                    [{"to": normalized_beacon, "data": BEACON_IMPLEMENTATION_SELECTOR}, selector],
                ),
                "eth_call",
            ),
            "beacon_implementation",
            66,
        )

    return {
        "provider_id": provider_id,
        "provider_family": family,
        "chain_id": chain_id,
        "block_number": number_semantic[0],
        "block_hash": number_semantic[1],
        "block_timestamp": number_semantic[2],
        "transaction_hash": transaction_hash,
        "trace_method": trace_method,
        "creation_set": [list(row) for row in creation_set],
        "known_creation_recovered": True,
        "runtime_code": code,
        "storage_slots": slots,
        "beacon_implementation": beacon_result,
    }


class _RecordedProvider:
    def __init__(self, provider: Any, recorder: _EvidenceRecorder) -> None:
        self._provider = provider
        self._recorder = recorder
        self.provider_id = provider.provider_id
        self.provider_family = provider.provider_family

    def call(self, method: str, params: list[object]) -> ProviderObservation:
        return self._recorder.call(self._provider, method, params)


def _semantic_state(row: Mapping[str, object]) -> tuple[object, ...]:
    return (
        row["chain_id"],
        row["block_number"],
        row["block_hash"],
        row["block_timestamp"],
        row["transaction_hash"],
        tuple(tuple(value) for value in row["creation_set"]),
        row["runtime_code"],
        _canonical_json(row["storage_slots"]),
        row["beacon_implementation"],
    )


def assess_trace_state_capability(
    *,
    fixtures: Sequence[Mapping[str, object]],
    providers: Sequence[Any],
    raw_root: Path,
    exhaustive_failures: bool = False,
) -> dict[str, object]:
    """Probe frozen fixtures and return a self-hashed, non-authorizing report."""
    if not fixtures:
        raise ControlTraceStateCapabilityError("fixtures_empty")
    recorder = _EvidenceRecorder(raw_root)
    chain_rows: list[dict[str, object]] = []
    report_errors: list[str] = []
    seen_chains: set[str] = set()
    for fixture in sorted(fixtures, key=lambda row: str(row.get("chain", ""))):
        chain = str(fixture.get("chain", "")).strip().lower()
        if not chain or chain in seen_chains:
            raise ControlTraceStateCapabilityError("fixture_chain_duplicate_or_missing")
        seen_chains.add(chain)
        chain_providers = [
            provider
            for provider in providers
            if str(getattr(provider, "chain", chain)).strip().lower() == chain
        ]
        chosen: list[Any] = []
        families: set[str] = set()
        for provider in sorted(chain_providers, key=lambda item: str(item.provider_id)):
            family = str(getattr(provider, "provider_family", "")).strip().lower()
            if not family or family == "unverified" or family in families:
                continue
            chosen.append(provider)
            families.add(family)
            if len(chosen) == 2:
                break
        if len(chosen) != 2:
            raise ControlTraceStateCapabilityError("provider_family_independence")
        provider_rows: list[dict[str, object]] = []
        provider_errors: list[str] = []
        for provider in chosen:
            try:
                provider_rows.append(
                    _provider_fixture_result(
                        provider=provider,
                        fixture=fixture,
                        recorder=recorder,
                    )
                )
            except ControlTraceStateCapabilityError as exc:
                if not exhaustive_failures:
                    raise
                error = str(exc)
                provider_id = str(provider.provider_id)
                provider_rows.append(
                    {
                        "provider_id": provider_id,
                        "provider_family": str(provider.provider_family).lower(),
                        "complete": False,
                        "errors": [error],
                    }
                )
                provider_errors.append(f"{chain}:{provider_id}:{error}")
        if provider_errors:
            report_errors.extend(provider_errors)
            chain_rows.append(
                {
                    "chain": chain,
                    "complete": False,
                    "known_creation_recovered_by_both": False,
                    "provider_count": 2,
                    "verified_operator_families": sorted(families),
                    "providers": provider_rows,
                    "errors": provider_errors,
                }
            )
            continue
        if _semantic_state(provider_rows[0]) != _semantic_state(provider_rows[1]):
            if not exhaustive_failures:
                raise ControlTraceStateCapabilityError(
                    "provider_semantic_disagreement"
                )
            disagreement = f"{chain}:provider_semantic_disagreement"
            report_errors.append(disagreement)
            chain_rows.append(
                {
                    "chain": chain,
                    "complete": False,
                    "known_creation_recovered_by_both": True,
                    "provider_count": 2,
                    "verified_operator_families": sorted(families),
                    "providers": provider_rows,
                    "errors": [disagreement],
                }
            )
            continue
        chain_rows.append(
            {
                "chain": chain,
                "complete": True,
                "known_creation_recovered_by_both": True,
                "provider_count": 2,
                "verified_operator_families": sorted(families),
                "providers": provider_rows,
                "errors": [],
            }
        )

    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "complete": not report_errors,
        "fixture_count": len(fixtures),
        "chain_count": len(chain_rows),
        "chains": chain_rows,
        "required_methods": list(REQUIRED_METHODS),
        "trace_method_candidates": list(TRACE_METHODS),
        "raw_evidence_count": len(recorder.entries),
        "raw_evidence": recorder.entries,
        "errors": report_errors,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    report["report_sha256"] = _canonical_sha(report)
    return report


def verify_trace_state_capability(
    *,
    report_path: Path,
    raw_root: Path,
    provider_registry_path: Path | None = None,
) -> dict[str, object]:
    """Re-hash the report/envelopes and optionally rebind providers to a registry."""
    report_file = _ordinary(report_path, "capability_report")
    try:
        report = json.loads(report_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlTraceStateCapabilityError("capability_report_json_invalid") from exc
    if not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION:
        raise ControlTraceStateCapabilityError("capability_report_schema_invalid")
    material = {key: value for key, value in report.items() if key != "report_sha256"}
    if report.get("report_sha256") != _canonical_sha(material):
        raise ControlTraceStateCapabilityError("capability_report_self_hash_invalid")
    if report.get("complete") is not True or report.get("errors") != []:
        raise ControlTraceStateCapabilityError("capability_report_not_complete")
    for flag in _FALSE_AUTHORITY_FLAGS:
        if report.get(flag) is not False:
            raise ControlTraceStateCapabilityError(f"{flag}_must_be_false")

    root = raw_root.expanduser()
    if root.is_symlink():
        raise ControlTraceStateCapabilityError("raw_root_symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ControlTraceStateCapabilityError("raw_root_not_directory")
    evidence = report.get("raw_evidence")
    if not isinstance(evidence, list) or len(evidence) != report.get("raw_evidence_count"):
        raise ControlTraceStateCapabilityError("raw_evidence_count_mismatch")
    for entry in evidence:
        if not isinstance(entry, Mapping):
            raise ControlTraceStateCapabilityError("raw_evidence_entry_invalid")
        relative = Path(str(entry.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise ControlTraceStateCapabilityError("raw_evidence_path_escape")
        path = root / relative
        ordinary = _ordinary(path, "raw_evidence")
        try:
            ordinary.relative_to(root)
        except ValueError as exc:
            raise ControlTraceStateCapabilityError("raw_evidence_path_escape") from exc
        if _sha(ordinary) != entry.get("sha256"):
            raise ControlTraceStateCapabilityError("raw_evidence_hash_mismatch")

    chains = report.get("chains")
    if not isinstance(chains, list) or len(chains) != report.get("chain_count"):
        raise ControlTraceStateCapabilityError("chain_count_mismatch")
    registry = (
        ProviderRegistry.from_path(_ordinary(provider_registry_path, "provider_registry"))
        if provider_registry_path is not None
        else None
    )
    for chain_entry in chains:
        if not isinstance(chain_entry, Mapping) or chain_entry.get("complete") is not True:
            raise ControlTraceStateCapabilityError("chain_entry_invalid")
        families = list(chain_entry.get("verified_operator_families") or [])
        if len(families) != 2 or len(set(families)) != 2:
            raise ControlTraceStateCapabilityError("provider_family_independence")
        provider_rows = chain_entry.get("providers")
        if not isinstance(provider_rows, list) or len(provider_rows) != 2:
            raise ControlTraceStateCapabilityError("provider_count_mismatch")
        if registry is not None:
            registry_rows = {
                row.provider_id: row
                for row in registry.providers_for_chain(
                    str(chain_entry["chain"]), verified_only=True
                )
            }
            for provider_row in provider_rows:
                if not isinstance(provider_row, Mapping):
                    raise ControlTraceStateCapabilityError("provider_entry_invalid")
                record = registry_rows.get(str(provider_row.get("provider_id", "")))
                if record is None or record.operator_family != provider_row.get("provider_family"):
                    raise ControlTraceStateCapabilityError("provider_registry_mismatch")

    verification: dict[str, object] = {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "complete": True,
        "report_sha256": report["report_sha256"],
        "report_file_sha256": _sha(report_file),
        "raw_evidence_count": len(evidence),
        "chain_count": len(chains),
        "provider_registry_verified": registry is not None,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "errors": [],
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification
