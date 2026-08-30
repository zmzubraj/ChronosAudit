from __future__ import annotations

import concurrent.futures
import os
from dataclasses import dataclass
from pathlib import Path
from threading import BoundedSemaphore
from typing import Any, Callable

import pandas as pd

from chronosaudit_stage2.onchain import (
    BEACON_IMPLEMENTATION_SELECTOR,
    JsonRpcProvider,
    historical_identity_snapshot,
    provider_urls_from_env,
)

from .ledger import AppendOnlyLedger
from .managed_providers import ManagedProviderConfigurationError
from .model import AcquisitionEvent, AcquisitionStatus
from .providers import ProviderRegistry
from .strict_snapshot import REQUIRED_STATE_CELLS, acquire_strict_historical_snapshot

_TERMINAL_STATUSES = {
    AcquisitionStatus.VERIFIED,
    AcquisitionStatus.DISPUTED,
    AcquisitionStatus.POLICY_EXCLUDED,
    AcquisitionStatus.WAITING_EXTERNAL,
}

_WAITING_EXTERNAL_REASONS = {
    "missing_prediction_cutoff_block",
    "missing_verified_cutoff_evidence",
    "missing_source_locator",
    "missing_creation_locator",
}
_DEFAULT_STRICT_CUTOFF_POLICY = {
    "rule": "deployment_timestamp_plus_24h",
    "primary_landmark_hours": 24,
    "minimum_incident_lead_hours": 1.0,
}


def _normalize_chain(value: Any) -> str:
    normalized = str(value).strip().lower()
    if normalized == "mainnet":
        return "ethereum"
    if normalized in {"arb", "arbi"}:
        return "arbitrum"
    return normalized


def _verified_family_name(value: str | None) -> str | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if not lowered or lowered.startswith("unverified"):
        return None
    return lowered


def _distinct_verified_families(providers: list[JsonRpcProvider]) -> set[str]:
    return {family for family in (_verified_family_name(provider.provider_family) for provider in providers) if family}


def public_provider_objects(
    chain: str,
    registry: ProviderRegistry,
    *,
    timeout_seconds: int = 20,
    max_retries: int = 3,
    backoff_seconds: float = 0.5,
    artifact_root: str | Path | None = None,
) -> list[JsonRpcProvider]:
    normalized = _normalize_chain(chain)
    providers: list[JsonRpcProvider] = []
    for record in registry.providers_for_chain(normalized, verified_only=False):
        family = record.operator_family if record.operator_verified else f"unverified:{record.operator_family}"
        providers.append(
            JsonRpcProvider(
                provider_id=record.provider_id,
                url=record.endpoint,
                timeout=timeout_seconds,
                max_retries=max_retries,
                backoff_seconds=backoff_seconds,
                provider_family=family,
                artifact_root=artifact_root,
            )
        )
    return providers


@dataclass(frozen=True)
class PublicRpcClient:
    chain: str
    providers: tuple[JsonRpcProvider, ...]
    policy: dict[str, Any]

    def acquire_snapshot(self, address: str, block_number: int, *, strict_provider_families: bool = True) -> dict[str, Any]:
        return historical_identity_snapshot(
            address,
            block_number,
            list(self.providers),
            strict_provider_families=strict_provider_families,
        )


def _cell_entry(status: str, block_selector: str, *, error_detail: str | None = None) -> dict[str, Any]:
    return {"status": status, "block_selector": block_selector, "error_detail": error_detail}


def _snapshot_status_to_cell(snapshot_status: str, *, not_applicable_status: str = "POLICY_EXCLUDED") -> str:
    mapping = {
        "complete": "VERIFIED",
        "consensus": "VERIFIED",
        "not_applicable": not_applicable_status,
        "blocked_beacon_disputed": "DISPUTED",
        "blocked_no_canonical_block_consensus": "PARTIAL",
        "partial_or_disputed": "PARTIAL",
    }
    return mapping.get(snapshot_status, "PARTIAL")


def _cutoff_is_verified(case: dict[str, Any]) -> bool:
    return (
        str(case.get("cutoff_status", "PARTIAL")).upper() == "VERIFIED"
        and pd.notna(case.get("prediction_cutoff_block"))
        and str(case.get("deployment_verification_status", "")).upper() == "VERIFIED"
        and str(case.get("prediction_cutoff_block_verification_status", "")).upper() == "VERIFIED"
        and str(case.get("source_availability_verification_status", "")).upper() == "VERIFIED"
        and bool(case.get("incident_eligibility")) is True
        and float(case.get("cutoff_lead_hours", 0) or 0) >= 1.0
    )


def _strict_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    effective = {"cutoff_policy": dict(_DEFAULT_STRICT_CUTOFF_POLICY)}
    for key, value in dict(policy or {}).items():
        if key == "cutoff_policy" and isinstance(value, dict):
            effective["cutoff_policy"].update(value)
            continue
        effective[key] = value
    return effective


def _prediction_block_selector(prediction_cutoff_block: Any) -> str:
    return f"prediction:{int(prediction_cutoff_block)}"


def _default_cell_results(
    case: dict[str, Any],
    *,
    capability_snapshot: dict[str, Any],
    providers: list[JsonRpcProvider],
    blocked_reason: str,
    prediction_snapshot: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    incident_selector = f"incident:{int(case['incident_block'])}"
    prediction_cutoff_block = case.get("prediction_cutoff_block")
    has_prediction_cutoff_block = prediction_cutoff_block not in (None, "") and not pd.isna(prediction_cutoff_block)
    prediction_selector = _prediction_block_selector(prediction_cutoff_block) if has_prediction_cutoff_block else "prediction:unresolved"

    capability_status = _snapshot_status_to_cell(capability_snapshot.get("status", "partial_or_disputed"))
    if blocked_reason == "insufficient_independent_provider_families":
        capability_status = "PARTIAL"

    cell_results: dict[str, dict[str, Any]] = {
        "block_capability": _cell_entry(capability_status, incident_selector, error_detail=None if capability_status == "VERIFIED" else blocked_reason),
        "runtime_code": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocked_reason),
        "eip1967_implementation_slot": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocked_reason),
        "eip1967_beacon_slot": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocked_reason),
        "eip1967_admin_slot": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocked_reason),
        "beacon_implementation_call": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocked_reason),
        "implementation_runtime_code": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocked_reason),
        "source_locator": _cell_entry("WAITING_EXTERNAL", "source", error_detail="missing_source_locator"),
        "creation_locator": _cell_entry("WAITING_EXTERNAL", "creation", error_detail="missing_creation_locator"),
    }
    if prediction_snapshot is None:
        return cell_results

    cell_results["runtime_code"] = _cell_entry(
        _snapshot_status_to_cell(prediction_snapshot["code"]["status"]),
        prediction_selector,
        error_detail=blocked_reason if prediction_snapshot["code"]["status"] != "consensus" else None,
    )
    cell_results["eip1967_implementation_slot"] = _cell_entry(
        _snapshot_status_to_cell(prediction_snapshot["implementation"]["status"]),
        prediction_selector,
        error_detail=blocked_reason if prediction_snapshot["implementation"]["status"] != "consensus" else None,
    )
    cell_results["eip1967_beacon_slot"] = _cell_entry(
        _snapshot_status_to_cell(prediction_snapshot["beacon"]["status"]),
        prediction_selector,
        error_detail=blocked_reason if prediction_snapshot["beacon"]["status"] not in {"consensus", "not_applicable"} else None,
    )
    cell_results["eip1967_admin_slot"] = _cell_entry(
        _snapshot_status_to_cell(prediction_snapshot["admin"]["status"]),
        prediction_selector,
        error_detail=blocked_reason if prediction_snapshot["admin"]["status"] != "consensus" else None,
    )
    cell_results["beacon_implementation_call"] = _cell_entry(
        _snapshot_status_to_cell(prediction_snapshot["beacon_implementation"]["status"]),
        prediction_selector,
        error_detail=blocked_reason if prediction_snapshot["beacon_implementation"]["status"] not in {"consensus", "not_applicable"} else None,
    )

    implementation_state = prediction_snapshot.get("implementation_runtime_code", {"status": "missing"})
    cell_results["implementation_runtime_code"] = _cell_entry(
        _snapshot_status_to_cell(implementation_state["status"]),
        prediction_selector,
        error_detail=blocked_reason if implementation_state["status"] != "consensus" else None,
    )
    return cell_results


def _provider_configuration_blocked_result(
    case: dict[str, Any],
    error: ManagedProviderConfigurationError,
) -> dict[str, Any]:
    raw_code = str(getattr(error, "code", "provider_configuration_blocked")).strip().lower()
    blocker = (
        raw_code
        if raw_code and all(char.isalnum() or char == "_" for char in raw_code)
        else "provider_configuration_blocked"
    )
    prediction_cutoff_block = case.get("prediction_cutoff_block")
    has_prediction_block = prediction_cutoff_block not in (None, "") and not pd.isna(prediction_cutoff_block)
    prediction_selector = (
        _prediction_block_selector(prediction_cutoff_block) if has_prediction_block else "prediction:unresolved"
    )
    incident_selector = f"incident:{int(case['incident_block'])}"
    cell_results = {
        "block_capability": _cell_entry("WAITING_EXTERNAL", incident_selector, error_detail=blocker),
        "runtime_code": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocker),
        "eip1967_implementation_slot": _cell_entry(
            "WAITING_EXTERNAL",
            prediction_selector,
            error_detail=blocker,
        ),
        "eip1967_beacon_slot": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocker),
        "eip1967_admin_slot": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocker),
        "beacon_implementation_call": _cell_entry("WAITING_EXTERNAL", prediction_selector, error_detail=blocker),
        "implementation_runtime_code": _cell_entry(
            "WAITING_EXTERNAL",
            prediction_selector,
            error_detail=blocker,
        ),
        "source_locator": _cell_entry("WAITING_EXTERNAL", "source", error_detail=blocker),
        "creation_locator": _cell_entry("WAITING_EXTERNAL", "creation", error_detail=blocker),
    }
    return {
        "case_id": case["case_id"],
        "case_name": case.get("case_name", ""),
        "chain": _normalize_chain(case["chain"]),
        "address": str(case.get("address", "")).lower(),
        "incident_block": int(case["incident_block"]),
        "status": "WAITING_EXTERNAL",
        "strict_snapshot_closed": False,
        "blocked_reason": blocker,
        "provider_configuration_error": {"code": blocker},
        "provider_families": [],
        "capability_snapshot": None,
        "prediction_snapshot": None,
        "cell_results": cell_results,
    }


def acquire_case_snapshot(
    case: dict[str, Any],
    *,
    providers: list[JsonRpcProvider],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_chain = _normalize_chain(case["chain"])
    address = str(case["address"]).lower()
    incident_block = int(case["incident_block"])
    verified_families = sorted(_distinct_verified_families(providers))
    effective_policy = _strict_policy(policy)

    capability_snapshot = historical_identity_snapshot(
        address,
        incident_block,
        providers,
        strict_provider_families=False,
    )

    base_result = {
        "case_id": case["case_id"],
        "case_name": case["case_name"],
        "chain": normalized_chain,
        "address": address,
        "incident_block": incident_block,
        "capability_snapshot": capability_snapshot,
        "provider_families": verified_families,
    }

    if len(verified_families) < 2:
        blocked_reason = "insufficient_independent_provider_families"
        return {
            **base_result,
            "status": "PARTIAL",
            "blocked_reason": blocked_reason,
            "prediction_snapshot": None,
            "cell_results": _default_cell_results(
                case,
                capability_snapshot=capability_snapshot,
                providers=providers,
                blocked_reason=blocked_reason,
                prediction_snapshot=None,
            ),
        }

    if not _cutoff_is_verified(case) or pd.isna(case.get("deployment_block")):
        blocked_reason = "missing_verified_cutoff_evidence"
        return {
            **base_result,
            "status": "PARTIAL",
            "blocked_reason": blocked_reason,
            "prediction_snapshot": None,
            "cell_results": _default_cell_results(
                case,
                capability_snapshot=capability_snapshot,
                providers=providers,
                blocked_reason=blocked_reason,
                prediction_snapshot=None,
            ),
        }

    strict_snapshot = acquire_strict_historical_snapshot(
        case,
        providers=providers,
        policy=effective_policy,
        receipt_root=next(
            (
                provider.artifact_root
                for provider in providers
                if getattr(provider, "artifact_root", None) is not None
            ),
            Path.cwd(),
        ),
    )
    blocked_reason = None if strict_snapshot.get("strict_snapshot_closed") else strict_snapshot.get("blocked_reason")
    prediction_snapshot = dict(strict_snapshot.get("snapshot") or {})
    prediction_snapshot["implementation_runtime_code"] = dict(
        (strict_snapshot.get("state_cells") or {}).get("implementation_runtime_code", {"status": "missing"})
    )
    return {
        **base_result,
        **strict_snapshot,
        "status": "VERIFIED" if blocked_reason is None else "PARTIAL",
        "blocked_reason": blocked_reason,
        "prediction_snapshot": prediction_snapshot,
        "cell_results": _default_cell_results(
            case,
            capability_snapshot=capability_snapshot,
            providers=providers,
            blocked_reason=blocked_reason or "resolved",
            prediction_snapshot=prediction_snapshot,
        ),
    }


def _cell_initial_event(case: dict[str, Any], method: str, block_selector: str) -> AcquisitionEvent:
    return AcquisitionEvent.queued(case["case_id"], case["chain"], None, method, block_selector)


def _ensure_cell_event(
    ledger: AppendOnlyLedger,
    case: dict[str, Any],
    method: str,
    block_selector: str,
    outcome_status: str,
    error_detail: str | None,
    retry_terminal: bool,
) -> tuple[str, str]:
    resume = ledger.resume_index()
    queued = _cell_initial_event(case, method, block_selector)
    current_status = resume.get(queued.cell_id)
    if current_status in _TERMINAL_STATUSES and not retry_terminal:
        return "skipped_terminal", current_status.value

    event = queued
    if current_status is None:
        ledger.append(queued)
        current_status = AcquisitionStatus.QUEUED

    if outcome_status == "VERIFIED":
        if current_status == AcquisitionStatus.QUEUED:
            event = queued.transition(AcquisitionStatus.WAITING_EXTERNAL, error_detail=error_detail)
            event = ledger.append(event)
            current_status = event.status
        if current_status == AcquisitionStatus.WAITING_EXTERNAL:
            event = event.transition(AcquisitionStatus.VERIFIED, error_detail=error_detail)
            ledger.append(event)
        return "recorded", "VERIFIED"

    target_status = AcquisitionStatus(outcome_status)
    if current_status == target_status and not retry_terminal:
        return "skipped_terminal", target_status.value
    if current_status != AcquisitionStatus.QUEUED:
        return "skipped_terminal", current_status.value
    ledger.append(queued.transition(target_status, error_detail=error_detail))
    return "recorded", target_status.value


def acquire_queue(
    queue: pd.DataFrame,
    policy: dict[str, Any],
    *,
    registry: ProviderRegistry,
    ledger: AppendOnlyLedger,
    execute: bool = False,
    retry_terminal: bool = False,
    env: dict[str, str] | None = None,
    artifact_root: str | Path | None = None,
    provider_factory: Callable[[dict[str, Any]], list[JsonRpcProvider]] | None = None,
    snapshot_acquirer: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    cases = queue.to_dict(orient="records")
    if not execute:
        return {
            "status": "dry_run",
            "queued_cases": len(cases),
            "pilot_cases": int(queue["pilot_member"].sum()) if "pilot_member" in queue.columns else 0,
        }

    provider_semaphores: dict[str, BoundedSemaphore] = {}
    for record in registry.providers:
        provider_semaphores.setdefault(record.provider_id, BoundedSemaphore(int(policy["per_provider_concurrency"])))

    default_provider_factory = provider_factory
    if default_provider_factory is None:
        def default_provider_factory(case: dict[str, Any]) -> list[JsonRpcProvider]:
            resolved = provider_urls_from_env(
                case["chain"],
                registry=registry,
                env=os.environ if env is None else env,
                timeout=int(policy.get("timeout_seconds", 20)),
                max_retries=int(policy.get("max_retries", 3)),
                backoff_seconds=float(policy.get("backoff_base_seconds", 0.5)),
                artifact_root=artifact_root,
            )
            if resolved:
                return resolved
            return public_provider_objects(
                case["chain"],
                registry,
                timeout_seconds=int(policy.get("timeout_seconds", 20)),
                max_retries=int(policy.get("max_retries", 3)),
                backoff_seconds=float(policy.get("backoff_base_seconds", 0.5)),
                artifact_root=artifact_root,
            )

    snapshot_fn = snapshot_acquirer or acquire_case_snapshot

    def run_case(case: dict[str, Any]) -> dict[str, Any]:
        try:
            providers = default_provider_factory(case)
        except ManagedProviderConfigurationError as exc:
            result = _provider_configuration_blocked_result(case, exc)
        else:
            for provider in providers:
                semaphore = provider_semaphores.setdefault(
                    provider.provider_id,
                    BoundedSemaphore(int(policy["per_provider_concurrency"])),
                )
                semaphore.acquire()
            try:
                result = snapshot_fn(case, providers=providers, policy=policy)
            finally:
                for provider in providers:
                    provider_semaphores[provider.provider_id].release()

        cell_audit: dict[str, dict[str, str]] = {}
        for method, detail in result.get("cell_results", {}).items():
            cell_action, final_status = _ensure_cell_event(
                ledger,
                case,
                method,
                str(detail["block_selector"]),
                str(detail["status"]),
                detail.get("error_detail"),
                retry_terminal,
            )
            cell_audit[method] = {"action": cell_action, "status": final_status}
        result["cell_audit"] = cell_audit
        return result

    max_workers = int(policy["global_concurrency"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(run_case, cases))

    return {
        "status": "completed",
        "results": results,
    }
