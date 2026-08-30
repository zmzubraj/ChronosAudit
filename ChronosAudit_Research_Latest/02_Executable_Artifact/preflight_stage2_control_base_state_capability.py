#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.onchain import JsonRpcProvider
from chronosaudit_stage2.public_acquisition.control_base_state_capability import (
    ControlBaseStateCapabilityError,
    assess_base_state_capability,
    verify_base_state_capability,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _bindings(targets_path: Path) -> dict[str, tuple[str, str]]:
    payload = json.loads(targets_path.read_text(encoding="utf-8"))
    targets = payload.get("targets") if isinstance(payload, dict) else None
    if not isinstance(targets, list) or not targets:
        raise ValueError("base_state_targets_invalid")
    bindings: dict[str, tuple[str, str]] = {}
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("base_state_target_invalid")
        chain = str(target.get("chain", "")).strip().lower()
        for call in target.get("calls", []):
            if not isinstance(call, dict):
                raise ValueError("base_state_call_invalid")
            provider_id = str(call.get("provider_id", "")).strip()
            family = str(call.get("operator_family", "")).strip().lower()
            value = (chain, family)
            if not provider_id or not chain or not family:
                raise ValueError("base_state_provider_binding_invalid")
            if provider_id in bindings and bindings[provider_id] != value:
                raise ValueError("base_state_provider_binding_conflict")
            bindings[provider_id] = value
    return bindings


class _PacedProvider:
    def __init__(self, provider: JsonRpcProvider, chain: str, interval: float) -> None:
        self._provider = provider
        self.provider_id = provider.provider_id
        self.provider_family = provider.provider_family
        self.chain = chain
        self._interval = interval
        self._last_call = 0.0

    def call(self, method: str, params: list[object]):
        remaining = self._interval - (time.monotonic() - self._last_call)
        if remaining > 0:
            time.sleep(remaining)
        result = self._provider.call(method, params)
        self._last_call = time.monotonic()
        return result


def build_runtime_providers(
    *,
    targets_path: Path,
    provider_registry_path: Path,
    timeout_seconds: int,
    max_retries: int,
    backoff_seconds: float,
    minimum_interval_seconds: float,
) -> list[_PacedProvider]:
    bindings = _bindings(targets_path)
    registry = ProviderRegistry.from_path(provider_registry_path)
    records = {row.provider_id: row for row in registry.providers}
    providers: list[_PacedProvider] = []
    for provider_id, (chain, family) in sorted(bindings.items()):
        record = records.get(provider_id)
        if (
            record is None
            or record.chain != chain
            or record.operator_family != family
            or not record.operator_verified
            or not record.tracking_enabled
        ):
            raise ValueError(f"{provider_id}:provider_registry_mismatch")
        provider = JsonRpcProvider(
            provider_id=record.provider_id,
            url=record.resolved_endpoint(),
            timeout=timeout_seconds,
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
            provider_family=record.operator_family,
            provider_identity_evidence={
                "public_endpoint_template": record.public_endpoint,
                "endpoint_template_sha256": record.public_endpoint_id,
            },
        )
        providers.append(
            _PacedProvider(provider, chain, minimum_interval_seconds)
        )
    return providers


def _failure_verification(
    *, capability_path: Path, capability: dict[str, object]
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": "stage2_control_base_state_capability_verification.v1",
        "decision": "BASE_STATE_CAPABILITY_NOT_VERIFIED",
        "complete": False,
        "capability_file_sha256": _file_sha(capability_path),
        "capability_sha256": capability.get("capability_sha256"),
        "base_state_targets_file_sha256": capability.get(
            "base_state_targets_file_sha256"
        ),
        "provider_registry_sha256": capability.get("provider_registry_sha256"),
        "probe_target_count": capability.get("probe_target_count", 0),
        "raw_evidence_count": capability.get("raw_evidence_count", 0),
        "errors": list(capability.get("errors") or ["capability_incomplete"]),
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["verification_sha256"] = _canonical_sha(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Probe oldest/newest frozen Phase 1 exact calls through both bound "
            "provider families. Outputs are non-authorizing."
        )
    )
    parser.add_argument("--base-state-targets", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--output-capability", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--max-retries", type=int, default=0)
    parser.add_argument("--backoff-seconds", type=float, default=0.5)
    parser.add_argument("--minimum-interval-seconds", type=float, default=0.15)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.timeout_seconds > 300:
        raise ValueError("timeout_seconds_invalid")
    if args.max_retries < 0 or args.max_retries > 3:
        raise ValueError("max_retries_invalid")
    if args.backoff_seconds < 0 or args.backoff_seconds > 30:
        raise ValueError("backoff_seconds_invalid")
    if args.minimum_interval_seconds < 0 or args.minimum_interval_seconds > 10:
        raise ValueError("minimum_interval_seconds_invalid")

    targets = args.base_state_targets.expanduser().resolve(strict=True)
    registry = args.provider_registry.expanduser().resolve(strict=True)
    raw_root = args.raw_root.expanduser().resolve(strict=False)
    capability_output = args.output_capability.expanduser().resolve(strict=False)
    verification_output = args.output_verification.expanduser().resolve(strict=False)
    if capability_output in {targets, registry} or verification_output in {
        targets,
        registry,
    }:
        raise ValueError("outputs_must_not_overwrite_inputs")
    if capability_output == verification_output:
        raise ValueError("capability_and_verification_outputs_must_differ")

    try:
        providers = build_runtime_providers(
            targets_path=targets,
            provider_registry_path=registry,
            timeout_seconds=args.timeout_seconds,
            max_retries=args.max_retries,
            backoff_seconds=args.backoff_seconds,
            minimum_interval_seconds=args.minimum_interval_seconds,
        )
        capability = assess_base_state_capability(
            base_state_targets_path=targets,
            provider_registry_path=registry,
            providers=providers,
            raw_root=raw_root,
        )
    except (ControlBaseStateCapabilityError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "decision": "BASE_STATE_CAPABILITY_PREFLIGHT_FAILED",
                    "complete": False,
                    "errors": [str(exc)],
                    "rpc_authorized": False,
                    "selection_authorized": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 3

    _atomic_write(capability_output, capability)
    if capability.get("complete") is not True:
        verification = _failure_verification(
            capability_path=capability_output, capability=capability
        )
        _atomic_write(verification_output, verification)
        print(json.dumps(verification, indent=2, sort_keys=True))
        return 3
    verification = verify_base_state_capability(
        capability_path=capability_output,
        base_state_targets_path=targets,
        provider_registry_path=registry,
        raw_root=raw_root,
    )
    _atomic_write(verification_output, verification)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
