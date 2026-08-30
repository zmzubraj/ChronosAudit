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
from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_capability import (
    ControlCutoffBoundaryCapabilityError,
    assess_cutoff_boundary_capability,
    verify_cutoff_boundary_capability,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


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


def _required_chains(requirements_path: Path) -> set[str]:
    candidate = requirements_path.expanduser()
    if candidate.is_symlink():
        raise ValueError("requirements_not_ordinary")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("requirements_not_ordinary")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    targets = payload.get("targets") if isinstance(payload, dict) else None
    if not isinstance(targets, list) or not targets:
        raise ValueError("requirements_targets_invalid")
    chains = {
        str(row.get("chain", "")).strip().lower()
        for row in targets
        if isinstance(row, dict)
    }
    if not chains or "" in chains:
        raise ValueError("requirements_chain_scope_invalid")
    return chains


def build_runtime_providers(
    *,
    provider_registry_path: Path,
    required_chains: set[str],
    timeout_seconds: int,
    max_retries: int = 0,
    backoff_seconds: float = 0.5,
    minimum_interval_seconds: float = 0.0,
) -> list[_PacedProvider]:
    """Resolve exactly two verified families per required chain at runtime."""
    registry = ProviderRegistry.from_path(provider_registry_path)
    selected = []
    for chain in sorted(required_chains):
        by_family = {}
        for record in sorted(
            (
                row
                for row in registry.providers
                if row.chain == chain
                and row.operator_verified
                and row.tracking_enabled
                and row.operator_family != "unverified"
            ),
            key=lambda row: (row.operator_family, row.provider_id),
        ):
            by_family.setdefault(record.operator_family, record)
        if len(by_family) < 2:
            raise ValueError(f"{chain}:provider_family_independence")
        selected.extend(by_family[family] for family in sorted(by_family)[:2])

    providers: list[_PacedProvider] = []
    for record in selected:
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
            _PacedProvider(provider, record.chain, minimum_interval_seconds)
        )
    return providers


def _failure_verification(
    *, capability_path: Path, capability: dict[str, object]
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": (
            "stage2_control_cutoff_boundary_capability_verification.v1"
        ),
        "decision": "CUTOFF_BOUNDARY_CAPABILITY_NOT_VERIFIED",
        "complete": False,
        "capability_file_sha256": _file_sha(capability_path),
        "capability_sha256": capability.get("capability_sha256"),
        "requirements_file_sha256": capability.get("requirements_file_sha256"),
        "provider_registry_sha256": capability.get("provider_registry_sha256"),
        "chain_count": capability.get("chain_count", 0),
        "raw_evidence_count": capability.get("raw_evidence_count", 0),
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "errors": list(capability.get("errors") or ["capability_incomplete"]),
    }
    result["verification_sha256"] = _canonical_sha(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Probe the oldest and newest frozen Stage 2 cutoff-boundary blocks "
            "through two verified provider families per chain. Outputs are "
            "non-authorizing and do not permit boundary resolution or selection."
        )
    )
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--output-capability", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
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
    requirements = args.requirements.expanduser().resolve(strict=True)
    registry = args.provider_registry.expanduser().resolve(strict=True)
    capability_output = args.output_capability.expanduser().resolve(strict=False)
    verification_output = args.output_verification.expanduser().resolve(strict=False)
    if capability_output in {requirements, registry} or verification_output in {
        requirements,
        registry,
    }:
        raise ValueError("outputs_must_not_overwrite_inputs")
    if capability_output == verification_output:
        raise ValueError("capability_and_verification_outputs_must_differ")
    raw_root = args.raw_root.expanduser().resolve(strict=False)
    raw_root.mkdir(parents=True, exist_ok=True)

    try:
        providers = build_runtime_providers(
            provider_registry_path=registry,
            required_chains=_required_chains(requirements),
            timeout_seconds=args.timeout_seconds,
            max_retries=args.max_retries,
            backoff_seconds=args.backoff_seconds,
            minimum_interval_seconds=args.minimum_interval_seconds,
        )
        capability = assess_cutoff_boundary_capability(
            requirements_path=requirements,
            provider_registry_path=registry,
            providers=providers,
            raw_root=raw_root,
        )
    except (ControlCutoffBoundaryCapabilityError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "decision": "CUTOFF_BOUNDARY_CAPABILITY_PREFLIGHT_FAILED",
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

    verification = verify_cutoff_boundary_capability(
        capability_path=capability_output,
        requirements_path=requirements,
        provider_registry_path=registry,
        raw_root=raw_root,
    )
    _atomic_write(verification_output, verification)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
