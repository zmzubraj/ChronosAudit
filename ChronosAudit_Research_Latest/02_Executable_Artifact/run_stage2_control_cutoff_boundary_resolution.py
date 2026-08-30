from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.onchain import JsonRpcProvider
from chronosaudit_stage2.public_acquisition.control_cutoff_boundary_resolution import (
    execute_cutoff_boundary_batch,
    resume_cutoff_boundary_batch,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


def _provider_min_intervals(values: list[str]) -> dict[str, float]:
    intervals: dict[str, float] = {}
    for value in values:
        provider_id, separator, raw_seconds = value.partition("=")
        provider_id = provider_id.strip()
        if not separator or not provider_id or provider_id in intervals:
            raise ValueError("provider_min_interval_invalid")
        try:
            seconds = float(raw_seconds)
        except ValueError as exc:
            raise ValueError("provider_min_interval_invalid") from exc
        if seconds < 0 or seconds > 5:
            raise ValueError("provider_min_interval_invalid")
        intervals[provider_id] = seconds
    return intervals


def _load_json_ordinary(path: Path, label: str) -> dict[str, object]:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ValueError(f"{label}_not_ordinary")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label}_not_ordinary")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label}_root_invalid")
    return payload


def build_runtime_providers(
    *,
    activation: Mapping[str, object],
    provider_registry_path: Path,
    timeout_seconds: int,
) -> dict[str, JsonRpcProvider]:
    """Resolve only verified providers named by the exact activation.

    Resolved endpoints remain runtime-only and are never included in the
    command's JSON result.
    """
    scopes = activation.get("range_scopes")
    if not isinstance(scopes, list) or not scopes:
        raise ValueError("activation_range_scopes_invalid")
    provider_ids = {
        str(scope.get("provider_id", "")).strip()
        for scope in scopes
        if isinstance(scope, Mapping)
    }
    if not provider_ids or "" in provider_ids:
        raise ValueError("activation_provider_set_invalid")
    registry = ProviderRegistry.from_path(provider_registry_path)
    providers = {
        record.provider_id: JsonRpcProvider(
            provider_id=record.provider_id,
            url=record.resolved_endpoint(),
            timeout=timeout_seconds,
            max_retries=0,
            provider_family=record.operator_family,
            provider_identity_evidence={
                "public_endpoint_template": record.public_endpoint,
                "endpoint_template_sha256": record.public_endpoint_id,
            },
        )
        for record in registry.providers
        if record.provider_id in provider_ids
        and record.tracking_enabled
        and record.operator_verified
    }
    if set(providers) != provider_ids:
        raise ValueError("activation_provider_absent_or_unverified")
    return providers


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run or resume the exact range-bound Stage 2 dual-provider cutoff "
            "boundary batch. Outputs remain non-authorizing."
        )
    )
    parser.add_argument("--activation-verification", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--now-utc", required=True)
    parser.add_argument("--max-targets", type=int)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument(
        "--provider-min-interval",
        action="append",
        default=[],
        metavar="PROVIDER_ID=SECONDS",
        help=(
            "Pace only the named activation provider before each authorized "
            "network call; repeat for multiple providers (0-5 seconds)."
        ),
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    provider_min_intervals = _provider_min_intervals(
        args.provider_min_interval
    )

    activation = _load_json_ordinary(
        args.activation_verification, "activation_verification"
    )
    providers = build_runtime_providers(
        activation=activation,
        provider_registry_path=args.provider_registry,
        timeout_seconds=args.timeout_seconds,
    )
    operation = (
        resume_cutoff_boundary_batch if args.resume else execute_cutoff_boundary_batch
    )
    result = operation(
        requirements_path=args.requirements,
        activation=activation,
        providers_by_id=providers,
        output_root=args.output_root,
        now_utc=args.now_utc,
        max_targets=args.max_targets,
        provider_min_intervals=provider_min_intervals,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "COMPLETE_NON_AUTHORIZING" else 3


if __name__ == "__main__":
    raise SystemExit(main())
