from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time
from collections.abc import Callable

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.onchain import JsonRpcProvider
from chronosaudit_stage2.public_acquisition.control_candidate_rpc_activation import (
    assess_control_candidate_rpc_provider_readiness,
)
from chronosaudit_stage2.public_acquisition.control_trace_state_capability import (
    ControlTraceStateCapabilityError,
    assess_trace_state_capability,
    verify_trace_state_capability,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


def _parse_family_intervals(values: list[str]) -> dict[str, float]:
    intervals: dict[str, float] = {}
    for value in values:
        family, separator, raw_interval = value.partition("=")
        normalized = family.strip().lower()
        try:
            interval = float(raw_interval)
        except ValueError as exc:
            raise ValueError("provider_family_interval_invalid") from exc
        if (
            separator != "="
            or not normalized
            or not math.isfinite(interval)
            or interval < 0
            or interval > 60
        ):
            raise ValueError("provider_family_interval_invalid")
        if normalized in intervals:
            raise ValueError("provider_family_interval_duplicate")
        intervals[normalized] = interval
    return dict(sorted(intervals.items()))


class _PacedProvider:
    """Apply one shared minimum call-start interval per operator family."""

    def __init__(
        self,
        provider: object,
        *,
        family_intervals: dict[str, float],
        family_last_started: dict[str, float],
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._provider = provider
        self._family_intervals = family_intervals
        self._family_last_started = family_last_started
        self._monotonic = monotonic
        self._sleep = sleep
        self.provider_id = str(getattr(provider, "provider_id"))
        self.provider_family = str(getattr(provider, "provider_family"))
        self.chain = str(getattr(provider, "chain"))

    def call(self, method: str, params: list[object]) -> object:
        family = self.provider_family.strip().lower()
        interval = self._family_intervals.get(family, 0.0)
        now = self._monotonic()
        if family in self._family_last_started:
            remaining = interval - (now - self._family_last_started[family])
            if remaining > 0:
                self._sleep(remaining)
                now = self._monotonic()
        self._family_last_started[family] = now
        return self._provider.call(method, params)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _canonical_sha(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _failure_report(
    *,
    error: str,
    fixtures: list[dict[str, object]],
    raw_root: Path,
) -> dict[str, object]:
    root = raw_root.expanduser().resolve(strict=True)
    evidence = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _file_sha(path),
        }
        for path in sorted(root.rglob("*.json"))
        if path.is_file() and not path.is_symlink()
    ]
    report: dict[str, object] = {
        "schema_version": "stage2_control_trace_state_capability.v1",
        "complete": False,
        "fixture_count": len(fixtures),
        "chain_count": len(
            {str(row.get("chain", "")).strip().lower() for row in fixtures}
        ),
        "chains": [],
        "raw_evidence_count": len(evidence),
        "raw_evidence": evidence,
        "errors": [error],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    report["report_sha256"] = _canonical_sha(report)
    return report


def _failure_verification(
    *, report_path: Path, report: dict[str, object]
) -> dict[str, object]:
    verification: dict[str, object] = {
        "schema_version": (
            "stage2_control_trace_state_capability_verification.v1"
        ),
        "complete": False,
        "report_sha256": report["report_sha256"],
        "report_file_sha256": _file_sha(report_path),
        "raw_evidence_count": report["raw_evidence_count"],
        "chain_count": report["chain_count"],
        "provider_registry_verified": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "errors": list(report["errors"]),
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification


def _load_fixtures(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("fixtures") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError("fixtures must be a non-empty JSON list or a fixtures object")
    return rows


def _verified_scope_chains(
    *,
    fixtures: list[dict[str, object]],
    provider_identity_verification_path: Path,
) -> list[str]:
    """Return the full verified identity scope while requiring fixture coverage."""
    payload = json.loads(
        provider_identity_verification_path.read_text(encoding="utf-8")
    )
    entries = payload.get("chains") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict) for entry in entries
    ):
        raise ValueError("provider identity verification chains are invalid")
    identity_chains = sorted(
        {str(entry.get("chain", "")).strip().lower() for entry in entries}
    )
    fixture_chains = {
        str(row.get("chain", "")).strip().lower() for row in fixtures
    }
    if "" in identity_chains or "" in fixture_chains:
        raise ValueError("chain scope contains an empty chain")
    if not fixture_chains.issubset(identity_chains):
        raise ValueError("fixture chain is absent from provider identity verification")
    return identity_chains


def _legacy_alias_provider_readiness(
    *,
    provider_registry_path: Path,
    provider_identity_verification_path: Path,
    required_chains: list[str],
) -> dict[str, object]:
    """Validate the signed-revision legacy identity projection against a registry.

    The legacy-alias revision uses a deliberately distinct local-test schema.  This
    adapter does not translate it into scientific or RPC authority; it only
    supplies the provider bindings required by the non-authorizing capability
    probe.
    """
    identity_path = provider_identity_verification_path.expanduser().resolve(
        strict=True
    )
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    blockers: set[str] = set()
    if identity.get("schema_version") != (
        "chronosaudit.control_provider_identity_legacy_alias_verification.v1"
    ):
        blockers.add("provider_identity_schema_invalid")
    material = {
        key: value for key, value in identity.items() if key != "report_sha256"
    }
    if identity.get("report_sha256") != _canonical_sha(material):
        blockers.add("provider_identity_self_hash_invalid")
    if (
        identity.get("complete") is not True
        or identity.get("errors") != []
        or identity.get("provider_identity_verified") is not True
    ):
        blockers.add("provider_identity_not_complete")
    for flag in ("rpc_authorized", "selection_authorized", "counter_authority"):
        if identity.get(flag) is not False:
            blockers.add(f"provider_identity_{flag}_invalid")

    entries = identity.get("chains")
    if not isinstance(entries, list):
        entries = []
        blockers.add("provider_identity_chains_invalid")
    by_chain: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            blockers.add("provider_identity_chain_invalid")
            continue
        chain = str(entry.get("chain", "")).strip().lower()
        if not chain or chain in by_chain:
            blockers.add("provider_identity_chain_duplicate")
            continue
        by_chain[chain] = entry
    if sorted(by_chain) != sorted(required_chains):
        blockers.add("provider_identity_chain_coverage_mismatch")
    if identity.get("chain_count") != len(by_chain):
        blockers.add("provider_identity_chain_count_mismatch")

    registry = ProviderRegistry.from_path(provider_registry_path)
    chain_summaries: list[dict[str, object]] = []
    for chain in sorted(required_chains):
        entry = by_chain.get(chain, {})
        rows = entry.get("providers") if isinstance(entry, dict) else None
        if not isinstance(rows, list):
            rows = []
            blockers.add(f"provider_identity_provider_count_invalid:{chain}")
        report_by_id = {
            str(row.get("provider_id", "")).strip(): row
            for row in rows
            if isinstance(row, dict) and str(row.get("provider_id", "")).strip()
        }
        registry_rows = [
            row
            for row in registry.providers_for_chain(chain)
            if row.tracking_enabled
        ]
        registry_ids = {row.provider_id for row in registry_rows}
        matched_ids: list[str] = []
        families: set[str] = set()
        for record in registry_rows:
            observed = report_by_id.get(record.provider_id)
            if (
                observed is None
                or observed.get("complete") is not True
                or observed.get("verified_operator_family")
                != record.operator_family
            ):
                blockers.add(
                    f"provider_identity_registry_mismatch:{record.provider_id}"
                )
                continue
            standard_evidence = bool(record.operator_evidence_url) and len(
                str(record.operator_evidence_sha256)
            ) == 64
            approved_legacy_alias = (
                observed.get("identity_basis")
                == "SIGNED_LOCAL_TEST_LEGACY_ALIAS_REVISION"
                and observed.get("endpoint_template_sha256")
                == record.public_endpoint_id
            )
            if (
                not record.operator_verified
                or not (standard_evidence or approved_legacy_alias)
            ):
                blockers.add(f"provider_evidence_incomplete:{record.provider_id}")
                continue
            matched_ids.append(record.provider_id)
            families.add(record.operator_family)
        for provider_id in sorted(set(report_by_id) - registry_ids):
            blockers.add(f"provider_identity_registry_mismatch:{provider_id}")
        if len(families) < 2:
            blockers.add(
                f"independent_verified_provider_families_insufficient:{chain}"
            )
        chain_summaries.append(
            {
                "chain": chain,
                "registry_provider_ids": sorted(registry_ids),
                "identity_report_provider_ids": sorted(report_by_id),
                "fully_matching_provider_ids": sorted(matched_ids),
                "fully_matching_operator_families": sorted(families),
            }
        )
    result: dict[str, object] = {
        "schema_version": (
            "chronosaudit.control_trace_state_legacy_alias_provider_readiness.v1"
        ),
        "decision": (
            "RPC_PROVIDER_IDENTITY_READY_NON_AUTHORIZING"
            if not blockers
            else "RPC_PROVIDER_IDENTITY_NOT_READY"
        ),
        "provider_registry_sha256": _file_sha(
            provider_registry_path.expanduser().resolve(strict=True)
        ),
        "provider_identity_verification_sha256": _file_sha(identity_path),
        "required_chains": sorted(required_chains),
        "chains": chain_summaries,
        "blockers": sorted(blockers),
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    result["readiness_report_sha256"] = _canonical_sha(result)
    return result


def _assess_provider_readiness(
    *,
    provider_registry_path: Path,
    provider_identity_verification_path: Path,
    required_chains: list[str],
) -> dict[str, object]:
    identity = json.loads(
        provider_identity_verification_path.expanduser()
        .resolve(strict=True)
        .read_text(encoding="utf-8")
    )
    if identity.get("schema_version") == (
        "chronosaudit.control_provider_identity_legacy_alias_verification.v1"
    ):
        return _legacy_alias_provider_readiness(
            provider_registry_path=provider_registry_path,
            provider_identity_verification_path=provider_identity_verification_path,
            required_chains=required_chains,
        )
    return assess_control_candidate_rpc_provider_readiness(
        provider_registry_path=provider_registry_path,
        provider_identity_verification_path=provider_identity_verification_path,
        required_chains=required_chains,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Probe frozen Stage 2 historical trace/state fixtures. This writes "
            "non-authorizing evidence and never permits later RPC, selection, "
            "qualification, stage promotion, or Recovery3 mutation."
        )
    )
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--provider-identity-verification", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument(
        "--provider-family-min-interval",
        action="append",
        default=[],
        metavar="FAMILY=SECONDS",
        help=(
            "Diagnostic-only minimum interval between call starts sharing one "
            "operator family; repeat for multiple families."
        ),
    )
    args = parser.parse_args()
    family_intervals = _parse_family_intervals(
        args.provider_family_min_interval
    )

    fixtures_path = args.fixtures.expanduser().resolve(strict=True)
    fixtures = _load_fixtures(fixtures_path)
    chains = _verified_scope_chains(
        fixtures=fixtures,
        provider_identity_verification_path=(
            args.provider_identity_verification.expanduser().resolve(strict=True)
        ),
    )
    readiness = _assess_provider_readiness(
        provider_registry_path=args.provider_registry,
        provider_identity_verification_path=args.provider_identity_verification,
        required_chains=chains,
    )
    if readiness["blockers"]:
        print(json.dumps(readiness, indent=2, sort_keys=True))
        return 3

    output_report = args.output_report.expanduser().resolve(strict=False)
    output_verification = args.output_verification.expanduser().resolve(strict=False)
    sources = {
        fixtures_path,
        args.provider_registry.expanduser().resolve(strict=True),
        args.provider_identity_verification.expanduser().resolve(strict=True),
    }
    if output_report in sources or output_verification in sources:
        raise ValueError("capability outputs must not overwrite inputs")

    raw_root = args.raw_root.expanduser().resolve(strict=False)
    raw_root.mkdir(parents=True, exist_ok=True)
    registry = ProviderRegistry.from_path(args.provider_registry)
    providers = []
    try:
        for chain_summary in readiness["chains"]:
            chain = str(chain_summary["chain"])
            allowed_ids = set(chain_summary["fully_matching_provider_ids"])
            for record in registry.providers_for_chain(chain, verified_only=True):
                if record.provider_id not in allowed_ids:
                    continue
                providers.append(
                    JsonRpcProvider(
                        provider_id=record.provider_id,
                        url=record.resolved_endpoint(),
                        timeout=args.timeout_seconds,
                        max_retries=0,
                        provider_family=record.operator_family,
                        provider_identity_evidence={
                            "public_endpoint_template": record.public_endpoint,
                            "endpoint_template_sha256": record.public_endpoint_id,
                        },
                    )
                )
                providers[-1].chain = chain
    except ValueError as exc:
        report = _failure_report(
            error=str(exc), fixtures=fixtures, raw_root=raw_root
        )
        _atomic_write(output_report, report)
        verification = _failure_verification(
            report_path=output_report, report=report
        )
        _atomic_write(output_verification, verification)
        print(json.dumps(verification, indent=2, sort_keys=True))
        return 3

    observed_families = {
        str(provider.provider_family).strip().lower() for provider in providers
    }
    if unknown := sorted(set(family_intervals) - observed_families):
        raise ValueError(
            f"provider_family_interval_unknown:{','.join(unknown)}"
        )
    if family_intervals:
        family_last_started: dict[str, float] = {}
        providers = [
            _PacedProvider(
                provider,
                family_intervals=family_intervals,
                family_last_started=family_last_started,
            )
            for provider in providers
        ]

    try:
        report = assess_trace_state_capability(
            fixtures=fixtures,
            providers=providers,
            raw_root=raw_root,
            exhaustive_failures=True,
        )
    except ControlTraceStateCapabilityError as exc:
        report = _failure_report(
            error=str(exc),
            fixtures=fixtures,
            raw_root=raw_root,
        )
        _atomic_write(output_report, report)
        verification = _failure_verification(
            report_path=output_report,
            report=report,
        )
        _atomic_write(output_verification, verification)
        print(json.dumps(verification, indent=2, sort_keys=True))
        return 3
    if family_intervals:
        report = {
            key: value for key, value in report.items() if key != "report_sha256"
        }
        report["observation_strategy"] = {
            "schema_version": (
                "stage2_control_trace_state_capability_pacing.v1"
            ),
            "provider_family_min_interval_seconds": family_intervals,
            "transport_retries": 0,
        }
        report["report_sha256"] = _canonical_sha(report)
    _atomic_write(output_report, report)
    if report.get("complete") is not True:
        verification = _failure_verification(
            report_path=output_report,
            report=report,
        )
        _atomic_write(output_verification, verification)
        print(json.dumps(verification, indent=2, sort_keys=True))
        return 3
    verification = verify_trace_state_capability(
        report_path=output_report,
        raw_root=raw_root,
        provider_registry_path=args.provider_registry,
    )
    _atomic_write(output_verification, verification)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
