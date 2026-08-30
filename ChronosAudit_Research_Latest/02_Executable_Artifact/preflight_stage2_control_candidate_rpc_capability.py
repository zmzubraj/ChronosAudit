from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.onchain import JsonRpcProvider
from chronosaudit_stage2.public_acquisition.control_candidate_rpc_activation import (
    assess_control_candidate_rpc_provider_readiness,
)
from chronosaudit_stage2.public_acquisition.control_candidate_rpc_capability import (
    assess_candidate_rpc_capability,
    verify_candidate_rpc_capability,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe exact receipt/block capability for the frozen candidate batch.")
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--provider-identity-verification", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    fixture_payload = json.loads(args.fixtures.read_text(encoding="utf-8"))
    fixtures = fixture_payload.get("fixtures") if isinstance(fixture_payload, dict) else None
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("fixtures_invalid")
    chains = sorted({str(row["chain"]).lower() for row in fixtures})
    readiness = assess_control_candidate_rpc_provider_readiness(
        provider_registry_path=args.provider_registry,
        provider_identity_verification_path=args.provider_identity_verification,
        required_chains=chains,
        allow_extra_chains=True,
    )
    if readiness["blockers"]:
        print(json.dumps(readiness, indent=2, sort_keys=True))
        return 3
    allowed = {
        (str(chain["chain"]), provider_id)
        for chain in readiness["chains"]
        for provider_id in chain["fully_matching_provider_ids"]
    }
    registry = ProviderRegistry.from_path(args.provider_registry)
    providers = []
    for record in registry.providers:
        if (record.chain, record.provider_id) not in allowed:
            continue
        provider = JsonRpcProvider(
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
        provider.chain = record.chain
        providers.append(provider)
    report = assess_candidate_rpc_capability(
        fixtures=fixtures, providers=providers, raw_root=args.raw_root
    )
    _write(args.output_report, report)
    verification = verify_candidate_rpc_capability(
        report_path=args.output_report,
        raw_root=args.raw_root,
        provider_registry_path=args.provider_registry,
    )
    _write(args.output_verification, verification)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0 if verification["complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
