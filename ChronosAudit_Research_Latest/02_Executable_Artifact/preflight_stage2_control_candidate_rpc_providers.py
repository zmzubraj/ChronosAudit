from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_activation import (
    assess_control_candidate_rpc_provider_readiness,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Assess whether the Stage 2 control RPC registry and provider-identity "
            "report are mutually bound and ready. This never authorizes RPC."
        )
    )
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument(
        "--provider-identity-verification", type=Path, required=True
    )
    parser.add_argument("--required-chain", action="append", required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()
    sources = {
        args.provider_registry.expanduser().resolve(strict=True),
        args.provider_identity_verification.expanduser().resolve(strict=True),
    }
    output = args.output_report.expanduser().resolve(strict=False)
    if output in sources:
        raise ValueError("readiness report must not overwrite an input")
    report = assess_control_candidate_rpc_provider_readiness(
        provider_registry_path=args.provider_registry,
        provider_identity_verification_path=args.provider_identity_verification,
        required_chains=args.required_chain,
    )
    _atomic_write(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not report["blockers"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
