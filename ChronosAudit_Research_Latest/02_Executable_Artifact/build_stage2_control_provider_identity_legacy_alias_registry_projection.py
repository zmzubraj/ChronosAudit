from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

import yaml


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_registry_projection import (
    build_legacy_alias_full_registry_projection,
)


def _stage(path: Path, data: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(data)
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    return temporary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Project the exact six-provider local-test registry from a verified "
            "legacy-alias revision. This grants no RPC or scientific authority."
        )
    )
    parser.add_argument("--revision-verification", type=Path, required=True)
    parser.add_argument("--registry-fragment", type=Path, required=True)
    parser.add_argument("--identity-report", type=Path, required=True)
    parser.add_argument("--candidate-registry", type=Path, required=True)
    parser.add_argument("--capability-report", type=Path, required=True)
    parser.add_argument("--trace-targets", type=Path, required=True)
    parser.add_argument("--output-registry", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.revision_verification,
            args.registry_fragment,
            args.identity_report,
            args.candidate_registry,
            args.capability_report,
            args.trace_targets,
        )
    }
    registry_output = args.output_registry.expanduser().resolve(strict=False)
    verification_output = args.output_verification.expanduser().resolve(
        strict=False
    )
    if (
        registry_output == verification_output
        or registry_output in inputs
        or verification_output in inputs
    ):
        raise ValueError("outputs_must_be_distinct_and_not_overwrite_inputs")

    result = build_legacy_alias_full_registry_projection(
        revision_verification_path=args.revision_verification,
        registry_fragment_path=args.registry_fragment,
        identity_report_path=args.identity_report,
        candidate_registry_path=args.candidate_registry,
        capability_report_path=args.capability_report,
        trace_targets_path=args.trace_targets,
    )
    registry_text = yaml.safe_dump(
        result["provider_registry"], sort_keys=True, allow_unicode=False
    )
    verification_text = (
        json.dumps(result["projection_verification"], indent=2, sort_keys=True)
        + "\n"
    )
    staged = [
        (registry_output, _stage(registry_output, registry_text)),
        (
            verification_output,
            _stage(verification_output, verification_text),
        ),
    ]
    try:
        for output, temporary in staged:
            os.replace(temporary, output)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)
    print(json.dumps(result["projection_verification"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
