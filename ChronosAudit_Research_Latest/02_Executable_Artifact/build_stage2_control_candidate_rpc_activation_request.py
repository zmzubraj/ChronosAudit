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
    build_control_candidate_rpc_activation_request,
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
            "Build a non-authorizing RPC-activation request bound to an exact "
            "verified Stage 2 control reserve queue and provider identity report."
        )
    )
    for name in (
        "queue",
        "queue-manifest",
        "query-plan",
        "chunk-plan",
        "positive-projection",
        "authority-projection",
        "import-manifest",
        "provider-registry",
        "provider-identity-verification",
        "output-request",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--block-window", type=Path)
    args = parser.parse_args()
    source_paths = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.queue,
            args.queue_manifest,
            args.query_plan,
            args.chunk_plan,
            args.positive_projection,
            args.authority_projection,
            args.import_manifest,
            args.provider_registry,
            args.provider_identity_verification,
            *([args.block_window] if args.block_window else []),
        )
    }
    output = args.output_request.expanduser().resolve(strict=False)
    if output in source_paths:
        raise ValueError("activation request output must not overwrite an input")
    request = build_control_candidate_rpc_activation_request(
        queue_path=args.queue,
        queue_manifest_path=args.queue_manifest,
        query_plan_path=args.query_plan,
        chunk_plan_path=args.chunk_plan,
        positive_projection_path=args.positive_projection,
        authority_projection_path=args.authority_projection,
        import_manifest_path=args.import_manifest,
        provider_registry_path=args.provider_registry,
        provider_identity_verification_path=args.provider_identity_verification,
        block_window_path=args.block_window,
    )
    _atomic_write(output, request)
    print(json.dumps(request, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
