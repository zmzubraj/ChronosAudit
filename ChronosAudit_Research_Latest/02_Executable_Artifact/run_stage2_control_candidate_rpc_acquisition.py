from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_acquisition import (
    execute_control_candidate_rpc_acquisition,
    prepare_control_candidate_rpc_acquisition,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run exact-scope Stage 2 candidate deployment RPC acquisition.")
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--activation-request", type=Path, required=True)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--max-candidates", type=int)
    parser.add_argument("--max-workers", type=int, default=1)
    args = parser.parse_args()
    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=args.activation,
        activation_request_path=args.activation_request,
        queue_path=args.queue,
        provider_registry_path=args.provider_registry,
        output_root=args.output_root,
    )
    summary = execute_control_candidate_rpc_acquisition(
        prepared,
        max_candidates=args.max_candidates,
        max_workers=args.max_workers,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["new_partial_count"] == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
