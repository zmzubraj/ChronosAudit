#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_base_state_retry_merge import (
    merge_base_state_retry_results,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge signed Phase 1 retry evidence.")
    parser.add_argument("--original-checkpoint", type=Path, required=True)
    parser.add_argument("--original-signature", type=Path, required=True)
    parser.add_argument("--retry-checkpoint", type=Path, required=True)
    parser.add_argument("--retry-signature", type=Path, required=True)
    parser.add_argument("--retry-targets", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = merge_base_state_retry_results(
        original_checkpoint_path=args.original_checkpoint,
        original_signature_path=args.original_signature,
        retry_checkpoint_path=args.retry_checkpoint,
        retry_signature_path=args.retry_signature,
        retry_targets_path=args.retry_targets,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        output_path=args.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
