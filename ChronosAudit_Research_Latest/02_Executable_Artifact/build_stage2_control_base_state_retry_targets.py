#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_base_state_retry_targets import (
    build_base_state_retry_targets,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive a fail-closed Phase 1 retry subset from provider-error evidence."
    )
    parser.add_argument("--original-targets", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_base_state_retry_targets(
        original_targets_path=args.original_targets,
        checkpoint_path=args.checkpoint,
        output_path=args.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
