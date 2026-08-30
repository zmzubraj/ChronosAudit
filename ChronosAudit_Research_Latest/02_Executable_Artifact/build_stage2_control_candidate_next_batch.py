from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_next_batch import (
    build_control_candidate_next_batch,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze the smallest pending reserve prefix reaching deployment capacity.")
    parser.add_argument("--original-pair-scope", type=Path, required=True)
    parser.add_argument("--expansion-requirements", type=Path, required=True)
    parser.add_argument("--full-queue", type=Path, required=True)
    parser.add_argument("--acquisition-summary", type=Path, required=True)
    parser.add_argument("--acquisition-root", type=Path, required=True)
    parser.add_argument("--output-queue", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_control_candidate_next_batch(
        original_pair_scope_path=args.original_pair_scope,
        expansion_requirements_path=args.expansion_requirements,
        full_queue_path=args.full_queue,
        acquisition_summary_path=args.acquisition_summary,
        acquisition_root=args.acquisition_root,
        output_queue_path=args.output_queue,
    )
    args.output_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.output_manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
