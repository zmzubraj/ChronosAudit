from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_candidate_attrition_extension import (
    build_control_candidate_attrition_extension,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze the smallest remaining reserve prefix after verified attrition."
    )
    parser.add_argument("--original-pair-scope", type=Path, required=True)
    parser.add_argument("--expansion-requirements", type=Path, required=True)
    parser.add_argument("--full-queue", type=Path, required=True)
    parser.add_argument("--attempted-queue", type=Path, required=True)
    parser.add_argument("--reconciliation-manifest", type=Path, required=True)
    parser.add_argument("--effective-complete", type=Path, required=True)
    parser.add_argument("--effective-rejected", type=Path, required=True)
    parser.add_argument("--prior-acquisition-summary", type=Path, required=True)
    parser.add_argument("--prior-acquisition-root", type=Path, required=True)
    parser.add_argument("--output-queue", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_control_candidate_attrition_extension(
        original_pair_scope_path=args.original_pair_scope,
        expansion_requirements_path=args.expansion_requirements,
        full_queue_path=args.full_queue,
        attempted_queue_path=args.attempted_queue,
        reconciliation_manifest_path=args.reconciliation_manifest,
        effective_complete_path=args.effective_complete,
        effective_rejected_path=args.effective_rejected,
        prior_acquisition_summary_path=args.prior_acquisition_summary,
        prior_acquisition_root=args.prior_acquisition_root,
        output_queue_path=args.output_queue,
    )
    args.output_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.output_manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
