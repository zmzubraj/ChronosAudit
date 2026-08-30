from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_capacity_audit import (
    build_control_capacity_audit,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the current non-authorizing Stage 2 control-capacity audit.")
    parser.add_argument("--original-pair-scope", type=Path, required=True)
    parser.add_argument("--expansion-requirements", type=Path, required=True)
    parser.add_argument("--acquisition-summary", type=Path, required=True)
    parser.add_argument("--acquisition-root", type=Path, required=True)
    parser.add_argument("--staged-state-results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    audit = build_control_capacity_audit(
        original_pair_scope_path=args.original_pair_scope,
        expansion_requirements_path=args.expansion_requirements,
        acquisition_summary_path=args.acquisition_summary,
        acquisition_root=args.acquisition_root,
        staged_state_results_path=args.staged_state_results,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
