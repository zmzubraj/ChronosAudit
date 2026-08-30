from __future__ import annotations

import argparse
import json
from pathlib import Path

from chronosaudit_stage2.public_acquisition.cohort_revision import build_cohort_revision


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze a pre-provider historical snapshot cohort revision plan.")
    parser.add_argument("--parent-run-root", type=Path, required=True)
    parser.add_argument("--verification-report", type=Path, required=True)
    parser.add_argument("--candidate-staging-root", type=Path, required=True)
    parser.add_argument("--candidate-repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--seed", required=True)
    args = parser.parse_args()
    result = build_cohort_revision(
        parent_run_root=args.parent_run_root,
        verification_report_path=args.verification_report,
        candidate_staging_root=args.candidate_staging_root,
        candidate_repository_root=args.candidate_repository_root,
        output_root=args.output_root,
        seed=args.seed,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
