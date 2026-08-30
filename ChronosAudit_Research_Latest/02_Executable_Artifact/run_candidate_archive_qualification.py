from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from chronosaudit_stage2.public_acquisition.candidate_archive_qualification import (
    build_candidate_archive_run_plan,
    default_case_executor,
    default_provider_resolver,
    execute_candidate_archive_qualification,
    prepare_candidate_archive_run,
    _sha256_json,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Qualify frozen historical-snapshot replacement candidates.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "execute"):
        child = subparsers.add_parser(command)
        child.add_argument("--cohort-revision-root", type=Path, required=True)
        child.add_argument("--output-root", type=Path, required=True)
        child.add_argument("--revision", required=True)
        child.add_argument("--run-id", required=True)
        if command == "execute":
            child.add_argument("--max-workers", type=int, default=1)
            child.add_argument(
                "--incident-block-policy",
                choices=("require_fork_block_match", "two_provider_exploit_receipt"),
                default="require_fork_block_match",
            )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "plan":
        plan = build_candidate_archive_run_plan(args.cohort_revision_root)
        print(json.dumps({"command": "plan", "candidate_count": plan["candidate_count"], "plan_sha256": _sha256_json(plan)}, sort_keys=True))
        return 0
    prepared = prepare_candidate_archive_run(
        cohort_revision_root=args.cohort_revision_root,
        output_root=args.output_root,
        revision=args.revision,
        run_id=args.run_id,
        incident_block_policy=args.incident_block_policy,
    )
    result = execute_candidate_archive_qualification(
        prepared,
        provider_resolver=default_provider_resolver,
        case_executor=default_case_executor,
        max_workers=args.max_workers,
    )
    print(json.dumps({"command": "execute", "run_root": result["run_root"], "qualified_count": result["qualified_count"], "candidate_count": result["candidate_count"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
