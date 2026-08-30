from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from chronosaudit_stage2.public_acquisition.candidate_archive_verifier import (
    verify_candidate_archive_run,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline verification for a sealed candidate archive run")
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--revision-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = verify_candidate_archive_run(
        run_root=args.run_root,
        revision_root=args.revision_root,
        output_dir=args.output_dir,
    )
    summary = {
        "schema_version": report["schema_version"],
        "candidate_count": report["candidate_count"],
        "eligible_count": report["eligible_count"],
        "eligible_chain_counts": report["eligible_chain_counts"],
        "counter_authority": report["counter_authority"],
        "integrity_error_count": len(report["integrity_errors"]),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if report["counter_authority"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
