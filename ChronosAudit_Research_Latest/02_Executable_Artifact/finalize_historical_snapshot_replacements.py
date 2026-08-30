from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.replacement_finalization import (  # noqa: E402
    finalize_historical_snapshot_replacements,
)


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        print(
            json.dumps(
                {
                    "error": "historical_snapshot_replacement_finalization_failed",
                    "code": "invalid_cli_argument",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = _SanitizedArgumentParser(
        description="Finalize deterministic historical snapshot replacements offline."
    )
    parser.add_argument("--parent-run-root", required=True)
    parser.add_argument("--parent-report-root", required=True)
    parser.add_argument("--revision-root", required=True)
    parser.add_argument("--candidate-run-root", required=True)
    parser.add_argument("--candidate-report-root", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = finalize_historical_snapshot_replacements(
            parent_run_root=args.parent_run_root,
            parent_report_root=args.parent_report_root,
            revision_root=args.revision_root,
            candidate_run_root=args.candidate_run_root,
            candidate_report_root=args.candidate_report_root,
            output_dir=args.output_dir,
        )
    except Exception:
        print(
            json.dumps(
                {
                    "error": "historical_snapshot_replacement_finalization_failed",
                    "code": "finalization_failed",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "schema_version": manifest["schema_version"],
                "replacement_count": manifest["counts"]["replacement_count"],
                "retained_count": manifest["counts"]["retained_count"],
                "revised_population_count": manifest["counts"]["revised_population_count"],
                "slot_quotas": manifest["slot_quotas"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
