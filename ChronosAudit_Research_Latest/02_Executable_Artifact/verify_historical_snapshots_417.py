from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.historical_snapshot_verifier import (  # noqa: E402
    verify_historical_snapshot_run,
)


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        print(
            json.dumps(
                {
                    "error": "historical_snapshot_verification_failed",
                    "code": "invalid_cli_argument",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)


def main() -> int:
    parser = _SanitizedArgumentParser(description="Verify historical snapshot preservation offline.")
    parser.add_argument("--run-root", required=True, help="Prepared historical snapshot run root.")
    parser.add_argument(
        "--output",
        help="Optional output directory for verifier report and projection.",
    )
    args = parser.parse_args()
    try:
        payload = verify_historical_snapshot_run(
            args.run_root,
            output_path=args.output,
        )
    except Exception:
        print(
            json.dumps(
                {
                    "error": "historical_snapshot_verification_failed",
                    "code": "verification_failed",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
