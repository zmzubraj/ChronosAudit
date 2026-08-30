from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_follow_up_horizon import (
    build_follow_up_horizon_request,
)


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the non-authorizing Stage 2 request for an accountable, "
            "signed primary follow-up-horizon decision."
        )
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--positive-projection", type=Path, required=True)
    parser.add_argument("--output-request", type=Path, required=True)
    args = parser.parse_args()
    policy = args.policy.expanduser().resolve(strict=True)
    positives = args.positive_projection.expanduser().resolve(strict=True)
    output = args.output_request.expanduser().resolve(strict=False)
    if output in {policy, positives}:
        raise ValueError("horizon request output must not overwrite an input")
    request = build_follow_up_horizon_request(
        policy_path=policy, positive_projection_path=positives
    )
    _atomic_write_json(output, request)
    print(json.dumps(request, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
