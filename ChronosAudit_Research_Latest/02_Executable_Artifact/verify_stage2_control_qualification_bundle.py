from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_qualification_bundle import (
    verify_control_qualification_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independently reverify a Stage 2 signed control-qualification "
            "bundle from its original evidence and authority inputs."
        )
    )
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    result = verify_control_qualification_bundle(manifest_path=args.manifest)
    print(json.dumps(result["bundle_verification"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
