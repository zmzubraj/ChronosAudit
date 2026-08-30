from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from build_stage2_control_trace_completion_overlay import add_arguments, reconstruction
from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay import (
    verify_trace_completion_overlay,
)


def _atomic_new(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise ValueError("output_exists_or_not_ordinary")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconstruct a complete trace provenance overlay.")
    parser.add_argument("--overlay", type=Path, required=True)
    add_arguments(parser)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify_trace_completion_overlay(
        overlay_path=args.overlay,
        **reconstruction(args),
    )
    _atomic_new(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
