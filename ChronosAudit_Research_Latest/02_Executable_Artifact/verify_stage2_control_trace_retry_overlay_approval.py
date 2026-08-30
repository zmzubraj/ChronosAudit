from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay_approval import (
    verify_trace_retry_overlay_spec_approval,
)


def _atomic_write_new(path: Path, payload: dict[str, object]) -> None:
    candidate = path.expanduser()
    candidate.parent.mkdir(parents=True, exist_ok=True)
    if candidate.is_symlink() or candidate.exists():
        raise ValueError("output_exists_or_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=candidate.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, candidate)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruct and verify the Trace Retry Overlay V1 spec approval."
    )
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--specification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify_trace_retry_overlay_spec_approval(
        approval_path=args.approval,
        specification_path=args.specification,
    )
    _atomic_write_new(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
