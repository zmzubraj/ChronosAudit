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
    build_trace_retry_overlay_spec_approval,
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
        description="Record the exact non-authorizing Trace Retry Overlay V1 spec approval."
    )
    parser.add_argument("--specification", type=Path, required=True)
    parser.add_argument("--approval-text", required=True)
    parser.add_argument("--approved-by-principal", default="zmzubraj")
    parser.add_argument("--approved-at-date", default="2026-08-25")
    parser.add_argument("--approval-source", default="CODEX_CHAT_EXACT_USER_TOKEN")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = build_trace_retry_overlay_spec_approval(
        specification_path=args.specification,
        approval_text=args.approval_text,
        approved_by_principal=args.approved_by_principal,
        approved_at_date=args.approved_at_date,
        approval_source=args.approval_source,
    )
    _atomic_write_new(args.output, record)
    print(json.dumps({
        "record_sha256": record["record_sha256"],
        "implementation_authorized": True,
        "rpc_authorized": False,
        "counter_authority": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
