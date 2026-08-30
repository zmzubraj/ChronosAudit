from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_trace_targets import (
    materialize_trace_targets,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Bind frozen Stage 2 trace identities to exact capability-observed "
            "provider calls. This does not authorize RPC, selection, or counters."
        )
    )
    parser.add_argument("--target-identities", type=Path, required=True)
    parser.add_argument("--capability-report", type=Path, required=True)
    parser.add_argument("--capability-verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = materialize_trace_targets(
        target_identities_path=args.target_identities,
        capability_report_path=args.capability_report,
        capability_verification_path=args.capability_verification,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, payload)
    print(json.dumps({
        "target_count": payload["target_count"],
        "rpc_call_count": payload["rpc_call_count"],
        "trace_targets_sha256": payload["trace_targets_sha256"],
        "provider_registry_verified": payload["provider_registry_verified"],
        "rpc_authorized": False,
        "selection_authorized": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
