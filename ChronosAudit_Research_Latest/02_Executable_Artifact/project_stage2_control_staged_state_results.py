from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_staged_state_projection import project_staged_state_results


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Project one cutoff-state record per control from separately activated Phase 1/2/3 evidence.")
    parser.add_argument("--base-state-results", type=Path, required=True)
    parser.add_argument("--derived-state-results", type=Path, required=True)
    parser.add_argument("--beacon-implementation-results", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = project_staged_state_results(base_state_results_path=args.base_state_results, derived_state_results_path=args.derived_state_results, beacon_implementation_results_path=args.beacon_implementation_results)
    _write(args.output.expanduser().resolve(strict=False), payload)
    print(json.dumps({"decision": payload["decision"], "target_count": payload["target_count"], "complete": payload["complete"], "projection_sha256": payload["projection_sha256"], "selection_authorized": False, "qualification_authorized": False}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
