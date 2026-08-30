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
    build_trace_target_identities,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
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
            "Freeze exact unresolved Stage 2 trace identities from the signed "
            "receipt-acquisition checkpoint. This does not authorize RPC or selection."
        )
    )
    parser.add_argument("--acquisition-summary", type=Path, required=True)
    parser.add_argument("--signature-verification", type=Path, required=True)
    parser.add_argument("--acquisition-ledger", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = build_trace_target_identities(
        acquisition_summary_path=args.acquisition_summary,
        signature_verification_path=args.signature_verification,
        acquisition_ledger_path=args.acquisition_ledger,
        candidate_root=args.candidate_root,
    )
    _atomic_write(args.output.expanduser().resolve(strict=False), payload)
    print(json.dumps({
        "target_count": payload["target_count"],
        "target_identities_sha256": payload["target_identities_sha256"],
        "rpc_authorized": False,
        "selection_authorized": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
