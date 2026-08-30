from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_approval import (
    build_legacy_alias_approval_record,
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
            "Record the exact accountable local-test legacy-alias method decision. "
            "This does not verify provider identity or authorize RPC."
        )
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--approval-text", required=True)
    parser.add_argument("--approved-by-principal", required=True)
    parser.add_argument("--approved-at-date", required=True)
    parser.add_argument("--approval-source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output = args.output.expanduser().resolve(strict=False)
    request = args.request.expanduser().resolve(strict=True)
    if output == request:
        raise ValueError("output_must_not_overwrite_request")
    approval = build_legacy_alias_approval_record(
        project_root=args.project_root,
        request_path=request,
        approval_text=args.approval_text,
        approved_by_principal=args.approved_by_principal,
        approved_at_date=args.approved_at_date,
        approval_source=args.approval_source,
    )
    _atomic_write(output, approval)
    print(
        json.dumps(
            {
                "decision": approval["decision"],
                "record_sha256": approval["record_sha256"],
                "method_approved": True,
                "provider_identity_verified": False,
                "rpc_authorized": False,
                "counter_authority": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
