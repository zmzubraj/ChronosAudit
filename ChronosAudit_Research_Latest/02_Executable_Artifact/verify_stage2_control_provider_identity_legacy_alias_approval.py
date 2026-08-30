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
    verify_legacy_alias_approval_record,
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
            "Verify the exact local-test legacy-alias method decision without "
            "granting provider, RPC, selection, or counter authority."
        )
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path)
    args = parser.parse_args()

    verification = verify_legacy_alias_approval_record(
        project_root=args.project_root,
        request_path=args.request,
        approval_path=args.approval,
    )
    if args.output_verification is not None:
        output = args.output_verification.expanduser().resolve(strict=False)
        sources = {
            args.request.expanduser().resolve(strict=True),
            args.approval.expanduser().resolve(strict=True),
        }
        if output in sources:
            raise ValueError("output_must_not_overwrite_input")
        _atomic_write(output, verification)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
