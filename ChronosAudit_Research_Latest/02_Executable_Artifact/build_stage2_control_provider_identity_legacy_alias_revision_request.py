from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_revision import (
    build_legacy_alias_identity_revision_request,
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
            "Build a hash-bound legacy-alias evidence packet awaiting an "
            "accountable provider-identity revision signature."
        )
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--approval-verification", type=Path, required=True)
    parser.add_argument("--evidence-manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--created-at-utc", required=True)
    parser.add_argument("--expires-at-utc", required=True)
    parser.add_argument("--reviewer-principal", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output = args.output.expanduser().resolve(strict=False)
    sources = {
        args.request.expanduser().resolve(strict=True),
        args.approval.expanduser().resolve(strict=True),
        args.approval_verification.expanduser().resolve(strict=True),
        args.evidence_manifest.expanduser().resolve(strict=True),
    }
    if output in sources:
        raise ValueError("output_must_not_overwrite_input")
    revision = build_legacy_alias_identity_revision_request(
        project_root=args.project_root,
        request_path=args.request,
        approval_path=args.approval,
        approval_verification_path=args.approval_verification,
        evidence_manifest_path=args.evidence_manifest,
        evidence_root=args.evidence_root,
        created_at_utc=args.created_at_utc,
        expires_at_utc=args.expires_at_utc,
        reviewer_principal=args.reviewer_principal,
    )
    _atomic_write(output, revision)
    print(
        json.dumps(
            {
                "decision": revision["decision"],
                "revision_request_sha256": revision["revision_request_sha256"],
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
