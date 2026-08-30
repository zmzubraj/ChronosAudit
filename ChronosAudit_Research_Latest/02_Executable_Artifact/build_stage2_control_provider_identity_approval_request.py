from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_approval import (
    build_control_provider_identity_approval_request,
)


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
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
            "Build the non-authorizing accountable provider-identity review "
            "request without creating an approval or signature."
        )
    )
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--capture-index", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-request", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        args.review.expanduser().resolve(strict=True),
        args.provider_registry.expanduser().resolve(strict=True),
        args.capture_index.expanduser().resolve(strict=True),
    }
    output = args.output_request.expanduser().resolve(strict=False)
    if output in inputs:
        raise ValueError("request output must not overwrite an input")
    request = build_control_provider_identity_approval_request(
        review_path=args.review,
        provider_registry_path=args.provider_registry,
        capture_index_path=args.capture_index,
        evidence_root=args.evidence_root,
    )
    _atomic_write_json(output, request)
    print(json.dumps(request, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
