from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_evidence import (
    build_control_provider_identity_evidence_review,
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
            "Build a hash-bound Stage 2 provider documentation review packet. "
            "The packet does not verify operators or authorize RPC or selection."
        )
    )
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--capture-index", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-review", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        args.provider_registry.expanduser().resolve(strict=True),
        args.capture_index.expanduser().resolve(strict=True),
    }
    output = args.output_review.expanduser().resolve(strict=False)
    if output in inputs:
        raise ValueError("review output must not overwrite an input")
    review = build_control_provider_identity_evidence_review(
        provider_registry_path=args.provider_registry,
        capture_index_path=args.capture_index,
        evidence_root=args.evidence_root,
    )
    _atomic_write_json(output, review)
    print(json.dumps(review, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
