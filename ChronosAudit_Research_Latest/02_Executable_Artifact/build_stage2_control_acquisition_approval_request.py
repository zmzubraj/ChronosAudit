from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_acquisition_approval import (
    build_control_acquisition_approval_request,
)
from chronosaudit_stage2.public_acquisition.control_historical_expansion_query_plan import (
    verify_historical_expansion_query_plan,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
            "Build a non-authorizing Stage 2 acquisition approval request bound "
            "to the exact expansion chunks and optional frozen query plan."
        )
    )
    parser.add_argument("--chunk-plan", type=Path, required=True)
    parser.add_argument("--chunk-manifest", type=Path, required=True)
    parser.add_argument("--query-plan", type=Path)
    parser.add_argument("--output-request", type=Path, required=True)
    args = parser.parse_args()

    sources = {
        args.chunk_plan.expanduser().resolve(strict=True),
        args.chunk_manifest.expanduser().resolve(strict=True),
    }
    query_hash = None
    source_object_count = None
    maximum_download_bytes = None
    if args.query_plan:
        query_plan = args.query_plan.expanduser().resolve(strict=True)
        sources.add(query_plan)
        verification = verify_historical_expansion_query_plan(
            query_plan_path=query_plan,
            chunk_plan_path=args.chunk_plan,
            chunk_manifest_path=args.chunk_manifest,
        )
        query_hash = _sha256_file(query_plan)
        source_object_count = int(verification["source_object_count"])
        maximum_download_bytes = int(verification["source_total_bytes"])
    output = args.output_request.expanduser().resolve(strict=False)
    if output in sources:
        raise ValueError("approval request output must not overwrite an input")

    request = build_control_acquisition_approval_request(
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
        query_plan_sha256=query_hash,
        source_object_count=source_object_count,
        maximum_download_bytes=maximum_download_bytes,
    )
    _atomic_write_json(output, request)
    print(json.dumps(request, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
