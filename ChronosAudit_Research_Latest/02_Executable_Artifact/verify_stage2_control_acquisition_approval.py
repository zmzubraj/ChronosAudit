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
    verify_control_acquisition_approval,
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
            "Verify a bounded, detached-OpenSSH-signed Stage 2 historical "
            "denominator source-download approval. This never authorizes RPC."
        )
    )
    parser.add_argument("--chunk-plan", type=Path, required=True)
    parser.add_argument("--chunk-manifest", type=Path, required=True)
    parser.add_argument("--query-plan", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-principal", required=True)
    parser.add_argument("--verification-time-utc", required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    args = parser.parse_args()

    source_paths = {
        value.expanduser().resolve(strict=True)
        for value in (
            args.chunk_plan,
            args.chunk_manifest,
            args.query_plan,
            args.approval,
            args.signature,
            args.allowed_signers,
        )
    }
    output = args.output_report.expanduser().resolve(strict=False)
    if output in source_paths:
        raise ValueError("approval report must not overwrite an input")
    query_plan = args.query_plan.expanduser().resolve(strict=True)
    plan_verification = verify_historical_expansion_query_plan(
        query_plan_path=query_plan,
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
    )
    request = build_control_acquisition_approval_request(
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
        query_plan_sha256=_sha256_file(query_plan),
        source_object_count=int(plan_verification["source_object_count"]),
        maximum_download_bytes=int(plan_verification["source_total_bytes"]),
    )
    report = verify_control_acquisition_approval(
        request=request,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    _atomic_write_json(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
