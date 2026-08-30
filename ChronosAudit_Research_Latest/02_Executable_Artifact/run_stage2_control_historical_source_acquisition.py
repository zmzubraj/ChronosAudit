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
from chronosaudit_stage2.public_acquisition.control_historical_source_acquisition import (
    acquire_historical_source_batch,
)
from chronosaudit_stage2.public_acquisition.control_historical_source_import import (
    verify_historical_source_import,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: object) -> None:
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
            "Execute the exact signed Stage 2 historical-source acquisition, "
            "capture receipts, and verify the batch for local transformation."
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
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--import-manifest", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    args = parser.parse_args()

    query_plan_path = args.query_plan.expanduser().resolve(strict=True)
    plan_verification = verify_historical_expansion_query_plan(
        query_plan_path=query_plan_path,
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
    )
    request = build_control_acquisition_approval_request(
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
        query_plan_sha256=_sha256_file(query_plan_path),
        source_object_count=int(plan_verification["source_object_count"]),
        maximum_download_bytes=int(plan_verification["source_total_bytes"]),
    )
    approval_verification = verify_control_acquisition_approval(
        request=request,
        approval_path=args.approval,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        expected_principal=args.expected_principal,
        verification_time_utc=args.verification_time_utc,
    )
    query_plan = json.loads(query_plan_path.read_text(encoding="utf-8"))
    manifest = acquire_historical_source_batch(
        query_plan=query_plan,
        approval_verification=approval_verification,
        query_plan_file_sha256=_sha256_file(query_plan_path),
        source_root=args.source_root,
        receipt_root=args.receipt_root,
    )
    import_manifest = args.import_manifest.expanduser().resolve(strict=False)
    _atomic_json(import_manifest, manifest)
    import_verification = verify_historical_source_import(
        query_plan_path=query_plan_path,
        import_manifest_path=import_manifest,
        source_root=args.source_root,
        receipt_root=args.receipt_root,
    )
    output = args.output_verification.expanduser().resolve(strict=False)
    _atomic_json(output, import_verification)
    print(json.dumps(import_verification, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
