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
    build_control_acquisition_approval,
    build_control_acquisition_approval_request,
    canonical_signed_payload,
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


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build, but do not sign, the exact Stage 2 source-only acquisition "
            "approval and canonical signing payload for the frozen historical "
            "expansion plan."
        )
    )
    parser.add_argument("--chunk-plan", type=Path, required=True)
    parser.add_argument("--chunk-manifest", type=Path, required=True)
    parser.add_argument("--query-plan", type=Path, required=True)
    parser.add_argument("--signer-principal", required=True)
    parser.add_argument("--approval-start-utc", required=True)
    parser.add_argument("--approval-expires-utc", required=True)
    parser.add_argument("--output-approval", type=Path, required=True)
    parser.add_argument("--output-signing-payload", type=Path, required=True)
    args = parser.parse_args()

    inputs = {
        value.expanduser().resolve(strict=True)
        for value in (args.chunk_plan, args.chunk_manifest, args.query_plan)
    }
    approval_output = args.output_approval.expanduser().resolve(strict=False)
    signing_output = args.output_signing_payload.expanduser().resolve(strict=False)
    if approval_output == signing_output:
        raise ValueError("approval and signing-payload outputs must differ")
    if approval_output in inputs or signing_output in inputs:
        raise ValueError("outputs must not overwrite inputs")

    query_plan_path = args.query_plan.expanduser().resolve(strict=True)
    query_verification = verify_historical_expansion_query_plan(
        query_plan_path=query_plan_path,
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
    )
    request = build_control_acquisition_approval_request(
        chunk_plan_path=args.chunk_plan,
        chunk_manifest_path=args.chunk_manifest,
        query_plan_sha256=_sha256_file(query_plan_path),
        source_object_count=int(query_verification["source_object_count"]),
        maximum_download_bytes=int(query_verification["source_total_bytes"]),
    )
    approval = build_control_acquisition_approval(
        request=request,
        signer_principal=args.signer_principal,
        approval_start_utc=args.approval_start_utc,
        approval_expires_utc=args.approval_expires_utc,
    )
    approval_bytes = (
        json.dumps(approval, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    signing_payload = canonical_signed_payload(approval)
    _atomic_write(approval_output, approval_bytes)
    _atomic_write(signing_output, signing_payload)
    result = {
        "approval": approval,
        "approval_file_sha256": hashlib.sha256(approval_bytes).hexdigest(),
        "signing_payload_sha256": hashlib.sha256(signing_payload).hexdigest(),
        "signature_namespace": (
            "chronosaudit-stage2-control-source-acquisition-v2"
        ),
        "signature_created": False,
        "effective_authority_without_valid_signature": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
