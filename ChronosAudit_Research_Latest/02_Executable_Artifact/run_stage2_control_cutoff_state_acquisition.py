#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.onchain import JsonRpcProvider
from chronosaudit_stage2.public_acquisition.control_cutoff_state_acquisition import (
    CHECKPOINT_NAMESPACE,
    canonical_checkpoint_payload,
    execute_control_cutoff_state_acquisition,
    resume_cutoff_state_acquisition,
    verify_cutoff_state_checkpoint_signature,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run or revalidate exact-scope Stage 2 dual-provider cutoff-state "
            "acquisition. Outputs remain non-authorizing."
        )
    )
    parser.add_argument("--activation-verification", type=Path, required=True)
    parser.add_argument("--state-targets", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--now-utc", required=True)
    parser.add_argument("--resume-checkpoint", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument(
        "--provider-min-interval",
        action="append",
        default=[],
        metavar="PROVIDER_ID=SECONDS",
        help="Pace the named provider before every exact activated call.",
    )
    parser.add_argument("--checkpoint-signing-key", type=Path, required=True)
    parser.add_argument("--checkpoint-signer-principal", required=True)
    parser.add_argument("--checkpoint-allowed-signers", type=Path, required=True)
    return parser


def _provider_intervals(values: list[str]) -> dict[str, float]:
    intervals: dict[str, float] = {}
    for value in values:
        provider_id, separator, raw = value.partition("=")
        provider_id = provider_id.strip()
        try:
            seconds = float(raw)
        except ValueError as exc:
            raise ValueError("provider_min_interval_invalid") from exc
        if not separator or not provider_id or provider_id in intervals or seconds < 0 or seconds > 10:
            raise ValueError("provider_min_interval_invalid")
        intervals[provider_id] = seconds
    return intervals


def _atomic_bytes(path: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    args = build_parser().parse_args()
    activation_path = args.activation_verification.expanduser().resolve(strict=True)
    activation = json.loads(activation_path.read_text(encoding="utf-8"))
    provider_intervals = _provider_intervals(args.provider_min_interval)
    registry = ProviderRegistry.from_path(args.provider_registry)
    provider_ids = {
        str(scope["provider_id"])
        for scope in activation.get("rpc_call_scopes", [])
        if isinstance(scope, dict)
        and scope.get("target_type") in {"state", "base_state"}
    }
    records = {
        record.provider_id: record
        for record in registry.providers
        if record.provider_id in provider_ids
        and record.tracking_enabled
        and record.operator_verified
    }
    if set(records) != provider_ids:
        raise ValueError("activation provider is absent or unverified in registry")
    if set(provider_intervals) - provider_ids:
        raise ValueError("provider_min_interval_provider_invalid")

    providers: dict[str, JsonRpcProvider] = {}
    last_call: dict[str, float] = {}

    def transport(provider_id: str, method: str, params: list[object]):
        # Construction is lazy: execute() validates activation and target hashes
        # before the first network-capable provider exists.
        if provider_id not in providers:
            record = records[provider_id]
            providers[provider_id] = JsonRpcProvider(
                provider_id=record.provider_id,
                url=record.resolved_endpoint(),
                timeout=args.timeout_seconds,
                # Activated retries are recorded by the acquisition layer so
                # every attempt is exact-scope authorized and hash-chained.
                max_retries=0,
                provider_family=record.operator_family,
                provider_identity_evidence={
                    "public_endpoint_template": record.public_endpoint,
                    "endpoint_template_sha256": record.public_endpoint_id,
                },
            )
        interval = provider_intervals.get(provider_id, 0.0)
        if interval > 0:
            elapsed = time.monotonic() - last_call.get(provider_id, 0.0)
            if elapsed < interval:
                time.sleep(interval - elapsed)
        last_call[provider_id] = time.monotonic()
        return providers[provider_id].call(method, params)

    if args.resume_checkpoint is not None:
        result = resume_cutoff_state_acquisition(
            args.resume_checkpoint, transport=transport
        )
    else:
        result = execute_control_cutoff_state_acquisition(
            activation=activation,
            state_targets_path=args.state_targets,
            output_root=args.output_root,
            transport=transport,
            now_utc=args.now_utc,
        )
    checkpoint_path = Path(result["checkpoint_path"]).resolve(strict=True)
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    payload_path = checkpoint_path.parent / (
        f"checkpoint-signing-payload-{checkpoint['checkpoint_sha256']}.json"
    )
    if not payload_path.exists():
        _atomic_bytes(payload_path, canonical_checkpoint_payload(checkpoint))
    signature_path = Path(str(payload_path) + ".sig")
    if not signature_path.exists():
        signing = subprocess.run(
            [
                "/usr/bin/ssh-keygen", "-Y", "sign",
                "-f", str(args.checkpoint_signing_key.expanduser().resolve(strict=True)),
                "-n", CHECKPOINT_NAMESPACE,
                str(payload_path),
            ],
            capture_output=True,
            check=False,
        )
        if signing.returncode != 0:
            raise ValueError("checkpoint signing failed")
    verification = verify_cutoff_state_checkpoint_signature(
        checkpoint_path=checkpoint_path,
        signature_path=signature_path,
        allowed_signers_path=args.checkpoint_allowed_signers,
        expected_principal=args.checkpoint_signer_principal,
    )
    result["checkpoint_signature_path"] = str(signature_path)
    result["checkpoint_signature_verification"] = verification
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "COMPLETE" else 3


if __name__ == "__main__":
    raise SystemExit(main())
