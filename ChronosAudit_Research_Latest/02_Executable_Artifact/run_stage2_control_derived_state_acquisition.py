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
from chronosaudit_stage2.public_acquisition.control_derived_state_acquisition import (
    DERIVED_STATE_CHECKPOINT_NAMESPACE,
    canonical_derived_state_checkpoint_payload,
    execute_control_derived_state_acquisition,
    verify_derived_state_checkpoint_signature,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


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
    parser = argparse.ArgumentParser(description="Run exact activated Phase 2 dual-provider reads; outputs remain non-authorizing.")
    parser.add_argument("--activation-verification", type=Path, required=True)
    parser.add_argument("--derived-state-targets", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--now-utc", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--minimum-interval-seconds", type=float, default=0.15)
    parser.add_argument("--checkpoint-signing-key", type=Path, required=True)
    parser.add_argument("--checkpoint-signer-principal", required=True)
    parser.add_argument("--checkpoint-allowed-signers", type=Path, required=True)
    parser.add_argument("--checkpoint-verification-output", type=Path, required=True)
    args = parser.parse_args()
    activation = json.loads(args.activation_verification.read_text(encoding="utf-8"))
    provider_ids = {scope["provider_id"] for scope in activation["rpc_call_scopes"] if scope.get("target_type") == "derived_state"}
    records = {row.provider_id: row for row in ProviderRegistry.from_path(args.provider_registry).providers if row.provider_id in provider_ids and row.operator_verified and row.tracking_enabled}
    if set(records) != provider_ids:
        raise ValueError("activation_provider_absent_or_unverified")
    providers: dict[str, JsonRpcProvider] = {}
    last: dict[str, float] = {}

    def transport(provider_id: str, method: str, params: list[object]):
        if provider_id not in providers:
            record = records[provider_id]
            providers[provider_id] = JsonRpcProvider(provider_id=record.provider_id, url=record.resolved_endpoint(), timeout=args.timeout_seconds, max_retries=0, provider_family=record.operator_family)
        elapsed = time.monotonic() - last.get(provider_id, 0.0)
        if elapsed < args.minimum_interval_seconds:
            time.sleep(args.minimum_interval_seconds - elapsed)
        result = providers[provider_id].call(method, params)
        last[provider_id] = time.monotonic()
        return result

    result = execute_control_derived_state_acquisition(activation=activation, derived_state_targets_path=args.derived_state_targets, output_root=args.output_root, transport=transport, now_utc=args.now_utc)
    checkpoint_path = Path(result["checkpoint_path"]).resolve(strict=True)
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    payload_path = checkpoint_path.parent / (
        f"checkpoint-signing-payload-{checkpoint['checkpoint_sha256']}.json"
    )
    if not payload_path.exists():
        _atomic_bytes(
            payload_path,
            canonical_derived_state_checkpoint_payload(checkpoint),
        )
    signature_path = Path(str(payload_path) + ".sig")
    if not signature_path.exists():
        signing = subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(args.checkpoint_signing_key.expanduser().resolve(strict=True)),
                "-n",
                DERIVED_STATE_CHECKPOINT_NAMESPACE,
                str(payload_path),
            ],
            capture_output=True,
            check=False,
        )
        if signing.returncode != 0:
            raise ValueError("checkpoint_signing_failed")
    verification = verify_derived_state_checkpoint_signature(
        checkpoint_path=checkpoint_path,
        signature_path=signature_path,
        allowed_signers_path=args.checkpoint_allowed_signers,
        expected_principal=args.checkpoint_signer_principal,
    )
    verification_output = args.checkpoint_verification_output.expanduser()
    verification_output.parent.mkdir(parents=True, exist_ok=True)
    _atomic_bytes(
        verification_output,
        (json.dumps(verification, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    result["checkpoint_signature_path"] = str(signature_path)
    result["checkpoint_signature_verification_path"] = str(
        verification_output.resolve(strict=True)
    )
    result["checkpoint_signature_verification"] = verification
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "COMPLETE" else 3


if __name__ == "__main__":
    raise SystemExit(main())
