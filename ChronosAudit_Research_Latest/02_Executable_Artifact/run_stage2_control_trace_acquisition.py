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
from chronosaudit_stage2.public_acquisition.control_trace_acquisition import (
    CHECKPOINT_NAMESPACE,
    canonical_checkpoint_payload,
    execute_control_trace_acquisition,
    reverify_trace_activation_for_execution,
    resume_trace_acquisition,
    verify_trace_checkpoint_signature,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry
from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay import (
    TraceSourceRoot,
)


def _provider_min_intervals(values: list[str]) -> dict[str, float]:
    intervals: dict[str, float] = {}
    for value in values:
        provider_id, separator, raw_seconds = value.partition("=")
        provider_id = provider_id.strip()
        if not separator or not provider_id or provider_id in intervals:
            raise ValueError("provider_min_interval_invalid")
        try:
            seconds = float(raw_seconds)
        except ValueError as exc:
            raise ValueError("provider_min_interval_invalid") from exc
        if seconds < 0 or seconds > 5:
            raise ValueError("provider_min_interval_invalid")
        intervals[provider_id] = seconds
    return intervals


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run or resume exact-scope Stage 2 dual-provider trace acquisition. "
            "Outputs remain non-authorizing."
        )
    )
    parser.add_argument("--activation-verification", type=Path, required=True)
    parser.add_argument("--activation-request", type=Path, required=True)
    parser.add_argument("--activation-approval", type=Path, required=True)
    parser.add_argument("--activation-signature", type=Path, required=True)
    parser.add_argument("--activation-allowed-signers", type=Path, required=True)
    parser.add_argument("--activation-expected-principal", required=True)
    parser.add_argument("--trace-targets", type=Path, required=True)
    parser.add_argument("--retry-specification", type=Path)
    parser.add_argument("--retry-spec-approval", type=Path)
    parser.add_argument("--retry-original-targets", type=Path)
    parser.add_argument("--retry-original-activation-request", type=Path)
    parser.add_argument("--retry-original-activation-approval", type=Path)
    parser.add_argument("--retry-original-activation-signature", type=Path)
    parser.add_argument("--retry-original-activation-allowed-signers", type=Path)
    parser.add_argument("--retry-original-activation-verification", type=Path)
    parser.add_argument("--retry-expected-principal", default="zmzubraj")
    parser.add_argument("--retry-source-root", type=Path, action="append", default=[])
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
        help=(
            "Enforce a deterministic minimum interval between calls to the "
            "named provider; repeat for multiple providers (0-5 seconds)."
        ),
    )
    parser.add_argument("--checkpoint-signing-key", type=Path, required=True)
    parser.add_argument("--checkpoint-signer-principal", required=True)
    parser.add_argument("--checkpoint-allowed-signers", type=Path, required=True)
    args = parser.parse_args()
    provider_min_intervals = _provider_min_intervals(
        args.provider_min_interval
    )

    retry_inputs = None
    target_payload = json.loads(args.trace_targets.read_text(encoding="utf-8"))
    if target_payload.get("schema_version") == "stage2_control_trace_retry_targets.v1":
        required = (
            args.retry_specification,
            args.retry_spec_approval,
            args.retry_original_targets,
            args.retry_original_activation_request,
            args.retry_original_activation_approval,
            args.retry_original_activation_signature,
            args.retry_original_activation_allowed_signers,
            args.retry_original_activation_verification,
        )
        if any(value is None for value in required) or len(args.retry_source_root) != 3:
            raise ValueError("retry_reconstruction_inputs_required")
        sources = []
        for root in args.retry_source_root:
            signatures = sorted(root.glob("interrupted-checkpoint-signing-payload-*.json.sig"))
            if len(signatures) != 1:
                raise ValueError("source_checkpoint_signature_ambiguous")
            sources.append(TraceSourceRoot(
                root / "checkpoint.json",
                signatures[0],
                args.retry_original_activation_allowed_signers,
                args.retry_expected_principal,
            ))
        retry_inputs = {
            "specification_path": args.retry_specification,
            "spec_approval_path": args.retry_spec_approval,
            "original_targets_path": args.retry_original_targets,
            "activation_request_path": args.retry_original_activation_request,
            "activation_approval_path": args.retry_original_activation_approval,
            "activation_signature_path": args.retry_original_activation_signature,
            "activation_allowed_signers_path": args.retry_original_activation_allowed_signers,
            "activation_verification_path": args.retry_original_activation_verification,
            "activation_expected_principal": args.retry_expected_principal,
            "sources": sources,
        }

    request_path = args.activation_request.expanduser()
    if request_path.is_symlink():
        raise ValueError("activation request must be an ordinary file")
    request_path = request_path.resolve(strict=True)
    if not request_path.is_file():
        raise ValueError("activation request must be an ordinary file")
    request = json.loads(request_path.read_text(encoding="utf-8"))
    activation = reverify_trace_activation_for_execution(
        activation_verification_path=args.activation_verification,
        request=request,
        approval_path=args.activation_approval,
        signature_path=args.activation_signature,
        allowed_signers_path=args.activation_allowed_signers,
        expected_principal=args.activation_expected_principal,
        verification_time_utc=args.now_utc,
    )
    registry = ProviderRegistry.from_path(args.provider_registry)
    provider_ids = {
        str(scope["provider_id"])
        for scope in activation.get("rpc_call_scopes", [])
        if isinstance(scope, dict) and scope.get("target_type") == "trace"
    }
    providers = {
        record.provider_id: JsonRpcProvider(
            provider_id=record.provider_id,
            url=record.resolved_endpoint(),
            timeout=args.timeout_seconds,
            max_retries=0,
            provider_family=record.operator_family,
            provider_identity_evidence={
                "public_endpoint_template": record.public_endpoint,
                "endpoint_template_sha256": record.public_endpoint_id,
            },
        )
        for record in registry.providers
        if record.provider_id in provider_ids
        and record.tracking_enabled
        and record.operator_verified
    }
    if set(providers) != provider_ids:
        raise ValueError("activation provider is absent or unverified in registry")
    if set(provider_min_intervals) - provider_ids:
        raise ValueError("provider_min_interval_provider_invalid")

    last_call_started: dict[str, float] = {}

    def transport(provider_id: str, method: str, params: list[object]):
        interval = provider_min_intervals.get(provider_id, 0.0)
        previous = last_call_started.get(provider_id)
        if interval > 0 and previous is not None:
            remaining = interval - (time.monotonic() - previous)
            if remaining > 0:
                time.sleep(remaining)
        last_call_started[provider_id] = time.monotonic()
        return providers[provider_id].call(method, params)

    if args.resume_checkpoint is not None:
        result = resume_trace_acquisition(
            args.resume_checkpoint,
            transport=transport,
            activation=activation,
            unresolved_trace_path=args.trace_targets,
            now_utc=args.now_utc,
            retry_reconstruction_inputs=retry_inputs,
        )
    else:
        result = execute_control_trace_acquisition(
            activation=activation,
            unresolved_trace_path=args.trace_targets,
            output_root=args.output_root,
            transport=transport,
            now_utc=args.now_utc,
            retry_reconstruction_inputs=retry_inputs,
        )
    checkpoint_path = Path(result["checkpoint_path"]).resolve(strict=True)
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    payload_path = checkpoint_path.parent / (
        f"checkpoint-signing-payload-{checkpoint['checkpoint_sha256']}.json"
    )
    if not payload_path.exists():
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{payload_path.name}.", suffix=".tmp", dir=payload_path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(canonical_checkpoint_payload(checkpoint))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, payload_path)
        finally:
            temporary.unlink(missing_ok=True)
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
    checkpoint_verification = verify_trace_checkpoint_signature(
        checkpoint_path=checkpoint_path,
        signature_path=signature_path,
        allowed_signers_path=args.checkpoint_allowed_signers,
        expected_principal=args.checkpoint_signer_principal,
    )
    result["checkpoint_signature_path"] = str(signature_path)
    result["checkpoint_signature_verification"] = checkpoint_verification
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "COMPLETE" else 3


if __name__ == "__main__":
    raise SystemExit(main())
