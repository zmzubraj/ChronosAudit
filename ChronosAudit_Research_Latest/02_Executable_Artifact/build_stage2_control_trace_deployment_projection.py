from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_trace_deployment_projection import (
    build_trace_deployment_projection,
)
from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay import (
    TraceSourceRoot,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise ValueError("output_exists_or_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _overlay_inputs(config_path: Path) -> dict[str, object]:
    if config_path.is_symlink():
        raise ValueError("overlay_reconstruction_config_not_ordinary")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("overlay_reconstruction_config_invalid")
    principal = str(config.get("expected_principal", "zmzubraj"))
    original_allowed = Path(config["original_activation_allowed_signers_path"])

    def signed_root(value: object, allowed: Path) -> TraceSourceRoot:
        root = Path(str(value))
        signatures = sorted(root.glob("*checkpoint-signing-payload-*.json.sig"))
        if len(signatures) != 1:
            raise ValueError("checkpoint_signature_ambiguous")
        return TraceSourceRoot(root / "checkpoint.json", signatures[0], allowed, principal)

    roots = config.get("original_source_roots")
    if not isinstance(roots, list) or len(roots) != 3:
        raise ValueError("exactly_three_source_roots_required")
    retry_inputs = {
        "specification_path": Path(config["specification_path"]),
        "spec_approval_path": Path(config["spec_approval_path"]),
        "original_targets_path": Path(config["original_targets_path"]),
        "activation_request_path": Path(config["original_activation_request_path"]),
        "activation_approval_path": Path(config["original_activation_approval_path"]),
        "activation_signature_path": Path(config["original_activation_signature_path"]),
        "activation_allowed_signers_path": original_allowed,
        "activation_verification_path": Path(config["original_activation_verification_path"]),
        "activation_expected_principal": principal,
        "sources": [signed_root(value, original_allowed) for value in roots],
    }
    retry_allowed = Path(config["retry_activation_allowed_signers_path"])
    return {
        "retry_targets_path": Path(config["retry_targets_path"]),
        "retry_targets_verification_path": Path(config["retry_targets_verification_path"]),
        "retry_reconstruction_inputs": retry_inputs,
        "retry_activation_request_path": Path(config["retry_activation_request_path"]),
        "retry_activation_approval_path": Path(config["retry_activation_approval_path"]),
        "retry_activation_signature_path": Path(config["retry_activation_signature_path"]),
        "retry_activation_allowed_signers_path": retry_allowed,
        "retry_activation_verification_path": Path(config["retry_activation_verification_path"]),
        "retry_activation_expected_principal": principal,
        "retry_source": signed_root(config["retry_root"], retry_allowed),
        "retry_verification_time_utc": str(config["retry_verification_time_utc"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Project complete dual-provider trace evidence into immutable "
            "deployment classifications. This does not admit rows to pair "
            "scope, select controls, or change canonical counters."
        )
    )
    parser.add_argument("--trace-targets", type=Path, required=True)
    parser.add_argument("--trace-results", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--checkpoint-verification", type=Path)
    parser.add_argument("--trace-overlay", type=Path)
    parser.add_argument("--trace-overlay-verification", type=Path)
    parser.add_argument("--overlay-reconstruction-config", type=Path)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    overlay_inputs = (
        _overlay_inputs(args.overlay_reconstruction_config)
        if args.overlay_reconstruction_config is not None
        else None
    )
    payload = build_trace_deployment_projection(
        trace_targets_path=args.trace_targets,
        trace_results_path=args.trace_results,
        checkpoint_path=args.checkpoint,
        checkpoint_verification_path=args.checkpoint_verification,
        trace_overlay_path=args.trace_overlay,
        trace_overlay_verification_path=args.trace_overlay_verification,
        overlay_reconstruction_inputs=overlay_inputs,
        candidate_root=args.candidate_root,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, payload)
    print(
        json.dumps(
            {
                "record_count": payload["record_count"],
                "projection_sha256": payload["projection_sha256"],
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
