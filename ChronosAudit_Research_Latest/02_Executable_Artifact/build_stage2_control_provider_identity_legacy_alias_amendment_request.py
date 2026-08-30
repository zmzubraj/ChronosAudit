from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_amendment import (
    build_legacy_alias_amendment_request,
)


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("output_not_ordinary")
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the exact non-authorizing local-test legacy provider-alias "
            "method-decision request."
        )
    )
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--review-kit", type=Path, required=True)
    parser.add_argument("--historical-request", type=Path, required=True)
    parser.add_argument("--target-identities", type=Path, required=True)
    parser.add_argument("--trace-targets", type=Path, required=True)
    parser.add_argument("--transport-report", type=Path, required=True)
    parser.add_argument("--transport-verification", type=Path, required=True)
    parser.add_argument("--fresh-report", type=Path, required=True)
    parser.add_argument("--fresh-verification", type=Path, required=True)
    parser.add_argument("--created-at-utc", required=True)
    parser.add_argument("--decision-owner", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    request = build_legacy_alias_amendment_request(
        project_root=args.project_root,
        review_kit_path=args.review_kit,
        historical_request_path=args.historical_request,
        target_identities_path=args.target_identities,
        trace_targets_path=args.trace_targets,
        transport_report_path=args.transport_report,
        transport_verification_path=args.transport_verification,
        fresh_report_path=args.fresh_report,
        fresh_verification_path=args.fresh_verification,
        created_at_utc=args.created_at_utc,
        decision_owner=args.decision_owner,
    )
    output = args.output.expanduser().resolve(strict=False)
    _atomic_write(output, request)
    print(
        json.dumps(
            {
                "decision": request["decision"],
                "request_sha256": request["request_sha256"],
                "target_count": request["effective_trace_scope"]["target_count"],
                "rpc_call_count": request["effective_trace_scope"]["rpc_call_count"],
                "rpc_authorized": False,
                "counter_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
