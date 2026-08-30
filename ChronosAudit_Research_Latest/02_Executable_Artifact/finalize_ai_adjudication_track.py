from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.ai_adjudication import (
    AI_TRACK_NAME,
    assemble_ai_adjudication_rows,
    evaluate_ai_adjudications,
    make_author_signoff_attestation_sha256,
)


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Finalize the separate Stage 2 AI-only track.")
    parser.add_argument("track_dir", type=Path)
    parser.add_argument("--author-directive", type=Path, required=True)
    parser.add_argument(
        "--author-identity",
        default="current_workspace_user_as_accountable_author",
        help="Role identifier only; this script does not create external identity proof.",
    )
    args = parser.parse_args()
    track = args.track_dir.resolve()
    packets = _read(track / "ai_evidence_packets.json")
    protocol = _read(track / "ai_adjudication_protocol.json")
    primary_a = _read(track / "primary_a_results.json")
    primary_b = _read(track / "primary_b_results.json")
    adjudicator = _read(track / "adjudicator_results.json")
    sensitivity = _read(track / "sensitivity_results.json")

    completed = [
        _parse_utc(decision["completed_at_utc"])
        for values in (primary_a, primary_b, adjudicator, sensitivity)
        for decision in values
    ]
    finalized_at = max(datetime.now(timezone.utc), max(completed) + timedelta(seconds=1))
    finalized_at_utc = finalized_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    rows = assemble_ai_adjudication_rows(
        packets=packets,
        primary_a_results=primary_a,
        primary_b_results=primary_b,
        adjudicator_results=adjudicator,
        sensitivity_results=sensitivity,
        finalized_at_utc=finalized_at_utc,
    )
    results_path = track / "ai_adjudication_results.json"
    _write(results_path, rows)
    unsigned = evaluate_ai_adjudications(rows=rows, protocol=protocol, packets=packets)

    directive_sha = _sha(args.author_directive.resolve())
    signoff = {
        "artifact_schema_version": "2026-08-17.accountable-author-ai-gate-signoff.v1",
        "track_name": AI_TRACK_NAME,
        "status": "SIGNED_INTERNAL_PROGRESSION_AUTHORIZATION",
        "accountable_author_identity": args.author_identity,
        "attestation_type": "HASH_BOUND_CURRENT_TASK_DIRECTIVE",
        "authorization_source_sha256": directive_sha,
        "authorization_basis": "ACCOUNTABLE_AUTHOR_DIRECTIVE_IN_CURRENT_CODEX_TASK",
        "identity_binding_limit": (
            "The role identifier is bound to the current workspace user directive; "
            "it is not an external cryptographic or institutional identity proof."
        ),
        "signed_at_utc": finalized_at_utc,
        "author_decision": "AUTHORIZE_INTERNAL_PROGRESSION",
        "protocol_sha256": protocol["protocol_sha256"],
        "results_sha256": unsigned["signoff_binding_inputs"]["results_sha256"],
        "reliability_and_sensitivity_sha256": unsigned["signoff_binding_inputs"][
            "reliability_and_sensitivity_sha256"
        ],
    }
    signoff["signature_or_attestation_sha256"] = make_author_signoff_attestation_sha256(signoff)
    _write(track / "accountable_author_signoff.json", signoff)
    summary = evaluate_ai_adjudications(
        rows=rows,
        protocol=protocol,
        packets=packets,
        author_signoff=signoff,
    )
    _write(track / "ai_adjudication_summary.json", summary)

    manifest_path = track / "ai_adjudication_manifest.json"
    manifest = _read(manifest_path)
    artifact_files = {
        "evidence_packets": "ai_evidence_packets.json",
        "protocol": "ai_adjudication_protocol.json",
        "run_templates": "ai_adjudication_run_templates.json",
        "primary_a_results": "primary_a_results.json",
        "primary_b_results": "primary_b_results.json",
        "adjudicator_request": "adjudicator_request.json",
        "adjudicator_results": "adjudicator_results.json",
        "sensitivity_results": "sensitivity_results.json",
        "results": "ai_adjudication_results.json",
        "summary": "ai_adjudication_summary.json",
        "author_signoff": "accountable_author_signoff.json",
        "protocol_amendment": "ai_adjudication_protocol_amendment_v1.yaml",
    }
    manifest["artifacts"] = {
        name: {"path": filename, "sha256": _sha(track / filename)}
        for name, filename in artifact_files.items()
    }
    manifest["status"] = summary["status"]
    manifest["internal_progression_gate_status"] = summary["internal_progression_gate"]["status"]
    manifest.pop("manifest_sha256", None)
    manifest["manifest_sha256"] = _canonical_sha(manifest)
    _write(manifest_path, manifest)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
