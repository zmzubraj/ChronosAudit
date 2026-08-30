from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.ai_adjudication import make_ai_decision_sha256


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mechanically normalize the frozen sensitivity artifact without changing labels."
    )
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    artifact = json.loads(args.path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict) or not isinstance(artifact.get("ordered_decisions"), list):
        raise ValueError("expected wrapped sensitivity artifact with ordered_decisions")
    normalized = []
    for original in artifact["ordered_decisions"]:
        decision = dict(original)
        interval = decision.pop("decision_utc_interval", {})
        decision["started_at_utc"] = interval.get("started_at_utc", "")
        decision["completed_at_utc"] = interval.get("completed_at_utc", "")
        decision["decision_rationale"] = decision.pop("rationale", "")
        decision["evidence_references"] = [
            json.dumps(value, sort_keys=True, separators=(",", ":"))
            if isinstance(value, dict)
            else str(value)
            for value in decision.get("evidence_references", [])
        ]
        decision.pop("decision_sha256", None)
        decision["decision_sha256"] = make_ai_decision_sha256(decision)
        normalized.append(decision)
    args.path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
