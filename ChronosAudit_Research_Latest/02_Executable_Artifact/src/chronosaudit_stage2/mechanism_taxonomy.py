from __future__ import annotations

import re
from dataclasses import dataclass

# This is deliberately a *candidate* taxonomy only. Public incident labels are
# attack descriptions, not independently adjudicated root causes. The rules
# exist to make reviewer packets consistent and auditable; they never satisfy
# the two-reviewer completion gate by themselves.

@dataclass(frozen=True)
class MechanismCandidate:
    family: str
    confidence: str
    matched_rule: str


RULES: list[tuple[str, tuple[str, ...]]] = [
    ("authorization_failure", (
        r"access\s*control", r"permission", r"ownership", r"public function", r"arbitrary (external )?call",
        r"msg\.sender", r"privilege", r"unauthorized", r"malicious proposal",
    )),
    ("oracle_or_market_manipulation", (
        r"price", r"oracle", r"pair manipulate", r"pool manipulation", r"share price", r"exchange.?rate",
        r"flash.?loan.*manip", r"manipulation of funds", r"inflation attack",
    )),
    ("reentrancy", (r"reentr", r"read.?only.?reentr", r"cross contract reentr")),
    ("validation_failure", (
        r"validation", r"incorrect.*check", r"unchecked user input", r"signature verification",
        r"healthfactor", r"merkle", r"recipient balance", r"parameter setting", r"address verification",
    )),
    ("arithmetic_or_precision_failure", (
        r"overflow", r"underflow", r"rounding", r"precision", r"precission", r"calculation", r"mathematical",
        r"div precision", r"reward calculation", r"dividends calculation", r"k value",
    )),
    ("token_semantics_mismatch", (
        r"reflection token", r"deflationary token", r"token incompatible", r"token incompatible", r"token balance",
        r"skim", r"rebasing", r"burn shares", r"token migrate", r"any token is destroyed",
    )),
    ("economic_constraint_failure", (
        r"slippage", r"liquidity migration", r"economic", r"donate", r"incentive", r"cached data",
    )),
    ("cross_domain_validation_failure", (r"bridge", r"cross.?chain", r"cross.?domain")),
    ("signature_or_replay_failure", (r"signature replay", r"replay")),
    ("storage_or_upgrade_failure", (r"storage collision", r"upgrade", r"proxy")),
    ("randomness_failure", (r"random", r"predicting random")),
    ("availability_failure", (r"denial of service", r"dos\b", r"emergency withdraw")),
    ("transaction_ordering_or_mev", (r"sandwich", r"front.?run", r"mev")),
    ("business_logic_failure", (
        r"business logic", r"logic flaw", r"fault logic", r"incorrect logic", r"logic issue",
        r"wrong balance", r"misconfiguration", r"outdated global", r"incorrect transfer",
    )),
]


def candidate_from_public_label(label: str | None) -> MechanismCandidate:
    text = re.sub(r"\s+", " ", str(label or "").strip().lower())
    if not text:
        return MechanismCandidate("unassigned", "none", "empty")

    hits: list[str] = []
    for family, patterns in RULES:
        if any(re.search(p, text) for p in patterns):
            hits.append(family)

    # Multi-label public descriptions are not collapsed silently. We expose a
    # deterministic primary candidate but lower its confidence so reviewers can
    # adjudicate cause vs. exploit technique explicitly.
    if not hits:
        if "flash" in text or "loan" in text:
            return MechanismCandidate("economic_state_manipulation", "low", "fallback_flash_loan")
        return MechanismCandidate("unclassified_public_label", "low", "no_rule")
    if len(hits) == 1:
        return MechanismCandidate(hits[0], "medium", f"rule:{hits[0]}")

    priority = [
        "authorization_failure", "validation_failure", "storage_or_upgrade_failure",
        "arithmetic_or_precision_failure", "token_semantics_mismatch", "reentrancy",
        "oracle_or_market_manipulation", "economic_constraint_failure",
        "cross_domain_validation_failure", "signature_or_replay_failure",
        "randomness_failure", "availability_failure", "transaction_ordering_or_mev",
        "business_logic_failure",
    ]
    primary = next((x for x in priority if x in hits), hits[0])
    return MechanismCandidate(primary, "low", "multi_rule:" + "+".join(sorted(set(hits))))
