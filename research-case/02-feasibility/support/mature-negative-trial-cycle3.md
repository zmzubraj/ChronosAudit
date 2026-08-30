# CA-P09 prespecified mature-negative trial

## Status

`PREREGISTERED — RIGHT_CENSORED_UNRESOLVED`

This is a feasibility trial of the status rule, not a declaration that the
contract is safe and not a mature-negative result. The protocol was frozen on
`2026-08-01T19:28:31Z`, before the follow-up evidence windows below. The earliest
possible mature-negative adjudication is `2027-08-01T19:28:31Z`.

## Deterministic candidate rule

1. Use the official Uniswap v4 deployment registry as retrieved at the freeze
   time.
2. Restrict to Ethereum mainnet (`chainId=1`).
3. Select the contract whose registry name exactly equals `PoolManager`.
4. Require a public core-audit bundle, a public vulnerability-reporting path,
   and a public source-verification record before enrollment.
5. Reject a proxy or unresolved implementation edge.

The rule yields `0x000000000004444c5dc75cB358380D2e3dE08A90`.
The official registry names this address as the Ethereum v4 `PoolManager`.
Sourcify reports a verified `match`, Solidity
`0.8.26+commit.8a97fa7a`, a non-proxy disposition, deployment block
`21688329`, and the binding fields preserved in
`mature-negative-candidate-binding.json`.

## Frozen property set

The trial is limited to these target-contract properties:

| ID | Property | Positive endpoint |
|---|---|---|
| `MN-P1` | An `unlock` completes only when the tracked nonzero currency-delta count returns to zero. | A public, attributable transaction or independently reproducible counterexample shows a completed `unlock` with an unsettled value-bearing delta. |
| `MN-P2` | The PoolManager lock prevents a nested `unlock` while already unlocked. | A public, attributable transaction or independently reproducible counterexample bypasses the lock and produces a value-bearing nested-unlock state transition. |
| `MN-P3` | Dynamic LP-fee updates require the authorized hook for a dynamic-fee pool. | A public, attributable transaction or independently reproducible counterexample changes a dynamic LP fee without the authorized hook condition. |

Properties outside this set, third-party hooks, routers, user interfaces,
governance, oracle quality, token behavior, MEV, and economic loss without a
demonstrated `MN-P1`–`MN-P3` violation are out of scope.

## Baseline investigative evidence frozen before follow-up

- the official deployment registry identifies the target;
- the official v4 site and Uniswap security announcement identify nine core and
  periphery reviews, a public security competition, and an active bounty path;
- the core audit directory contains reports from ABDK, Certora, Spearbit,
  OpenZeppelin, and Trail of Bits;
- the public `v4-core` repository and Sourcify record provide a source and
  deployed-artifact binding path;
- the Sourcify record is a `match`, not `exact_match`, so its limitation is
  retained rather than upgraded.

No audit is treated as proof of absence, and no source is treated as a global
safety certificate.

## Follow-up schedule and frozen searches

Evidence snapshots are due at `+90`, `+180`, `+270`, and `+365` days from the
freeze time. At each snapshot, the assigned investigator must search and record:

1. official Uniswap security posts, deployment registry, and v4 core security
   materials;
2. the public Uniswap v4 bounty/disclosure surface for publicly disclosed
   resolved findings;
3. public incident catalogues and primary transaction evidence for any alleged
   PoolManager exploit;
4. the Sourcify binding record and the deployed address identity;
5. public audit-report revisions or errata relevant to `MN-P1`–`MN-P3`.

Every query, retrieval timestamp, source URL, inclusion/exclusion decision, and
content hash that can be lawfully preserved must be logged. Private bounty
reports and nonpublic disclosures are not requested or inferred.

## Outcome rule at close

- `CONFIRMED_POSITIVE` if direct public evidence meets any positive endpoint and
  independent adjudication attributes it to this target and property.
- `MATURE_INVESTIGATED_NEGATIVE` only if the full 365-day window closes, all four
  snapshots and the baseline binding remain complete, no positive endpoint is
  met, all admissible allegations are adjudicated, and an independent reviewer
  reproduces the assignment. The label is restricted to `MN-P1`–`MN-P3` and the
  frozen target artifact.
- `RIGHT_CENSORED_UNRESOLVED` if follow-up is incomplete, binding changes or is
  disputed, an allegation cannot be adjudicated, independent review is absent,
  or required public evidence becomes unavailable.

Absence from an incident list is never sufficient for the mature-negative label.

## Independence and stop rules

- The investigator collecting follow-up evidence may not be the final status
  adjudicator.
- The adjudicator must receive the frozen protocol, the complete evidence log,
  and blinded primary assignment; no consensus vote substitutes for evidence.
- Any material change to the address, property set, window, or outcome rule
  invalidates this trial rather than silently amending it.
- Discovery of a credible vulnerability follows the applicable public bounty or
  disclosure rules; this research package does not execute disclosure.
- Until the window closes, `CA-P09` remains right-censored and contributes no
  mature-negative denominator.
- While right-censored, `CA-P09` is also excluded from the benchmark-core
  manifest-completeness denominator; it is tracked only in the status-trial
  registry. This rule is frozen before follow-up and prevents denominator drift.

## Primary public sources

- https://developers.uniswap.org/docs/protocols/v4/deployments
- https://v4.uniswap.org/
- https://blog.uniswap.org/v4-bug-bounty
- https://github.com/Uniswap/v4-core/tree/46c6834698c48bc4a463a86d8420f4eb1d7f3b75/docs/security/audits
- https://github.com/Uniswap/v4-core/tree/46c6834698c48bc4a463a86d8420f4eb1d7f3b75
- https://sourcify.dev/server/v2/contract/1/0x000000000004444c5dc75cB358380D2e3dE08A90
- https://docs.sourcify.dev/docs/api/index.html
