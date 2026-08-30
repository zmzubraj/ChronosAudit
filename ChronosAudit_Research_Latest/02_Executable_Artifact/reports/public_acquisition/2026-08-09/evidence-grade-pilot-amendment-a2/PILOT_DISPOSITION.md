# ChronosAudit evidence-grade pilot disposition

## Decision

`COMPLETE`

The amendment-A2 pilot contains 10 protocol-eligible cases across Arbitrum (3),
BSC (3), Ethereum (3), and Base (1), while leaving the canonical 417-case
corpus unchanged. All 10 cases satisfy the Section 6 historical-snapshot and
receipt-binding contract. This closes the evidence-grade pilot only; it does
not make the broader ChronosAudit release eligible.

## Verified result

| Item | Result |
|---|---:|
| Pilot cases attempted | 10 |
| Strict historical snapshots closed | 10 |
| Protocol-ineligible cases | 0 |
| Archive-access-blocked cases | 0 |
| Preserved content-addressed RPC receipts | 295 |
| Invalid receipt content addresses | 0 |

The protocol-ineligible `leetswap` case was replaced under the frozen A2
amendment by `gmxv1`, an Arbitrum case selected before observing replacement
provider results. The A2 audit preserves the replacement trigger, parent
manifest, selection seed, and no-reselection declaration.

## Arbitrum independence and binding

The Arbitrum cases `futureswap`, `treasuredao`, and replacement case `gmxv1`
were queried through the independently operated Infura and Alchemy provider
families. Each provider agreed on the canonical cutoff block and all applicable
prediction-time state cells. Every required cell is either consensus-verified
from both providers or explicitly `not_applicable`, and every observation is
bound to a preserved raw response and SHA-256 digest.

## Evidence anchors

- `pilot_closure_report.json` is the canonical machine-readable disposition.
- `rpc_receipt_manifest.json` inventories and validates all 295 responses.
- `pilot_amendment_audit.json` records the prespecified GMX V1 replacement and
  confirms that the canonical program-case count did not change.
- `provider_identity_verification.json` preserves the independent-operator and
  method-capability evidence for each provider family.
- `cases/*.json` binds each required state cell to its request, provider family,
  raw response path, and SHA-256 digest.

## Scope boundary

The canonical closure report deliberately retains `release_eligible: false`.
Independent adjudication, denominator qualification, matched controls,
independent R5 replication, and the remaining release gates are separate work
and are not satisfied by this pilot.
