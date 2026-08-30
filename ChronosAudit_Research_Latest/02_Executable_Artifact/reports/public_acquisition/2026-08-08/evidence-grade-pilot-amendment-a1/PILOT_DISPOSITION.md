# ChronosAudit evidence-grade pilot disposition

## Decision

`BLOCKED_PROTOCOL`

The amended pilot contains the intended 10 cases across Ethereum (3), BSC (3),
Base (2), and Arbitrum (2), while leaving the canonical 417-case corpus
unchanged. Nine cases satisfy the complete Section 6 historical-snapshot and
receipt-binding contract. The pilot is not complete and is not release eligible.

## Verified result

| Item | Result |
|---|---:|
| Pilot cases attempted | 10 |
| Strict historical snapshots closed | 9 |
| Protocol-ineligible cases | 1 |
| Archive-access-blocked cases | 0 |
| Preserved content-addressed RPC receipts | 363 |
| Invalid receipt content addresses | 0 |

Strictly closed cases: `futureswap`, `carolprotocol`, `shadowfi`, `bbox`, `vtf`,
`saddle`, `uerii`, `88mph`, and `treasuredao`.

## Blocking findings

1. `leetswap` has complete state-cell and receipt evidence, but its frozen
   deployment-plus-24-hour cutoff is only 0.805 hours before the verified
   incident. This violates the preregistered minimum one-hour incident lead.
   Changing that threshold after observing the case would be a protocol change,
   so the case remains ineligible.
2. The authorized Infura Arbitrum archive path and the independent keyed Alchemy
   path now agree on the canonical cutoff blocks and every required EIP-1898
   block-hash-bound state cell for `futureswap` and `treasuredao`. Both cases are
   closed with preserved content-addressed receipts; no archive-access blocker
   remains in the amended pilot.

## Evidence anchors

- `pilot_closure_report.json` is the canonical machine-readable disposition.
- `rpc_receipt_manifest.json` inventories and verifies every preserved response.
- `pilot_amendment_audit.json` records the deterministic post-freeze Arbitrum
  supplement and proves that the canonical program-case count did not change.
- `cases/*.json` binds each required state cell to its request, provider family,
  raw response path, and SHA-256 digest.
- Captured provider-identity response headers retain status and provenance
  metadata, but ephemeral Cloudflare bot-management cookie values are explicitly
  redacted; the hashed HTML evidence used by the verifier is unchanged.

## Smallest responsible resolution

1. Obtain an accountable protocol decision either to replace `leetswap` under a
   prospective amendment defined before replacement-provider results are seen,
   or to redefine the completed eligible pilot denominator as nine. The current
   workflow must not make that scientific decision autonomously.

Until that protocol issue is resolved, the pilot remains fail-closed and no
release or production-qualification claim is permitted.
