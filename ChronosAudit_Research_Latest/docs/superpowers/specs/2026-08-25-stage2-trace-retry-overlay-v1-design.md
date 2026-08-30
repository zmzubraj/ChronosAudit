# Stage 2 Trace Retry Overlay V1

**Status:** Written specification awaiting exact-revision approval  
**Governance label:** `TRACE_RETRY_OVERLAY_V1`  
**Approval in principle received:** `APPROVE_TRACE_RETRY_OVERLAY_V1_FOR_LOCAL_TEST_ONLY` on 2026-08-25  
**Scope:** local-test-only, no-replay recovery of the frozen 1,768-target trace acquisition  
**Preserves:** all prior trace roots, Recovery3, canonical counters, and downstream authority gates

## Purpose

The frozen Stage 2 trace input contains 1,768 unique targets and 3,536 exact provider calls. Three local-test executions were deliberately stopped after public-provider quota failure. Each root is signed, hash-bound, and non-authorizing, but none is complete and the current projection accepts no incomplete checkpoint. Starting another full acquisition would replay targets already attempted under earlier roots and would discard valid dual-provider-complete evidence.

This specification adds a deterministic recovery boundary that:

1. independently reverifies each immutable source root;
2. recognizes only targets with complete dual-provider agreement;
3. freezes only unresolved targets for a fresh activation;
4. preserves prior evidence by reference rather than copying or rewriting it;
5. reconstructs one complete 1,768-target overlay only after every target is supported by verified evidence; and
6. grants no scientific, selection, qualification, counter, stage, Recovery3, review, or release authority.

## Frozen source boundary

The implementation must bind the following exact inputs before deriving any retry scope.

### Original target and activation

- Trace-target file: `02_Executable_Artifact/processed/stage2_controls/2026-08-23/control-effective-unverified-trace-targets-v1/control_trace_targets.json`
- Trace-target file SHA-256: `d2b93c0924d5b64b870fb55481dc12040223eee3e9ebf5ad516fdb28b0b4938a`
- Trace-target internal SHA-256: `19605da2e7ebf8e82d54938b3e060aec870de773ec02c637effea99e20dd00e9`
- Target count: 1,768
- Original call count: 3,536
- Activation-verification file SHA-256: `1610d3473159b85d3e19092e28f3e27fba7d0a4ce2cf49a63a75474710808c99`
- Activation-verification internal SHA-256: `ce398b5c5a8d7e1af69d8e83f6a7538e1fce393588f9ccebd9cbe1d1acb86d04`

### Immutable partial roots

| Root | Checkpoint file SHA-256 | Checkpoint internal SHA-256 | Processed | Complete | Requests | Signature-verification internal SHA-256 |
|---|---|---|---:|---:|---:|---|
| `control-trace-acquisition-v1` | `cc5b603352bb2d3215bca7e6f86a29d4daae99e9cec28ae629028b0d7886e544` | `4a4935a082f7614e81ede54f62de9cac43f7826e21f83eea1a886b8e73c11aef` | 188 | 74 | 290 | `682de4e4664c8900430ff649302df897ff0e24ce3c92e8f75ba2f8b60ae6fcd8` |
| `control-trace-acquisition-paced-v2` | `fa3386e0d730909b856eab3ae17bb9ce658f866af1f397efe109ef75abf3097b` | `a4ea8c7cbbd25e60eeb3bc089c614da48f37f5e81e303643c3ea7f7775c580d0` | 63 | 30 | 94 | `ca3464ddb0d7bc8d355bc0401b20d2cea05560ba172d8d1caad52b239290ab2b` |
| `control-trace-acquisition-paced-v3` | `d409ab8405e8305563d64506412323ed30425f9383c5cb81c003b92563716168` | `d78e92d2b97e393b6dfa3ca8c0fdba23dfb7046d74fa1e923554b0809d7f8f78` | 30 | 10 | 42 | `9515d68d12c1f0b663b3b5d70b983e9f4abb7bdcf6416af2fa5b02a17bcf22e9` |

These roots remain immutable. Their counts are source facts, not additive totals: the same target can appear in more than one root.

## Source-root revalidation

For each root, the retry builder must fail closed unless all of the following are true:

1. checkpoint, detached signature, allowed-signers file, signature-verification file, normalized results, event ledger, and every referenced raw request/response are ordinary files inside the declared root;
2. checkpoint and signature-verification self-hashes are valid and the detached OpenSSH signature reverifies under namespace `chronosaudit-stage2-control-trace-acquisition-local-test-v1` for the expected principal;
3. checkpoint status is `IN_PROGRESS_NON_AUTHORIZING` or `PARTIAL_NON_AUTHORIZING`, never an unrecognized or authority-bearing state;
4. checkpoint, normalized results, and every event bind the exact frozen target-file hash and original activation-verification internal hash;
5. processed target IDs are the exact deterministic prefix declared by the checkpoint, are unique, and match normalized-result rows one-for-one;
6. request sequences are unique and monotonic within that root, request count equals the sequence ledger, and the event hash chain closes at the checkpoint tip;
7. every event references an existing raw request and response whose file hashes, provider, method, parameters, call-scope hash, sequence, target ID, and normalized creation-set hash agree;
8. each normalized row has a valid self-hash and exactly matches the corresponding original target identity and immutable deployment fields; and
9. all authority flags remain false.

The builder must not trust a stored signature-verification JSON alone; it must cryptographically reverify the checkpoint signature and reconstruct every mechanical invariant above.

## Canonical completed-evidence union

Only a normalized row with disposition `complete` may satisfy a target from a partial root. The underlying event chain must prove two terminal successful calls from the two exact activated provider IDs and two distinct verified operator families, with identical normalized creation sets containing the frozen chain-address.

For every original target ID:

- no complete source row means `UNRESOLVED`;
- one complete source row means `SOURCE_COMPLETE`;
- multiple semantically identical complete source rows mean `SOURCE_COMPLETE_DUPLICATE_AGREEMENT`; and
- any semantic or immutable-field disagreement between complete rows fails the entire build as `COMPLETE_SOURCE_CONFLICT`.

When identical complete rows occur in multiple roots, the canonical source is the lexicographically smallest tuple `(checkpoint_sha256, record_sha256)`. All other agreeing sources remain listed in the provenance array. Failure, retry-exhausted, unsupported, malformed, disagreement, candidate-missing, or interrupted rows never override a complete row and never disappear from the source-root manifest.

## Retry-target artifact

The deterministic builder emits `trace_retry_targets.json` with schema `stage2_control_trace_retry_targets.v1`. It contains:

- the exact original target-file physical and internal hashes;
- the original activation-verification physical and internal hashes;
- a sorted manifest of all source roots and every verified source-file hash;
- exact source-complete, duplicate-agreement, and unresolved counts;
- the sorted IDs and canonical provenance of source-complete targets;
- only the original target rows for unresolved IDs, byte-semantically unchanged;
- exact per-chain target counts and two-call-per-target counts;
- false authority flags; and
- a canonical self-hash.

Ordering is ascending `target_id`. No control outcome, incident status, post-cutoff field, capacity pressure, case deficit, or favorable evidence may influence membership or order.

The companion `trace_retry_targets_verification.json` must independently rebuild the artifact byte-for-byte. Any change to an original target, source root, signature, event, receipt, or authority flag invalidates the retry target.

## Fresh retry activation

The retry-target artifact does not authorize RPC. A separate fresh activation must:

1. bind the exact retry-target file and internal hashes;
2. materialize exactly two provider calls per unresolved target;
3. use only identity-verified, registry-verified, trace-capable providers from two distinct operator families per chain;
4. set a new activation start, expiry, retry limit, exact request ceiling, signature, and internal activation hash;
5. use no call scope for any source-complete target;
6. be cryptographically reverified immediately before RPC; and
7. retain acquisition, selection, qualification, counter, stage-promotion, Recovery3, independent-review, R5, release, and publication authority as false.

The prior activation and its consumed calls remain historical. A fresh activation cannot retroactively authorize or relabel an earlier request.

## Retry execution

Retry acquisition uses a new output root and the existing secret-safe request/response/event/checkpoint discipline. It may process only the frozen retry-target IDs and exact activated calls. Hidden HTTP retries, wildcard parameters, target substitution, cross-root resume, and reuse of prior activation sequences are prohibited.

A retry root is usable by the overlay only when it is `COMPLETE`, its checkpoint signature reverifies, its event/raw-evidence chain closes, and every retry target has disposition `complete`. Partial retry roots remain immutable inputs to a later revision; they cannot be silently appended to this revision's retry scope.

## Completion overlay

After a complete retry root exists, a separate builder emits `trace_completion_overlay.json` with schema `stage2_control_trace_completion_overlay.v1`. It must:

- reverify the original target artifact, all partial source roots, the retry-target artifact and verification, the fresh activation and signature, and the complete retry root;
- cover every original target ID exactly once;
- use the deterministic canonical source row for every source-complete target and the complete retry row for every previously unresolved target;
- preserve all source and retry raw evidence by ordinary-file path plus SHA-256 without copying, rewriting, or deleting it;
- prove zero missing, extra, or duplicate canonical target IDs;
- prove every canonical target has dual-provider cross-family semantic agreement and contains the frozen chain-address in its creation set;
- preserve the original target order for downstream reconstruction;
- include exact provenance for the chosen canonical row and every agreeing duplicate source; and
- retain all authority flags as false.

The independent `trace_completion_overlay_verification.json` must rebuild the overlay byte-for-byte. Its only successful mechanical disposition is `COMPLETE_NON_AUTHORIZING` with exactly 1,768 completed targets.

## Downstream projection boundary

The trace-to-deployment projection may accept either its existing single-complete-root contract or a verified `TRACE_RETRY_OVERLAY_V1` input. The overlay path must not weaken any existing deployment check. It must reconstruct the same normalized trace semantics expected from one complete root and must additionally verify the overlay's complete provenance closure.

No trace row enters the deployment projection from an incomplete checkpoint, an unverified overlay, a missing raw receipt, a conflicting complete source, or a retry target absent from the fresh activation.

Only after the trace-to-deployment projection, staged cutoff-state projection, and exact capacity audit all verify may the separate denominator-expansion admission gate be evaluated. Trace completion alone does not admit a row or change either control counter.

## Failure behavior

The implementation must fail closed for at least:

- missing, non-ordinary, symlinked, or path-escaping source files;
- checkpoint, signature, verifier, result, ledger, event, or raw-receipt hash drift;
- wrong signer principal or namespace;
- nonclosing event chains or replayed/duplicated sequences;
- target-prefix, activation, provider, method, parameter, chain-address, or immutable-field mismatch;
- complete rows lacking two verified operator families;
- conflicting complete rows across roots;
- retry inclusion of a source-complete target;
- retry omission or mutation of an unresolved target;
- partial, expired, over-budget, wrong-scope, or unsigned retry activation;
- incomplete retry result;
- overlay target duplication, omission, substitution, or provenance break;
- any true downstream authority flag; and
- any attempt to mutate Recovery3 or canonical counters.

Failures produce no partially authoritative artifact. Atomic writers must refuse overwriting an existing canonical output and must reject symlink destinations.

## Required implementation surfaces

The implementation plan must cover these focused surfaces:

1. `control_trace_retry_overlay.py`: source-root verification, completed-evidence union, retry-target construction, and completion-overlay construction;
2. deterministic builder/verifier CLIs for retry targets and completion overlays;
3. the smallest compatible extension to `control_trace_deployment_projection.py` for a verified overlay input;
4. TDD coverage for every invariant and failure listed above;
5. byte-for-byte deterministic fixture reconstruction;
6. integrated trace activation/acquisition/projection regression; and
7. canonical `CONTINUE_HERE.md` synchronization after verified implementation or execution changes.

The implementation may split the module if one file would mix source-root verification, retry targeting, and downstream overlay verification beyond a clear single responsibility. Shared canonical hashing and ordinary-file checks should reuse existing project patterns rather than create a weaker parallel implementation.

## Authority boundary

The approval-in-principle token authorizes writing and reviewing this specification. It does not approve this exact file revision and does not authorize implementation, RPC, acquisition, denominator admission, pair construction, horizon assignment, control selection, qualification, counter mutation, Stage 2 promotion, Recovery3 mutation, independent review, R5, release, or publication.

Approval of the exact written revision must use the ASCII prefix
`APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: ` immediately followed
by the independently computed lowercase SHA-256 of this file. The approval
record must store the supplied digest separately and rehash the ordinary file;
it must not trust a digest embedded inside the specification.

After exact-revision approval, implementation may proceed through a written plan and TDD. RPC still requires a separately signed fresh exact activation after provider capability is reverified.

## Success criteria

This subsystem is implementation-complete only when:

1. the exact written specification revision is approved;
2. every required source-root invariant is regression-tested and passes;
3. the real three-root retry-target artifact rebuilds byte-for-byte;
4. the fresh activation machinery accepts exactly the retry subset and rejects all replay;
5. completion-overlay fixtures rebuild byte-for-byte and the existing single-root path remains compatible;
6. focused and integrated trace tests pass with no warnings or skipped critical checks; and
7. all non-RPC and downstream authority flags remain false.

Stage 2 Controls completion requires substantially more: real provider capacity, complete retry evidence, trace/deployment/state projection, exact capacity of at least 4,170, authorizing denominator admission, final outcome-blind pair-feature and horizon freeze, ten globally unique controls for every positive case, and all eight control checks. This specification cannot claim or substitute for those results.
