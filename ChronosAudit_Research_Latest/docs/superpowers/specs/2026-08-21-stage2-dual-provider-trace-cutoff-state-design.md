# ChronosAudit Stage 2 Dual-Provider Trace and Cutoff-State Design

Status: USER-APPROVED WRITTEN SPECIFICATION
Design date: 2026-08-21  
System: ChronosAudit Stage 2 control selection and qualification  
Approved approach: `DUAL_PROVIDER_TRACE_AND_CUTOFF_STATE_V1`  
Approval statement: `Approve Approach 1: dual-provider trace and cutoff-state pipeline`
Written-specification approval: `Approve the written specification`

## 1. Decision

ChronosAudit will extend the frozen control-candidate acquisition boundary with a separately approved, exact-scope pipeline for two purposes:

1. prove internal and factory-created deployment identities using agreement from two independently owned RPC provider families; and
2. reconstruct the code, proxy, clone, source-verification, and protocol covariates that were observable at each positive case's frozen prediction cutoff.

The extension preserves the existing 34,900-row reserve order, no-repeat ledger, global no-reuse allocation rule, `REFERENCE_IDENTITY_DEDUP_V1`, and `DYNAMIC_HORIZON_V1`. It does not inspect candidate outcomes before the selected cohort is frozen.

This design is not an authorization to execute RPC calls, select controls, qualify controls, mutate Recovery3, increment a counter, promote Stage 2, or claim independent human review. Each execution boundary requires its own hash-bound request, approval, and verification artifact.

## 2. Current state and target

The authoritative starting state is:

- historical snapshots: 417/417;
- deployment denominator: 20,000/20,000;
- AI-only adjudications: 417/417 complete, with `FAIL_RELIABILITY_THRESHOLD`;
- canonical independent-human adjudications: 0/417;
- original deployment-only control graph: 680/4,170 maximum flow;
- historical reserve queue: 34,900 rows with zero prespecified reserve shortfall;
- dual-provider receipt checkpoint: 1,366 complete observations across all 380 deficit cases;
- top-level deployment-classification complete: 808;
- internal or factory trace required: 558;
- selected control candidates: 0/4,170;
- qualified controls: 0/4,170.

The target remains exactly ten unique same-chain controls for every one of the 417 positive cases, with no chain-address reused across cases. A qualified control must pass maturity, censoring, temporal, lineage, clone, proxy, protocol, and mechanism-separation checks. No partial cohort changes either canonical control counter.

## 3. Governing invariants

### 3.1 Frozen inputs

Every run binds the ordinary-file SHA-256 values of:

- the canonical v4 positive snapshot/counter authority;
- the frozen selection policy;
- the 34,900-row reserve queue and its manifest;
- the exact block-window artifact;
- the pair-scope artifact;
- the provider registry and verified provider-identity projection;
- the `REFERENCE_IDENTITY_DEDUP_V1` reference package;
- the `DYNAMIC_HORIZON_V1` model specification;
- the existing acquisition ledger and latest verified checkpoint.

A mismatch, missing file, symlink, path escape, duplicate identity, reordered queue, stale signature, or incompatible schema stops the run before network access.

### 3.2 Cutoff safety

Deployment and covariate evidence may use only chain state, source records, registry records, and classifications demonstrably available at or before the positive case's frozen prediction cutoff. Prohibited inputs include later incidents, later exploit labels, qualification outcomes, current source-verification state without historical proof, allocation success, maturity as of execution time, and target-completion pressure.

### 3.3 Unknown values

Unavailable cutoff-safe protocol, proxy, or complexity evidence normalizes to the explicit category `unknown`; unestablished historical source verification normalizes to `false`. `unknown` is a category, not proof of separation. In particular:

- `unknown` versus `unknown` cannot pass clone, proxy, protocol, or mechanism separation;
- a hash-shaped placeholder cannot replace an evidence artifact;
- a provider error cannot be normalized into `unknown` when the field was expected to be observable;
- unresolved or disputed evidence remains a blocker unless the frozen policy explicitly permits the resulting category.

### 3.4 Independence and agreement

For each chain, decision-bearing RPC evidence requires two verified provider identities from two distinct operator families. Different hostnames, API tokens, gateways, or backends do not establish independence when the operator family is the same.

Agreement is computed over canonical semantic values, not raw JSON bytes. Both raw request/response envelopes remain preserved and hash-bound.

## 4. Architecture

The pipeline has five isolated stages. A stage consumes only verified outputs from the preceding stage and emits non-authorizing evidence for the next stage.

### 4.1 Stage A: capability preflight

Before an activation request is built, a bounded, non-authorizing capability preflight probes one or more frozen historical examples per chain. It records raw evidence for:

- `eth_chainId`;
- `eth_getBlockByHash` and `eth_getBlockByNumber`;
- `eth_getTransactionReceipt`;
- at least one supported trace backend from `trace_block`, `trace_transaction`, `debug_traceTransaction` with `callTracer`, or `debug_traceBlockByNumber` with `callTracer`;
- `eth_getCode` at the frozen historical block;
- `eth_getStorageAt` for the EIP-1967 implementation, beacon, and admin slots at the same block;
- `eth_call` at the same block for beacon `implementation()` when applicable.

The preflight must verify historical availability, canonical block identity, complete raw evidence, and two-family semantic agreement. A trace method returning an empty result is not considered capable until the fixture is known to contain the target internal creation.

Capability failure does not relax the evidence contract. If the currently registered provider pair cannot satisfy a method, the chain remains blocked until a separately reviewed provider-identity replacement is approved. No credential is inferred, borrowed, or exposed.

### 4.2 Stage B: exact-scope activation

The activation request is a new versioned contract rather than a mutation of the receipt-only activation. It binds:

- exact provider identities and operator families;
- allowed RPC methods by provider and chain;
- exact transaction hashes, block hashes or numbers, contract addresses, and pair-scope hashes;
- the unresolved trace set and cutoff-state acquisition set;
- a deterministic maximum-request formula and hard request ceiling;
- activation start and expiry times;
- raw-envelope and hash-chained no-repeat-ledger requirements;
- retry limits and terminal failure categories;
- `selection_authorized=false`;
- `stage_promotion_authorized=false`;
- `recovery3_mutation_authorized=false`.

An activated method cannot be called outside its frozen transaction, block, address, pair, provider, or time scope. Adding a provider, method, target, or request budget requires a new request and signature.

The existing local-test key may sign this mechanical activation and later checkpoints under new, purpose-specific OpenSSH namespaces. Its signature proves payload integrity and possession of the local-test key only; it is not production identity binding, scientific verification, independent human review, or counter authority.

### 4.3 Stage C: dual-provider deployment tracing

Top-level creations continue to use receipt `contractAddress` evidence with agreed block identity. Internal and factory-created rows require trace evidence.

For each activated transaction or block:

1. call the provider's approved trace backend;
2. parse `CREATE` and `CREATE2` frames recursively;
3. normalize each creation to chain, block number, block hash, transaction hash, created address, creator address when available, creation type, and canonical trace path;
4. locate the reserve candidate's chain-address within the normalized creation set;
5. compare the complete normalized creation set from both provider families;
6. mark deployment complete only when the providers agree on the candidate and the relevant creation set.

Provider-specific trace shapes are adapter concerns. Cross-backend agreement is permitted only after normalization. Missing traces, address mismatches, incomplete frames, chain mismatches, block disagreements, and trace-set disagreements fail closed.

The preferred scope is transaction-level tracing because it minimizes data and request cost. Block-level tracing is allowed only when transaction-level tracing is unavailable and the activation binds the exact block and its request budget. A block trace may not introduce unqueued controls.

### 4.4 Stage D: cutoff-state and provenance acquisition

For every deployment-complete reserve row admitted to pair scope, resolve the canonical block at or immediately before the required covariate cutoff. Two providers must agree on the block number, block hash, and timestamp. All state reads use the agreed historical selector; EIP-1898 block-hash selectors are preferred. A numeric block tag is acceptable only when each response is bound back to the agreed block hash.

The cutoff-state collector obtains:

- runtime bytecode and code size;
- normalized runtime-code hash;
- EIP-1967 implementation, beacon, and admin slots;
- beacon implementation through `implementation()` when applicable;
- EIP-1167 minimal-proxy target when detectable from runtime bytecode;
- implementation runtime code and code hash when a target is resolved;
- explicit proxy status and proxy family;
- clone family derived from the frozen normalized code/implementation rule;
- chain-address identity group and deployment lineage;
- historically demonstrable source-verification state;
- cutoff-safe protocol-family evidence;
- explicit complexity class used by `DYNAMIC_HORIZON_V1`.

Nonstandard proxy patterns, diamonds, ambiguous implementations, disputed provider values, historically unprovable source verification, and insufficient protocol evidence remain explicit `unknown` or `false` values under the approved normalization rule. They are never guessed.

Source verification is `true` only when an ordinary, hash-bound source record proves that verification existed at or before the cutoff. A current Sourcify row without cutoff-safe timing is not enough. Protocol classification similarly requires a cutoff-safe, hash-bound registry, source, or contract evidence record; present-day labels and post-incident reports are prohibited.

Each pair-covariate row binds the pair-scope record hash, case, chain-address, denominator record hash, cutoff, evidence block number/hash/timestamp, semantic covariates, all raw evidence hashes, and its canonical record hash. Import uses the existing no-repeat pair ledger and remains non-authorizing.

### 4.5 Stage E: horizon, selection, and qualification handoff

Verified pair covariates feed the already approved `DYNAMIC_HORIZON_V1` implementation. The final eight-artifact horizon package must be rebuilt for the production pair set and receive its separate author signature before selection.

Selection then:

1. combines the original eligible controls with the verified reserve candidates;
2. excludes every positive chain-address and every forbidden identity, clone, proxy, and protocol linkage;
3. applies exact matching and frozen calipers without outcome knowledge;
4. runs deterministic global maximum-cardinality allocation with chain-address capacity one;
5. succeeds only with all 417 cases, exactly ranks 1-10 per case, and 4,170 unique chain-address controls;
6. freezes the cohort before outcome review.

No selected control may be replaced after its outcome, maturity, censoring, or mechanism evidence is inspected. If global allocation cannot reach 4,170 before outcome review, the selection stage emits a verified shortfall and no cohort. If a frozen selected control later fails qualification, the qualified counter remains below target; target pressure cannot authorize favorable replacement.

Qualification remains a separate human-accountability boundary. Every selected row requires eight candidate-hash-bound evidence records:

- maturity;
- censoring;
- temporal;
- lineage;
- clone;
- proxy;
- protocol;
- mechanism separation.

Maturity, censoring, and mechanism separation require the human review already mandated by the qualification contract. The evidence reviewer, outcome reviewer, and approval authority must satisfy the frozen ownership and conflict-separation rules. The existing local-test key cannot impersonate those roles.

## 5. Data flow and artifacts

The implementation will produce versioned packages rather than overwrite the receipt-only checkpoint:

1. capability-preflight request, raw envelopes, summary, and verifier report;
2. exact-scope activation request, approval payload, detached signature, and verification;
3. trace run binding, hash-chained event ledger, raw trace envelopes, normalized deployment results, summary, signed checkpoint, and non-authorizing signature verification;
4. cutoff-state run binding, raw state envelopes, block-agreement records, semantic state projections, source/protocol evidence manifests, pair-covariate batch, import verification, and no-repeat ledger;
5. final `DYNAMIC_HORIZON_V1` eight-artifact package and signed verification;
6. deterministic selection cohort, allocation/min-cut audit, selection manifest, and candidate projection;
7. eight-check evidence bundle, accountable qualification approval, qualified projection, and canonical counter projection.

All raw paths in portable manifests are relative, path-contained, ordinary files. Every manifest records schema version, upstream hashes, row counts, status counts, exclusions, errors, authority limits, and a canonical self-hash.

## 6. Resume, retry, and failure handling

Runs are resumable and append-only at the event-ledger boundary. Resume logic revalidates every previously completed result hash before skipping it.

Retry is permitted only for transient transport failures such as rate limiting, timeouts, and temporary server errors. Retries use deterministic bounded backoff and remain inside the activation window and request ceiling. Malformed responses, semantic mismatches, provider disagreement, target-address absence, block mismatch, unsupported methods, exhausted retries, and expired activation are terminal for that attempt.

A new attempt may use a materially different approved provider or method only through a new activation. It may not rewrite prior events, recycle request sequence numbers, or mark an unresolved row complete.

At every stage, partial progress is checkpointed without changing selection, qualification, Stage 2, Release, or Recovery3 authority.

## 7. Testing and verification

Implementation follows test-driven development. Required tests include:

### 7.1 Activation and scope

- reject every method not explicitly activated;
- reject out-of-scope chains, providers, transactions, blocks, addresses, or pair hashes;
- reject stale, expired, tampered, or wrong-namespace signatures;
- enforce the deterministic request ceiling and no-repeat ledger;
- preserve all authority flags as false except the exact RPC permission.

### 7.2 Trace normalization

- parse Parity/OpenEthereum and Geth call-tracer `CREATE` and `CREATE2` fixtures;
- normalize transaction-level and block-level traces identically;
- reject missing candidate addresses, incomplete frames, and trace-set disagreements;
- require two distinct verified operator families;
- prove deterministic result hashes and resume behavior.

### 7.3 Historical state

- require block number/hash/timestamp agreement;
- verify EIP-1898 or hash-reconciled historical reads;
- reconstruct EIP-1967, beacon, and EIP-1167 fixtures;
- reject code, storage, beacon-call, or implementation disagreements;
- normalize legitimate unavailable classifications to `unknown` or `false` without converting acquisition errors into data;
- reject post-cutoff source or protocol evidence.

### 7.4 Pair projection and selection

- bind every covariate to the pair-scope and denominator hashes;
- prevent raw-path escape, replay, duplication, and hash substitution;
- ensure `unknown` versus `unknown` never proves separation;
- reproduce final horizons deterministically;
- verify exact 417-by-10 structure, global no reuse, rank closure, and match-set integrity;
- preserve no-replacement after cohort freeze.

### 7.5 Qualification and counters

- require all eight semantic evidence records per selected candidate;
- require human outcome review where frozen policy demands it;
- reject same-owner or conflicted approval chains;
- keep candidate and qualified counters at zero for incomplete, partial, unsigned, local-test-only, or caller-supplied projections;
- rerun the full relevant control/public-acquisition regression suite, canonical production qualification, and fresh signature verification.

Passing tests prove implementation behavior only. They do not establish provider independence, scientific validity, human review, selection authority, qualification authority, or counter completion.

## 8. Implementation boundaries

The intended implementation is additive:

- retain the receipt-only activation and checkpoint as immutable history;
- create new versioned trace/state activation and acquisition modules or tightly scoped extensions;
- reuse the existing provider registry, raw-envelope conventions, strict snapshot semantics, pair-covariate importer, dynamic-horizon verifier, global allocation, qualification evidence verifier, and counter projection;
- avoid refactoring unrelated Stage 2 or Recovery3 code;
- keep one canonical integration owner for shared schemas, selection, counters, and continuation documentation.

The implementation plan must name exact files, interfaces, migration compatibility, test batches, execution budgets, and verification commands before code changes begin.

## 9. Acceptance criteria

The pipeline implementation is acceptable only when:

1. the capability preflight is deterministic, bounded, raw-evidence preserving, and non-authorizing;
2. an exact-scope signed activation cannot call undeclared methods or targets;
3. internal deployment classification requires two-family trace agreement;
4. cutoff-state rows reconstruct at the exact agreed historical block and bind all raw evidence;
5. source and protocol evidence are demonstrably cutoff-safe or normalize fail-closed;
6. pair-covariate imports are replay-safe and compatible with `DYNAMIC_HORIZON_V1`;
7. selection remains outcome-blind, global, deterministic, exactly ten per case, and no-reuse;
8. qualification still requires all eight checks and the frozen human-accountability boundary;
9. local-test signatures remain explicitly non-authorizing;
10. all focused and relevant regression tests pass, and fresh canonical counter verification reports the evidence-supported value without manual override.

The overall Stage 2 control goal is complete only when authoritative current-state evidence proves all 4,170 selected controls and all 4,170 qualified controls satisfy the complete contract. A capability pass, RPC checkpoint, trace completion, pair-feature cohort, horizon package, maximum-flow result, test pass, or local signature alone is not completion.

## 10. Residual risks

- The current public provider pairs may not expose historical trace or EIP-1898 state methods; a reviewed archive provider or credential may be required.
- Cross-client trace schemas can omit or represent failed creation frames differently; semantic normalization and disagreement fixtures are mandatory.
- Historical source-verification timestamps and protocol ownership may remain unavailable for many reserve rows, producing `false` or `unknown` and reducing feasible matches.
- Nonstandard proxies and diamonds may remain unresolved without additional frozen historical calls or event evidence.
- The dynamic horizon may yield `INSUFFICIENT_EVIDENCE` for sparse feature strata.
- Outcome-blind selection can produce controls that later fail maturity, censoring, or mechanism separation. The no-replacement rule may therefore keep the qualified total below 4,170.
- Local-test signatures provide tamper evidence but not real-world accountable identity or independent scientific verification.

None of these risks permits silent policy relaxation, favorable replacement, fabricated evidence, counter override, or release promotion.
