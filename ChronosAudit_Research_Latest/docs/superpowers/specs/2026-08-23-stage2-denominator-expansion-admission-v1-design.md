# Stage 2 Denominator Expansion Admission V1

**Status:** User-approved for implementation on 2026-08-23  
**Governance label:** `DENOMINATOR_EXPANSION_ADMISSION_V1`  
**Scope:** additive control-input authority only  
**Preserves:** sealed Recovery3 history and the canonical 20,000/20,000 deployment-denominator counter

## Purpose

The sealed 20,000-row denominator is counter-authorized but cannot supply ten globally unique same-chain controls for every one of the 417 positive cases. Reserve acquisition may supply additional evidence-backed control inputs, but local-test acquisition, a valid hash, or provider agreement cannot by itself grant counter authority. This specification defines the only admissible bridge.

## Frozen admission unit

One admission unit is one unique `chain:control_address` reserve deployment record bound to:

1. the frozen 34,900-row globally no-reuse reserve queue and its source lineage;
2. one positive case and its frozen prediction cutoff;
3. dual-provider deployment evidence, using either an agreed top-level CREATE receipt or an agreed trace-proven internal CREATE/CREATE2;
4. an exact deployment block hash, timestamp, transaction hash, creation type, and record hash;
5. a deterministic queue rank fixed before any control outcome inspection.

The unit is case-specific for matching and globally capacity-one for selection. It does not increase or rewrite the canonical 20,000-row denominator counter.

## Conjunctive admission checks

Every admitted unit must pass all of the following:

- `queue_membership`: exact identity and assignment membership in the frozen reserve queue;
- `source_lineage`: ordinary-file hashes close from source object through queue row and deployment result;
- `provider_independence`: two distinct verified provider IDs and operator families agree semantically;
- `deployment_identity`: transaction, block number/hash, address, and creation path are exact and self-consistent;
- `temporal_pre_cutoff`: deployment timestamp is strictly earlier than the paired positive cutoff;
- `global_no_reuse`: no chain-address occurs in another admitted reserve assignment or the selected cohort;
- `outcome_blindness`: neither admission inputs nor ordering contain control outcomes or post-cutoff fields;
- `evidence_completeness`: no acquisition error, partial scope, unresolved trace requirement, or unavailable deployment fact is normalized into a passing category.

Failure of any check rejects the unit. Rejected and partial units remain historical evidence and cannot be silently replaced within a frozen selection run.

## Deterministic deduplication and ordering

Identity is lowercase `chain:control_address`. Duplicate identity is resolved before admission by the earliest frozen reserve queue rank; `reserve_assignment_sha256` is the deterministic tie-break. Admission order is the frozen round-robin case order already used by the next-batch planner. No ranking may use maturity outcomes, incidents, protocol success, exploit labels, mechanism adjudication, or post-cutoff state.

## Authority boundary

The local-test key may sign mechanical acquisition checkpoints and non-authorizing projections. It cannot set `counter_authority=true`.

An authorizing admission requires a distinct accountable approval that binds:

- this specification file and SHA-256;
- the sealed Recovery3 denominator authority bridge;
- the exact reserve queue and source manifests;
- the complete deployment-evidence projection and its independently verified raw evidence;
- the admitted-row projection and all row hashes;
- the deterministic max-flow capacity audit;
- an attestation that no control outcomes were inspected before admission/order freeze;
- signer principal, public-key identity binding, validity window, and detached OpenSSH signature.

Approval grants only additive control-input counter authority. It grants no selection, qualification, human outcome review, R5, release, stage-promotion, or Recovery3 mutation authority.

## Projection invariants

An authorizing projection must be all-or-nothing and machine-verified:

- every admitted row is unique by chain-address and reserve assignment;
- every row passes all eight admission checks above;
- every referenced artifact is an ordinary file with matching SHA-256;
- the combined original-plus-admitted graph has exact maximum assignable capacity at least 4,170 under ten-per-case and global no-reuse constraints;
- original sealed rows remain byte- and hash-identical;
- authority flags are false unless a valid accountable approval is independently reverified;
- any material upstream change invalidates the projection and requires a new revision rather than mutation.

## Downstream boundary

Only rows from the sealed denominator authority bridge or an independently verified authorizing expansion projection may enter pair-feature construction. Admission is necessary but not sufficient: final `DYNAMIC_HORIZON_V1` maturity/censoring, temporal, lineage, clone, proxy, protocol, and mechanism-separation checks remain separate conjunctive gates.

## Exact approval text

`APPROVE_DENOMINATOR_EXPANSION_ADMISSION_V1`

The exact text was supplied on 2026-08-23 and authorizes implementation of this admission path. It does not admit any row. Until a distinct accountable admission signature over the completed projection is verified, every expansion artifact must retain `counter_authority=false`, and both control counters remain 0/4,170.
