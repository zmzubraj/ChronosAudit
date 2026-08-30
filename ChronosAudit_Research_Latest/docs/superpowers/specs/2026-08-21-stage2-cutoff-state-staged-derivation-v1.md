# Stage 2 Cutoff-State Staged Derivation V1

**Status:** User-approved for local-test implementation and staged exact-read execution on 2026-08-22  
**Scope:** Local-test authorization and acquisition mechanics only  
**Method effect:** None; the frozen control-selection and `DYNAMIC_HORIZON_V1` methods are unchanged  
**Authority effect:** Implementation is approved; each RPC phase still requires a separate exact signed activation and verified upstream gates

## Problem statement

The approved dual-provider cutoff-state design requires exact RPC parameters to
be frozen before activation. Some proxy parameters do not exist before earlier
cutoff-state reads complete:

1. an EIP-1967 implementation address is obtained from a fixed storage slot;
2. an EIP-1967 beacon address is obtained from a different fixed storage slot;
3. a beacon's implementation address is obtained only by calling
   `implementation()` on the discovered beacon;
4. implementation bytecode can be read only after the relevant implementation
   address is known.

A single exact-call activation cannot contain those later addresses without
guessing them. A wildcard address scope would weaken the approved exact-scope
boundary. The state pipeline must therefore follow the dependency graph.

## Frozen staged execution

### Phase 0 — canonical cutoff bracket

For every unique case/chain/cutoff, two verified provider families independently
resolve:

- the last canonical block whose timestamp is not after cutoff; and
- the immediately adjacent next block whose timestamp is after cutoff.

Both block numbers, hashes, and timestamps must agree exactly.

### Phase 1 — fixed-address base discovery

For every pair target and both verified provider families, activate only:

- the agreed evidence block header;
- the agreed adjacent next block header;
- target `eth_getCode` at the EIP-1898 evidence-block selector;
- target EIP-1967 implementation-slot read;
- target EIP-1967 beacon-slot read; and
- target EIP-1967 admin-slot read.

No `eth_call` and no code read for a derived address is permitted in this phase.
EIP-1167 target detection is a deterministic local projection from the agreed
target bytecode and performs no new RPC.

### Phase 2 — first-order derived reads

From a complete, self-hashed, dual-provider-agreed Phase 1 result, freeze a new
exact target set:

- read bytecode for a nonzero direct EIP-1967 implementation address;
- read bytecode for a locally parsed EIP-1167 target; and
- call `implementation()` on a nonzero EIP-1967 beacon address.

Each address must be bound to the exact Phase 1 result hash that produced it.
Every Phase 2 call requires a separate signed exact activation. Direct
implementation and EIP-1167 code evidence may complete here. A beacon path does
not complete here because the beacon-returned implementation address was not
known before Phase 2.

### Phase 3 — beacon implementation code

From a complete, self-hashed, dual-provider-agreed Phase 2 beacon result, freeze
and separately activate the exact `eth_getCode` call for the returned beacon
implementation address at the same EIP-1898 evidence-block selector.

The returned implementation address and bytecode must agree across the same two
verified operator families. A zero, malformed, disputed, or failed beacon result
does not become an `unknown` category; it remains an acquisition failure or an
explicit unavailable state according to the frozen normalization rule.

## Combined result invariant

The final cutoff-state result is valid only when it binds:

- the Phase 0 adjacent bracket result and raw evidence;
- the Phase 1 target code and all fixed-slot results;
- every applicable Phase 2 result;
- every applicable Phase 3 result;
- the exact provider registry and two-family bindings;
- every activation request, approval, detached signature, and verification;
- every raw request/response hash and hash-chained checkpoint; and
- the originating reserve pair-scope record and deployment evidence hashes.

The combined result may classify proxy and clone state only within the observed
cutoff-bound evidence. Nonstandard mechanisms remain `unknown`; provider errors,
disagreement, missing required reads, reorg/hash mismatch, or authorization
escape remain blocking errors.

## Prohibited shortcuts

- no guessed implementation or beacon address;
- no wildcard address or method scope;
- no current-state read substituted for a cutoff-state read;
- no single-provider promotion;
- no conversion of acquisition errors to `unknown`;
- no selection, qualification, counter, stage-promotion, or Recovery3 authority;
- no mutation of the approved control-selection or dynamic-horizon methods.

## Approval contract

Approval text:

`APPROVE_CUTOFF_STATE_STAGED_DERIVATION_V1_FOR_LOCAL_TEST_ONLY`

Approval authorizes implementation and local-test execution of the staged exact
read mechanics only after all upstream provider-identity, capability, activation,
and signature gates pass. It does not authorize control selection, qualification,
counter changes, Recovery3 mutation, independent adjudication, R5, release, or
publication claims.

The exact approval was received from user principal `zmzubraj` on 2026-08-22
and is recorded without inflating its identity assurance at
`02_Executable_Artifact/reports/stage2_controls/2026-08-22/local-test-staged-derivation-approval-v1/staged_derivation_user_approval.json`.
