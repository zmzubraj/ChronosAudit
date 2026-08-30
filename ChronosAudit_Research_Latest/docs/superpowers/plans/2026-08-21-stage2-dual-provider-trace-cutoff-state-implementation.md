# ChronosAudit Stage 2 Dual-Provider Trace and Cutoff-State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify the additive, fail-closed pipeline that can acquire dual-provider deployment traces and cutoff-safe state/provenance evidence, generate the frozen pair features, and hand a deterministic 417-by-10 cohort into the existing eight-check qualification boundary without prematurely changing the canonical `0/4,170` counters.

**Architecture:** Add a new trace/state capability and activation boundary beside the receipt-only v1 history, then implement resumable trace and cutoff-state acquisition packages. Reuse the existing strict historical snapshot, pair-covariate import, `DYNAMIC_HORIZON_V1`, global no-reuse allocation, qualification-evidence, approval, and counter authorities. Every network method and target is hash-bound; every partial result remains non-authorizing.

**Tech Stack:** Python 3, standard library, pandas, pytest, OpenSSH detached signatures, existing ChronosAudit public-acquisition modules and CLIs.

**Spec:** `docs/superpowers/specs/2026-08-21-stage2-dual-provider-trace-cutoff-state-design.md`

## Global Constraints

- Preserve `CONTINUE_HERE.md` as the sole current human-readable authority and preserve Recovery3/history without mutation.
- Preserve the receipt-only activation, acquisition ledger, and checkpoint as immutable historical inputs. New contracts use new schema versions and signature namespaces.
- Do not execute any RPC until Tasks 1-6 pass locally and a separately signed exact-scope activation verifies.
- Never expose the local-test private key. Its signatures prove mechanical payload integrity only and cannot establish provider independence, human review, scientific qualification, stage promotion, or counter authority.
- Require two verified provider identities from distinct operator families for decision-bearing trace and cutoff-state evidence.
- Normalize legitimate unavailable cutoff-safe protocol/proxy/complexity values to lower-case `unknown` and unestablished historical source verification to `false`. An acquisition error is not an unavailable value, and `unknown` versus `unknown` never proves separation.
- Do not inspect outcomes before cohort freeze. Do not replace a selected control after outcome, maturity, censoring, or mechanism evidence is inspected.
- The pipeline may prepare and mechanically verify qualification inputs. It cannot manufacture the accountable human maturity, censoring, mechanism-separation, outcome-review, or approval evidence required to complete 4,170/4,170.
- Use `./.venv/bin/python -m pytest` for tests. Stage and commit only the exact files named in each task; do not absorb unrelated dirty-worktree changes.

---

## Task 1: Canonical transaction- and block-trace adapters

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/deployment_stream.py`
- Modify: `02_Executable_Artifact/tests/test_deployment_stream_full.py`

**Contract:** Both Parity/OpenEthereum and Geth call-tracer responses must normalize to the same semantic creation key: `(transaction_hash, contract_address, creation_type, creator_address, trace_address)`. Transaction-level tracing is preferred; block-level fallback is explicit. Provider response hashes remain evidence metadata and do not affect semantic agreement.

- [ ] Add failing cross-backend transaction fixtures.

```python
def test_transaction_trace_backends_normalize_to_same_creation_set():
    parity = creations_from_parity_traces(
        "ethereum", 10, BH,
        [{"type": "create", "transactionHash": TX, "traceAddress": [0],
          "action": {"from": CREATOR, "creationMethod": "create2"},
          "result": {"address": ADDR}}],
    )
    geth = creations_from_geth_calltracer(
        "ethereum", 10, BH,
        [{"txHash": TX, "result": {"type": "CALL", "calls": [
            {"type": "CREATE2", "from": CREATOR, "to": ADDR}
        ]}}],
    )
    assert canonical_creation_set(parity) == canonical_creation_set(geth)

def test_trace_backend_prefers_transaction_scope():
    method, rows, _, error = trace_transaction_backend(
        TraceProvider("a", "quicknode", "parity"), TX
    )
    assert method == "trace_transaction"
    assert rows and error is None
```

- [ ] Run the focused tests and confirm the new imports/functions fail.

Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_deployment_stream_full.py -q`

Expected: FAIL with missing `canonical_creation_set` and `trace_transaction_backend`.

- [ ] Implement the minimal canonical adapter API.

```python
CreationKey = tuple[str, str, str, str | None, str]

def canonical_creation_set(records: Iterable[DeploymentRecord]) -> tuple[CreationKey, ...]:
    return tuple(sorted({
        (row.transaction_hash, row.contract_address, row.creation_type,
         row.creator_address, row.trace_address)
        for row in records
    }))

def trace_transaction_backend(provider: JsonRpcProvider, tx_hash: str):
    parity = provider.call("trace_transaction", [tx_hash])
    if parity.error is None and isinstance(parity.result, list):
        return "trace_transaction", parity.result, parity.response_sha256, None
    geth = provider.call(
        "debug_traceTransaction", [tx_hash, {"tracer": "callTracer", "timeout": "120s"}]
    )
    if geth.error is None and isinstance(geth.result, dict):
        return "debug_traceTransaction_callTracer", geth.result, geth.response_sha256, None
    return None, None, None, {
        "trace_transaction": parity.error,
        "debug_traceTransaction": geth.error,
    }
```

- [ ] Update `collect_block_deployments` to compare `canonical_creation_set(...)`, require the candidate address to be present, and use block tracing only when the activated caller requests fallback.
- [ ] Add tests for recursive CREATE/CREATE2, missing address, incomplete frame, block mismatch, same-family providers, semantic disagreement, stable sorting, and deterministic evidence hashes.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_deployment_stream_full.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/deployment_stream.py 02_Executable_Artifact/tests/test_deployment_stream_full.py
git commit -m "feat: normalize Stage 2 deployment traces"
```

## Task 2: Non-authorizing trace/state capability preflight

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_state_capability.py`
- Create: `02_Executable_Artifact/tests/test_control_trace_state_capability.py`
- Create: `02_Executable_Artifact/preflight_stage2_control_trace_state_capability.py`

**Contract:** Probe only frozen fixtures. Emit raw request/response envelopes, one canonical summary, and a verifier report. A trace method is capable only when a known internal-creation fixture is recovered. Capability does not authorize later calls.

- [ ] Add failing tests for the capability assessment.

```python
def test_capability_requires_two_families_and_known_creation(tmp_path):
    result = assess_trace_state_capability(
        fixtures=[fixture("ethereum", block=10, tx_hash=TX, created_address=ADDR)],
        providers=[provider("p1", "family-a"), provider("p2", "family-b")],
        raw_root=tmp_path / "raw",
    )
    assert result["complete"] is True
    assert result["selection_authorized"] is False
    assert result["stage_promotion_authorized"] is False
    assert result["chains"][0]["known_creation_recovered_by_both"] is True

def test_empty_trace_does_not_establish_capability(tmp_path):
    with pytest.raises(ControlTraceStateCapabilityError, match="known_creation_missing"):
        assess_trace_state_capability(
            fixtures=[fixture("ethereum", 10, TX, ADDR)],
            providers=[empty_trace_provider("p1", "family-a"),
                       empty_trace_provider("p2", "family-b")],
            raw_root=tmp_path / "raw",
        )
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_trace_state_capability.py -q`
- [ ] Expected: FAIL because the module does not exist.
- [ ] Implement the versioned interface and method matrix.

```python
SCHEMA_VERSION = "stage2_control_trace_state_capability.v1"
REQUIRED_METHODS = (
    "eth_chainId", "eth_getBlockByHash", "eth_getBlockByNumber",
    "eth_getTransactionReceipt", "eth_getCode", "eth_getStorageAt",
)
TRACE_METHODS = (
    "trace_transaction", "debug_traceTransaction",
    "trace_block", "debug_traceBlockByNumber",
)

class ControlTraceStateCapabilityError(ValueError):
    pass

def assess_trace_state_capability(*, fixtures, providers, raw_root: Path) -> dict[str, object]:
    """Return a self-hashed, non-authorizing capability report."""

def verify_trace_state_capability(*, report_path: Path, raw_root: Path,
                                  provider_registry_path: Path) -> dict[str, object]:
    """Re-hash envelopes and prove two-family fixture recovery."""
```

- [ ] Store each JSON-RPC request and response in an ordinary file below `raw_root`, bind method/params/provider/chain/timestamp/status/hash, and reject symlinks or path escape.
- [ ] Add CLI arguments for provider registry, verified provider-identity report, frozen fixture JSON, raw root, report output, and verifier output. The CLI must not accept selection or qualification outputs.
- [ ] Add tests for chain mismatch, historical block mismatch, missing raw envelope, tampered envelope, same-family providers, unsupported state method, beacon-call conditionality, post-run self-hash change, and all authority flags fixed to false.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_trace_state_capability.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_state_capability.py 02_Executable_Artifact/tests/test_control_trace_state_capability.py 02_Executable_Artifact/preflight_stage2_control_trace_state_capability.py
git commit -m "feat: add trace state capability preflight"
```

## Task 3: Exact-scope trace/state activation and signature verification

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_state_activation.py`
- Create: `02_Executable_Artifact/tests/test_control_trace_state_activation.py`
- Create: `02_Executable_Artifact/build_stage2_control_trace_state_activation_request.py`
- Create: `02_Executable_Artifact/build_stage2_control_trace_state_activation_approval.py`
- Create: `02_Executable_Artifact/verify_stage2_control_trace_state_activation.py`

**Contract:** Bind exact providers, operator families, methods, targets, pair-scope hashes, time window, retry limits, and deterministic request ceiling. Preserve `selection_authorized=false`, `stage_promotion_authorized=false`, and `recovery3_mutation_authorized=false` as schema invariants.

- [ ] Add failing tests for scope and signature boundaries.

```python
def test_activation_binds_exact_targets_and_false_authority_flags(tmp_path):
    request = build_trace_state_activation_request(
        capability_report=capability_path,
        trace_targets=trace_targets_path,
        state_targets=state_targets_path,
        starts_at="2026-08-21T00:00:00Z",
        expires_at="2026-08-22T00:00:00Z",
        retry_limit=2,
    )
    assert request["selection_authorized"] is False
    assert request["stage_promotion_authorized"] is False
    assert request["recovery3_mutation_authorized"] is False
    assert request["maximum_request_count"] == expected_request_ceiling(request)

def test_activation_rejects_unlisted_method(signed_activation):
    with pytest.raises(ControlTraceStateActivationError, match="method_not_activated"):
        authorize_rpc_call(signed_activation, "p1", "eth_getLogs", ["0x0"])
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_trace_state_activation.py -q`
- [ ] Expected: FAIL because the activation module does not exist.
- [ ] Implement the contract and namespaces.

```python
REQUEST_SCHEMA = "stage2_control_trace_state_activation_request.v1"
APPROVAL_SCHEMA = "stage2_control_trace_state_activation_approval.v1"
SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-trace-state-activation-v1"
ALLOWED_METHODS = frozenset({
    "eth_chainId", "eth_getBlockByHash", "eth_getBlockByNumber",
    "eth_getTransactionReceipt", "trace_transaction",
    "debug_traceTransaction", "trace_block", "debug_traceBlockByNumber",
    "eth_getCode", "eth_getStorageAt", "eth_call",
})

def expected_request_ceiling(request: Mapping[str, object]) -> int:
    trace_calls = sum(int(row["provider_count"]) for row in request["trace_targets"])
    state_calls = sum(int(row["provider_count"]) * int(row["method_count"])
                      for row in request["state_targets"])
    retries = int(request["retry_limit"])
    return (trace_calls + state_calls) * (1 + retries)
```

- [ ] Reuse the existing canonical JSON, ordinary-file, time, provider-identity, and `ssh-keygen -Y verify` patterns without importing private-key material into the case.
- [ ] `authorize_rpc_call` must match provider, chain, method, normalized params, target identifier, activation time, sequence number, and remaining request budget before transport.
- [ ] Add tests for tampered capability hash, stale pair-scope hash, provider substitution, operator-family collapse, target/path escape, transaction/block/address escape, expired time, ceiling exhaustion, retry overflow, replayed sequence, wrong public key, wrong namespace, local-test authority overclaim, and changed false flags.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_trace_state_activation.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_state_activation.py 02_Executable_Artifact/tests/test_control_trace_state_activation.py 02_Executable_Artifact/build_stage2_control_trace_state_activation_request.py 02_Executable_Artifact/build_stage2_control_trace_state_activation_approval.py 02_Executable_Artifact/verify_stage2_control_trace_state_activation.py
git commit -m "feat: bind exact trace state RPC authority"
```

## Task 4: Resumable dual-provider trace acquisition

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_acquisition.py`
- Create: `02_Executable_Artifact/tests/test_control_trace_acquisition.py`
- Create: `02_Executable_Artifact/run_stage2_control_trace_acquisition.py`

**Contract:** Consume only a verified activation and the frozen 558-row unresolved trace set. Prefer transaction tracing and use block fallback only when explicitly activated. Append raw envelopes and hash-chained events; resume only after revalidating completed record hashes.

- [ ] Add the failing happy-path and resume tests.

```python
def test_trace_acquisition_requires_cross_family_semantic_agreement(tmp_path):
    result = execute_control_trace_acquisition(
        activation=verified_activation,
        unresolved_trace_path=trace_targets,
        output_root=tmp_path,
        transport=fixture_transport(parity_creation=ADDR, geth_creation=ADDR),
    )
    assert result["status"] == "COMPLETE"
    assert result["completed_target_count"] == 1
    assert result["selection_authorized"] is False

def test_resume_rehashes_completed_trace_before_skip(tmp_path):
    first = run_one_trace(tmp_path)
    tamper(Path(first["normalized_results_path"]))
    with pytest.raises(ControlTraceAcquisitionError, match="resume_hash_mismatch"):
        resume_trace_acquisition(first["checkpoint_path"], transport=no_calls_allowed())
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_trace_acquisition.py -q`
- [ ] Expected: FAIL because the module does not exist.
- [ ] Implement the additive event/checkpoint contract.

```python
TRACE_RUN_SCHEMA = "stage2_control_trace_acquisition_run.v1"
TRACE_EVENT_SCHEMA = "stage2_control_trace_acquisition_event.v1"
TRACE_CHECKPOINT_SCHEMA = "stage2_control_trace_acquisition_checkpoint.v1"
CHECKPOINT_NAMESPACE = "chronosaudit-stage2-control-trace-acquisition-local-test-v1"

@dataclass(frozen=True)
class TraceTarget:
    case_id: str
    chain: str
    chain_address: str
    transaction_hash: str
    block_number: int
    block_hash: str
    reserve_record_sha256: str

def execute_control_trace_acquisition(*, activation, unresolved_trace_path: Path,
                                      output_root: Path, transport) -> dict[str, object]:
    """Append authorized calls/events and emit non-authorizing normalized results."""
```

- [ ] Each event binds previous event hash, sequence, activation hash, provider identity, target hash, method, params hash, request/response envelope hashes, normalized creation-set hash, disposition, and event hash.
- [ ] Terminal dispositions are: `complete`, `candidate_missing`, `trace_disagreement`, `block_mismatch`, `method_unsupported`, `malformed_response`, `retry_exhausted`, `activation_expired`, and `budget_exhausted`. Only `complete` advances a target.
- [ ] Enforce target count/hash equality with the activation, two distinct verified families, complete semantic-set equality, candidate presence, and unchanged block identity.
- [ ] Add CLI support for new run and resume. It must verify activation before constructing transport and must print only paths, counts, hashes, and dispositions—never credentials.
- [ ] Add tests for transaction preference, activated block fallback, unactivated fallback rejection, malformed nested frame, missing candidate, disagreement, same family, checkpoint tampering, ledger deletion/reorder, idempotent resume, bounded retry, expiry, and request ceiling.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_trace_acquisition.py tests/test_deployment_stream_full.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_acquisition.py 02_Executable_Artifact/tests/test_control_trace_acquisition.py 02_Executable_Artifact/run_stage2_control_trace_acquisition.py
git commit -m "feat: acquire dual provider control traces"
```

## Task 5: Dual-provider cutoff block and historical state acquisition

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_cutoff_state_acquisition.py`
- Create: `02_Executable_Artifact/tests/test_control_cutoff_state_acquisition.py`
- Create: `02_Executable_Artifact/run_stage2_control_cutoff_state_acquisition.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/onchain.py`
- Modify: `02_Executable_Artifact/tests/test_onchain.py`

**Contract:** For every deployment-complete pair target, resolve the last canonical block at or before its frozen covariate cutoff and acquire agreed historical code/proxy/clone state. Reuse `historical_identity_snapshot`; prefer EIP-1898 and reconcile numeric tags to the agreed hash.

- [ ] Add failing tests for cutoff bracketing and proxy reconstruction.

```python
def test_cutoff_state_uses_last_block_not_after_cutoff(tmp_path):
    result = acquire_cutoff_state(
        target=state_target(cutoff="2020-01-01T00:00:10Z"),
        providers=[state_provider("p1", "family-a"), state_provider("p2", "family-b")],
        raw_root=tmp_path / "raw",
    )
    assert result["evidence_block_timestamp"] <= result["cutoff_timestamp"]
    assert result["next_block_timestamp"] > result["cutoff_timestamp"]
    assert result["provider_agreement"] is True

def test_eip1967_and_eip1167_are_cutoff_block_bound(tmp_path):
    result = acquire_cutoff_state(
        target=state_target(address=PROXY), providers=proxy_providers(),
        raw_root=tmp_path / "raw",
    )
    assert result["proxy_status"] == "proxy"
    assert result["implementation_address"] == IMPLEMENTATION
    assert result["implementation_code_hash"] == IMPLEMENTATION_CODE_HASH
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_cutoff_state_acquisition.py tests/test_onchain.py -q`
- [ ] Expected: FAIL because the acquisition module does not exist or cutoff binding is incomplete.
- [ ] Implement the target/result interface.

```python
STATE_RUN_SCHEMA = "stage2_control_cutoff_state_acquisition_run.v1"
STATE_RESULT_SCHEMA = "stage2_control_cutoff_state_result.v1"

@dataclass(frozen=True)
class CutoffStateTarget:
    case_id: str
    chain: str
    chain_address: str
    cutoff_timestamp: str
    pair_scope_record_sha256: str
    denominator_record_sha256: str
    deployment_result_sha256: str

def acquire_cutoff_state(*, target: CutoffStateTarget, providers,
                         raw_root: Path) -> dict[str, object]:
    """Resolve the historical block and emit an agreed semantic state projection."""
```

- [ ] Extend `historical_identity_snapshot` only where needed to return raw observation hashes and explicit `observable`, `unavailable`, or `error` status per field. Do not collapse `error` to `unknown`.
- [ ] Bind code size/hash, EIP-1967 implementation/beacon/admin, beacon implementation call, EIP-1167 target, implementation code/hash, proxy status/family, normalized identity/clone family, exact block number/hash/timestamp, next-block bracket, and every raw evidence hash.
- [ ] Implement the same append-only event/checkpoint/resume rules as Task 4 under a distinct schema and signature namespace.
- [ ] Add tests for EIP-1898 success, numeric-tag hash reconciliation, reorg/hash mismatch, code disagreement, storage disagreement, beacon-call disagreement, implementation-code disagreement, nonstandard proxy `unknown`, genuine unavailable data, provider error, source path escape, same-family providers, resume tampering, and deterministic self-hash.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_cutoff_state_acquisition.py tests/test_onchain.py tests/test_public_acquisition_strict_snapshot.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_cutoff_state_acquisition.py 02_Executable_Artifact/tests/test_control_cutoff_state_acquisition.py 02_Executable_Artifact/run_stage2_control_cutoff_state_acquisition.py 02_Executable_Artifact/src/chronosaudit_stage2/onchain.py 02_Executable_Artifact/tests/test_onchain.py
git commit -m "feat: acquire cutoff safe control state"
```

## Task 6: Cutoff-safe provenance and pair-feature projection

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_pair_feature_projection.py`
- Create: `02_Executable_Artifact/tests/test_control_pair_feature_projection.py`
- Create: `02_Executable_Artifact/build_stage2_control_pair_features.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_pair_covariate_import.py`
- Modify: `02_Executable_Artifact/tests/test_control_pair_covariate_import.py`

**Contract:** Combine verified pair scope, denominator row, trace result, cutoff state, historical source record, and cutoff-safe protocol record into the existing pair-covariate schema and the pair-feature input consumed by `DYNAMIC_HORIZON_V1`.

- [ ] Add failing normalization and cutoff tests.

```python
def test_unavailable_fields_use_explicit_categories(tmp_path):
    row = build_pair_feature(
        pair_scope=pair_scope(), denominator=denominator(), trace=trace_result(),
        state=state_result(proxy_status="unavailable"),
        source=None, protocol=None,
    )
    assert row["proxy_status"] == "unknown"
    assert row["protocol_family"] == "unknown"
    assert row["complexity_class"] == "unknown"
    assert row["source_verified_at_cutoff"] is False

def test_post_cutoff_source_record_is_not_accepted():
    with pytest.raises(ControlPairFeatureProjectionError, match="source_after_cutoff"):
        build_pair_feature(source=source_record(verified_at="2021-01-01T00:00:00Z"),
                           **pair_inputs(cutoff="2020-01-01T00:00:00Z"))
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_pair_feature_projection.py tests/test_control_pair_covariate_import.py -q`
- [ ] Expected: FAIL because the projection module does not exist.
- [ ] Implement the projection API and provenance statuses.

```python
PAIR_FEATURE_SCHEMA = "stage2_control_pair_feature.v1"

class ControlPairFeatureProjectionError(ValueError):
    pass

def normalize_cutoff_category(value: object, *, status: str) -> str:
    if status == "unavailable":
        return "unknown"
    if status != "observed":
        raise ControlPairFeatureProjectionError("acquisition_error_not_category")
    normalized = str(value).strip().lower()
    return normalized or "unknown"

def build_pair_feature(*, pair_scope, denominator, trace, state,
                       source, protocol) -> dict[str, object]:
    """Build one self-hashed cutoff-safe pair feature with full upstream binding."""
```

- [ ] Require the source record to prove verification time `<= cutoff`; otherwise set false only when no qualifying record exists. Require protocol evidence timestamps and content validity `<= cutoff`; do not use current labels.
- [ ] Derive complexity only from the frozen `DYNAMIC_HORIZON_V1` mapping. Bind the exact mapping/spec hash.
- [ ] Extend pair-covariate import verification to require trace/state/source/protocol raw evidence hashes and their manifests, while preserving backward verification for historical schemas.
- [ ] Emit deterministic CSV plus manifest with record count, case coverage, status counts, exclusion/error lists, upstream hashes, and self-hash.
- [ ] Add tests for unknown-vs-unknown non-separation, false source default, post-cutoff protocol rejection, current-only Sourcify rejection, evidence-hash substitution, duplicate pair, denominator mismatch, pair-scope mismatch, raw path escape, stable ordering, and deterministic CSV hash.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_pair_feature_projection.py tests/test_control_pair_covariate_import.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_pair_feature_projection.py 02_Executable_Artifact/tests/test_control_pair_feature_projection.py 02_Executable_Artifact/build_stage2_control_pair_features.py 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_pair_covariate_import.py 02_Executable_Artifact/tests/test_control_pair_covariate_import.py
git commit -m "feat: project cutoff safe control pair features"
```

## Task 7: Final `DYNAMIC_HORIZON_V1` package integration

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_dynamic_horizon.py`
- Modify: `02_Executable_Artifact/tests/test_control_dynamic_horizon.py`
- Modify: `02_Executable_Artifact/build_stage2_control_dynamic_horizon.py`
- Modify: `02_Executable_Artifact/verify_stage2_control_dynamic_horizon.py`

**Contract:** Accept only the verified final pair-feature projection and rebuild the complete eight-artifact horizon package. The package remains non-authorizing until its separate author signature verifies.

- [ ] Add a failing end-to-end package-binding test.

```python
def test_final_horizon_package_binds_pair_feature_manifest(tmp_path):
    package = build_dynamic_horizon_package(
        pair_features_path=FINAL_PAIR_FEATURES,
        pair_feature_manifest_path=FINAL_PAIR_MANIFEST,
        output_root=tmp_path,
    )
    report = verify_dynamic_horizon_artifacts(package["manifest_path"])
    assert report["complete"] is True
    assert report["pair_feature_manifest_sha256"] == sha256(FINAL_PAIR_MANIFEST)
    assert len(report["artifact_sha256s"]) == 8
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_dynamic_horizon.py -q`
- [ ] Expected: FAIL because final pair-feature manifest binding is not enforced.
- [ ] Add `pair_feature_manifest_sha256` and trace/state/provenance upstream hashes to the package manifest and approval payload. Verify exact case/pair coverage and cutoff-safe field set before fitting.
- [ ] Preserve the current model specification, frozen variables, missingness handling, fit rule, and assignment rule. Do not refit based on allocation success or outcomes.
- [ ] Add tests for stale pair manifest, changed row order, missing case, duplicate pair, forbidden post-outcome column, unknown category handling, artifact deletion, unsigned package, wrong author namespace, and deterministic rebuild.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_dynamic_horizon.py tests/test_control_pair_feature_projection.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_dynamic_horizon.py 02_Executable_Artifact/tests/test_control_dynamic_horizon.py 02_Executable_Artifact/build_stage2_control_dynamic_horizon.py 02_Executable_Artifact/verify_stage2_control_dynamic_horizon.py
git commit -m "feat: bind final control horizon package"
```

## Task 8: Deterministic global 417-by-10 selection and freeze boundary

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/qualification.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_pair_scope.py`
- Modify: `02_Executable_Artifact/tests/test_public_acquisition_qualification.py`
- Modify: `02_Executable_Artifact/tests/test_control_pair_scope.py`
- Create: `02_Executable_Artifact/tests/test_control_selection_freeze.py`

**Contract:** Merge original eligible rows and verified reserve rows, apply frozen exact/caliper rules, and run one deterministic global maximum-cardinality allocation with chain-address capacity one. Emit either an exact 4,170-row frozen cohort or a verified shortfall; never emit a partial selected cohort.

- [ ] Add failing exact-structure and no-replacement tests.

```python
def test_selection_is_exact_global_no_reuse_or_no_cohort(tmp_path):
    result = build_frozen_control_cohort(
        cases=cases_417(), candidates=feasible_candidates_4170(),
        horizon_manifest=verified_horizon_manifest(), output_root=tmp_path,
    )
    assert result["status"] == "FROZEN_COMPLETE"
    cohort = pd.read_csv(result["cohort_path"])
    assert len(cohort) == 4170
    assert cohort.groupby("case_id").size().eq(10).all()
    assert cohort["chain_address"].nunique() == 4170

def test_frozen_candidate_cannot_be_replaced_after_outcome_review(tmp_path):
    frozen = freeze_one_case(tmp_path)
    with pytest.raises(ControlQualificationError, match="post_freeze_replacement_forbidden"):
        replace_frozen_candidate(frozen, failed_rank=3, replacement=reserve_row())
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_selection_freeze.py tests/test_public_acquisition_qualification.py tests/test_control_pair_scope.py -q`
- [ ] Expected: FAIL because the freeze API and explicit no-replacement guard do not exist.
- [ ] Implement the integration API.

```python
def build_frozen_control_cohort(*, cases: pd.DataFrame, candidates: pd.DataFrame,
                                horizon_manifest: Mapping[str, object],
                                output_root: Path) -> dict[str, object]:
    """Return FROZEN_COMPLETE with 4,170 rows or VERIFIED_SHORTFALL with no cohort."""

def replace_frozen_candidate(*args, **kwargs):
    raise ControlQualificationError("post_freeze_replacement_forbidden")
```

- [ ] Enforce `REFERENCE_IDENTITY_DEDUP_V1`: one row per chain-address, earliest frozen risk-entry, first qualifying incident strictly afterward, earliest case ID tie-break. Exclude positive identities and forbidden lineage/clone/proxy/protocol/mechanism links before allocation.
- [ ] Bind the cohort to policy, queue, denominator, pair scope, pair-feature, horizon, positive authority, and allocation/min-cut audit hashes. Freeze ranks 1-10 and candidate hashes.
- [ ] Add tests for deterministic tie-break, positive-address exclusion, identity reuse, clone/proxy/protocol unknown-vs-unknown, insufficient maximum flow, partial cohort suppression, rank gap, output tampering, changed candidate order, and outcome-column leakage.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_selection_freeze.py tests/test_public_acquisition_qualification.py tests/test_control_pair_scope.py tests/test_control_matching.py -q`
- [ ] Expected: PASS.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/qualification.py 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_pair_scope.py 02_Executable_Artifact/tests/test_public_acquisition_qualification.py 02_Executable_Artifact/tests/test_control_pair_scope.py 02_Executable_Artifact/tests/test_control_selection_freeze.py
git commit -m "feat: freeze global Stage 2 control cohort"
```

## Task 9: Eight-check qualification and counter closure safeguards

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_qualification_evidence.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_qualification_approval.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_qualification_bundle.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/counters.py`
- Modify: `02_Executable_Artifact/tests/test_control_qualification_evidence.py`
- Modify: `02_Executable_Artifact/tests/test_control_qualification_approval.py`
- Create: `02_Executable_Artifact/tests/test_control_qualification_closure.py`
- Modify: `02_Executable_Artifact/tests/test_public_acquisition_counters.py`

**Contract:** Every frozen candidate needs eight candidate-hash-bound evidence records. Maturity, censoring, and mechanism separation require the mandated accountable human review. Evidence reviewer, outcome reviewer, and approval authority must satisfy frozen ownership/conflict rules. Only a complete, independently approved 4,170-row projection may update the canonical counter.

- [ ] Add failing closure tests.

```python
CHECKS = {
    "maturity", "censoring", "temporal", "lineage",
    "clone", "proxy", "protocol", "mechanism_separation",
}

def test_each_candidate_requires_exactly_eight_hash_bound_checks():
    report = verify_control_qualification_bundle(bundle_missing("mechanism_separation"))
    assert report["complete"] is False
    assert report["qualified_control_count"] == 0
    assert "mechanism_separation_missing" in report["errors"]

def test_local_test_signature_cannot_satisfy_human_review():
    with pytest.raises(ControlQualificationApprovalError, match="human_authority_required"):
        verify_control_qualification_approval(local_test_only_approval())

def test_partial_bundle_cannot_increment_canonical_counter():
    counter = project_stage2_counters(partial_qualification_bundle(4169))
    assert counter["selected_controls"] == 0
    assert counter["qualified_controls"] == 0
```

- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_qualification_closure.py tests/test_control_qualification_evidence.py tests/test_control_qualification_approval.py tests/test_public_acquisition_counters.py -q`
- [ ] Expected: FAIL until exact eight-check and authority closure are enforced end to end.
- [ ] Enforce exact check names, one final disposition per check, candidate/cohort hash binding, ordinary evidence files, reviewer identity/type, review timestamp, independence basis, and no conflicting supersession.
- [ ] Reject `unknown` as a passing separation proof, especially `unknown` versus `unknown`. Reject caller-supplied booleans without evidence records.
- [ ] Require accountable human reviewer type for maturity, censoring, mechanism separation, and outcome review. Require distinct approval authority and the existing conflict-separation rules.
- [ ] In `counters.py`, accept selected/qualified completion only from the canonical frozen cohort, complete evidence bundle, verified accountable approval, and exact 417-by-10 qualified structure. Incomplete or local-test-only artifacts must project zero canonical controls.
- [ ] Add tests for duplicate check, missing check, wrong candidate hash, same-owner review, conflicted reviewer, stale evidence, post-freeze replacement, unsigned approval, wrong namespace, 4,169 rows, 4,170 rows with duplicate address, rank gap, case gap, caller counter injection, and exact valid fixture closure.
- [ ] Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest tests/test_control_qualification_closure.py tests/test_control_qualification_evidence.py tests/test_control_qualification_approval.py tests/test_public_acquisition_counters.py -q`
- [ ] Expected: PASS. The valid fixture proves mechanics only; it does not claim real human review.
- [ ] Commit:

```bash
git add 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_qualification_evidence.py 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_qualification_approval.py 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_qualification_bundle.py 02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/counters.py 02_Executable_Artifact/tests/test_control_qualification_evidence.py 02_Executable_Artifact/tests/test_control_qualification_approval.py 02_Executable_Artifact/tests/test_control_qualification_closure.py 02_Executable_Artifact/tests/test_public_acquisition_counters.py
git commit -m "test: enforce Stage 2 control qualification closure"
```

## Task 10: Integrated regression and execution runbook

**Files:**
- Modify: `02_Executable_Artifact/README.md`
- Modify: `03_Research_Reports/Stage2_Control_Prespecification_and_Preflight.md`
- Modify: `03_Research_Reports/Stage2_Live_Execution_Runbook.md`
- Modify only after fresh verification: `CONTINUE_HERE.md`
- Modify only after fresh verification: `03_Research_Reports/Scientific_Gate_Status.csv`

**Contract:** Document the exact offline-to-live sequence, authority boundaries, resume commands, expected artifacts, and counter rules. Update current authority/status only from freshly verified canonical artifacts—not from test fixtures, local signatures, or partial checkpoints.

- [ ] Run the complete targeted regression before editing authority docs.

```bash
cd 02_Executable_Artifact
./.venv/bin/python -m pytest \
  tests/test_deployment_stream_full.py \
  tests/test_onchain.py \
  tests/test_public_acquisition_strict_snapshot.py \
  tests/test_control_trace_state_capability.py \
  tests/test_control_trace_state_activation.py \
  tests/test_control_trace_acquisition.py \
  tests/test_control_cutoff_state_acquisition.py \
  tests/test_control_pair_feature_projection.py \
  tests/test_control_pair_covariate_import.py \
  tests/test_control_dynamic_horizon.py \
  tests/test_control_pair_scope.py \
  tests/test_control_selection_freeze.py \
  tests/test_public_acquisition_qualification.py \
  tests/test_control_qualification_evidence.py \
  tests/test_control_qualification_approval.py \
  tests/test_control_qualification_closure.py \
  tests/test_public_acquisition_counters.py -q
```

Expected: all selected tests PASS.

- [ ] Run the full executable-artifact suite.

Run: `cd 02_Executable_Artifact && ./.venv/bin/python -m pytest -q`

Expected: PASS, or document every pre-existing unrelated failure with command, test name, and evidence that it predates this change. Do not claim full-suite pass otherwise.

- [ ] Run canonical production qualification and signature/counter verification using the repository's current documented commands. Confirm that tests alone leave canonical controls at `0/4,170`.
- [ ] Update the runbook with this exact gated order:
  1. verify frozen authorities and current checkpoint;
  2. run capability preflight without authorization;
  3. review capability evidence and provider identity;
  4. build, sign, and verify exact-scope activation;
  5. run/resume trace acquisition;
  6. run/resume cutoff-state acquisition;
  7. build and verify pair features/import;
  8. rebuild, sign, and verify the final horizon package;
  9. build/freeze the deterministic global cohort;
  10. obtain eight-check accountable human evidence and independent approval;
  11. project and verify canonical counters.
- [ ] Include stop conditions for unsupported provider methods, missing archive state, provider-family collapse, trace/state disagreement, activation expiry, request exhaustion, short allocation, incomplete human evidence, and failed approval.
- [ ] If capability preflight reveals missing provider credentials or unsupported methods, stop and record a reviewed provider-replacement requirement. Do not borrow another credential or expand scope.
- [ ] Only after a real run produces new verified canonical artifacts, update `CONTINUE_HERE.md` and `Scientific_Gate_Status.csv` with exact artifact paths, hashes, signatures, counts, authority limits, and remaining blockers. If no real run occurs, preserve their current `0/4,170` values.
- [ ] Run documentation consistency checks.

```bash
rg -n "0/4,170|4,170/4,170|selected controls|qualified controls|Recovery3|local-test" \
  CONTINUE_HERE.md 02_Executable_Artifact/README.md \
  03_Research_Reports/Stage2_Control_Prespecification_and_Preflight.md \
  03_Research_Reports/Stage2_Live_Execution_Runbook.md \
  03_Research_Reports/Scientific_Gate_Status.csv
git diff --check
```

Expected: counters agree with canonical verification; no whitespace errors.

- [ ] Commit only verified documentation/status changes.

```bash
git add 02_Executable_Artifact/README.md 03_Research_Reports/Stage2_Control_Prespecification_and_Preflight.md 03_Research_Reports/Stage2_Live_Execution_Runbook.md
git add CONTINUE_HERE.md 03_Research_Reports/Scientific_Gate_Status.csv
git commit -m "docs: add Stage 2 trace state execution gates"
```

## Final Acceptance Gate

- [ ] All new and affected tests pass with fresh output.
- [ ] Capability report proves the required methods on known historical fixtures for two distinct verified operator families.
- [ ] Exact-scope activation has a valid detached signature and all non-RPC authority flags remain false.
- [ ] All 558 trace-required rows either have verified cross-provider trace agreement or remain explicitly blocked; no unresolved row is silently normalized.
- [ ] Every pair admitted downstream has agreed cutoff block/state and cutoff-safe source/protocol provenance.
- [ ] The final horizon package is complete, deterministic, and separately signed.
- [ ] Selection emits either exactly 4,170 unique ranked controls across 417 cases or no cohort plus a verified shortfall.
- [ ] Qualification emits a positive canonical counter only after all eight checks, required human reviews, ownership separation, and accountable approval verify for every frozen candidate.
- [ ] The canonical status report, counter artifact, signatures, and hashes agree. Until then, report controls as `0/4,170` and the goal as incomplete/blocked at the earliest unmet evidence gate.
