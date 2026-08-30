# Stage 2 Trace Retry Overlay V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and locally verify the no-replay retry-target and provenance-overlay path for the frozen 1,768-target Stage 2 trace acquisition while preserving all authority and counter gates.

**Architecture:** A new approval module binds the exact approved design revision. A focused retry-overlay module cryptographically and mechanically reverifies each immutable source root, unions only complete agreeing targets, freezes the unresolved subset, and later constructs one complete provenance overlay from a separately activated retry root. Existing activation, acquisition, and deployment-projection modules gain narrowly typed support for the verified retry and overlay schemas without weakening their original single-root path.

**Tech Stack:** Python 3.11+, standard-library `hashlib`, `json`, `pathlib`, `subprocess`, OpenSSH `ssh-keygen -Y verify`, `pytest`, existing ChronosAudit canonical JSON and atomic-write patterns.

**Spec:** `docs/superpowers/specs/2026-08-25-stage2-trace-retry-overlay-v1-design.md`

## Global Constraints

- Approved specification file SHA-256: `ddc8d91165640469f3d7d5abb883c32d4ed4ac6f717e69150c8eb6c7671e5877`.
- Approval text must equal `APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: ddc8d91165640469f3d7d5abb883c32d4ed4ac6f717e69150c8eb6c7671e5877`.
- Original trace input remains exactly 1,768 targets and 3,536 calls.
- Source roots `control-trace-acquisition-v1`, `control-trace-acquisition-paced-v2`, and `control-trace-acquisition-paced-v3` are immutable inputs.
- All source checkpoint and activation signatures must be cryptographically reverified; stored verification JSON is corroborating evidence only.
- Only dual-provider, cross-family, semantically agreeing `complete` rows may satisfy a target.
- Conflicting complete source rows fail the entire union.
- Retry membership is the exact original target set minus the verified source-complete set, ordered by ascending `target_id`.
- No source-complete target may enter a retry activation or retry acquisition.
- No RPC is authorized by the design approval, approval record, implementation, tests, or retry-target artifact.
- Selection, qualification, counters, stage promotion, Recovery3 mutation, independent review, R5, release, and publication authority remain false throughout this plan.
- Writers are atomic, reject symlink destinations, and refuse to overwrite canonical outputs.
- Preserve compatibility with the existing complete single-root trace-deployment projection.

---

## File Structure

- Create `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_retry_overlay_approval.py`: exact specification-approval construction and reconstruction verification.
- Create `02_Executable_Artifact/build_stage2_control_trace_retry_overlay_approval.py`: atomic approval-record CLI.
- Create `02_Executable_Artifact/verify_stage2_control_trace_retry_overlay_approval.py`: reconstruction-verification CLI.
- Create `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_retry_overlay.py`: immutable-root verification, complete-source union, retry-target construction/verification, and completion-overlay construction/verification.
- Create `02_Executable_Artifact/build_stage2_control_trace_retry_targets.py`: deterministic real/fixture retry-target builder.
- Create `02_Executable_Artifact/verify_stage2_control_trace_retry_targets.py`: independent retry-target reconstruction verifier.
- Create `02_Executable_Artifact/build_stage2_control_trace_completion_overlay.py`: deterministic completion-overlay builder.
- Create `02_Executable_Artifact/verify_stage2_control_trace_completion_overlay.py`: independent completion-overlay reconstruction verifier.
- Modify `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_state_activation.py`: accept only reconstruction-verified retry-target artifacts as trace-only activation input.
- Modify `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_acquisition.py`: execute a verified retry target schema without relaxing ordinary trace-target validation.
- Modify `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_deployment_projection.py`: add mutually exclusive verified-overlay input while retaining the current complete-root interface.
- Modify `02_Executable_Artifact/build_stage2_control_trace_deployment_projection.py`: expose mutually exclusive single-root versus overlay arguments.
- Create `02_Executable_Artifact/tests/test_control_trace_retry_overlay_approval.py`: approval binding and tamper tests.
- Create `02_Executable_Artifact/tests/test_control_trace_retry_overlay.py`: source-root, retry-target, conflict, overlay, and provenance tests.
- Modify `02_Executable_Artifact/tests/test_control_trace_state_activation.py`: exact retry-subset activation and replay rejection tests.
- Modify `02_Executable_Artifact/tests/test_control_trace_acquisition.py`: verified retry-schema execution tests.
- Modify `02_Executable_Artifact/tests/test_control_trace_deployment_projection.py`: overlay compatibility and incomplete-overlay rejection tests.
- Create `02_Executable_Artifact/reports/stage2_controls/2026-08-25/control-trace-retry-overlay-spec-approval-v1/`: exact approval and verification artifacts.
- Create `02_Executable_Artifact/processed/stage2_controls/2026-08-25/control-trace-retry-targets-v1/`: real retry-target and verification artifacts after all local checks pass.
- Modify `CONTINUE_HERE.md`: synchronize verified approval, implementation, retry-subset counts, hashes, and unchanged counters.

---

### Task 1: Exact Written-Spec Approval Record

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_retry_overlay_approval.py`
- Create: `02_Executable_Artifact/build_stage2_control_trace_retry_overlay_approval.py`
- Create: `02_Executable_Artifact/verify_stage2_control_trace_retry_overlay_approval.py`
- Test: `02_Executable_Artifact/tests/test_control_trace_retry_overlay_approval.py`
- Create artifact: `02_Executable_Artifact/reports/stage2_controls/2026-08-25/control-trace-retry-overlay-spec-approval-v1/`

**Interfaces:**
- Consumes: `Path` to the ordinary specification, exact approval text, principal `zmzubraj`, approval date `2026-08-25`, and source label `CODEX_CHAT_EXACT_USER_TOKEN`.
- Produces: `build_trace_retry_overlay_spec_approval(...) -> dict[str, object]` and `verify_trace_retry_overlay_spec_approval(...) -> dict[str, object]`.

- [ ] **Step 1: Write failing approval tests**

```python
def test_approval_rehashes_exact_spec_and_grants_only_implementation(tmp_path: Path):
    spec = tmp_path / "design.md"
    spec.write_bytes(APPROVED_SPEC_BYTES)
    digest = hashlib.sha256(APPROVED_SPEC_BYTES).hexdigest()
    approval = build_trace_retry_overlay_spec_approval(
        specification_path=spec,
        approval_text=f"APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: {digest}",
        approved_by_principal="zmzubraj",
        approved_at_date="2026-08-25",
        approval_source="CODEX_CHAT_EXACT_USER_TOKEN",
    )
    assert approval["specification_file_sha256"] == digest
    assert approval["implementation_authorized"] is True
    assert approval["rpc_authorized"] is False
    assert approval["counter_authority"] is False


def test_approval_rejects_supplied_digest_that_does_not_match_file(tmp_path: Path):
    spec = tmp_path / "design.md"
    spec.write_text("changed", encoding="utf-8")
    with pytest.raises(ControlTraceRetryOverlayApprovalError, match="approved_specification_mismatch"):
        build_trace_retry_overlay_spec_approval(
            specification_path=spec,
            approval_text="APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: " + "0" * 64,
            approved_by_principal="zmzubraj",
            approved_at_date="2026-08-25",
            approval_source="CODEX_CHAT_EXACT_USER_TOKEN",
        )
```

- [ ] **Step 2: Run the tests and confirm the missing-module failure**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_retry_overlay_approval.py -q`

Expected: collection fails because `control_trace_retry_overlay_approval` does not exist.

- [ ] **Step 3: Implement exact parsing, hashing, authority flags, and reconstruction**

```python
APPROVAL_PREFIX = "APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: "
APPROVED_SPEC_SHA256 = "ddc8d91165640469f3d7d5abb883c32d4ed4ac6f717e69150c8eb6c7671e5877"


def _approved_digest(approval_text: str) -> str:
    if not approval_text.startswith(APPROVAL_PREFIX):
        raise ControlTraceRetryOverlayApprovalError("approval_text_invalid")
    supplied = approval_text[len(APPROVAL_PREFIX):]
    if supplied != APPROVED_SPEC_SHA256:
        raise ControlTraceRetryOverlayApprovalError("approval_digest_invalid")
    return supplied


def build_trace_retry_overlay_spec_approval(...):
    spec = _ordinary(specification_path, "specification")
    supplied = _approved_digest(approval_text)
    if _file_sha(spec) != supplied:
        raise ControlTraceRetryOverlayApprovalError("approved_specification_mismatch")
    record = {
        "schema_version": "chronosaudit.control_trace_retry_overlay_spec_approval.v1",
        "decision": "APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256",
        "approval_text": approval_text,
        "specification_path": project_relative_path,
        "specification_file_sha256": supplied,
        "implementation_authorized": True,
        **FALSE_DOWNSTREAM_AUTHORITY,
    }
    record["record_sha256"] = _canonical_sha(record)
    return record
```

The verifier must validate the self-hash, every false authority field, rebuild from the ordinary specification, and compare the entire record byte-semantically.

- [ ] **Step 4: Add atomic CLIs and test wrong token, file drift, record drift, symlink input, and authority escalation**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_retry_overlay_approval.py -q`

Expected: all approval tests pass.

- [ ] **Step 5: Build and verify the canonical approval artifacts**

Run the build CLI with the exact approved specification and user token, then run the verifier CLI against the emitted record. Run both a second time into a temporary directory and compare the JSON bytes.

Expected: byte-identical approval and verification, with `implementation_authorized=true` and every downstream authority false.

- [ ] **Step 6: Checkpoint the task**

If execution is in a clean isolated worktree, commit only the four approval files and approval artifact. In the current dirty main checkout, preserve the diff without staging unrelated user changes.

---

### Task 2: Immutable Source-Root Verifier and Complete-Source Union

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_retry_overlay.py`
- Create: `02_Executable_Artifact/tests/test_control_trace_retry_overlay.py`

**Interfaces:**
- Consumes: `TraceSourceRoot(checkpoint_path, signature_path, allowed_signers_path, expected_principal)` plus original target and activation inputs.
- Produces: `verify_trace_source_root(...) -> VerifiedTraceSourceRoot` and `build_complete_source_union(...) -> CompleteSourceUnion`.

- [ ] **Step 1: Write fixture builders and failing root-verification tests**

```python
@dataclass(frozen=True)
class TraceSourceRoot:
    checkpoint_path: Path
    signature_path: Path
    allowed_signers_path: Path
    expected_principal: str


def test_source_root_rejects_event_chain_gap(trace_root_fixture):
    mutate_jsonl_event(trace_root_fixture.ledger, 1, {"previous_event_sha256": "f" * 64})
    with pytest.raises(ControlTraceRetryOverlayError, match="source_event_chain_invalid"):
        verify_trace_source_root(**trace_root_fixture.inputs)


def test_identical_complete_rows_choose_deterministic_canonical_source(two_agreeing_roots):
    union = build_complete_source_union(two_agreeing_roots, original_targets=two_agreeing_roots.targets)
    chosen = union.completed_by_target["trace-1"]
    assert chosen.canonical_source_key == min(two_agreeing_roots.source_keys)
    assert len(chosen.agreeing_sources) == 2
```

- [ ] **Step 2: Confirm the tests fail because the module and interfaces are absent**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_retry_overlay.py -q`

Expected: missing module/interface failure.

- [ ] **Step 3: Implement ordinary-file, path-confinement, self-hash, signature, results, checkpoint, and ledger verification**

```python
def verify_trace_source_root(*, source: TraceSourceRoot, original_targets_path: Path,
                             activation_request_path: Path, activation_approval_path: Path,
                             activation_signature_path: Path,
                             activation_allowed_signers_path: Path,
                             activation_expected_principal: str) -> VerifiedTraceSourceRoot:
    checkpoint = _load_self_hashed(source.checkpoint_path, "checkpoint_sha256")
    signature = verify_trace_checkpoint_signature(
        checkpoint_path=source.checkpoint_path,
        signature_path=source.signature_path,
        allowed_signers_path=source.allowed_signers_path,
        expected_principal=source.expected_principal,
    )
    activation = reverify_trace_activation_for_execution(
        request_path=activation_request_path,
        approval_path=activation_approval_path,
        signature_path=activation_signature_path,
        allowed_signers_path=activation_allowed_signers_path,
        expected_principal=activation_expected_principal,
        verification_time_utc=FROZEN_SOURCE_VERIFICATION_TIME,
    )
    results_path = _confined_child(source.checkpoint_path.parent, checkpoint["normalized_results_path"])
    ledger_path = _confined_child(source.checkpoint_path.parent, checkpoint["event_ledger_path"])
    return _reconstruct_source_root(checkpoint, signature, activation, results_path, ledger_path)
```

Reconstruction must parse `results["targets"]`, not a nonexistent `results` array; enforce processed IDs as the exact original sorted prefix; check all event/raw request/raw response hashes and semantic bindings; and prove each complete row from its two terminal successful events.

- [ ] **Step 4: Implement deterministic union and conflict rejection**

```python
def _complete_semantics(row: Mapping[str, object]) -> tuple[object, ...]:
    return (
        row["target_sha256"], row["case_id"], row["chain"], row["chain_address"],
        row["transaction_hash"], row["block_number"], row["block_hash"],
        row["reserve_record_sha256"], row["creation_set_sha256"],
        tuple(tuple(value) for value in row["creation_set"]),
    )


def build_complete_source_union(...):
    for target_id, rows in complete_rows_by_target.items():
        if len({_complete_semantics(row.record) for row in rows}) != 1:
            raise ControlTraceRetryOverlayError("complete_source_conflict")
        rows.sort(key=lambda row: (row.checkpoint_file_sha256, row.record_sha256))
```

- [ ] **Step 5: Add the complete adversarial test matrix**

Cover missing/symlink/path-escaping files; wrong checkpoint signer/namespace; altered activation; checkpoint/results/ledger drift; nonmonotonic or duplicate sequences; event-tip mismatch; raw receipt hash/provider/method/parameter/scope mismatch; processed-prefix mismatch; row self-hash mismatch; source-complete rows without two providers/two families; candidate missing; conflicting complete evidence; and true authority flags.

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_retry_overlay.py -q`

Expected: all source-root and union tests pass.

- [ ] **Step 6: Checkpoint the task without staging unrelated files**

---

### Task 3: Deterministic Retry-Target Artifact and Reconstruction Verifier

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_retry_overlay.py`
- Create: `02_Executable_Artifact/build_stage2_control_trace_retry_targets.py`
- Create: `02_Executable_Artifact/verify_stage2_control_trace_retry_targets.py`
- Modify: `02_Executable_Artifact/tests/test_control_trace_retry_overlay.py`

**Interfaces:**
- Consumes: verified spec approval, original target artifact, activation material, and exactly three verified source roots.
- Produces: `build_trace_retry_targets(...) -> dict[str, object]` and `verify_trace_retry_targets(...) -> dict[str, object]`.

- [ ] **Step 1: Write failing exact-set and determinism tests**

```python
def test_retry_targets_are_original_minus_source_complete(verified_sources):
    artifact = build_trace_retry_targets(**verified_sources.inputs)
    expected = sorted(set(verified_sources.original_ids) - set(verified_sources.complete_ids))
    assert [row["target_id"] for row in artifact["targets"]] == expected
    assert artifact["source_complete_count"] + artifact["unresolved_count"] == artifact["original_target_count"]
    assert artifact["rpc_authorized"] is False


def test_retry_builder_rejects_source_complete_replay(verified_sources):
    artifact = build_trace_retry_targets(**verified_sources.inputs)
    artifact["targets"].append(verified_sources.original_by_id[verified_sources.complete_ids[0]])
    with pytest.raises(ControlTraceRetryOverlayError, match="retry_contains_source_complete"):
        verify_trace_retry_targets(artifact_path=write_rehashed(artifact), **verified_sources.inputs)
```

- [ ] **Step 2: Run the new tests and confirm missing-function failures**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_retry_overlay.py -q`

- [ ] **Step 3: Implement the retry-target schema and independent reconstruction**

```python
artifact = {
    "schema_version": "stage2_control_trace_retry_targets.v1",
    "decision": "TRACE_RETRY_TARGETS_FROZEN_NON_AUTHORIZING",
    "approved_specification_sha256": APPROVED_SPEC_SHA256,
    "spec_approval_record_sha256": approval["record_sha256"],
    "original_trace_targets_file_sha256": _file_sha(original_targets_path),
    "original_trace_targets_sha256": original_payload["trace_targets_sha256"],
    "original_activation_verification_file_sha256": _file_sha(original_activation_verification_path),
    "original_activation_verification_sha256": activation["verification_sha256"],
    "source_roots": source_manifests,
    "original_target_count": len(original_targets),
    "source_complete_count": len(complete_ids),
    "duplicate_agreement_count": duplicate_agreement_count,
    "unresolved_count": len(unresolved_ids),
    "rpc_call_count": len(unresolved_ids) * 2,
    "source_complete_targets": source_complete_provenance,
    "targets": [original_by_id[target_id] for target_id in unresolved_ids],
    **FALSE_AUTHORITY,
}
artifact["retry_targets_sha256"] = _canonical_sha(artifact)
```

The verifier must call the same source-root reconstruction from raw inputs, rebuild the artifact, compare the entire mapping, and expose only `TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING`.

- [ ] **Step 4: Implement atomic builder/verifier CLIs with explicit repeated root arguments**

Use three repeated groups containing checkpoint, checkpoint signature, checkpoint allowed-signers, and principal. Require exact activation request, approval, signature, allowed-signers, verification, and expected principal arguments. Refuse output overwrite and symlink destinations.

- [ ] **Step 5: Test byte-identical rebuild, ordering, count reconciliation, mutation rejection, and no-overwrite behavior**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_retry_overlay.py -q`

Expected: all retry-target tests pass.

- [ ] **Step 6: Checkpoint the task without staging unrelated files**

---

### Task 4: Retry-Subset Activation and Acquisition Compatibility

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_state_activation.py`
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_acquisition.py`
- Modify: `02_Executable_Artifact/tests/test_control_trace_state_activation.py`
- Modify: `02_Executable_Artifact/tests/test_control_trace_acquisition.py`

**Interfaces:**
- Consumes: reconstruction-verified `stage2_control_trace_retry_targets.v1`.
- Produces: unchanged activation request/approval/verification schemas bound to the retry-target physical hash, and unchanged acquisition result/checkpoint schemas scoped only to retry IDs.

- [ ] **Step 1: Write failing activation and execution tests**

```python
def test_trace_only_activation_accepts_verified_retry_subset(monkeypatch, retry_fixture):
    request = build_trace_only_activation_request(
        trace_targets_path=retry_fixture.path,
        trace_retry_verification_inputs=retry_fixture.verification_inputs,
        **retry_fixture.capability_inputs,
    )
    assert request["trace_targets_sha256"] == _sha(retry_fixture.path)
    assert request["trace_target_count"] == retry_fixture.unresolved_count
    assert {scope["target_id"] for scope in request["rpc_call_scopes"]} == set(retry_fixture.unresolved_ids)
    assert not set(retry_fixture.source_complete_ids) & {scope["target_id"] for scope in request["rpc_call_scopes"]}


def test_acquisition_rejects_unverified_retry_schema_before_transport(retry_fixture):
    retry_fixture.mutate("source_complete_count", 0)
    with pytest.raises(ControlTraceAcquisitionError, match="trace_retry_targets_invalid"):
        execute_control_trace_acquisition(...)
```

- [ ] **Step 2: Run targeted tests and capture schema-invalid failures**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_state_activation.py 02_Executable_Artifact/tests/test_control_trace_acquisition.py -q`

- [ ] **Step 3: Add one strict target-loading helper and route both modules through it**

```python
def load_trace_execution_targets(path: Path, *, retry_verification_inputs: TraceRetryVerificationInputs | None = None) -> list[dict[str, object]]:
    payload = _load_json(path, "trace_targets")
    if payload.get("schema_version") == "stage2_control_trace_targets.v1":
        return _validate_original_trace_targets(payload)
    if payload.get("schema_version") == "stage2_control_trace_retry_targets.v1" and retry_verification_inputs is not None:
        verification = verify_trace_retry_targets(artifact_path=path, **retry_verification_inputs.as_kwargs())
        if verification["decision"] != "TRACE_RETRY_TARGETS_VERIFIED_NON_AUTHORIZING":
            raise ControlTraceRetryOverlayError("trace_retry_targets_invalid")
        return [dict(row) for row in payload["targets"]]
    raise ControlTraceRetryOverlayError("trace_targets_schema_invalid")
```

Do not accept the retry schema based only on its self-hash. Bind verification inputs through both CLI call paths and execution-time activation reverification.

- [ ] **Step 4: Add replay, mutation, injected-state, wrong-scope, over-budget, expiry, and missing-verification tests**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_state_activation.py 02_Executable_Artifact/tests/test_control_trace_acquisition.py -q`

Expected: original-target and retry-target paths both pass, with no transport call on invalid retry inputs.

- [ ] **Step 5: Checkpoint the task without staging unrelated files**

---

### Task 5: Complete Retry Root and Provenance Overlay

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_retry_overlay.py`
- Create: `02_Executable_Artifact/build_stage2_control_trace_completion_overlay.py`
- Create: `02_Executable_Artifact/verify_stage2_control_trace_completion_overlay.py`
- Modify: `02_Executable_Artifact/tests/test_control_trace_retry_overlay.py`

**Interfaces:**
- Consumes: verified original target, three source roots, verified retry targets, fresh activation request/approval/signature/verification, and a signed `COMPLETE` retry root.
- Produces: `build_trace_completion_overlay(...) -> dict[str, object]` and `verify_trace_completion_overlay(...) -> dict[str, object]`.

- [ ] **Step 1: Write failing full-coverage and incomplete-retry tests**

```python
def test_completion_overlay_covers_every_original_target_once(complete_retry_fixture):
    overlay = build_trace_completion_overlay(**complete_retry_fixture.inputs)
    assert overlay["decision"] == "COMPLETE_NON_AUTHORIZING"
    assert overlay["completed_target_count"] == overlay["original_target_count"]
    assert len({row["target_id"] for row in overlay["targets"]}) == overlay["original_target_count"]
    assert overlay["rpc_authorized"] is False


def test_completion_overlay_rejects_partial_retry_root(partial_retry_fixture):
    with pytest.raises(ControlTraceRetryOverlayError, match="retry_root_not_complete"):
        build_trace_completion_overlay(**partial_retry_fixture.inputs)
```

- [ ] **Step 2: Run tests and confirm missing overlay function failures**

- [ ] **Step 3: Implement complete retry verification and canonical overlay construction**

```python
for target_id in original_order:
    if target_id in source_union.completed_by_target:
        chosen = source_union.completed_by_target[target_id]
        origin = "IMMUTABLE_SOURCE_ROOT"
    else:
        chosen = retry_complete_by_target[target_id]
        origin = "FRESH_RETRY_ROOT"
    overlay_rows.append({
        **chosen.record,
        "evidence_origin": origin,
        "canonical_source": chosen.canonical_provenance,
        "agreeing_source_provenance": chosen.agreeing_provenance,
    })
```

Require exact partition closure: source-complete IDs and retry IDs are disjoint; their union equals all original IDs; the retry root has no extra ID; each retry record has two cross-family agreeing providers and contains the frozen address.

- [ ] **Step 4: Add provenance path/hash, raw-receipt drift, activation drift, target substitution, duplicate, omission, and authority-escalation tests**

- [ ] **Step 5: Implement atomic builder/verifier CLIs and byte-identical fixture reconstruction**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_retry_overlay.py -q`

Expected: overlay fixtures pass and partial/inconsistent evidence fails closed.

- [ ] **Step 6: Checkpoint the task without staging unrelated files**

---

### Task 6: Deployment Projection Overlay Input

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_trace_deployment_projection.py`
- Modify: `02_Executable_Artifact/build_stage2_control_trace_deployment_projection.py`
- Modify: `02_Executable_Artifact/tests/test_control_trace_deployment_projection.py`

**Interfaces:**
- Consumes either the existing `(trace_results_path, checkpoint_path, checkpoint_verification_path)` tuple or `(trace_overlay_path, trace_overlay_verification_path, overlay_reconstruction_inputs)`.
- Produces the unchanged `stage2_control_trace_deployment_projection.v1` record semantics with additional provenance bindings for overlay mode.

- [ ] **Step 1: Write failing overlay compatibility and mutual-exclusion tests**

```python
def test_projection_accepts_verified_complete_overlay(complete_overlay_fixture):
    projection = build_trace_deployment_projection(
        trace_targets_path=complete_overlay_fixture.original_targets,
        trace_overlay_path=complete_overlay_fixture.overlay,
        trace_overlay_verification_path=complete_overlay_fixture.verification,
        overlay_reconstruction_inputs=complete_overlay_fixture.reconstruction_inputs,
        candidate_root=complete_overlay_fixture.candidate_root,
    )
    assert projection["record_count"] == complete_overlay_fixture.target_count
    assert projection["trace_evidence_mode"] == "TRACE_RETRY_OVERLAY_V1"


def test_projection_rejects_single_root_and_overlay_supplied_together(...):
    with pytest.raises(ControlTraceDeploymentProjectionError, match="trace_evidence_mode_ambiguous"):
        build_trace_deployment_projection(...)
```

- [ ] **Step 2: Run projection tests and capture the unsupported-argument failure**

- [ ] **Step 3: Refactor only input normalization, not deployment semantics**

```python
def _verified_trace_rows(...inputs...) -> tuple[list[dict[str, object]], dict[str, object]]:
    if single_root_mode:
        return _verified_single_root_rows(...), single_root_bindings
    if overlay_mode:
        verified = verify_trace_completion_overlay(...)
        if verified["decision"] != "COMPLETE_NON_AUTHORIZING":
            raise ControlTraceDeploymentProjectionError("trace_overlay_not_complete")
        return overlay["targets"], overlay_bindings
    raise ControlTraceDeploymentProjectionError("trace_evidence_mode_invalid")
```

Keep the existing per-target immutable-field, creation-set, candidate-record, temporal, and one-canonical-creation checks unchanged after row normalization.

- [ ] **Step 4: Update CLI mutually exclusive arguments and help-contract tests**

- [ ] **Step 5: Run original and overlay projection suites**

Run: `./.venv/bin/python -m pytest 02_Executable_Artifact/tests/test_control_trace_deployment_projection.py 02_Executable_Artifact/tests/test_control_trace_retry_overlay.py -q`

Expected: original single-root fixtures still pass; verified overlays pass; incomplete/unverified overlays fail.

- [ ] **Step 6: Checkpoint the task without staging unrelated files**

---

### Task 7: Real Three-Root Retry Target, Integrated Regression, and Canonical Status

**Files:**
- Create artifact: `02_Executable_Artifact/processed/stage2_controls/2026-08-25/control-trace-retry-targets-v1/trace_retry_targets.json`
- Create artifact: `02_Executable_Artifact/processed/stage2_controls/2026-08-25/control-trace-retry-targets-v1/trace_retry_targets_verification.json`
- Modify: `CONTINUE_HERE.md`

**Interfaces:**
- Consumes the exact approved spec record and the three frozen signed roots.
- Produces a byte-identical verified retry subset and current continuation hashes/counts; performs no RPC.

- [ ] **Step 1: Run the real builder against all three immutable roots**

Use the exact original targets and activation inputs named by the specification, three checkpoint/signature groups, and principal `zmzubraj`.

Expected: one non-authorizing retry-target artifact; no source file changes; no network access.

- [ ] **Step 2: Independently run the verifier and a second temporary rebuild**

Compare the canonical and temporary output bytes with `cmp`. Verify count closure equals 1,768 and call closure equals twice the unresolved count.

- [ ] **Step 3: Run focused and integrated regression**

Run:

```bash
./.venv/bin/python -m pytest \
  02_Executable_Artifact/tests/test_control_trace_retry_overlay_approval.py \
  02_Executable_Artifact/tests/test_control_trace_retry_overlay.py \
  02_Executable_Artifact/tests/test_control_trace_state_activation.py \
  02_Executable_Artifact/tests/test_control_trace_acquisition.py \
  02_Executable_Artifact/tests/test_control_trace_deployment_projection.py \
  -q
```

Expected: all selected tests pass with no critical skip or warning.

- [ ] **Step 4: Run compilation, placeholder, secret, and diff checks**

Run:

```bash
./.venv/bin/python -m compileall -q \
  02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition \
  02_Executable_Artifact/*.py
git diff --check
```

Expected: compile and diff checks pass. Manually inspect the approved spec and plan for incomplete-marker language before delivery.

- [ ] **Step 5: Reverify canonical counters before editing status**

Verify the counter artifact file SHA-256 remains `51cf0b260ef0fdd275f97699db3ed95c41db09f5f2f3c350249d246d53550fdc` and its nested counters still report control candidates 0/4,170, qualified controls 0/4,170, independent adjudications 0/417, and release 0.

- [ ] **Step 6: Update only `CONTINUE_HERE.md` as human-readable status**

Record approval and verification hashes, implementation source hashes, exact verified source-complete and unresolved counts, retry artifact hashes, tests run, and the next gate: fresh capability plus separately signed exact activation for only the retry subset. Explicitly retain all counters and downstream authority as false.

- [ ] **Step 7: Final verification checkpoint**

Recompute hashes after the status edit, run `git diff --check`, and inspect `git status --short` to ensure no prior user evidence or unrelated dirty file was overwritten or staged.

Do not run a provider capability probe, create a signed retry activation, execute retry RPC, build a real completion overlay, project deployment evidence, admit denominator rows, select controls, or change counters in this task. Those actions require their separately verified inputs and authority gates.
