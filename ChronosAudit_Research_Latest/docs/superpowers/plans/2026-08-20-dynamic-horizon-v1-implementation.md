# DYNAMIC_HORIZON_V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved outcome-blind, pair-specific dynamic follow-up horizon and an independently reproducible, signed, non-authorizing verification boundary.

**Architecture:** Add one focused scientific module that validates the frozen reference cohort and pair features, fits a deterministic hierarchical Kaplan-Meier/seeded-bootstrap model, creates assignments, and re-verifies all derived artifacts. Add separate CLIs for unsigned artifact generation, author-approval payload creation, and signed verification; retain the fixed-duration implementation only as historical compatibility and do not grant selection, qualification, counter, RPC, acquisition, or Recovery3 authority.

**Tech Stack:** Python 3.13, pandas, NumPy, OpenSSH `ssh-keygen -Y`, pytest, canonical JSON/SHA-256.

---

## Frozen statistical contract

- Estimator: Kaplan-Meier product-limit survival estimator with deterministic stable ordering of tied event times; the requested event-time quantile is the first observed time where `1 - S(t) >= p`.
- Target quantile: `p=0.95`.
- Information gates: at least 30 valid reference rows and at least 20 observed events in a chosen stratum; otherwise follow the frozen hierarchy. If the global pool fails, return `INSUFFICIENT_EVIDENCE`.
- Hierarchy: exact mechanism+protocol+architecture/proxy; architecture+protocol; chain; global.
- Uncertainty: 1,000 row-bootstrap replicates using NumPy `PCG64`; the seed is the first unsigned 64 bits of SHA-256 over the canonical model specification plus canonical stratum descriptor. At least 900 replicates must produce the requested quantile. The one-sided 95% bootstrap upper quantile minus the point estimate, floored at zero, is the uncertainty allowance.
- Data-derived bounds: the global pooled Kaplan-Meier 0.80 point quantile is the lower bound. The global pooled 0.99 point quantile plus its one-sided 95% bootstrap allowance is the upper bound. If either bound is unavailable or the upper bound is below the lower bound, all assignments are `INSUFFICIENT_EVIDENCE`.
- Assignment: `ceil(clamp(q95 + allowance, pooled_q80, pooled_conservative_q99))`; maturity is prediction cutoff plus the assigned integer days.
- Timing precision: canonical seconds-precision UTC only. Interval-censored, imprecise, missing, nonpositive, or hash-unbound reference timing fails closed.
- Prohibited pair fields: outcome, incident, post-cutoff activity, last observation, maturity/qualification state, allocation/target pressure, replacement status, or future-latency fields. Presence of any prohibited field fails the entire input rather than silently dropping it.

### Task 1: Reference cohort and pair-feature schemas

**Files:**
- Create: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_dynamic_horizon.py`
- Create: `02_Executable_Artifact/tests/test_control_dynamic_horizon.py`

- [ ] **Step 1: Write failing tests** for canonical timestamps, exact latency reconstruction, required hashes, unique reference IDs, forbidden pair columns, candidate/reference overlap, deterministic feature hashes, and non-authorizing flags.
- [ ] **Step 2: Run** `./.venv/bin/python -m pytest -q tests/test_control_dynamic_horizon.py` and require failure because the module is absent.
- [ ] **Step 3: Implement** `validate_reference_latency_cohort(frame)`, `validate_cutoff_safe_pair_features(frame, reference_ids=...)`, `make_reference_record_sha256`, and `make_feature_vector_sha256` with explicit schemas and `ControlDynamicHorizonError`.
- [ ] **Step 4: Rerun** the focused tests and require pass.

### Task 2: Deterministic survival model

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_dynamic_horizon.py`
- Modify: `02_Executable_Artifact/tests/test_control_dynamic_horizon.py`

- [ ] **Step 1: Write failing tests** for Kaplan-Meier quantiles, tied events, censoring, exact hierarchy selection, sparse fallback, deterministic bootstrap output, data-derived bounds, and pooled insufficiency.
- [ ] **Step 2: Run** the focused test file and confirm the new tests fail for missing model functions.
- [ ] **Step 3: Implement** `_kaplan_meier_quantile`, `_bootstrap_upper_quantile`, `build_dynamic_horizon_model`, and deterministic seed derivation exactly as frozen above.
- [ ] **Step 4: Rerun** the focused tests and require pass.

### Task 3: Assignment generation and independent reconstruction

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_dynamic_horizon.py`
- Modify: `02_Executable_Artifact/tests/test_control_dynamic_horizon.py`

- [ ] **Step 1: Write failing tests** for assignment hashes, pair-specific maturity timestamps, no favorable replacement fields, exact model/reference bindings, and deterministic byte-for-byte regeneration.
- [ ] **Step 2: Run** the focused test file and confirm RED.
- [ ] **Step 3: Implement** `assign_dynamic_horizons` and `verify_dynamic_horizon_artifacts`, returning explicit `ASSIGNED` or `INSUFFICIENT_EVIDENCE` per pair while keeping every authority flag false.
- [ ] **Step 4: Rerun** the focused tests and require GREEN.

### Task 4: Artifact and author-approval CLIs

**Files:**
- Create: `02_Executable_Artifact/build_stage2_control_dynamic_horizon.py`
- Create: `02_Executable_Artifact/build_stage2_control_dynamic_horizon_approval.py`
- Create: `02_Executable_Artifact/verify_stage2_control_dynamic_horizon.py`
- Modify: `02_Executable_Artifact/tests/test_control_dynamic_horizon.py`

- [ ] **Step 1: Write failing CLI tests** covering all eight required artifact names, atomic non-overwriting writes, canonical approval payload bytes, namespace `chronosaudit-stage2-control-dynamic-horizon-v1`, principal/hash/time binding, invalid/expired signatures, and no private-key reads.
- [ ] **Step 2: Run** those tests and confirm RED.
- [ ] **Step 3: Implement** the three CLIs using argv-only OpenSSH verification and ordinary-file/symlink/path-containment checks.
- [ ] **Step 4: Rerun** the focused tests and require GREEN.

### Task 5: Current-workflow integration

**Files:**
- Modify: `02_Executable_Artifact/src/chronosaudit_stage2/public_acquisition/control_follow_up_horizon.py`
- Modify: `02_Executable_Artifact/config/stage2_control_selection_policy_v1.yaml`
- Modify: `02_Executable_Artifact/tests/test_control_follow_up_horizon.py`
- Modify: `02_Executable_Artifact/docs/stage2_control_follow_up_horizon_methods_owner_kit.md`
- Modify: `03_Research_Reports/Stage2_Control_Prespecification_and_Preflight.md`

- [ ] **Step 1: Write failing compatibility tests** requiring current requests to name `DYNAMIC_HORIZON_V1` while legacy fixed decisions remain verifiable only when explicitly classified as historical/non-current.
- [ ] **Step 2: Run** the horizon tests and confirm RED.
- [ ] **Step 3: Update** the current request/policy/docs to the dynamic contract without deleting or rewriting historical fixed artifacts.
- [ ] **Step 4: Rerun** focused dynamic and fixed-horizon compatibility tests.

### Task 6: Integrated verification and canonical handoff

**Files:**
- Modify: `CONTINUE_HERE.md`
- Modify only curated entries in: `00_README/FILE_MANIFEST.csv`
- Modify only matching hashes in: `00_README/SHA256SUMS.txt`

- [ ] **Step 1: Run** `./.venv/bin/python -m py_compile` for every new/changed Python entrypoint.
- [ ] **Step 2: Run** `./.venv/bin/python -m pytest -q tests/test_control*.py tests/test_public_acquisition*.py` and require zero failures.
- [ ] **Step 3: Run** CLI `--help` smoke checks, `git diff --check`, package checksum verification, and curated manifest/ledger verification.
- [ ] **Step 4: Update** `CONTINUE_HERE.md` with only verified implementation status; retain candidates and qualified controls at `0/4,170` until real selection/evidence/qualification passes.

## Self-review

- Spec coverage: reference timing, prohibited inputs, hierarchy, survival estimator, uncertainty, bounds, assignments, artifacts, signature, authority separation, and failure handling are each assigned to a task.
- Placeholder scan: no `TBD`, `TODO`, or unspecified scientific defaults remain.
- Type consistency: all public functions accept pandas DataFrames or ordinary artifact paths and return dictionaries/DataFrames with explicit decisions; hashes use lowercase SHA-256 hex; timestamps use canonical seconds-precision UTC.
- Scope: this plan implements the approved dynamic-horizon gate only. It does not perform network acquisition, pair-evidence assembly, candidate selection, outcome review, or counter promotion.
