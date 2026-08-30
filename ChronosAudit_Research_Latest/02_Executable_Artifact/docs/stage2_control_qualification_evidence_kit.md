# Stage 2 control qualification evidence kit

This kit verifies the evidence package for all eight required control checks. It does **not** select controls, import a qualification decision, authorize a counter, promote Stage 2, or modify Recovery3.

## Required order

1. Freeze and authorize the follow-up horizon before inspecting control outcomes.
2. Complete the authorized historical-source expansion and verify the resulting denominator and pair covariates.
3. Select exactly ten globally unique same-chain candidates per positive with the frozen policy and deterministic global allocator.
4. Preserve the selected candidate CSV and its `control_row_sha256` values.
5. Create exactly one check row for each candidate and each gate: `maturity`, `censoring`, `temporal`, `lineage`, `clone`, `proxy`, `protocol`, and `mechanism_separation`.
6. Run the evidence verifier below. A passing report is evidence-package validation only.
7. Build the exact approval request, obtain an independently owned accountable signature, and run the signed verifier.
8. Assemble the original frozen inputs, evidence tree, approval, signature, and allowed-signers file into one portable bundle. Canonical counter projection independently re-verifies that bundle; it does not trust a saved verification report.

## Check-row contract

The checks CSV uses schema `chronosaudit.control_qualification_check.v1` and must contain:

- `case_name`, `chain`, `contract_address`, and the exact `candidate_control_row_sha256`;
- one of the eight gate names and `check_status=PASS`;
- a relative `evidence_path`, its `evidence_sha256`, and a canonical `evidence_record_sha256` over the row excluding that self-hash;
- `reviewer_identity`, `reviewer_owner`, `reviewer_kind`, `reviewer_conflict_clear`, `reviewer_confidence`, and a seconds-precision UTC review time.

Maturity, censoring, and mechanism separation are outcome-dependent and require `reviewer_kind=HUMAN`. The other five gates accept a human or mechanical verifier, but still require a conflict-clear named reviewer/owner and direct evidence.

## Evidence-file contract

Every check row points to an ordinary JSON file under the evidence root with schema `chronosaudit.control_check_evidence.v1`. It must repeat the exact candidate identity, candidate hash, gate, and `result=PASS`; state a non-empty decision rule and observations; and point to a second ordinary source artifact under the same root with a verified SHA-256. Paths that are absolute, missing, symlinked, or escape the root fail closed.

## Verification command

```bash
./.venv/bin/python verify_stage2_control_qualification_evidence.py \
  --candidates '<frozen-selected-control-candidates.csv>' \
  --checks '<control-qualification-checks.csv>' \
  --evidence-root '<control-qualification-evidence-root>' \
  --output-report '<control-qualification-evidence-verification.json>'
```

A successful result is `QUALIFICATION_EVIDENCE_VERIFIED_NON_AUTHORIZING` and explicitly keeps `qualification_authorized`, `counter_authority`, `stage_promotion_authorized`, and `recovery3_mutation_authorized` false. Do not increment either control counter from this report.

## Accountable qualification approval

Build the deterministic non-authorizing request:

```bash
./.venv/bin/python build_stage2_control_qualification_approval_request.py \
  --candidate-rows '<frozen-selected-control-candidates.csv>' \
  --check-rows '<control-qualification-checks.csv>' \
  --positive-cases '<frozen-positive-cases.csv>' \
  --evidence-root '<control-qualification-evidence-root>' \
  --output-request '<control-qualification-approval-request.json>'
```

The accountable qualification authority must be distinct from every human evidence reviewer and reviewer owner. After choosing a canonical UTC validity window, build the exact unsigned approval and canonical signing bytes:

```bash
./.venv/bin/python build_stage2_control_qualification_approval.py \
  --request '<control-qualification-approval-request.json>' \
  --authority-principal '<allowed-signers principal>' \
  --approval-start-utc 'YYYY-MM-DDTHH:MM:SSZ' \
  --approval-expires-utc 'YYYY-MM-DDTHH:MM:SSZ' \
  --output-approval '<control-qualification-approval.json>' \
  --output-signing-payload '<control-qualification-approval-signing-payload.json>'

ssh-keygen -Y sign -f '<private-key>' \
  -n chronosaudit-stage2-control-qualification-v1 \
  '<control-qualification-approval-signing-payload.json>'
```

Verify the signature and regenerate the exact counter-bound projection from the frozen candidates and all eight source-backed checks:

```bash
./.venv/bin/python verify_stage2_control_qualification_approval.py \
  --candidate-rows '<frozen-selected-control-candidates.csv>' \
  --check-rows '<control-qualification-checks.csv>' \
  --positive-cases '<frozen-positive-cases.csv>' \
  --evidence-root '<control-qualification-evidence-root>' \
  --approval '<control-qualification-approval.json>' \
  --signature '<control-qualification-approval-signing-payload.json.sig>' \
  --allowed-signers '<allowed-signers>' \
  --expected-principal '<allowed-signers principal>' \
  --verification-time-utc 'YYYY-MM-DDTHH:MM:SSZ' \
  --output-verification '<control-qualification-verification.json>' \
  --output-qualified-controls '<qualified-controls.csv>'
```

The successful decision is `CONTROL_QUALIFICATION_APPROVAL_VERIFIED`. It authorizes only the exact qualified projection and qualified-control counter input. It does not authorize candidate selection, Stage 2 promotion, Recovery3 mutation, source acquisition, or RPC. The saved report and projection are useful operator diagnostics, but canonical projection does not trust them as standalone inputs.

Assemble a new self-contained bundle. The destination must not already exist; the assembler validates the source files and evidence tree, copies them into a staging directory, rebuilds and verifies the signed qualification, and publishes the bundle only after that verification succeeds:

```bash
./.venv/bin/python build_stage2_control_qualification_bundle.py \
  --bundle-root '<new-portable-bundle-directory>' \
  --candidate-rows '<frozen-selected-control-candidates.csv>' \
  --check-rows '<control-qualification-checks.csv>' \
  --positive-cases '<frozen-positive-cases.csv>' \
  --evidence-root '<control-qualification-evidence-root>' \
  --approval '<control-qualification-approval.json>' \
  --signature '<control-qualification-approval-signing-payload.json.sig>' \
  --allowed-signers '<allowed-signers>' \
  --expected-principal '<allowed-signers principal>' \
  --verification-time-utc 'YYYY-MM-DDTHH:MM:SSZ'
```

Re-verify the portable bundle directly:

```bash
./.venv/bin/python verify_stage2_control_qualification_bundle.py \
  --manifest '<new-portable-bundle-directory/control_qualification_bundle_manifest.json>'
```

The successful bundle decision is `CONTROL_QUALIFICATION_BUNDLE_VERIFIED`. The verifier rehashes every bundled input and evidence artifact, rebuilds the approval request, reruns the eight semantic checks and OpenSSH signature validation, regenerates the qualified projection, and compares its exact bytes with the bundled projection.

When projecting canonical counters, provide only the bundle manifest:

```bash
./.venv/bin/python run_public_evidence_acquisition.py project \
  --control-qualification-bundle \
  '<new-portable-bundle-directory/control_qualification_bundle_manifest.json>'
```

The project runner and production verifier independently rerun bundle verification and require the exact regenerated projection before counter calculation. The counter records zero qualified controls when the bundle is absent, tampered, semantically invalid, incorrectly signed, expired/not-yet-valid at the recorded verification time, or mismatched to the projected rows. Keep the original request and operator reports as audit history, but use the portable bundle as the canonical counter input. The recorded verification time is not external timestamping or notarization, and key possession alone does not prove the signer’s real-world accountable authority.

## Candidate versus qualified state

Temporal, lineage, clone, proxy, and protocol separation are selection-time provenance gates. Mechanism separation is deliberately deferred because it is an outcome, not a cutoff-safe matching covariate. Therefore a selected row may be a valid `CANDIDATE_CONTROL` while maturity, censoring, mechanism separation, and independent outcome review remain pending. It becomes a `QUALIFIED_CONTROL` only after all qualification gates, the independently signed approval, exact projection regeneration, and the counter’s verification binding pass.
