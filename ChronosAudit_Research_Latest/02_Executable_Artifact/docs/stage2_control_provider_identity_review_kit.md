# Stage 2 control RPC provider identity review kit

This kit prepares the eight configured PublicNode/1RPC records for accountable identity review. It does **not** verify an operator, establish independent provider-family ownership, authorize RPC, authorize control selection, change a counter, or modify Recovery3.

## Frozen inputs

- Provider registry: `config/public_provider_registry.yaml`
- Capture index: `raw/public_provider_identity/2026-08-20/capture-index.json`
- Evidence root: `raw/public_provider_identity/2026-08-20/`
- Review packet: `reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_evidence_review.json`
- Verification report: `reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_evidence_verification.json`
- Accountable approval request: `reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_approval_request.json`

The capture index binds four official PublicNode network pages and the official 1RPC network list to local SHA-256 values. The builder requires every tracking-enabled provider ID to be covered, requires the exact configured public endpoint literal in the corresponding capture, and rejects a non-HTTPS or non-official host, a tampered file, a symlink, a path escape, duplicate coverage, and operator-family drift.

## Rebuild and verify

Run from `02_Executable_Artifact`:

```bash
./.venv/bin/python build_stage2_control_provider_identity_evidence_review.py \
  --provider-registry config/public_provider_registry.yaml \
  --capture-index raw/public_provider_identity/2026-08-20/capture-index.json \
  --evidence-root raw/public_provider_identity/2026-08-20 \
  --output-review reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_evidence_review.json

./.venv/bin/python verify_stage2_control_provider_identity_evidence_review.py \
  --review reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_evidence_review.json \
  --provider-registry config/public_provider_registry.yaml \
  --capture-index raw/public_provider_identity/2026-08-20/capture-index.json \
  --evidence-root raw/public_provider_identity/2026-08-20 \
  --output-report reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_evidence_verification.json
```

Expected decisions:

- review: `EVIDENCE_CAPTURED_AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_REVIEW`
- verification: `PROVIDER_IDENTITY_EVIDENCE_REVIEW_VERIFIED_NON_AUTHORIZING`

## Accountable reviewer duties

The reviewer must independently establish the real-world entity behind each official domain and endpoint, whether PublicNode and 1RPC are genuinely separate operator families for the relevant evidence path, and whether the evidence is sufficient under the study's provider-independence standard. Documentation-domain control and endpoint publication are evidence, but they are not by themselves proof of corporate identity, infrastructure independence, archive capability, or accountable approval.

If the review passes, preserve a signed decision bound to the review-packet SHA-256, capture-index SHA-256, provider-registry SHA-256, exact provider IDs, exact endpoint identity hashes, verified operator families, reviewer identity/key binding, decision time, and validity window. Only then may a separately reviewed registry revision and matching provider-identity report be prepared. Rerun `preflight_stage2_control_candidate_rpc_providers.py`; do not obtain or execute the queue-bound RPC activation until that preflight passes.

## Build the exact approval and signing payload

The accountable reviewer must replace the bracketed values and sign only after completing the duties above. The builder re-verifies the evidence packet and regenerates the request; it cannot create a signature.

```bash
./.venv/bin/python build_stage2_control_provider_identity_approval.py \
  --review reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_evidence_review.json \
  --provider-registry config/public_provider_registry.yaml \
  --capture-index raw/public_provider_identity/2026-08-20/capture-index.json \
  --evidence-root raw/public_provider_identity/2026-08-20 \
  --reviewer-principal '[accountable reviewer principal]' \
  --review-start-utc '[canonical UTC start]' \
  --review-expires-utc '[canonical UTC expiry]' \
  --output-request '[request output].json' \
  --output-approval '[approval output].json' \
  --output-signing-payload '[signing payload output].json'

/usr/bin/ssh-keygen -Y sign \
  -f '[reviewer private key]' \
  -n chronosaudit-stage2-control-provider-identity-review-v1 \
  '[signing payload output].json'
```

The approval explicitly attests the operator bindings and that PublicNode and 1RPC are distinct operator families for this evidence path. It explicitly does **not** assess archive capability. It grants only registry and identity-report projection authority; acquisition, RPC, selection, stage promotion, and Recovery3 mutation remain false.

## Verify and project without mutating the source registry

```bash
./.venv/bin/python verify_stage2_control_provider_identity_approval.py \
  --review reports/stage2_controls/2026-08-17/expansion-chunks/control_provider_identity_evidence_review.json \
  --provider-registry config/public_provider_registry.yaml \
  --capture-index raw/public_provider_identity/2026-08-20/capture-index.json \
  --evidence-root raw/public_provider_identity/2026-08-20 \
  --approval '[approval output].json' \
  --signature '[signing payload output].json.sig' \
  --allowed-signers '[allowed signers file]' \
  --expected-principal '[accountable reviewer principal]' \
  --verification-time-utc '[canonical UTC verification time]' \
  --output-verification '[verification output].json' \
  --output-registry-projection '[registry projection output].yaml' \
  --output-identity-report '[identity report output].json'
```

The projected registry and identity report are deterministic outputs of a valid signature. They are separate from `config/public_provider_registry.yaml`; the source registry is not edited. Run the provider-readiness preflight against the projections. A ready result remains non-authorizing and does not establish archive capability or grant RPC.

If the review fails or remains uncertain, do not sign. Keep every live `operator_verified` value false and replace the proposed provider set with evidence-supported independent families. Never edit a verification result merely to align it with the registry.
