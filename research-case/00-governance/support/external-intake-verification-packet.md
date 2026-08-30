# ChronosAudit External Intake Verification Packet

Run ID: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`  
Prepared: 2026-08-02  
Purpose: resolve the authenticated independent-scientific-review portion of the schema-v4 `INTAKE` gate without treating AI review, key possession, or administrative signatures as scientific independence.

## Frozen review targets

Review these exact revisions. Any content change invalidates the hashes and requires a new review.

| Artifact | SHA-256 | Current disposition |
| --- | --- | --- |
| `00-governance/program-charter.md` | `755b1a454abd7d2a69739abda47d1a9ea87c6a44412e0065d7936cc96f443f9d` | `BLOCKED`; producer `intake_integration` |
| `00-governance/study-profile.json` | `15a3933f3c87b2537b0286cc062e55eb11cd7364b64381cbdba4e46dff58f324` | `BLOCKED`; producer `intake_integration` |

The reviewer must be a real, accountable person distinct from the producer and competent to challenge computational security benchmark scope, evidence boundaries, and research-governance routing. The review may accept the narrow public-evidence methods/preregistration route while keeping historical execution, private vulnerability handling, analyst-participant research, prospective deployment, and submission unauthorized.

## Non-substitution rules

- The AI root and its subagents cannot be the independent scientific verifier.
- The run's `runtime-governance` key can attest only mechanical facts.
- A registry administrator authenticates registry changes but does not thereby become the scientific reviewer.
- An `ACCOUNTABLE_HUMAN` or `EXTERNAL_AUTHORITY` signature establishes its named authority but does not satisfy the runtime's `INDEPENDENT_REVIEWER` gate.
- Public-key possession does not prove real-world identity. Record the out-of-band identity-binding method outside the case.
- No step below authorizes archive/RPC execution, live-target testing, private disclosure work, human-subject research, prospective deployment, or submission.

## Human-controlled trust bootstrap

Generate and retain both private keys outside the research case. Substitute real secure paths and stable identifiers.

```bash
ssh-keygen -t ed25519 -f /secure/outside-case/chronosaudit-registry-admin
ssh-keygen -t ed25519 -f /secure/outside-case/chronosaudit-independent-reviewer

python3 /Users/rainbow/.codex/skills/orchestrate-top-journal-research/scripts/manage_verifier_identity.py \
  bootstrap-trust /Users/rainbow/Documents/ZTech/Research/ChronosAudit/research-case \
  --registry-admin-key-id chronosaudit-registry-admin-001 \
  --registry-admin-public-key /secure/outside-case/chronosaudit-registry-admin.pub \
  --registry-signing-key /secure/outside-case/chronosaudit-registry-admin

python3 /Users/rainbow/.codex/skills/orchestrate-top-journal-research/scripts/manage_verifier_identity.py \
  register /Users/rainbow/Documents/ZTech/Research/ChronosAudit/research-case \
  --registry-id chronosaudit-independent-reviewer-001 \
  --verifier-identity chronosaudit-independent-reviewer-001 \
  --verifier-type INDEPENDENT_REVIEWER \
  --signing-key-id chronosaudit-independent-reviewer-key-001 \
  --authority-tier SCIENTIFIC_INDEPENDENT \
  --public-key /secure/outside-case/chronosaudit-independent-reviewer.pub \
  --registry-signing-key /secure/outside-case/chronosaudit-registry-admin
```

Before registration, the accountable registry administrator must bind both identifiers to real people through an out-of-band process appropriate to the institution. Do not place private keys, identity documents, or credentials in the research case.

## Independent review procedure

1. Verify both target hashes.
2. Complete `intake-independent-review-checklist.csv` without relying on the existing AI advisory audit as the scientific decision.
3. Confirm that the research question is falsifiable and measurable.
4. Confirm that claim `C001` remains a hypothesis and that novelty is not asserted as verified.
5. Confirm that `C002` is a feasibility hypothesis and does not authorize execution.
6. Confirm that the study profile's field, study type, article type, evidence standard, jurisdiction boundary, ethics category, reporting route, and adapter are defensible for the narrow public-evidence draft.
7. Confirm that all excluded activities remain explicitly unauthorized.
8. Record disagreements or required edits. If an edit is required, do not sign the current hash; return the artifact for revision.
9. Sign the unchanged artifacts only after the review passes.

## Signing commands after a passing review

```bash
python3 /Users/rainbow/.codex/skills/orchestrate-top-journal-research/scripts/record_artifact.py \
  /Users/rainbow/Documents/ZTech/Research/ChronosAudit/research-case \
  --path 00-governance/program-charter.md \
  --status VERIFIED \
  --owner intake_integration \
  --produced-by root \
  --verified-by chronosaudit-independent-reviewer-001 \
  --verifier-identity chronosaudit-independent-reviewer-001 \
  --verifier-type INDEPENDENT_REVIEWER \
  --verification-id CHRONOSAUDIT-INTAKE-CHARTER-001 \
  --verification-method "independent scientific and scope-boundary review" \
  --independence-mode INDEPENDENT \
  --independence-basis "authenticated reviewer distinct from the AI producer; out-of-band identity binding retained by the registry administrator" \
  --signing-key /secure/outside-case/chronosaudit-independent-reviewer \
  --notes "Independent review of the frozen public-evidence intake charter; no execution, prospective, or submission authority granted."

python3 /Users/rainbow/.codex/skills/orchestrate-top-journal-research/scripts/record_artifact.py \
  /Users/rainbow/Documents/ZTech/Research/ChronosAudit/research-case \
  --path 00-governance/study-profile.json \
  --status VERIFIED \
  --owner intake_integration \
  --produced-by root \
  --verified-by chronosaudit-independent-reviewer-001 \
  --verifier-identity chronosaudit-independent-reviewer-001 \
  --verifier-type INDEPENDENT_REVIEWER \
  --verification-id CHRONOSAUDIT-INTAKE-PROFILE-001 \
  --verification-method "independent study-profile and authority-boundary review" \
  --independence-mode INDEPENDENT \
  --independence-basis "authenticated reviewer distinct from the AI producer; jurisdiction-dependent execution remains outside the reviewed scope" \
  --signing-key /secure/outside-case/chronosaudit-independent-reviewer \
  --notes "Independent review of the narrow public-evidence profile; downstream authority decisions remain external."
```

## Mechanical and gate checks after signing

The root integration owner, not the reviewer, should run:

```bash
python3 /Users/rainbow/.codex/skills/orchestrate-top-journal-research/scripts/check_research_case.py \
  /Users/rainbow/Documents/ZTech/Research/ChronosAudit/research-case

python3 /Users/rainbow/.codex/skills/orchestrate-top-journal-research/scripts/check_research_case.py \
  /Users/rainbow/Documents/ZTech/Research/ChronosAudit/research-case --strict

python3 /Users/rainbow/.codex/skills/orchestrate-top-journal-research/scripts/advance_research_case.py \
  /Users/rainbow/Documents/ZTech/Research/ChronosAudit/research-case \
  --decision PROCEED \
  --owner root-integration-owner
```

`PROCEED` advances only from `INTAKE` to `NOVELTY_AUDIT`. It does not establish novelty, feasibility `GO`, study authority, empirical support, prospective readiness, or submission approval.

## Failure and revision route

- If either artifact is scientifically unacceptable, return exact objections and do not sign.
- Revise only the affected canonical artifact, record a new draft revision, recompute its hash, and repeat the independent review.
- If the narrow public-evidence route itself is not supportable, preserve the current case and issue a responsible stop or further claim narrowing; do not broaden authority.

