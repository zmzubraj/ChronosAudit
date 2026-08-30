# ChronosAudit Independent-Verifier Bootstrap

> Status: governance draft. This artifact prepares the missing trust bootstrap; it does not itself establish an independently verified identity or scientific gate.

## Current blocker

The case is still running in mechanical-only trust mode:

- `00-governance/verifier-registry.json` has `trust_mode: CASE_LOCAL_MECHANICAL_ONLY`
- the `trust_root_fingerprint` is blank
- the only active entry is the runtime mechanical attestor

That is sufficient for structural integrity checks, but not for decision-bearing authority or scientific verification.

## Required outcome

Before the ChronosAudit intake gate can advance on authority-dependent work, the case needs:

1. a run-bound external registry-admin trust root bootstrapped outside the research case;
2. at least one accountable human identity bound out of band to that trust root;
3. at least one genuinely independent verifier identity registered under schema-v4 rules;
4. canonical verification events for the authority artifact(s) that unblock the intended next stage.

## Minimum bootstrap sequence

1. Name the accountable human authority roles.
   At minimum: scope owner, registry administrator, and any separate independent verifier.

2. Generate and hold the registry-admin private key outside the case.
   The key must not be copied into `research-case/`.

3. Bootstrap the trust root with the orchestration runtime.
   The resulting trust-root fingerprint must be recorded in the verifier registry.

4. Register the accountable human identity.
   This step needs out-of-band identity binding, not just possession of a key.

5. Register the independent verifier identity.
   The verifier cannot be only the same runtime-mechanical actor or an unbound pseudonym.

6. Record the first authority-verification event against the intended artifact.
   Examples: intake authority matrix approval, source-rights ledger approval, archive/RPC execution authorization.

7. Re-run strict validation and only then consider an intake outcome that depends on authority.

## Independence rules

- Mechanical checks may prove syntax, schema, hashes, or file presence.
- Mechanical checks may not certify scientific independence, human identity, ethics approval, or institutional authority.
- The same actor that produced a decision-bearing governance artifact should not be the sole independent verifier for that artifact.

## Suggested first authority artifacts to verify

1. `00-governance/intake-authority-matrix.md`
2. a source-rights and terms ledger for any planned archive/RPC or dataset use
3. a stage-specific authorization note for the first non-public-safe-route activity

## Evidence that should exist before archive/RPC execution

- named data sources and operators
- rights basis and terms review
- permitted retention and redistribution boundary
- cost and access approval
- sanctions/export-control or jurisdiction review if applicable
- accountable approval for execution

## Evidence that should exist before prospective shadow deployment

- frozen prospective cohort and thresholds
- disclosure and escalation procedure
- adjudicator role and independence
- partner approval and contact path
- explicit no-intervention boundary if truly shadow-only
- accountable approval for launch and retention

## Explicit limitation

Completing this checklist is necessary preparation, not gate passage. The gate passes only when the resulting authority artifacts are independently signed and verified under the schema-v4 registry.
