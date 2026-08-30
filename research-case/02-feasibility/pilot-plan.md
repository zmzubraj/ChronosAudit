# ChronosAudit benchmark-core feasibility pilot plan

## Status and boundary

- Run: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Phase: `FEASIBILITY_GATE`
- Decision linkage: this pilot is the required evidence cycle inside `FEASIBILITY_GATE` for the `PILOT FIRST` recommendation in `feasibility-report.md`; it is the prerequisite for any later request to promote the benchmark core to `STUDY_DESIGN`
- Execution status: `AUTHORIZED IN BOUNDED SCOPE` by the requesting user on `2026-08-01`; source-specific rights and measured resource/access checks remain mandatory before each source or tool enters the pilot
- Scope: public-data-only benchmark-core feasibility; no live-chain scanning, disclosure outreach, partner workflow, proprietary corpus, or shadow deployment

### Authorization interpretation

- The authorization permits manual public-source retrieval and local, non-production analysis needed for the prespecified feasibility objectives.
- It does not establish a third party's license, redistribution permission, archival-node access, paid service availability, or institutional/legal approval.
- A source with unclear rights may be cited and linked when lawful, but its contents may not be redistributed or silently incorporated into a release package.
- Downloaded or cloned code must pass the machine-wide codebase security preflight before any build, dependency installation, test, binary, container, or script is executed.
- The explicit exclusions below remain unchanged.

## Pilot objective

Resolve the smallest set of uncertainties that determine whether the benchmark core can enter `STUDY_DESIGN`:

1. case-level admissibility manifests can be completed from public evidence without post-cutoff leakage
2. lineage, source/bytecode clone, proxy/attacker, and exploit-mechanism assignments can be rerun independently
3. mature-negative versus unresolved exploit-status rules can be applied without ad hoc exceptions
4. one frozen public baseline or a justified substitute can be reproduced in a clean environment
5. source-rights and archival/public-access assumptions are lawful and operationally bounded

## Smallest informative public-data test

1. Select a heterogeneous public pilot cohort large enough to stress:
   - multiple protocol or entity lineages
   - multiple exploit mechanisms
   - at least one proxy or upgrade pattern
   - at least one clone or near-clone relationship
   - at least one public case whose exploit status remains unresolved or whose negative maturity must be argued
2. For every pilot case, build a prediction-time admissibility manifest that records:
   - contract identity and prediction timestamp
   - source and bytecode provenance
   - allowed and excluded information sources
   - lineage, clone, proxy/attacker, and mechanism assignments
   - exploit-status assignment and justification
   - rights/redistribution note
3. Independently rerun the assignments on the same pilot cohort and log every disagreement.
4. Reproduce one frozen public baseline or formally justify a substitute public baseline that supports the capability-survival question.
5. Record the public-access path and cost assumptions for every pilot dependency.

## Measures and denominators

- Manifest completeness: pilot cases with all critical fields completed lawfully / all pilot cases
- Split rerun stability: rerun cases with unchanged split eligibility / all rerun cases
- Status-rule operability: public follow-up examples assigned without ad hoc exceptions / all status-trial examples
- Baseline reproducibility: reproduced baseline stages / planned baseline stages
- Rights/access coverage: pilot sources with explicit lawful-use path / all pilot sources

## Sample or run rationale

This is an information-sufficiency pilot, not an efficacy study. The cohort should be just large enough to expose at least one plausible disagreement or failure mode in each of the core surfaces: admissibility, lineage, clone, mechanism, exploit status, and baseline reproduction. Numerical expansion beyond that point is not justified until the pilot answers whether the protocol is executable at all.

## Green / amber / red interpretation

Use `progression-criteria.csv` exactly. In summary:

- `Green`: the benchmark core may request `GO TO STUDY_DESIGN`
- `Amber`: repeat only the affected slice after rule or tooling refinement
- `Red`: stop or redesign the affected claim surface before further work

Only the rows with `scope=benchmark_core` and `blocks_benchmark_core_green=true` determine benchmark-core green. The `extension_authority_package` row is future-only and governs only whether the blocked prospective extension may ever be reopened.

## Stop conditions

Stop the pilot immediately if any of the following occurs:

1. a critical manifest field requires nonpublic or post-cutoff information
2. independent reruns change split eligibility and the disagreement cannot be resolved by prespecified rules
3. no public-data baseline can be reproduced or justified
4. a source-rights blocker removes a critical evidence path without a lawful fallback
5. the work drifts toward shadow deployment, disclosure, or partner operations

## Pilot-to-definitive contamination boundary

- Pilot artifacts exist to decide feasibility, not to support confirmatory performance claims.
- If pilot cases are later reused, that reuse must be disclosed explicitly and the definitive study must preserve a separate frozen confirmatory design.
- Any redesign triggered by the pilot invalidates downstream design assumptions built on the failed surface.

## Required follow-on evidence if green

If the pilot passes green criteria, the next gate request should include:

1. a versioned benchmark-core protocol
2. a design and analysis plan
3. a source-rights ledger
4. a clean baseline reproduction log
5. an independent methods/statistics challenge memo

## Explicit exclusions

- no prospective cohort
- no responsible-disclosure execution
- no partner data
- no human analysts or participant workload study
- no publication-readiness claim

## Execution record for pilot cycle 1

The authorized cycle instantiated the plan with an eight-case information-sufficiency cohort in `support/pilot-cohort.csv`. The frozen pilot rules and resulting admissibility manifest are in `support/pilot-rules.md` and `support/admissibility-manifest-pilot.csv`.

MANDO-LLM was not executed because the checked public repository did not expose a verified license and frozen artifact path. A pinned Slither `0.11.6` environment at source revision `050cc0a094e77bfd58e8228ae3bb6aa15c65edb4` was used as the lawful substitute baseline after static security preflight. This substitution tests reproducible benchmark plumbing only; it does not turn Slither into an equivalent model or support the capability-survival hypothesis.

Repository tests, exploit replays, RPC calls, live-chain actions, submodules, Docker builds, CI helpers, and download-and-execute paths remained excluded. The source-rights and resource outcomes, exact denominators, output hashes, and unresolved archival gaps are recorded in `pilot-results.md`.

The independent challenge to the execution wave is preserved separately in `support/independent-assignment-rerun-20260801.md`. That rerun leaves split eligibility unchanged for `8/8` rows and localizes the remaining status-rubric dispute to `CA-P08`.

## Execution record for pilot cycle 2

Cycle 2 was limited to the named recovery surfaces. The primary-link audit is
preserved in `support/pilot-cycle2-public-provenance.md`, the new immutable
manifest revision is `support/admissibility-manifest-pilot-cycle2.csv`, and the
provider evidence is `support/archive-access-cost-envelope-20260801.csv`.

The cycle recovered pre-cutoff deployment or primary documentation evidence for
`CA-P04`–`CA-P07`, but no incident case reached full prediction-time
admissibility. For `CA-P08`, the formal proof compiler (`0.6.8`) differs from
the deployed exact-match compiler (`0.6.11`) and the follow-up was not
prospectively frozen. The case is therefore `RIGHT_CENSORED_UNRESOLVED` rather
than a mature negative.

No account, API, RPC, BigQuery, paid service, live target, transaction, or replay
was used. Documented free and low-cost archive routes make the resource question
bounded, but not empirically verified. Cycle 2 therefore retains `PILOT_FIRST`;
it does not authorize `STUDY_DESIGN`.

## Execution record for pilot cycle 3

The user separately authorized one minimal archive or equivalent public-data
access test, one representative end-to-end real-case manifest attempt, and one
genuinely prespecified mature-negative trial. The exact authority and retained
exclusions are append-only in `00-governance/decision-log.md`.

For `CA-P04`, exactly two `eth_getCode` requests were attempted through the
Cloudflare public trial route: cutoff block `4043798` (`0x3db416`) and `latest`.
Both failed at DNS resolution before an HTTP or JSON-RPC response. The route was
therefore exercised but did not retrieve historical bytecode. No retry, fallback
provider, credential, account, or paid path was used.

The real-case manifest attempt is preserved as a new immutable cycle-3 revision.
`CA-P04` remains `HOLD_RECOVERABLE` because the failed transport attempt closes
none of the source, bytecode-to-source, proxy, compiler, clone, or lineage fields.

`CA-P09` freezes a public-data-only status trial for the Ethereum Uniswap v4
`PoolManager`. Its target, public source/security evidence, property set,
365-day follow-up, search schedule, outcome rules, and independent adjudication
requirement were fixed before follow-up. It is currently
`RIGHT_CENSORED_UNRESOLVED` and cannot enter a mature-negative denominator before
`2027-08-01T19:28:31Z`.

Cycle 3 remains a feasibility result. It does not authorize a prospective cohort,
shadow deployment, operational monitoring, disclosure execution, or
`STUDY_DESIGN`.
