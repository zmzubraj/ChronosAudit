# Stage 2 Latest Evidence Audit

Date checked: 2026-08-17

## Scope and authority boundary

This audit checks the latest local Stage 2 evidence and counter documents. It does not treat AI output, reviewer packets, or public blockchain data as independent human adjudication. It does not promote any release gate that lacks its required evidence.

## Historical snapshot finding

The stated 360/417 baseline was superseded by a sealed cohort revision. The current authoritative historical package contains 360 retained parent cases and 57 deterministic replacements. Its independent offline verifier reports:

- observed: 417
- required: 417
- counter authority: true
- integrity errors: none
- scientific blockers for this counter: none
- chain distribution: Ethereum 181, BSC 226, Base 9, Arbitrum 1

No continuation from ordinal 361 and no further RPC acquisition is required for the historical-snapshot counter. Re-reading those 57 cases would duplicate already sealed evidence and would not improve the independent-adjudication counter.

## Projection repair

The revised-v4 historical verifier was valid, but the later public counter manifest omitted its `historical_snapshot_verification` binding when the 20,000-row denominator was projected. The public projection was regenerated offline with the sealed run root explicitly supplied. The independent public-acquisition verifier then reported a structurally valid package with no integrity failures.

Current counters:

| Counter | Observed | Required | Status |
| --- | ---: | ---: | --- |
| Historical snapshots | 417 | 417 | PASS |
| Deployment denominator | 20,000 | 20,000 | PASS; 5,000 per chain |
| Independent human adjudications | 0 | 417 | BLOCKED; external human authority required |
| Independently AI adjudicated | 417 | 417 | COMPLETE; separate non-human counter |
| AI internal-progression gate | reliability 0.6667 / 0.6763 | at least 0.80 / 0.80 | FAIL_RELIABILITY_THRESHOLD |
| Control candidates | 0 | 4,170 | BLOCKED |
| Qualified controls | 0 | 4,170 | BLOCKED |
| Independent R5 blocks | 0 | 120 | BLOCKED |
| Release-eligible cases | 0 | greater than 0 | BLOCKED |

## Independent adjudication disposition

The 417 deterministic positive-case reviewer packets are preparation artifacts only. The counter remains 0/417 until each case has two conflict-cleared reviewers with distinct accountable ownership, preserved decision artifacts and confidence, schema and case-hash binding, an agreement disposition, and a distinct accountable third adjudicator for disagreements. AI-generated reviews, simulated identities, public labels, and same-owner reviewers remain non-qualifying.

The current reviewer-independence artifact is correctly `waiting_external`. No reviewer identities or decisions were fabricated.

The reviewer intake contract was hardened during this audit. A qualifying row must now also bind each reviewer to a packet SHA-256, preserve UTC start and completion timestamps with a positive review interval, and preserve a final-decision timestamp at or after both reviews. A disagreement additionally requires the third adjudicator's packet hash and UTC review interval, with finalization at or after that review. These fields participate in the final input-binding hash.

The audit also fixed a counter-path defect: `finalized_positive_adjudications.json` was manifest-bound but was not overlaid onto the positive-case rows before projection. Valid external decisions can now increment their covered cases, while duplicate cases, unexpected cases, and packet hashes that do not match the deterministic same-case packet fail closed.

## Human-review handoff package

The revised-v4 report directory now contains a manifest-bound external handoff for all 417 cases:

- `positive_case_review_packets.json`: the deterministic evidence payload and packet SHA-256 for each case
- `reviewer_a_response_template.json`: 417 packet-bound response slots
- `reviewer_b_response_template.json`: 417 packet-bound response slots
- `human_adjudication_protocol.json`: identity, ownership, conflict, timing, confidence, hashing, agreement, and third-adjudicator rules
- `human_adjudication_handoff_manifest.json`: artifact paths and SHA-256 values

Its status is `ready_for_external_human_assignment`. This is operational readiness only and has no counter effect until eligible humans complete and return valid artifacts.

## Separate AI-only adjudication track

The versioned `AI_ONLY_TRIANGULATION_V1` track is integrated as a core Stage 2 step without changing human authority. Its frozen evidence package excludes `mechanism_raw`, downstream review decisions, outcome adjudication IDs, and final labels. A read-only DeFiHackLabs checkout was frozen at commit `2c99b565ae24ea2006adf181da20c4419b3edc30`; 357/417 packets contain the pinned exploit-source bytes and SHA-256, while the remaining 60 are constrained to an explicit unknown disposition when packet evidence is inadequate.

Execution evidence:

- primary A: 417/417 valid blinded decisions
- primary B: 417/417 valid blinded decisions
- independent-primary agreements: 274
- disagreements with distinct third-model resolution: 143/143
- alternate-prompt sensitivity decisions: 417/417
- final valid AI dispositions: 417/417
- validation errors: 0
- accountable-author current-task attestation: hash-bound and verified, with no external identity-proof claim
- human counter effect: `NONE`; independent human adjudications remain 0/417

Reliability did not pass the frozen threshold. Protocol-family raw agreement is 0.6667 (Cohen kappa 0.1666; Gwet AC1 0.6577; nominal Krippendorff alpha 0.1496). Root-cause raw agreement is 0.6763 (Cohen kappa 0.1973; Gwet AC1 0.6711; nominal Krippendorff alpha 0.1790). Alternate-prompt stability is 0.7866. Consequently, the AI counter is complete but the internal progression gate is `FAIL_RELIABILITY_THRESHOLD` and grants no permissions. Third-model adjudication preserves complete dispositions; it does not rewrite the pre-adjudication reliability result.

## Verification evidence

Commands executed:

```text
./.venv/bin/python run_public_evidence_acquisition.py project --output-root . --revision 2026-08-11 --run-id public-acquisition-historical-revision-v4 --historical-snapshot-run-root raw/historical_snapshots/2026-08-11/historical-snapshots-417-revised-v4
./.venv/bin/python verify_public_evidence_acquisition.py --output-root . --revision 2026-08-11 --run-id public-acquisition-historical-revision-v4
./.venv/bin/python -m pytest -q tests/test_public_acquisition_counters.py tests/test_public_acquisition_cli.py tests/test_external_stage2_focus.py tests/test_stage2_upgrade.py
```

Observed verification:

- public-acquisition structure valid: true
- public-acquisition integrity failures: none
- separate independently AI-adjudicated counter: 417/417, zero invalid rows
- AI internal-progression gate: `FAIL_RELIABILITY_THRESHOLD`
- manifest-bound human-adjudication handoff: 417/417 packets verified
- public-acquisition scientifically complete: false
- public-acquisition release ready: false
- adjudication, counter, CLI, and Stage 2 workflow tests: 114 passed
- timestamp and packet-binding subset: 15 passed, 78 deselected
- production qualification: expected fail-closed exit 3; historical snapshots and denominator pass, all unresolved scientific gates remain false
- full workspace suite: 490 passed and 10 failed in 480.64 seconds. Nine failures depend on the missing ephemeral fixture `/tmp/defihacklabs-inventory.fyfvOY/staging`; one legacy Sourcify fixture uses the invalid short address `0xABC` after strict 20-byte address validation was introduced. None of the 10 failures is in the projection or adjudication-contract paths changed by this audit, but the full suite is not green and this remains an explicit QA limitation.

## Current artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/public_acquisition_counter_inputs.json` | `c04074e7c09ee5dac2b436da4962c2f88a79c8c94da22b63b9faa5c1e1b51324` |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/public_acquisition_counters.json` | `51cf0b260ef0fdd275f97699db3ed95c41db09f5f2f3c350249d246d53550fdc` |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/verification.json` | `c8d300a071b54bb11d8f3ec8db34858283fca25fcfc9a342bb3bc88aac0286b4` |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/human_adjudication_handoff_manifest.json` | `cd259f199642d369c7601a062ff2b41601596be31323155f612127d4836c0370` |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/ai_only_adjudication/ai_adjudication_manifest.json` | `1d4d0d392aee02322a653df6ea4c21a5e3972005c9f3c891a08c863f403cda6c` |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/ai_only_adjudication/ai_adjudication_results.json` | `8df048b5437c02a587259bdd935a44c7d5faf987e40ee5152bc4c717db008847` |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/ai_only_adjudication/ai_adjudication_summary.json` | `cfa340d8d5c3aea76291eef8694bd3ceb8940e42c9035f0b6c6246b7ff35a4fb` |
| `reports/public_acquisition/2026-08-11/public-acquisition-historical-revision-v4/ai_only_adjudication/accountable_author_signoff.json` | `9a09bb5846624e6d1a5b32b8c5df4cf2f3df8e95e9b64bdfc3c493d3d62e2a18` |
| `reports/production_qualification.json` | `0b32cefdd19e748a834e1672913a0b4dac70f09da709bd292c1e84f6e673c56f` |
| `reports/historical-snapshots-417-revised-v4-verification/historical_snapshot_verification_report.json` | `54b83b1abff09e99049aa5cd89fd78bae95d90c0408f8f5edd268904a0bea3f4` |
| `raw/cohort_finalizations/2026-08-11/defihacklabs-temporal-replacements-final-v1/finalization_manifest.json` | `42d9cc611ea261f9305a5ffac700dad1e945ce20085cd9c574e047a08e1b3b0b` |

## Remaining external action

To advance independent human adjudications, an accountable human coordinator must bind two genuinely independent, conflict-cleared reviewers to every case and arrange a separately owned third adjudicator for disagreements. The completed human artifacts can then be imported and reprojected through the existing fail-closed counter path. Public blockchain APIs cannot satisfy this human-authority gate.

To pass the separate AI internal-progression gate, a new protocol revision would need a prospectively justified remediation that improves evidence adequacy or model/prompt reliability without tuning against seed labels. The current failed reliability result must remain immutable and disclosed; it cannot be overwritten by post-hoc consensus seeking.
