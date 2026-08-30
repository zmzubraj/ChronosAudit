# ChronosAudit Intake Authority Matrix

> Status: advisory governance draft for intake continuation. This artifact does not grant legal, ethics, institutional, disclosure, or submission authority. It cannot satisfy the schema-v4 requirement for independently signed authority or scientific-verifier evidence by itself.
>
> Informational note: this is a research-governance template, not legal advice. Jurisdiction-specific questions require qualified counsel and the accountable institution.

## Purpose

Translate the ChronosAudit blockers into explicit stage-by-stage authority requirements so the research case can continue without implying that missing approvals already exist.

## Stage matrix

| Stage | Scope | Current status | Accountable authority required before execution | Minimum evidence or artifact required | May AI prepare? | May AI approve? | Smallest responsible next action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A | Public-source methods and preregistration drafting | AUTHORIZED within current safe route | Accountable human scope owner | Existing charter, study profile, and public-source-only egress policy | Yes | No | Keep work limited to public methods, protocol, and governance artifacts |
| B | Historical archive/RPC execution and retrospective benchmark construction | NOT AUTHORIZED | Accountable human plus institution or operator if terms, rights, or restricted infrastructure apply | Source-by-source rights ledger, archive/RPC terms review, approved execution plan, and independent verifier for the intake gate | Yes | No | Freeze the exact archive/RPC sources, rights basis, and operator constraints before any execution |
| C | Human analyst workload measurement or participant-style review tasks | NOT AUTHORIZED | Institution or ethics authority if analysts are studied or identifiable performance/workload data are collected | Written determination that the planned activity is exempt, waived, or approved; participant/data handling plan if applicable | Yes | No | Separate benchmark simulation from any human-subjects or personnel-measurement component and obtain a formal determination |
| D | Private vulnerability handling, partner coordination, or responsible-disclosure workflows | NOT AUTHORIZED | Accountable human, legal or policy authority, and disclosure partner as applicable | Responsible-disclosure protocol, partner authorization, confidentiality boundary, and contact/escalation plan | Yes | No | Draft the disclosure protocol only; do not receive or process nonpublic vulnerability material |
| E | Sealed prospective shadow deployment | NOT AUTHORIZED | Accountable human, institutional or organizational authority, partner authorization, and independent adjudication path | Frozen cohort and thresholds, disclosure plan, adjudicator commitment, rights/access package, and explicit go decision | Yes | No | Treat prospective deployment as a later extension gated behind a separate authority package |
| F | Manuscript submission, release, or external dissemination beyond current public safe-route drafting | NOT AUTHORIZED | Accountable human authors, institution if applicable, and venue-specific submission authority | Final approved manuscript, verified references, disclosure and authorship package, venue checklist, and explicit submission decision | Yes | No | Preserve `submission_performed: false` until all blocking scientific and governance gates are independently complete |

## Case-specific evidence already available

- Current public-safe-route authority is documented in `00-governance/program-charter.md`.
- The current schema-v4 study profile explicitly states that archive/RPC access, prospective deployment, analyst-participant work, disclosure operations, and submission are outside present authority in `00-governance/study-profile.json`.
- The current egress boundary permits only `public_web` and forbids nonpublic exploit details, credentials, participant data, and proprietary code in `00-governance/egress-policy.json`.
- The protocol artifact explicitly marks execution as `NOT RUN` and not authorized in `03-design/protocol.md`.

## Decision rule

Until a stage-specific authority artifact is independently signed and verified, the stage remains `WAIT_EXTERNAL` even if AI has prepared the draft materials needed for review.

## Non-authorizations

This matrix does not:

- authorize live-chain or target interaction;
- authorize access to partner, customer, or proprietary data;
- authorize private vulnerability receipt, storage, or disclosure;
- establish that no ethics, legal, export-control, sanctions, contract, or institutional review is required;
- satisfy the independent verifier gate for schema-v4 scientific or authority decisions.
