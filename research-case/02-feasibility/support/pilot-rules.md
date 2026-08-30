# ChronosAudit feasibility-pilot assignment rules

These rules are frozen for the bounded pilot only. They are a feasibility test,
not the definitive benchmark protocol.

## Information admissibility

1. A prediction-time field is admissible only when its content and public
   availability can be evidenced at or before the case cutoff.
2. Incident post-mortems, exploit transactions, replay files, later annotations,
   and later source verification may support the outcome label but never the
   prediction input.
3. A real case is split-eligible only if target identity, deployment/cutoff time,
   source or bytecode at cutoff, protocol/entity lineage, normalized code-clone
   family, proxy/implementation family, exploit-mechanism family, outcome status,
   and a lawful storage/analysis disposition are all auditable.
4. A curated or synthetic fixture can test tooling but is never counted as a
   pre-incident protocol observation.
5. Missing historical source, bytecode, proxy implementation, or timestamp
   evidence makes a case `HOLD_RECOVERABLE` when a named public/archive route
   plausibly exists, and `EXCLUDE` when no lawful route is identified.

## Mechanism assignment

- Assign the narrowest causal mechanism supported by direct code, transaction,
  replay, formal specification, or public incident evidence.
- Do not equate a detector taxonomy label with an exploit-mechanism family.
- Preserve multi-mechanism cases and record the primary split family separately.
- A disagreement that changes mechanism-family holdout eligibility is material.

## Outcome status

- `CONFIRMED_POSITIVE`: a public incident and attributable target/exploit evidence
  are available; post-cutoff evidence is label-only.
- `MATURE_INVESTIGATED_NEGATIVE`: only for an enumerated property set, with
  documented audit/formal/investigative evidence available before the cutoff and
  a prespecified follow-up window. It is never a global claim of safety.
- `RIGHT_CENSORED_UNRESOLVED`: follow-up ends without adequate evidence for either
  status; absence from an incident list is not a negative label.
- Fixtures retain their annotated label but do not enter population denominators.

## Rights disposition

- Repository/tool licenses apply only to works they actually cover.
- SmartBugs contract files retain original licenses; this pilot stores hashes,
  paths, and derived detector output only and does not redistribute those sources.
- DeFiHackLabs files may be used locally under Apache-2.0, but embedded or linked
  upstream protocol sources remain source-specific.
- Sourcify source-display permission is not treated as blanket redistribution
  permission. Ambiguous source code remains link/metadata-only.
- MANDO-LLM remains metadata-only until a retrievable license and artifact path
  are verified.
