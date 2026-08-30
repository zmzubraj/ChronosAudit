# Problem Investigation

## Practical problem

Historical exploit benchmarks commonly treat each row as an independent task and often anchor execution at a historical fork block. That is sufficient for replay but not, by itself, for a pre-incident measurement study. Three hidden dependencies can change what a benchmark can support:

1. **temporal availability** — a contract must already exist at a claimed pre-incident landmark;
2. **code-family dependence** — different addresses can contain identical or metadata-equivalent runtime code; and
3. **proxy dependence** — a proxy address can delegate behavior to a separate implementation or beacon.

Ignoring these layers can overstate usable sample size, independence, and diversity. The audit is therefore a validity analysis of the cohort, not an exploit detector.

## Causal bottleneck

The benchmark row is an incident/task identity, but the relevant unit for many scientific claims may instead be a deployed address, a runtime-code family, or an implementation family. A mismatch between the row identity and the scientific unit creates pseudo-replication. Separately, a pre-incident landmark that predates deployment is structurally impossible for that row.

## Useful negative result

The paper remains useful if dependence is small: it would bound the magnitude of clone/proxy leakage in the current 417-case cohort and document landmark-specific coverage. It also remains useful if the joint novelty claim is defeated; the deterministic audit can be released as a technical validation note with narrower wording.

## Scope exclusions

- no exploit-success or model-performance analysis;
- no matched controls or causal risk estimate;
- no claim that bytecode identity proves shared authorship or identical state;
- no attempt to resolve every proxy standard, diamond facet, metamorphic contract, or historical upgrade path;
- no generalization from the exploit cohort to all deployed EVM contracts.
