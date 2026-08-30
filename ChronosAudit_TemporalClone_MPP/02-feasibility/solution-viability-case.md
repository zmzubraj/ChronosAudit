# Solution Viability Case

## Exact claim

The MPP can produce a reproducible descriptive audit of the frozen 417-case SCONE-bench cohort using existing, read-only historical snapshot evidence.

## Evidence ladder

- **V0 ASSERTED:** joint temporal/identity audit proposed.
- **V1 ANALYTIC:** estimands and identity rules defined; existing envelope fields map to every variable.
- **V2 REPRODUCED:** deterministic script validated all 417 inputs and reproduced the result summary from a hash-bound manifest.
- **V3 INTERNAL:** pending qualified human review of scientific meaning and edge cases.
- **V4 EXTERNAL:** not claimed; no external reproduction has been completed.
- **V5 FIELD:** not applicable to a cohort-validity audit without broader field claims.

## Failure envelope

The analysis detects only exact address/bytecode equality, metadata-stripped equality already recorded in the source snapshots, and observable ERC-1967/beacon/ERC-1167 indicators. It does not identify semantic clones, diamonds, custom proxy slots, metamorphic histories, historical implementation upgrades outside the snapshot, or shared developer provenance. Consequently, its dependence estimates are lower-bound measurements under the specified abstractions.

## Decisive viability threshold

Viability requires: 417 unique verified inputs, two provider families per case, closed strict snapshots, no case blockers, monotone deployment/cutoff/incident timestamps, nonmissing bytecode hashes, deterministic rerun, and a manuscript claim no stronger than the measurements. The current local derivation meets the mechanical threshold; independent scientific verification remains open.
