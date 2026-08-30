# ChronosAudit Power or Precision Blueprint

## Target

Design the study for decision-relevant precision of `Delta_joint` and `Precision@Budget` under the strict `R4_JOINT` split, not for a favorable p-value.

## Assumptions

The number of eligible incidents, independent family blocks, base rate, censoring fraction, within-block dependence, and alert budget are unresolved. Existing pilot plumbing does not supply a scientific effect size and must not be used unshrunk as a power input.

## Calculation

Before execution, simulate or analytically evaluate interval width across conservative grids of eligible positive counts, joint blocks, censoring fractions, alert budgets, and plausible precisions. Freeze a maximum acceptable 95% interval width for `Delta_joint` and a minimum number of independent blocks per rung. Report the full design curve rather than one optimistic sample-size number.

## Decision

No precision target is currently authorized or verified. If the attainable interval cannot distinguish a decision-relevant drop from sampling noise, narrow the goal to a descriptive feasibility/contamination audit or stop the performance claim.

## Sensitivity

Recalculate under higher censoring, lower incident yield, stronger clustering, sample loss at `R4`, and zero surviving signal. Require a design that remains informative as a negative study.
