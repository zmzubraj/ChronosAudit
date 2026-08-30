# Protocol: Temporal and Identity Dependence Audit

## Design

Retrospective, full-cohort, descriptive measurement of 417 counter-authorized historical snapshot envelopes corresponding to the current SCONE-bench task list. The source files are read-only and are frozen by `04-data/provenance-manifest.csv`.

## Unit of observation

One benchmark case envelope. Results are reported under four identity abstractions:

1. chain-address: lowercase `chain:address`;
2. address-only: lowercase 20-byte contract address;
3. exact runtime: source-provided SHA-256 of runtime bytecode at the strict snapshot;
4. metadata-stripped runtime: source-provided SHA-256 after the source pipeline's metadata handling.

The last two are exact fingerprint collisions, not semantic-clone judgments.

## Temporal landmarks

For landmark `L` hours before the recorded incident, a case is eligible iff:

`incident_timestamp - deployment_timestamp >= L * 3600`.

The prespecified values are 1, 24, 168 (7 days), and 720 hours (30 days). This variable asks whether the target contract existed at the landmark. `cutoff_lead_hours` is reported separately and is not used to determine landmark existence.

## Proxy indicators

Report non-null normalized values from the snapshot's ERC-1967 implementation slot, admin slot, beacon slot/beacon implementation, and ERC-1167 target. The primary “any proxy indicator” union includes implementation, beacon, or ERC-1167 target; admin is reported separately because an admin value alone does not establish the active implementation path.

## Inclusion contract

Every file must have top-level and nested closed-snapshot flags, status `VERIFIED`, no blockers, exactly the provider families `alchemy` and `infura`, consistent case identifiers, monotone timestamps, timestamp-consistent cutoff lead, and nonmissing runtime hashes. Any violation stops the run.

## Safety and integrity

No network calls, live-chain interactions, secret use, model execution, or exploit replay occur. Results remain aggregate/descriptive. Address-level rows are preserved locally but are not automatically authorized for external release.
