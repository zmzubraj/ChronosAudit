# ChronosAudit pilot cycle 2: public prediction-time provenance audit

## Scope and authority

- Run: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Audit date: `2026-08-01`
- Cases: `CA-P04` through `CA-P08`
- Authority: public pages, public repositories, link-level metadata, and local
  derived records only
- Excluded: RPC calls, account creation, paid-provider use, automated scraping,
  live-target interaction, transaction submission, exploit replay, nonpublic
  data, outreach, and prospective deployment

This is a feasibility and information-admissibility audit. It is not a detector
evaluation and contains no efficacy result.

## Decision rule

A public page may close a field only when its content or immutable on-chain fact
is demonstrably available no later than the case cutoff. A current explorer
page, present-day proxy resolution, or post-cutoff source verification may
identify a recovery route, but it cannot establish prediction-time source or
implementation availability. A formal proof binds to a deployed contract only
when the compiled artifact, compiler version, settings, and deployed bytecode
are matched under the frozen rule.

## Incident-case audit

| Case | Prediction-time evidence recovered | Evidence that remains inadmissible as prediction input | Cycle-2 disposition | Residual critical gap |
|---|---|---|---|---|
| `CA-P04` Parity wallet | The Etherscan creation transaction is timestamped `2017-05-29 12:01:35 UTC`, before cutoff block `4043798`, and closes deployment provenance. | The current address page is unverified for source. No pre-cutoff source or proxy-family binding was established. | `HOLD_RECOVERABLE` | Prediction-time source, bytecode-to-source, and proxy-family binding. |
| `CA-P05` Nomad Replica | The creator transaction is timestamped `2022-04-21 18:00:05 UTC`. Nomad's primary Replica documentation records a `2022-06-26` update and links to `Replica.sol`, both before cutoff block `15259099`. | The current explorer resolves a present implementation; it does not prove the pre-cutoff proxy-to-implementation edge or upgrade time. | `HOLD_RECOVERABLE` | Pre-cutoff proxy implementation and upgrade-timestamp binding. |
| `CA-P06` Euler | The creator transaction is timestamped `2021-11-29 23:52:22 UTC`, before cutoff block `16817994`, and current explorer metadata exposes deployed bytecode. | The current page does not establish when verified source became public, and no pre-cutoff official lineage/source record was bound. | `HOLD_RECOVERABLE` | Prediction-time source availability and protocol-lineage binding. |
| `CA-P07` Curve pETH pool | The creator transaction is timestamped `2022-09-27 15:37:11 UTC`, before cutoff block `17806054`, and the current explorer exposes a verified proxy-style surface. | The official Curve page found in this pass is post-incident. Current lineage and implementation metadata cannot prove pre-cutoff Curve lineage or compiler provenance. | `HOLD_RECOVERABLE` | Prediction-time protocol lineage, compiler, and implementation binding. |

Primary links checked:

- `CA-P04`: [address](https://etherscan.io/address/0xBEc591De75b8699A3Ba52F073428822d0Bfc0D7e), [creation transaction](https://etherscan.io/tx/0x63aa819d9e6058020468a161dd2934ef4200804fa181adfd7983c8da91ec4881)
- `CA-P05`: [proxy](https://etherscan.io/address/0x5d94309e5a0090b165FA4181519701637B6DAEBA#code), [creation transaction](https://etherscan.io/tx/0x99662dacfb4b963479b159fc43c2b4d048562104fe154a4d0c2519ada72e50bf), [Nomad Replica documentation](https://docs.nomad.xyz/the-nomad-protocol/smart-contracts/replica)
- `CA-P06`: [address](https://etherscan.io/address/0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34#code), [creation transaction](https://etherscan.io/tx/0x6f8ae97657668abf965cc627dfa4355e2dd9366d58aaf587e54be60e008ec1ef)
- `CA-P07`: [address](https://etherscan.io/address/0x9848482da3Ee3076165ce6497eDA906E66bB85C5#code), [creation transaction](https://etherscan.io/tx/0x659f0eb12c4edf042be41885ed1a8bc78b0a2e87ca47339031b9253cd7ae61ce), [current Curve proposal](https://www.curve.finance/dao/ethereum/proposals/389-OWNERSHIP)

## `CA-P08` formal-evidence binding audit

Strong pre-cutoff public provenance was recovered:

1. The Ethereum Foundation's `2020-06-23` update identifies the Solidity
   deposit contract, its expert review, formal verification, and bug-bounty
   inclusion, and links the source and verification repositories.
2. Runtime Verification's artifact records bytecode verification for Solidity
   `0.6.8` with optimizer runs `5,000,000`.
3. The Ethereum consensus-specifications `v1.0.0` deposit-contract JSON contains
   the production creation bytecode whose metadata identifies Solidity
   `0.6.11`.
4. The Ethereum Foundation's `2020-11-04` release announces the v1.0
   specifications and mainnet deposit address
   `0x00000000219ab540356cBB839Cbe05303d7705Fa`.
5. The current exact-match explorer record identifies compiler
   `v0.6.11+commit.5ef660b1` and optimizer runs `5,000,000`.

The formal proof therefore does not bind exactly to the deployed artifact under
the frozen ChronosAudit rule: proof compiler `0.6.8` differs from deployed
compiler `0.6.11`. In addition, no prospective follow-up search and maturity
window were frozen for this negative trial. `CA-P08` is consequently assigned
`RIGHT_CENSORED_UNRESOLVED` and remains `HOLD_RECOVERABLE`; it is not a mature
negative or a global safety claim.

Primary links checked:

- [Ethereum Foundation update 12](https://blog.ethereum.org/2020/06/23/eth2-quick-update-no-12)
- [Solidity deposit-contract source repository](https://github.com/axic/eth2-deposit-contract)
- [Runtime Verification artifact](https://github.com/runtimeverification/deposit-contract-verification)
- [Runtime bytecode-verification settings](https://github.com/runtimeverification/deposit-contract-verification/tree/master/bytecode-verification)
- [Consensus specifications v1.0.0 Solidity source](https://github.com/ethereum/consensus-specs/blob/v1.0.0/solidity_deposit_contract/deposit_contract.sol)
- [Consensus specifications v1.0.0 production JSON](https://github.com/ethereum/consensus-specs/blob/v1.0.0/solidity_deposit_contract/deposit_contract.json)
- [Ethereum Foundation v1.0 and deposit-address announcement](https://blog.ethereum.org/2020/11/04/eth2-quick-update-no-19)
- [Exact-match deployed contract record](https://etherscan.io/address/0x00000000219ab540356cBB839Cbe05303d7705Fa#code)

The earlier Runtime Verification post about a Vyper version is historical
context only and is not treated as the proof of the deployed Solidity version:
[Vyper verification post](https://runtimeverification.com/blog/end-to-end-formal-verification-of-ethereum-2-0-deposit-smart-contract).

## Access and cost audit

The provider-level audit is preserved in
`archive-access-cost-envelope-20260801.csv`. It establishes bounded candidate
routes, not actual account or RPC access:

- current metadata sources alone cannot close all prediction-time fields;
- a hybrid of public metadata, an archive-state route, and source-publication
  provenance is required;
- Alchemy and Infura expose free archive-capable paths, BigQuery exposes a
  low-cost corroboration path, and QuickNode and Chainstack expose paid or
  trial routes under their current public documentation;
- no provider account was created and no API or RPC request was made in this
  cycle.

The cost/access criterion is therefore bounded `AMBER`, not `GREEN`: a small
pilot query has a documented low-cost route, but access, terms, runtime, and
case coverage were not empirically exercised under the current authority.

## Denominators and gate implication

- Incident provenance cases reviewed: `4/4`.
- Incident cases promoted to split-eligible: `0/4`.
- Incident cases retained as recoverable holds: `4/4`.
- Negative-trial cases reviewed: `1/1`.
- Negative-trial cases promoted to mature negative: `0/1`.
- All real cases split-eligible after cycle 2: `0/5`.
- All real cases with a named recovery route: `5/5`.

Cycle 2 closes specific deployment, documentation, formal-artifact, and cost
unknowns, but it does not satisfy the benchmark-core manifest-completeness
criterion. The feasibility decision remains `PILOT_FIRST`; `STUDY_DESIGN`
remains closed and the prospective extension remains `BLOCKED`.

