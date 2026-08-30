# Prior-Art Search Protocol

## Cutoff and surfaces

- Search cutoff: 2026-08-29 (Asia/Dhaka).
- Surfaces: arXiv, publisher/DOI landing pages, official benchmark repositories, official Ethereum Improvement Proposals, and backward/forward references visible from the strongest predecessors.
- Languages: English.
- Access boundary: public metadata and openly accessible full text only; Scopus, Web of Science, IEEE full-text subscription search, patents, and closed workshop proceedings were not comprehensively searched.

## Query families

1. `smart contract exploit benchmark historical state reconstruction EVM benchmark bytecode clone proxy`
2. `SCONE-bench 417 historical incidents dataset`
3. `smart contract benchmark duplicate contracts bytecode metadata stripping dataset leakage`
4. `code cloning smart contracts Ethereum empirical study`
5. `EIP-1898 historical state EIP-1967 proxy EIP-1167 minimal proxy`
6. strongest-predecessor names plus “duplicate,” “contamination,” “historical fork,” “proxy,” and “clone.”

## Known-item recovery

The search must recover SCONE-bench, EVMbench, Re-Evaluating EVMbench, CyberChainBench, DIVE, ERC-1898, ERC-1967, ERC-1167, and the 2023 IEEE TSE extended replication study on smart-contract code cloning. These items were recovered.

## Screening rule

Include work that addresses at least one of: exploit-benchmark construction, historical EVM state/replay, benchmark contamination/dependence, smart-contract duplicate/clone measurement, metadata-stripped bytecode identity, or proxy/implementation discovery. Exclude generic vulnerability detectors without a dataset-validity or identity contribution.

## Search limitations

The root investigator performed both the primary search and a hostile self-challenge because delegation was not authorized. Therefore, the required differently owned independent challenge remains open, and novelty cannot be certified beyond `POTENTIALLY_DIFFERENTIATING`.
