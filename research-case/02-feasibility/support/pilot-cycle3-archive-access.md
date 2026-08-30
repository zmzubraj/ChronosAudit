# Pilot cycle 3: authorized minimal historical-state access test

## Frozen scope

- Run: `chronosaudit-20260801T105039Z-e7e2c21c-64e42a`
- Case: `CA-P04`
- Target: `0xBEc591De75b8699A3Ba52F073428822d0Bfc0D7e`
- Cutoff block: decimal `4043798`, JSON-RPC quantity `0x3db416`
- Route: Cloudflare's documented public trial endpoint, `https://web3-trial.cloudflare-eth.com/v1/mainnet`
- Requests: exactly one `eth_getCode` request at the cutoff and one at `latest`
- Excluded: retries, fallback providers, account creation, credentials, paid access, transactions, scanning, replay, or any method other than the two frozen reads

## Method basis

Ethereum's JSON-RPC documentation defines `eth_getCode(address, block)` and
accepts a block quantity or `latest`. Cloudflare's current node-type
documentation states that its Ethereum Gateway provides archive-node access and
lists `eth_getCode` among the historical state methods. Cloudflare's usage guide
publishes the shared trial URL used here. These documents establish a plausible
method and endpoint; they do not guarantee that the endpoint resolves from this
workspace or that a shared trial endpoint is a durable production dependency.

## Observed result

Both requests were attempted once at `2026-08-01T19:25:47Z`. Both terminated
with curl exit code `6`, HTTP status `000`, and the exact transport error
`Could not resolve host: web3-trial.cloudflare-eth.com`. No HTTP response body or
JSON-RPC result was received.

| Request | Raw record | Result |
|---|---|---|
| cutoff `0x3db416` | `archive-test-ca-p04-cutoff.json` | DNS failure; no historical bytecode |
| `latest` | `archive-test-ca-p04-latest.json` | DNS failure; no current bytecode |

## Scientific interpretation

The access path was genuinely exercised and is therefore no longer
`NOT_EXECUTED`. The result is a measured access failure in this environment,
not evidence that Ethereum archive data is unavailable in general and not
evidence about the target bytecode. Because the authorized test was restricted
to one route, no retry or provider substitution was performed.

The cost/access criterion remains `AMBER`: the method is documented and the
incremental request cost was zero, but operational access was not demonstrated.
`CA-P04` remains `HOLD_RECOVERABLE`; the attempted route closes no source,
bytecode-to-source, proxy-family, compiler, or lineage field.

## Evidence boundaries

- Direct observation: two DNS failures and no RPC bodies.
- Documentary evidence: Cloudflare and Ethereum method documentation.
- Unsupported and therefore not claimed: archive availability from this
  workspace, historical bytecode identity, source publication timing, compiler
  binding, proxy or implementation lineage, and split eligibility.

## Source URLs

- https://ethereum.org/developers/docs/apis/json-rpc/
- https://developers.cloudflare.com/web3/ethereum-gateway/concepts/node-types/
- https://developers.cloudflare.com/web3/how-to/use-ethereum-gateway/
