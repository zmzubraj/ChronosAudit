# ChronosAudit feasibility-pilot execution ledger

## Boundary

This ledger records the bounded public-data-only pilot cycle executed on
`2026-08-01`. It is feasibility evidence, not detector-performance evidence.
No replay, RPC call, transaction, live-target action, submodule, container,
repository test, or third-party disclosure action was executed.

## Frozen external revisions

| Repository | Revision | Use |
|---|---|---|
| `SunWeb3Sec/DeFiHackLabs` | `311184fef6b995be019f6729c2bae279228ae5e8` | read-only incident-label and case-structure inspection |
| `smartbugs/smartbugs-curated` | `230e649123477eff332742a59a1c7cc6dc286cab` | local fixture inspection and derived analysis only |
| `crytic/slither` | `050cc0a094e77bfd58e8228ae3bb6aa15c65edb4` | pinned isolated CLI baseline |

The temporary checkout root was `/tmp/chronosaudit-pilot.IbfMjc`. It is not a
canonical artifact and may be removed by the operating system. The immutable
revision IDs and derived outputs above are the preserved identifiers.

## Preflight disposition

- DeFiHackLabs: `.gitmodules`, fork tests, RPC endpoints, and helpers invoking
  `cast` were identified and blocked from execution.
- SmartBugs Curated: Solidity inputs were treated as untrusted fixtures; no
  repository script or build entry point was executed.
- Slither: repository instructions were treated as untrusted input. CI
  download-and-execute paths, Docker downloads, benchmark helpers, shell-based
  test utilities, and cleanup targets were blocked.
- Allowed slice: install the dependencies frozen by Slither's inspected lockfile
  into an isolated environment, then run only the Slither CLI against selected
  local fixture files.

## Environment and commands

- Host: macOS arm64
- `uv`: `/Users/rainbow/.local/bin/uv`
- Isolated environment: `/tmp/chronosaudit-slither-venv`
- Python selected by the frozen environment: CPython `3.13.13`
- Slither: `0.11.6`
- `solc-select`: `1.2.0`
- Solidity compilers: `0.4.19`, `0.4.24`
- Foundry present: `1.5.1-stable`; not used for replay
- Docker binary present; daemon unavailable and not used

The dependency environment was instantiated from the inspected Slither lockfile:

```sh
UV_PROJECT_ENVIRONMENT=/tmp/chronosaudit-slither-venv uv sync --locked --no-dev
VIRTUAL_ENV=/tmp/chronosaudit-slither-venv solc-select install 0.4.19
VIRTUAL_ENV=/tmp/chronosaudit-slither-venv solc-select install 0.4.24
```

The analysis pattern was:

```sh
VIRTUAL_ENV=/tmp/chronosaudit-slither-venv solc-select use <required-version>
/tmp/chronosaudit-slither-venv/bin/slither <frozen-local-fixture> --json <research-case-output>
```

Slither returns a nonzero process status when findings exist. The preserved JSON
field `success=true` was therefore used to distinguish successful analysis from
process-exit convention.

## Determinism and output checks

- SimpleDAO was analyzed twice under the same frozen environment. Both JSON
  files are byte-identical with SHA-256
  `8ec971c332de8ed017e08843d01e4b388b87b3c6f4a81ca9511164d096c92171`.
- The two TokenBank fixture paths were normalized twice with
  `normalize_solidity.py`; each run produced a 1000-byte result with normalized
  SHA-256 `7128a161d626f9cf1c033252250e7e55a0d56559bc910525ba858e2ba654c50e`.
- Each preserved Slither JSON file parses successfully and reports
  `success=true`.

## Limitations

The environment is an internal pilot environment rather than a released
container. This ledger does not prove reproducibility on another host, semantic
clone equivalence, adequacy of Slither as an exploit detector, MANDO-LLM
reproducibility, or availability and cost of historical chain artifacts.
