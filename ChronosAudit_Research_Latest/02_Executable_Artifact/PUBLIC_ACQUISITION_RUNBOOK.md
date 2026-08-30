# Public Acquisition Runbook

This workflow is public-only, resumable, and fail-closed.

- `plan` is always offline and always writes the full 417-case queue plus the pilot shortfall audit.
- `inventory`, `rpc`, `denominator`, and `run-public` require explicit `--execute` before they may touch the network.
- `inventory`, `rpc`, `denominator`, `controls`, `review-packets`, `project`, and `verify` require explicit `--run-id` or `--latest`. They never silently attach to the latest run.
- Every run writes revisioned, non-overwriting outputs under:
  - `raw/public_acquisition/<revision>/<run_id>/`
  - `processed/public_acquisition/<revision>/<run_id>/`
  - `reports/public_acquisition/<revision>/<run_id>/`
- The scientific acquisition ledger is append-only at `raw/public_acquisition/<revision>/<run_id>/acquisition_events.jsonl`.
- `run_state.json` is atomically replaced after every command cell.

## Safe Commands

```bash
cd 02_Executable_Artifact
uv sync --locked
uv run python run_public_evidence_acquisition.py plan
uv run python verify_public_evidence_acquisition.py --latest
```

Optional user-supplied local-fixture example from the package root:

```bash
uv run python run_public_evidence_acquisition.py run-public --execute \
  --inventory-spec-file /absolute/path/to/public_inventory_spec.json \
  --rpc-fixture-file /absolute/path/to/public_rpc_fixture.json \
  --source-file /absolute/path/to/public_denominator_source.csv \
  --max-cases 417 --max-pages 1 --max-bytes 10485760 --deadline-seconds 21600
```

## Execute Prerequisites

- `inventory --execute` requires a bounded public source spec via `--inventory-spec-file`. The spec must point only to public Chainlist, S3 listing, Sourcify, or deployment-export inputs.
- `rpc --execute` requires a bounded public RPC fixture/source via `--rpc-fixture-file` in this offline-tested path.
- If `--rpc-fixture-file` is omitted, the command uses the configured public provider registry and may remain `partial` or `waiting_external` depending on cutoff/provider evidence.
- `denominator --execute` requires either:
  - a copied deployment export from `inventory --execute`, or
  - an explicit normalized CSV/Parquet input via `--source-file`
- `run-public --execute` threads those same prerequisites through one serial run. If any required source is absent, the run stops as `waiting_external`; if some stages execute but evidence remains short or partial, it stops as `partial`. It does not fabricate missing evidence.

## Subcommands

- `plan`: offline canonical queue construction and pilot shortfall audit.
- `inventory`: public inventory capture. Dry-run unless `--execute`.
- `rpc`: public RPC evidence acquisition. Dry-run unless `--execute`.
- `denominator`: public denominator materialization. Dry-run unless `--execute`.
- `controls`: deterministic control-candidate preparation from any materialized denominator.
- `review-packets`: blinded packet generation for positive and control review.
- `project`: counter projection, manifest binding, and release-predicate projection.
- `verify`: independent structural and scientific completeness verification.
- `run-public`: serial orchestration of the full public-only workflow.

## Resume

- Resume the latest run for a revision:

```bash
uv run python run_public_evidence_acquisition.py rpc --latest --execute --max-cases 25
uv run python run_public_evidence_acquisition.py project --latest
uv run python verify_public_evidence_acquisition.py --latest
```

- Resume a specific run explicitly:

```bash
uv run python run_public_evidence_acquisition.py rpc --run-id <run_id> --execute
uv run python run_public_evidence_acquisition.py controls --run-id <run_id>
uv run python verify_public_evidence_acquisition.py --run-id <run_id>
```

- Create a new run only with `plan` or `run-public`.
- Reuse an existing run only with explicit identity:
  - `--latest` for the newest run within a revision
  - `--run-id <run_id>` for a specific run

## Scientific Interpretation

- The canonical public corpus currently contains only one Arbitrum case.
- A 9-case pilot with `allocation_satisfied: false` for Arbitrum is structurally valid but scientifically incomplete.
- The verifier must not fabricate a tenth pilot case and must not promote any research phase automatically.
- Attempted RPC coverage, reviewer packet generation, and control-candidate preparation do not increment scientific counters by themselves.
- Dry-run or planned `run-public` output may report `status: incomplete`.
- `run-public --execute` may finish as `waiting_external`, `partial`, or `complete` when the command exits normally; integrity failures remain nonzero instead of returning a successful status payload.
- Structural validity with incomplete evidence exits `0` and reports:
  - `structure_valid: true`
  - `scientifically_complete: false`
- Tamper, schema, hash-chain, manifest, or counter-integrity failures exit nonzero.

## Endpoint and Rate-Limit Handling

- Remove dead or noisy public endpoints by editing the public provider registry candidates or by rerunning with a different public fixture/source before continuing.
- If a public endpoint rate-limits, stop expanding scope. Resume the same run later with a tighter `--max-cases`, a smaller deadline budget, or a different public candidate source.
- Independent provider-family evidence is still required for scientific closure. Two URLs from one operator do not satisfy that gate.

## Disk and Artifact Hygiene

- Raw responses, manifests, and verification reports are revisioned and must not be overwritten in place.
- If disk pressure rises, archive completed run directories externally before deleting anything local.
- Do not delete or rewrite `acquisition_events.jsonl`; start a new run revision if a clean ledger is required.

## External Review Handoff

- Reviewer packets are written as blinded JSON bundles in the run report directory.
- Human review artifacts remain external dependencies until accountable identities, conflict checks, decision hashes, and finalized adjudications are bound back into the run.
- External review absence is scientifically incomplete, not a structural verifier failure.
