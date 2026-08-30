# ChronosAudit GitHub export scope

## Purpose

This document defines the boundary of the private GitHub-compatible ChronosAudit snapshot created on 30 August 2026. The export is a research/source repository, not a byte-for-byte archive of the approximately 49 GB local workspace.

## Included

- Current main-program source, command-line entry points, tests, schemas, and configurations.
- Current and historical manuscripts, research reports, figures, QA outputs, provenance, and build scripts.
- GitHub-compatible processed evidence and verification/report artifacts.
- The complete TemporalClone MPP repository content, excluding its nested Git metadata and transient Python caches.
- Original `research-case/` and intake documents.
- Existing signatures, public keys, hashes, manifests, ledgers, and fail-closed status records that fall inside the export boundary.

## Intentionally excluded

| Boundary | Reason |
|---|---|
| All nested `.git/` directories | The export has one fresh repository history; source commit provenance is recorded separately. |
| `.worktrees/` and `.superpowers/` runtime directories | Local orchestration/checkouts rather than portable research artifacts. Reviewed specifications under `docs/superpowers/` remain included. |
| Virtual environments, caches, `.coverage`, `.DS_Store`, and compiled Python files | Machine-local or reproducible transient outputs. |
| Every `.env` file and private-key filename pattern | Credentials and secrets must never enter Git history. |
| `ChronosAudit_Research_Latest/02_Executable_Artifact/raw/` | Approximately 49 GB local raw acquisition/RPC evidence, including provider-sensitive material and files outside practical GitHub limits. |
| `.../control-trace-only-activation-v1/pre-target-count-fix/` | Four source files were not readable by the current OS user; the directory is historical pre-fix material and was not bypassed or copied. |
| Three 2026-08-08 provider inventory/run log files | Static scan detected provider URL credential-like suffixes. The exact files were excluded rather than altered: `run_state.json`, `inventory_manifest.json`, and `command_logs/chronosaudit-task6-inventory-20260808T122732Z/stdout.json` under `public-acquisition-20260808T122104Z-2942b2819e08/`. |
| `processed/.../denominator_prepared/001-contract_deployments_43000000_44000000.csv` | 207,408,686 bytes, exceeding the export's 90 MiB per-file ceiling. Its lineage remains represented by manifests and reports. |

## Security scan interpretation

- No GitHub access token or private-key block pattern was detected in the export candidate.
- A repeated 92-character `sk-...` value was classified as a hyphenated ChronosAudit incident identifier, not an API credential; it is retained as research data.
- Provider URL suffix patterns in two test files are deliberately synthetic test fixtures and are retained.
- Provider URL suffix patterns in the three historical run/inventory logs listed above were conservatively treated as credential-bearing and excluded.
- The final staged repository must pass the same filename and content-pattern scans before push.

## Scientific limitation

This export preserves a reproducible research control surface and the GitHub-compatible evidence bundle. It does not independently reproduce excluded raw evidence, establish redistribution rights, authorize public release, or promote any scientific gate.

