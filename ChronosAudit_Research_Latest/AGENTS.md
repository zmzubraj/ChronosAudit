# ChronosAudit continuation rules

Load and follow `/Users/rainbow/.codex/AGENTS.md` first. These project rules have higher priority for this workspace.

## Single active-context authority

- Start every new ChronosAudit task by reading `CONTINUE_HERE.md`.
- Treat `CONTINUE_HERE.md` as the only human-readable continuation and current-status document.
- Do not preload or summarize recovery directories, historical reports, command logs, `.worktrees/`, raw evidence, processed evidence, or prior chat memory.
- Open another artifact only when `CONTINUE_HERE.md` names it as a verification source or the current user request requires it.
- Machine-readable verifier outputs outrank prose when a named counter must be reverified.

## Preservation boundary

- Recovery runs, historical reports, manifests, hashes, and evidence artifacts are provenance. They are non-authoritative for current context but must not be deleted, rewritten, merged, or relabeled merely to reduce context.
- Do not create a new recovery lineage or parallel continuation document unless the user explicitly authorizes it.
- Preserve the Recovery3 denominator lineage and the additive authority bridge; do not silently replace or merge it.
- AI-only adjudication never increments or substitutes for independent human adjudication.

## Maintenance contract

- After a verified status change, update `CONTINUE_HERE.md` in the same task.
- Keep its counter table, current blockers, next-work queue, evidence pointers, revision date, and change note synchronized.
- Historical prose reports may remain unchanged; if edited, label them historical and point back to `CONTINUE_HERE.md`.
- Do not claim release readiness while any required gate remains open.
